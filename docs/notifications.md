# Notifications: Slack + generic webhook + email

Failed runs no longer land silently in `/runs`. Every workflow can route terminal status alerts to a Slack incoming webhook, a generic JSON webhook, or an SMTP email address, opt-in per workflow with per-route status filters.

## Quick start

1. Store each Slack webhook URL, SMTP password, or webhook auth header as a vault credential under `/credentials/new` in the destination tenant.
2. Open `/notifications` in the dashboard. Click **Add channel**, pick a kind, fill in the non-secret fields, and select the credential ID.
3. Click **Send test** on the new channel row to verify config without waiting for a real failure.
4. Open any `/workflows/{slug}` page and use the **Attach channel** form in the Notifications section.

The default route fires on `failed,failed_dlq`. An operator can broaden to `failed,failed_dlq,succeeded` for positive confirmations or narrow to `failed_dlq` only.

## Schema

The original two tables were added by migration 0011. Migration 0069 adds
`notification_dispatches` and `notification_deliveries` for durable route
snapshots and per-channel receipts, plus `runs.terminal_generation` so a
same-status dead-letter redrive is a new notification event. These ledger tables
store run, tenant, workflow, channel, status, generation, and timestamps only;
they never copy channel config or resolved vault values.

### `notification_channels`

| Column | Type | Notes |
|---|---|---|
| id | text PK | `nch_<hex>` |
| tenant_id | text NOT NULL | owning tenant, defaults to `default` |
| name | text | operator-chosen, UNIQUE **per tenant** |
| kind | text CHECK | `slack_webhook` \| `generic_webhook` \| `email_smtp` |
| config_json | text/jsonb | per-kind shape (see below) |
| created_at / updated_at | timestamp | |

`UNIQUE (tenant_id, name)`, so two tenants may each own a channel called
`ops-slack`. A duplicate inside one tenant returns `journal.ErrChannelNameTaken`,
which the dashboard renders as "you already have a channel named ...".

Reads are scoped accordingly. `/notifications` is admin-gated and admin is a
global role, so that page intentionally lists every channel in the install. The
member-facing workflow detail page uses `ListNotificationChannelsByTenant` for
its attach-channel picker, scoped to the workflow's owning tenant.

### `workflow_notification_routes`

| Column | Type | Notes |
|---|---|---|
| workflow_id | text FK CASCADE | |
| channel_id | text FK CASCADE | |
| on_statuses | text | comma-separated CSV; normalised on write (trim + lowercase + dedupe + sort) |
| created_at | timestamp | |

Primary key on `(workflow_id, channel_id)` so re-attaching the same pair upserts the status set.

## Channel kinds

### `slack_webhook`

```json
{ "url_credential_id": "cred_slack" }
```

The dashboard and MCP creation paths require a same-tenant vault credential reference. The webhook URL is resolved in memory immediately before sending.

Sender emits a Block Kit message:

- Header block: `[Reactor FAIL] demo-workflow: failed_dlq`
- Section block with markdown body (workflow, run id, trigger, status, started, duration)
- Optional "Open run" action button when `REACTOR_DASHBOARD_URL` is set

### `generic_webhook`

```json
{
  "url": "https://example.com/reactor",
  "header_name": "X-Auth-Token",
  "header_credential_id": "cred_hook"
}
```

Sender POSTs terminal metadata with snake_case JSON tags:

```json
{
  "run_id": "run_5b06a401ff4bd96d",
  "terminal_generation": 1,
  "notification_channel_id": "nch_ops",
  "workflow_id": "wf_demo",
  "workflow_slug": "demo-workflow",
  "status": "failed_dlq",
  "trigger_kind": "webhook",
  "started_at": "2026-05-31T19:14:07.172Z",
  "finished_at": "2026-05-31T19:14:08.012Z",
  "dashboard_url": "https://reactor.example.com/runs/run_5b06a401ff4bd96d"
}
```

`Content-Type: application/json`. `User-Agent: reactor-notifier/1.0`. Per-route auth headers are forwarded verbatim.

### `email_smtp`

```json
{
  "host": "smtp.gmail.com",
  "port": 587,
  "username": "alerts@example.com",
  "password_credential_id": "cred_smtp",
  "from": "alerts@example.com",
  "to": "ops@example.com, oncall@example.com",
  "starttls": true
}
```

`port` defaults to 587. Port 587 requires STARTTLS by default: if the server does not advertise it or TLS validation fails, Reactor sends neither credentials nor a message. Port 465 uses certificate-verified implicit TLS; MCP-created channels store `starttls:false`, and explicit `starttls:true` is rejected. On other ports, MCP-created channels request STARTTLS by default; legacy/operator configs with `starttls` omitted use plain SMTP. The `to` field accepts comma-separated recipients. The sender uses SMTP PLAIN authentication when a username is configured.

The email body is plain text mirroring the Slack message's content.

Raw step error text is omitted from Slack, generic webhook JSON, and email
notifications. Errors may contain credentials or other untrusted data. The run
ID, status, and dashboard link remain available so operators can inspect the
error in Reactor's authenticated run view. This is a fixed egress policy; channel
configuration cannot enable raw error delivery.

The dashboard and MCP creation paths reject plaintext credentials. With journal payload encryption enabled, new channel configs are sealed at rest and bound to their tenant and channel identity. Existing version-zero channels may still contain inline plaintext and need migration to vault references. For referenced channels, the notifier checks that the credential still belongs to the channel's tenant and resolves it from the vault at send time, including **Send test**. A missing or cross-tenant credential fails the send closed.

## Fire path

Every workflow run that lands in a terminal status (`failed`, `failed_dlq`, `succeeded`) drives the dispatcher's `OnTerminal` callback. The daemon calls `notifier.NotifyClaimed(ctx, event, terminalEffectClaim)`. The notifier:

1. Freezes the matching channel IDs once for the run's current terminal generation under the exact terminal-effect claim. Route changes during a retry do not add or remove recipients from that generation. A deleted destination is recorded as skipped and never sent after deletion.
2. Reads pending destinations in pages of at most 16 configs, and fans out with at most 16 concurrent sends across the notifier instance. Each send has a 5-second timeout by default; capacity exhaustion defers unattempted channels for a terminal-effect retry.
3. Records each confirmed channel send separately. A failed channel stays pending while successful peers are excluded from the next retry. The outer `terminal_effects` receipt is acknowledged only after every snapshot recipient was delivered or explicitly skipped; the database rejects an old daemon's acknowledgement while active routes or pending receipts lack a completed snapshot.

Route snapshots are capped at **256 routes per workflow** (including routes for
other statuses), and a legacy status filter longer than 4 KiB is rejected before
materialization. If a workflow exceeds either bound, terminal notification
delivery remains retryable and the daemon logs the error. An operator can reduce
the route count or shorten the status filter; the next terminal-effect retry
will create the snapshot. No recipient is silently truncated.

External delivery is **at least once**. A provider may accept a send just before
the process crashes or the receipt write fails; that channel can be sent again.
Generic webhook receivers that require deduplication can key on `run_id`,
`terminal_generation`, and `notification_channel_id` (legacy terminal rows may
omit a zero generation). Configuration remains attached to the channel, so an operator
may update or remove a destination after the membership snapshot; a removed
channel is skipped rather than contacted.

Migration 0069 is a coordinated daemon upgrade boundary. An older daemon can
still attempt a send, but the database refuses its terminal-effect
acknowledgement when a workflow has routes or an unfinished snapshot. Drain old
terminal handlers before enabling the new schema and restart them on the new
binary; a mixed-version period can repeat provider sends while old handlers
retry. The migration does not backfill success receipts for alerts sent before
the upgrade.

`suspended` runs do not fire notifications. Only terminal statuses do.

## Operator surfaces

### `POST /notifications/{id}/test`

Fires a synthetic alert via the channel:

```json
{
  "run_id": "test_20260601T191407Z",
  "workflow_slug": "(test channel)",
  "status": "test",
  "trigger_kind": "test"
}
```

Operators run this immediately after creating a channel so they catch misconfiguration before a real failure surfaces.

### `POST /notifications/{id}/delete`

Refuses with `409 Conflict` when any workflow route still references the channel. Error message: `notification channel has active routes: N workflow(s) routed; detach the per-workflow routes first`.

### Per-workflow attach

`POST /workflows/{slug}/notifications` with form fields `channel_id` and `on_statuses` (CSV). The form on `/workflows/{slug}` excludes already-attached channels from the dropdown so an operator does not accidentally double-route.

## Status CSV normalisation

The CSV is normalised on write: trimmed, lowercased, deduplicated, sorted. `"Failed, failed_dlq, FAILED"` becomes `"failed,failed_dlq"`. This means two callers with the same intended set always produce identical rows.

Valid status values: `succeeded`, `failed`, `failed_dlq`. Other values are accepted but never match the dispatcher's terminal event so they silently no-op.

## Dashboard URL for clickable links

`REACTOR_DASHBOARD_URL` (env var) is the base URL the notifier uses to render "Open run" buttons in Slack messages and `dashboard_url` in webhook payloads. When unset, defaults to `http://<listen-addr>`. Operators behind a reverse proxy should set this explicitly.

## Cascade on workflow delete

The `DeleteWorkflow` transaction explicitly drops `workflow_notification_routes` rows for the workflow. Channel rows are untouched (a channel can route many workflows; deleting one should not orphan the others). Channels are FK-constrained so cascading still works if the explicit DELETE is bypassed.

## Tests

- Journal: channel CRUD, upsert normalisation, status filter, delete-in-use rejection, cascade-on-workflow-delete, empty-statuses rejection.
- Notifier: fanout, aggregate sender errors, unregistered-kind errors, `TestChannel` delivery, Slack + webhook POST round-trip, non-2xx surfacing, empty-URL rejection, per-send timeout honoured.
- Server: page renders, bad Slack URL 422, happy path 303, test button 503 when notifier nil, per-workflow attach + list + detach round-trip.
- Dispatcher integration: drives the OnTerminal closure with a synthetic TerminalEvent and asserts the receiver got the right JSON.
