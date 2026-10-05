# REST API reference

The dashboard's URL surface doubles as an HTTP API for CI scripts, programmatic clients, and third-party integrations. Every endpoint accepts the same auth modes the dashboard does ([cookie](#authentication), Bearer token, or HTTP Basic) and returns the same status codes.

This page is the canonical reference. For the per-page UI walkthrough, see [Dashboard pages + endpoints](/docs/dashboard).

## Authentication

Three credential shapes work on every endpoint except the public ones listed below.

### Session cookie (`reactor_sess`)

Minted by:

```sh
curl -i -X POST https://reactor.example.com/login \
  -H "Origin: https://reactor.example.com" \
  -d "username=$YOUR_USER&password=$YOUR_PASSWORD&next=/"
# HTTP/1.1 303 See Other
# Set-Cookie: reactor_sess=<base64>; Path=/; HttpOnly; SameSite=Strict
# Location: /
```

Resubmit on every subsequent request:

```sh
curl --cookie reactor_sess=<base64> https://reactor.example.com/runs
```

Lifetime: 7 days. `POST /logout` destroys the row.

### Bearer token

Minted at `/tokens` in the dashboard. The raw token (`rtr_<base64>`) is shown exactly once at mint time.

```sh
curl -H "Authorization: Bearer rtr_YOUR_TOKEN_HERE" \
  https://reactor.example.com/runs
```

Tokens have the same role/permissions as the issuing user. Revoke with `POST /tokens/{id}/revoke`.

### HTTP Basic

Falls back to user-table authentication when at least one user exists, and to the legacy env-var BasicAuth (`REACTOR_BASIC_AUTH_USER` + `REACTOR_BASIC_AUTH_PASSWORD_SHA256`) on fresh deployments.

```sh
curl -u "$YOUR_USER:$YOUR_PASSWORD" https://reactor.example.com/runs
```

### Public endpoints (no auth)

- `GET /healthz`
- `GET /readyz`
- `POST /webhook/{token}` (HMAC verified per provider)
- `POST /command-webhook/{token_id}` (HMAC verified command-automation ingress)
- `POST /signal/{token}` (128-bit capability)
- `GET /login`
- `GET /docs`, `GET /docs/{page}`
- `GET /assets/*`

`POST /mcp` is not public. When the MCP server is exposed, it remains behind
the authenticated admin gate and the configured MCP capability scopes. Native
MCP clients should use a dedicated `REACTOR_MCP_TOKEN` bearer or a user API
token; browser sessions are not a portable client credential.

## Common request conventions

- **Content type for form POSTs:** `application/x-www-form-urlencoded`.
- **Origin header for state-changing methods:** required. The CSRF middleware rejects POST/PUT/PATCH/DELETE without `Origin` (or matching `Referer`) on every endpoint except the public ones above.
- **Slug shape:** `^[a-z][a-z0-9-]*$`. Validated at every handler entry.
- **Status filter values:** `running` | `succeeded` | `failed` | `failed_dlq` | `suspended`.

## Common response conventions

- **Form POST success:** `303 See Other` + `Location` header pointing at the result page.
- **Form POST validation failure:** `400 Bad Request` or `422 Unprocessable Entity` with a plain-text error message in the body.
- **Conflict:** `409 Conflict` with a remediation hint (e.g. "channel has 3 active routes; detach first").
- **Capability not wired:** `503 Service Unavailable` with an explanatory message.
- **JSON responses** (used by `/healthz`, `/readyz`, `/graph.json`, `/metrics`) set the right Content-Type.

## Endpoint catalogue

### Runs

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/healthz` | - | 200 `{"ok": true, "version": "..."}` |
| GET | `/readyz` | - | 200 when database, artifact store, HTTP MCP, and the serve runtime are ready; 503 otherwise |
| GET | `/metrics` | - | 200 Prometheus text format |
| GET | `/` | - | 200 HTML home (redirects to `/onboarding` if no workflows) |
| GET | `/runs` | query: `workflow_id`, `status`, `limit`, `offset` | 200 HTML list |
| GET | `/runs/{id}` | - | 200 HTML detail, 404 if missing |
| GET | `/runs/{id}/tail` | - | 200 `text/event-stream` SSE |
| POST | `/dlq/{id}/retry` | - | 303 to run detail, 404 if missing |
| GET | `/dlq` | `limit`, `offset` | Admin dead-letter queue HTML page |

### Workflows

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/workflows/{slug}` | - | 200 HTML detail |
| POST | `/workflows` | multipart: `slug`, `tarball` | 303 to `/workflows/{slug}` |
| POST | `/workflows/{slug}/code` | form: `body` (Go source) | 303 after rebuild/register, or 404/409/422/503 with validator, source-integrity, or capability output |
| POST | `/workflows/{slug}/dag` | form: `body` (DAG JSON); admin may add `?tenant=` for a same-slug tenant | 303, 404, 409, 422, or 503 |
| POST | `/workflows/{slug}/run` | form: `payload` (JSON, optional) | 303 to `/runs?workflow_id=...` |
| POST | `/workflows/{slug}/enable` | - | 303 |
| POST | `/workflows/{slug}/disable` | - | 303 |
| POST | `/workflows/{slug}/delete` | - | 303, 403 (non-admin), 409 (active runs) |
| POST | `/workflows/{slug}/minutes-saved` | form: `minutes` (int >= 0) | 303 |

### Triggers

`POST /workflows/{slug}/triggers` switches on a `kind` form field.

| `kind` | Required fields | What |
|---|---|---|
| `webhook` | `provider` | Mints token + 32-byte HMAC secret. Secret shown once through the encrypted flash handoff on the redirect target. |
| `cron` | `spec`, optional `timezone` | 5-field standard cron with optional IANA tz prefix. |
| `chain` | `source_slug`, optional `on_statuses` (default `succeeded`) | Fires this workflow whenever `source_slug` terminates with a matching status. |

Trigger management:

| Method | Path | What |
|---|---|---|
| POST | `/workflows/{slug}/triggers/{trigger_id}/delete` | Hard delete. |
| POST | `/workflows/{slug}/triggers/{trigger_id}/pause` | Sets state to `disabled`. |
| POST | `/workflows/{slug}/triggers/{trigger_id}/resume` | Sets state to `active`. |
| POST | `/workflows/{slug}/triggers/{trigger_id}/edit` | Cron only: form `spec`, `timezone`. |

Public trigger ingress is outside dashboard authentication and is protected by
the trigger-specific HMAC capability:

| Method | Path | What |
|---|---|---|
| POST | `/webhook/{token_id}` | Verifies the configured provider envelope and durably dispatches or deduplicates one run. `automation-v1` and `hash-v1` are always asynchronous. |
| POST | `/command-webhook/{token_id}` | Verifies the dedicated command-automation HMAC binding, admits the exact reviewed immutable version, and queues one bounded command run. The binding is tenant-fenced, disabled by default, and replayed deliveries are deduplicated; request bodies never enter the command or durable run metadata. |
| GET | `/webhook/{token_id}/status?delivery_id=...` | `automation-v1` only. Verifies an empty-body automation signature and returns the run state bound to that trigger and delivery. Active runs return 202; terminal runs return 200; absent or incomplete receipts return 404. Responses are `no-store`. |

The status signature covers `<timestamp>.<delivery_id>.` (including the final
dot), and the sole query value must equal `X-Webhook-Delivery`. See the
[Hash e-signature bridge](./hash-esign-bridge.md#least-privilege-reconciliation)
for the complete envelope and response contract.

### Credentials

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/credentials` | - | 200 HTML list |
| GET | `/credentials/new` | - | 200 HTML form |
| POST | `/credentials` | form: `name`, `service`, `provider`, `value` | 303 |
| GET | `/credentials/{id}` | - | 200 HTML detail with audit log |
| POST | `/credentials/{id}/rotate` | - | 303 |
| POST | `/credentials/{id}/value` | form: `value` | 303 |
| POST | `/credentials/{id}/grants` | form: `workflow_id` (slug or id) | 303 |
| POST | `/credentials/{id}/grants/{workflow_id}/revoke` | - | 303 |

### Notifications

See [Notifications](/docs/notifications) for the per-kind config shapes.

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/notifications` | - | 200 HTML |
| POST | `/notifications` | form: `name`, `kind`, per-kind fields | 303 or 422 |
| POST | `/notifications/{id}/delete` | - | 303, 409 if routed |
| POST | `/notifications/{id}/test` | - | 303, 502 on send failure, 503 if notifier nil |
| POST | `/workflows/{slug}/notifications` | form: `channel_id`, `on_statuses` (CSV) | 303 |
| POST | `/workflows/{slug}/notifications/{channel_id}/delete` | - | 303 |

### Knowledge

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/knowledge` | - | 200 HTML list |
| GET | `/knowledge/{id}` | - | 200 HTML detail |
| POST | `/knowledge` | form: `topic`, `title`, `tags`, `body` | 303 |
| POST | `/knowledge/{id}/promote` | - | 303 |
| POST | `/knowledge/{id}/stale` | - | 303 |
| POST | `/knowledge/{id}/supersede` | form: `superseded_by` | 303 |

### Audit + graph

| Method | Path | Returns |
|---|---|---|
| GET | `/audit` | 200 HTML aggregated credential audit |
| GET | `/graph.json` | 200 JSON environment graph (admin-only raw diagnostic export) |

### Auth + identity

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/login` | - | 200 HTML form |
| POST | `/login` | form: `username`, `password`, `next` | 303 + `Set-Cookie: reactor_sess=...` |
| POST | `/logout` | - | 303 + cookie clear |
| GET | `/tokens` | - | 200 HTML list (callers own tokens only) |
| POST | `/tokens` | form: `name`, optional `ttl_days` (1-3650; default 90) | 303 + one-time capability cookie; the raw token stays in encrypted flash storage until the redirect GET consumes it |
| POST | `/tokens/{id}/revoke` | - | 303 |
| GET | `/users` | - | 200 HTML, admin-only |
| POST | `/users` | form: `username`, `password`, `role` | 303 or 422 |
| POST | `/users/{id}/role` | form: `role` | 303 or 409 (last admin) |
| POST | `/users/{id}/disable` | - | 303 or 409 |
| POST | `/users/{id}/enable` | - | 303 |
| POST | `/users/{id}/delete` | - | 303 or 409 |

### Generate (codegen)

When the daemon was started with `ANTHROPIC_API_KEY` set:

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/generate` | form: `brief` (plain-English description), `tenant_id` (admin-selected target; defaults to `default`) | 303 to `/workflows/{slug}?tenant={tenant_id}` after 15-45s with the workflow staged disabled, or 500 with validator output |

The generated artifact remains disabled until an administrator reviews the
source + visual flow and enables it from the workflow page. Activation also
requires the immutable artifact and retained source/DAG manifest to verify
(`artifact_status: "verified"`, `source_dag_status: "verified"`, and
`visual_complete: true`); missing or legacy source remains inspectable but is
not dispatch-ready. This key-only gate applies to operator-requested code generation, not AI
post-mortems. Failed-run diagnostic egress remains off unless
`REACTOR_AI_POSTMORTEM_ENABLED=true` is also set; see
[Operations](/docs/operations#ai-post-mortem-egress).

### Webhook delivery + signal callbacks (public)

| Method | Path | What |
|---|---|---|
| POST | `/webhook/{token}` | Provider-specific HMAC verification for Stripe (`Stripe-Signature`), GitHub (`X-Hub-Signature-256`), generic (`X-Webhook-Signature: sha256=hex`), signed `automation-v1`, and Hash lifecycle `hash-v1`. See [Triggers](#triggers) and the [Hash bridge contract](/docs/hash-esign-bridge). |
| POST | `/signal/{token}` | 128-bit capability token; body must be valid, non-empty JSON and becomes the resumed workflow's `AwaitSignal` payload. Payloads over 960 KiB are rejected with `413` so the resume frame remains within the wire budget; malformed or empty JSON returns `400`. |

### MCP transport

| Method | Path | What |
|---|---|---|
| POST | `/mcp` | Streamable HTTP MCP transport per protocol version `2025-03-26`. Accepts single requests or batches up to 128 requests and a 1 MiB body; serialized responses are capped at 4 MiB and one request has a 150-second cumulative execution deadline; notifications return `202` with no body. |

See [MCP server + tool reference](/docs/mcp) for the tool catalogue.

## Error response shape

Plain text body with an HTTP status code. Example:

```http
HTTP/1.1 409 Conflict
Content-Type: text/plain; charset=utf-8

cannot delete: 2 active routes reference this channel; detach the per-workflow routes first
```

For JSON-RPC errors on `/mcp`, the body is a standard JSON-RPC envelope:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "invalid request"
  }
}
```

## Rate limiting

Per source IP. Defaults: 60-token burst, 10 tokens/second refill. Tunable via `REACTOR_RATE_BURST` and `REACTOR_RATE_REFILL`. `429 Too Many Requests` + `Retry-After: 1` when the bucket is empty.

The limiter map evicts idle buckets after 10 minutes and caps at 50,000 entries; a botnet or IPv6 spray cannot OOM the daemon.

## Trusted proxies

`X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` are honoured only from loopback or an explicitly configured proxy socket peer. Set `REACTOR_TRUSTED_PROXY_CIDRS=10.4.5.9` (or `--trusted-proxy-cidrs 10.4.5.9`) when the proxy reaches Reactor from that address; exact IPs and CIDRs are accepted. Prefer exact `/32` or `/128` proxy addresses. Do not include direct client addresses in the allowlist; all-address `/0` ranges are rejected. Reactor validates a bounded `X-Forwarded-For` chain and selects the nearest untrusted hop, so a client-supplied prefix cannot select a new rate-limit identity when a trusted proxy appends to the header. The separate `--mcp-trusted-proxy` flag only asserts a TLS-terminating proxy for non-loopback plain HTTP; it does not configure forwarded-header trust or restrict who can reach the listener.

## Build a workflow programmatically

```sh
# Mint a token in the dashboard, then:
TOKEN="rtr_..."
BASE="https://reactor.example.com"

# 1. Register a workflow from a tarball.
curl -X POST "$BASE/workflows" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: $BASE" \
  -F "slug=hourly-report" \
  -F "tarball=@build/hourly-report.tar.gz"

# 2. Attach a cron trigger.
curl -X POST "$BASE/workflows/hourly-report/triggers" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: $BASE" \
  -d "kind=cron&spec=0+*+*+*+*&timezone=UTC"

# 3. Manually dispatch a one-off run.
curl -X POST "$BASE/workflows/hourly-report/run" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: $BASE" \
  -d 'payload={"hello":"world"}'

# 4. Tail the run via SSE.
RUN_ID=$(curl -s "$BASE/runs?workflow_id=...&limit=1" \
  -H "Authorization: Bearer $TOKEN" \
  | grep -oE 'run_[a-f0-9]+' | head -1)
curl --no-buffer "$BASE/runs/$RUN_ID/tail" \
  -H "Authorization: Bearer $TOKEN"
```
