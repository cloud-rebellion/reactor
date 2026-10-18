# Flare incident delivery

A Reactor workflow can receive Flare's signed `flare.automation.v1` notices
through a `flare-v1` webhook trigger. Each trigger binds one Flare project to
one tenant-owned workflow and HMAC credential. Real notices return a durable
asynchronous run receipt; a signed channel test verifies authentication and
project binding without creating a delivery claim or workflow run.

## Configure the trigger

Review the workflow's source and retained flow, then enable the intended
immutable workflow version through the normal Reactor lifecycle. In the
dashboard, add a webhook with provider `flare-v1` and the expected Flare project
ID. Reactor generates a public token and a separate signing secret. Copy the
one-time secret exactly as displayed; the 64 ASCII hex characters are the key,
so do not hex-decode them.

For MCP setup, use a dedicated tenant-owned `reactor-webhook` / `shared-secret`
credential and the `triggers` write scope:

```json
{
  "name": "reactor_create_webhook_trigger",
  "arguments": {
    "slug": "flare-incident-draft",
    "credential_id": "flare-inbound-key",
    "provider": "flare-v1",
    "flare_project_id": "EXPECTED_FLARE_PROJECT_ID",
    "idempotency_key": "flare-inbound-setup-1"
  }
}
```

The create response returns the bearer token and
`/webhook/flare/whk_<32 lowercase hex characters>` endpoint once. Read/list
tools expose the validated project binding and token presence without
returning the token or secret. Updates require `expected_revision`; omitting
`flare_project_id` preserves an existing Flare binding. Switching another
provider to Flare requires an explicit project ID. Flare triggers always use
asynchronous dispatch, including legacy rows whose config says `sync=true`.

Configure Flare's project-routed `automation_webhook` channel with the public
HTTPS endpoint and the same signing secret. The public hostname and proxy
must be separately reviewed and deployed. Flare's outbound network policy
requires an allowed address; a loopback or Tailscale hostname is unsuitable.
Do not place the token or key in source, tickets, browser redirects or logs.

Only `/webhook/flare/{token_id}` accepts a stored `flare-v1` trigger. Other
provider tokens return 404 on that route before a secret is read. A Flare
token also returns 404 on the ordinary `/webhook/{token_id}` route. Dedicated
command-plan webhook authoring and runtime reject this provider until that
surface has equivalent project and notice policy.

## Signed request

Flare sends `Content-Type: application/json` and exactly one of each header:

```text
X-Flare-Automation-Timestamp: <canonical Unix seconds>
X-Flare-Automation-Signature: sha256=<64 lowercase hex characters>
X-Flare-Automation-Event: new_issue
```

The signature is HMAC SHA-256 using the secret's exact bytes over:

```text
<timestamp>.<exact UTF-8 request body>
```

The timestamp permits five minutes of skew. Flare's notice contains exactly
these six fields; unknown, duplicate, missing or null fields are rejected:

```json
{
  "schema": "flare.automation.v1",
  "event": "new_issue",
  "project_id": "EXPECTED_FLARE_PROJECT_ID",
  "issue_id": "ISSUE_ID",
  "event_count": 3,
  "observed_at": "2026-10-18T15:00:00Z"
}
```

The body is capped at 2 KiB. IDs are bounded ASCII identifiers, the count is
an integer from zero to 1,000,000,000, and `observed_at` must be canonical UTC
RFC3339. The event header must match the authenticated body. Supported events
match Flare's bounded alert vocabulary: `new_issue`, `regression`, `anomaly`,
`silence`, `monitor_missing`, `deploy_failure`, `deploy_acceptance`, `rollback`,
`spike`, `connector`, `release`, `service`, `log`, `usage`, `ai`, `alert`, `test`.
Issue text, stack traces and model output are not part of this notice.

## Delivery and replay

A valid `test` returns HTTP 200 with
`{"accepted":true,"test":true,"dispatched":false}`. This establishes the
signed route and project binding; it does not exercise workflow admission or
execution. A real accepted notice returns HTTP 202 with its `run_id`. Exact
body replays return HTTP 200 with the same `run_id` and `deduped:true`.

Reactor scopes the SHA-256 of authenticated body bytes to the trigger/provider
delivery ledger. Flare may re-sign the same bytes with a fresh timestamp
without starting another run. Changing unsigned delivery headers does not
change Flare's identity. In-progress deliveries return a retryable response;
existing delivery claims and completion receipts survive process restart.
The durable run also carries a trigger/body idempotency key. If a crash occurs
after the run commits but before its delivery receipt completes, a retry after
lease expiry recovers that run instead of enqueueing another one.

Before new dispatch, Reactor rechecks the active trigger, tenant, credential
and config, and retains normal workflow enabled, quota, rate, immutable
artifact and admission fences. A changed binding releases the claim; a caller
can retry against the current policy. Disabling the workflow prevents new real
runs. Replayed completed receipts can still report the already accepted run.

The receiver's run receipt proves durable acceptance, not successful workflow
completion, AI diagnosis, human approval, CI, merge or deployment. Flare's
current sender treats an HTTP success as delivery success; it does not retain
the receiver's `run_id` response. Correlate outbox and Reactor records during
acceptance, and add explicit sender-side receiver-receipt storage before
claiming a durable cross-service receipt chain.

## Release acceptance

Before enabling a production channel, require exact managed CI and release
identity, then verify a signed no-op, unsigned refusal, wrong provider/project
refusal, one real Flare outbox delivery with a matching durable Reactor run,
and replay after receiver restart without another run. Verify disabled and
changed-trigger behavior as well. The public proxy must expose only the
provider-bound path and must avoid logging token-bearing URLs. Hostname,
certificate, DNS and proxy deployment are separate managed release work.
