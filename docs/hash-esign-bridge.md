# Hash e-signature bridge

Reactor can bridge BrightCRM, Google Apps Script, or another automation producer
to Hash without making either application depend on the other. The core
`automation-v1` event and Hash command contracts are provider-neutral. Google
Apps Script is an optional optimized edge, not a runtime dependency. Hash also
remains directly callable as a standalone service through its machine API;
Reactor is required only when its authenticated normalization, workflow, retry,
and reconciliation layer is wanted.

```text
BrightCRM / Google / generic producer
              | signed canonical webhook
              v
     Reactor automation-v1 ingress
              | validate + trusted profile mapping
              v
      Hash atomic create-and-send API <--- trusted standalone client
              |                            (direct machine API)
              v
       durable signing ceremony
```

The separation is intentional:

- The producer owns customer data and a stable business-operation ID.
- Reactor owns ingress authentication, normalization, optional Google/CRM
  enrichment, retries, and the mapping from a public profile name to a Hash
  template UUID.
- Hash owns organization authorization, document construction, recipients,
  signature fields, retention, evidence, email outbox, and command idempotency.

No webhook field may select the Hash URL, organization, API key, concrete
template UUID, or arbitrary callback URL.

There are two independent call shapes:

- A trusted standalone client may call Hash directly at
  `POST /api/automation/v1/signature-requests` with its dedicated Hash bearer
  and stable `Idempotency-Key`.
- BrightCRM or another producer may persist customer data in an outbox and POST
  the signed provider-neutral `automation-v1` event below to Reactor. Reactor
  then maps the trusted profile and calls Hash. BrightCRM's managed e-sign
  action can own this producer role; a generic webhook action is compliant only
  if it implements the exact signing, strict-JSON, idempotency, receipt, and
  reconciliation contract in this document.

## Generate the workflow

```bash
reactor new hash-esign-bridge sales-partner-signing
```

The scaffold contains:

- a strict provider-neutral event decoder;
- a one-command Hash adapter;
- an operator-owned `templateProfiles` allowlist;
- one durable create-and-send Step;
- an optional Google Apps Script HMAC producer and delivery reconciler.

Edit the generated `trustedHashBaseURL` and profile mapping, store a dedicated
Hash key in Reactor's vault, and grant that credential only to this workflow.
The key needs Hash `write:authoring` and `write:workflow` scopes.

Use `reactor vault add --name hash-esign-<workflow-slug> ... --value-file /secure/path/hash-api-key`; do not pass
the key via `--value`, where it can be exposed in process arguments or shell
history. The file must contain the exact key bytes without a trailing newline.
Create an asynchronous webhook trigger with provider `automation-v1`. Reactor
rejects synchronous mode for this provider so its durable 202/200 run-receipt
contract cannot be changed by configuration.

## Ingress contract

Send the exact UTF-8 JSON body with:

```http
Content-Type: application/json
X-Webhook-Timestamp: <current Unix seconds>
X-Webhook-Delivery: <stable event_id>
X-Webhook-Signature: sha256=<64-character lower-case HMAC-SHA256 hex>
```

The signed bytes are exactly
`<timestamp>.<X-Webhook-Delivery>.<raw UTF-8 body>`. Reactor allows at most five
minutes of clock skew, rejects missing or repeated envelope headers, and
requires exactly one top-level JSON `event_id` equal to the delivery header.
The ID must be 1–200 UTF-8 bytes, trimmed, and free of control characters. A
retry keeps the event ID and body unchanged but uses a fresh timestamp and MAC.
`Content-Type` must occur exactly once and have the `application/json` media
type, optionally with only `charset=utf-8`; missing, repeated, differently
encoded, or extended media types receive HTTP `415`. This strict media-type
rule is specific to `automation-v1` and does not change Reactor's generic
webhook provider.

The body schema is `sdk/esign.DocumentRequested`. The important routing fields
are:

```json
{
  "spec_version": "1.0",
  "event_id": "partner-123:deal-456:agreement-v1",
  "event_type": "esignature.document.requested.v1",
  "occurred_at": "2026-08-31T12:00:00Z",
  "source": {"provider": "brightcrm", "tenant_external_id": "partner-123"},
  "customer": {
    "external_id": "customer-789",
    "name": "Ada Lovelace",
    "email": "ada@example.com"
  },
  "document": {
    "template_key": "sales-partner-agreement-v1",
    "name": "Partner agreement",
    "variables": {},
    "recipients": [
      {
        "role": "signer",
        "name": "Ada Lovelace",
        "email": "ada@example.com",
        "signing_order": 0
      }
    ]
  }
}
```

Customer and recipient names are limited to both 300 UTF-8 bytes and 200
Unicode code points, and plain email addresses to 254 bytes. A document may
contain at most 200 string variables, each value at most 16 KiB. Variable names
are at most 200 bytes and must match `^[A-Za-z_][A-Za-z0-9_.]*$`, exactly the
syntax accepted by Hash block templates.

`occurred_at` and optional `document.expires_at` use strict RFC 3339: uppercase
`T`/`Z`, a dot-prefixed fraction of at most nine digits, and a numeric offset no
larger than `+23:59`/`-23:59`. Comma fractions, longer fractions, and `+24:00`
are rejected rather than normalized. Expiry must be at least ten minutes after
the immutable `occurred_at`. Reactor compares those two persisted timestamps,
never the replay clock, so retrying an old identical event remains valid and
cacheable. The ten-minute relationship only provides a modest transport margin:
queue or outage delay can still leave fewer than Hash's required five minutes
at fresh command admission. Omit expiry when policy permits or choose a
comfortably future deadline, and route a final Hash expiry rejection to review
without minting a new event ID.

Persist the event ID and original body with the CRM automation record. A retry
must reuse both. Email is mutable and is not an idempotency key.

For an asynchronous trigger, a fresh request returns HTTP `202` and
`{"accepted":true,"deduped":false,"run_id":"..."}` once the run is durable and
queued. It does not confirm that Hash created or sent a document. The producer
must persist `run_id` before acknowledging its outbox record. A completed
delivery replay returns `200` with `deduped:true` and the same `run_id`, allowing
a producer that crashed before persistence to recover without creating a
second run.

## Least-privilege reconciliation

The producer does not need a dashboard session, tenant-wide run access, or a
second callback secret. It polls the same trigger capability with exactly one
URL-encoded delivery query value:

```http
GET /webhook/<token>/status?delivery_id=<URL-encoded event_id>
X-Webhook-Timestamp: <current Unix seconds>
X-Webhook-Delivery: <the exact original event_id>
X-Webhook-Signature: sha256=<64-character lower-case HMAC-SHA256 hex>
```

The GET has no body. Sign the exact bytes `<timestamp>.<event_id>.`, including
the final dot, using a fresh timestamp for every attempt. The header ID must
equal the decoded query ID. Reactor applies the same five-minute clock window
and identifier bounds as ingress, requires a completed receipt, and binds the
lookup to that trigger, provider, workflow, tenant, delivery, and run.

An active run returns `202`:

```json
{"run_id":"run_...","status":"running","terminal":false}
```

A terminal run returns `200`. For the generated bridge, successful output is
projected to a narrow result with no customer fields or bearer links:

```json
{
  "run_id": "run_...",
  "status": "succeeded",
  "terminal": true,
  "hash_result": {
    "automation_request_id": "req_...",
    "document_id": "doc_...",
    "status": "sent",
    "replayed": false
  }
}
```

Failed, dead-lettered, and cancelled runs are also terminal but are not business
success. `404` means there is no currently resolvable receipt in this exact
trigger/provider/workflow/tenant scope: the delivery may be nonexistent or
incomplete, its receipt or run may have aged out under retention, or its stored
ownership/reference may be stale or mismatched. It never falls through to an
arbitrary run lookup. Responses carry
`Cache-Control: no-store`. Retry a `202`, transport failure, malformed or
ambiguous success response, 408, 425, 429, or 5xx with bounded backoff. Treat
other 4xx responses as a configuration, clock, or state error requiring
correction rather than minting a new event ID.

The producer outbox must enforce this order:

1. Build the canonical event once and durably persist its `event_id` and exact
   raw body before the first POST. A Google Sheet is suitable only when the
   full body fits a cell; use Drive, Firestore, Cloud SQL, or another durable
   store for larger events.
2. Retry only those persisted bytes and the same ID. After a receipt, persist
   `run_id` before marking delivery accepted. A crash before that write is
   recovered by reposting the original delivery and receiving its deduplicated
   run receipt.
3. Once `run_id` is stored, stop POSTing and issue freshly signed status GETs.
   Persist each bounded retry schedule/attempt so restarts resume polling.
4. Persist the terminal status and safe Hash result atomically with the CRM
   operation state. Only `succeeded` is success; route `failed`, `failed_dlq`,
   `cancelled`, malformed responses, and expired poll deadlines to review.
5. A Reactor DLQ redrive reuses the same run. After an operator redrives
   `failed_dlq`, explicitly reopen the same outbox operation and resume signed
   status GETs for the persisted `run_id`; do not POST the command again or
   mint a new event ID. Plain failed/cancelled runs remain closed unless a new
   business command is separately authorized.

Apps Script producers should use `LockService` or transactional compare-and-set
updates so concurrent time triggers cannot race the same outbox record.

## Hash command contract

Reactor maps the approved profile to a concrete template and calls:

```http
POST /api/automation/v1/signature-requests
Authorization: Bearer <dedicated Hash API key>
Idempotency-Key: <Reactor-derived workflow/step/event namespace>
```

The endpoint instantiates and sends one block-template document. Same key and
same normalized request returns the original request/document IDs. Same key
with a different request returns 409. The response contains no signing links.
That makes a worker crash after Hash commits safe: the Reactor Step can run
again and recover the same result. Reactor derives this bounded key from the
trusted workflow slug, step name, event-ID field name, and external event ID;
raw producer IDs cannot collide across bridge workflows.

Producer locales may use common regional forms such as `sv-SE` or `en_GB`.
Reactor preserves that provider-neutral value; Hash canonicalizes a supported
regional tag to its reviewed base-language catalog at the standalone API
boundary and rejects malformed or unsupported bases.

## Optional Hash lifecycle callbacks

Document creation reconciliation proves that the workflow created and sent the
ceremony. Later signer activity arrives separately through Hash's outbound
webhooks. Generate the lifecycle workflow scaffold with
`reactor new hash-esign-lifecycle <slug>`, review it, configure its fixed
trusted Hash organization and BrightCRM base URL, and create an asynchronous
`hash-v1` trigger. A generated scaffold with placeholder configuration is not
a production deployment. Register the reviewed trigger URL in Hash for `document.sent`,
`document.opened`, `document.viewed`, `document.field_filled`,
`document.signed`, `document.changes_requested`, `document.completed`,
`document.declined`, `document.voided`, and `document.expired`. Recipient kinds
and `document.created` are intentionally excluded from CRM writeback.

There is one important secret handoff. Hash generates a new per-endpoint HMAC
secret when its webhook endpoint is created; it does not adopt the temporary
secret Reactor displayed while creating the trigger. Therefore:

1. Create the Reactor `hash-v1` trigger. Its one-time result shows the trigger
   URL, backing credential ID, and a direct link to that credential. The
   Reactor-generated secret is only useful for an initial local verifier test.
2. Register that URL as the Hash webhook endpoint and capture Hash's one-time
   `secret` response over TLS.
3. Follow the credential link, use **Manual update**, and immediately replace
   the Reactor trigger credential's value with the exact 64 ASCII-hex bytes
   returned by Hash. Do not hex-decode them. The original Reactor-generated
   value is no longer used.
4. Send a test event, then retain only the normal encrypted copies in Hash and
   Reactor. Do not place either value in workflow source or logs.

Each Hash callback has exactly one canonical signature header:

```http
X-Hash-Signature: t=<canonical Unix seconds>,v1=<64 lower-case hex characters>
```

Using the exact 64 ASCII-hex secret bytes from the handoff as the HMAC key (do
not hex-decode them), Hash computes HMAC-SHA256 over
`<timestamp>.<exact raw request body>`. Leading-zero, signed, or whitespace-
padded timestamps, additional signature fields, repeated signature headers,
and non-lowercase or non-64-character digests are rejected. Reactor allows at
most five minutes of clock skew. The authenticated JSON must contain exactly
one top-level `event_id`; it must be 1–200 valid UTF-8 bytes, trimmed, and free
of control characters. Reactor uses that signed value as the delivery
deduplication key. An identical replay converges on the existing run, while
reuse of the event ID with different signed body bytes is a conflict.

After verifying the raw signed body, `hash-v1` computes deduplication from those
original bytes but projects the run input before persistence, removing the
entire Hash payload and recipient object. The generated workflow strictly binds
`org_id` and forwards only `event_id`, `kind`, `occurred_at`,
`automation_request_id`, and `document_id` to the fixed BrightCRM lifecycle
endpoint. Its bearer is a dedicated Reactor-vault credential with only the
BrightCRM `esign:lifecycle` scope. Neither URL, credential ID, nor tenant may
come from the Hash event. Org-level Hash endpoints also receive manual document
events with no `automation_request_id`; those are acknowledged as a successful
no-op and never reach the CRM. BrightCRM owns durable deduplication and
out-of-order buffering for correlated events.

Google-hosted operators may stage that tenant-specific BrightCRM bearer in
Google Secret Manager and synchronize its exact bytes into Reactor's encrypted
vault during controlled bootstrap. The workflow itself uses only Reactor's
provider-neutral vault API and does not depend on Google at runtime.

## Google optimization without lock-in

Google stays at replaceable, optional edges. None of the event fields, webhook
authentication, retry rules, profile mapping, or Hash command semantics require
a Google service:

- Apps Script can normalize Sheets, Forms, or Workspace-driven customer data,
  calculate the `automation-v1` HMAC, and call the same webhook as any CRM. The
  scaffolded adapter uses a two-phase outbox contract: persist its exact raw
  body first, then deliver/retry those bytes, persist the returned run ID, and
  poll the signed least-privilege status endpoint. It requires HTTPS, refuses
  redirects, bounds IDs and responses, strictly validates the safe result, and
  surfaces bounded Retry-After data. A status 404 after a persisted run ID is
  inconsistent state for operator review, not ordinary polling activity.
  Its preparation boundary requires a plain variable object, applies the shared
  identifier/name/email/locale/variable bounds and Hash variable-name syntax,
  validates `occurredAt` and optional `expiresAt` as RFC 3339, preserves their
  exact valid strings, and enforces the replay-stable ten-minute relationship
  before the caller persists an outbox record.
- Reactor's existing Google OAuth/Gmail adapter can perform optional enrichment
  or notifications in separate Steps.
- Hash supports generic OIDC and SMTP providers at its deployment boundary.
  Reactor does not currently provide native dashboard OIDC; an estate requiring
  centralized SSO must add a separately reviewed authenticated ingress boundary
  in addition to Reactor's own access controls.

Hash storage is not interchangeable with native Google Cloud Storage today.
Its legal evidence path depends on S3-compatible object version IDs, Object
Lock compliance retention, and legal holds. A GCS adapter must prove those
semantics before it can replace the existing storage implementation.

## Production cutover gates

The repository does not provide an estate-specific production manifest, create
cloud resources, or prove a live provider. The generic
`deploy/docker-compose.yml` is a development-only SQLite example. Before Sales
Partner data enters this bridge, record evidence for every gate below.

### Runtime topology and release

- Run Reactor in distributed mode against production PostgreSQL, with at least
  one `serve` process and one dedicated `worker`. All replicas must use the same
  database, vault master-key generation, and reviewed configuration. Verify
  migrations, PostgreSQL TLS, connection limits, lease timing, clock sync, and
  graceful drain on the actual estate. Local/SQLite recovery is suitable for
  development and evaluation but is not approved for production Hash signing.
- Build both bridge workflows from reviewed source and DAGs tied to an immutable
  Reactor release, then register them so Reactor publishes content-addressed
  SHA-256 artifacts and pins each run to its workflow version and digest. Make
  every referenced artifact visible to every worker through a read-only shared
  mount or an atomic checksum-verified distribution into a read-only execution
  root. Registration/publishing must be separated from execution; workers must
  never rewrite artifacts in place. There is no automatic artifact garbage
  collection: retain every digest referenced by a queued, running, suspended,
  or DLQ run, and alert when a pinned artifact is missing or corrupt.
- Treat the release introducing durable `dlq_pending` repair and exact DLQ step
  identity as a drained cutover, not a mixed rolling worker upgrade. Quiesce
  admission and autoscaling, drain and stop every old worker, apply migrations,
  distribute the reviewed artifacts, then start only new-version workers and
  pass restart/DLQ-redrive smoke tests before reopening customer traffic.
- Terminate public TLS at Reactor or a trusted ingress. Verify the proxy trust
  boundary and source-IP propagation, require dashboard authentication and
  secure cookies, leave permissive vault ACL mode disabled, grant each workflow
  only its named credential, and enforce a shared ingress rate limit across all
  replicas. The process-local limiter alone is not an estate-wide control.
- Set bounded run and webhook-dedup retention for the approved privacy and
  recovery windows. `REACTOR_RUN_RETENTION_DAYS` and
  `REACTOR_WEBHOOK_DEDUP_RETAIN_HOURS` must both outlive the longest BrightCRM or
  Google producer polling deadline plus the maximum operator review and
  DLQ-redrive window. Do not purge either side while an outbox operation may
  still be reopened against its persisted `run_id`. Restrict workflow logs to
  derived fingerprints, event kind,
  provider request/document IDs needed for operations, and state; never log raw
  customer bodies, signing links, secrets, or recipient payloads.
- Leave AI post-mortems off for the initial Hash production cutover. An
  Anthropic key used for dashboard code generation does not enable them. Ensure
  the opt-in is absent from every `serve`, worker, and MCP process. If the
  privacy owner later approves this separate egress, set
  `REACTOR_AI_POSTMORTEM_ENABLED=true` as well as the key, approve the configured
  endpoint/region/retention, and verify that representative signer-name, email,
  company/address/document-title, and token-shaped failures are reduced to
  fixed categories/status codes before egress. Reactor does not send raw Step
  errors, trigger bodies, or Step outputs. This is still defense-in-depth: the
  bridge must avoid putting raw customer or signing data in errors.

### Durable data and recovery

- Enable monitored PostgreSQL backups/PITR for Reactor. Preserve the matching
  Reactor master key, workflow source/DAG, compiled artifacts and checksums, and
  configuration in a protected recovery generation. A backup of `<root>` alone
  does not contain a remote PostgreSQL database. Restore into isolation and
  prove vault decryption plus execution of the pinned workflows.
- Apply and verify BrightCRM's e-sign operation/lifecycle migrations on the
  production database. Back up and restore-drill that database together with
  the exact `ENCRYPTION_KEY` generation needed to decrypt tenant Reactor
  connections and delivery payloads. Prove that retained delivery jobs,
  provider run checkpoints, e-sign operations, buffered lifecycle events, and
  deal projections survive the restore without reposting a completed command.
- Complete Hash's separate coupled PostgreSQL + S3 backup/restore launch gates.
  Its evidence store must expose S3 version IDs, COMPLIANCE Object Lock,
  retention read-back, and legal holds; native GCS is not currently a drop-in
  substitute. Also verify the production SMTP, OIDC, public URL, audit key,
  webhook-encryption key, privacy/legal configuration, and server/worker
  topology documented by Hash.
- Configure alerting for Reactor failed/DLQ runs, stalled queues and leases,
  webhook failures, BrightCRM e-sign operations in `review`, Hash email outbox
  failures, and Hash lifecycle webhook retries. Assign an operator-owned redrive
  procedure that reuses the original stable event and reviews every 409.

### Producer and ceremony acceptance

- Configure a valid Hash block template whose signature roles match the
  recipients. PDF-template automation is outside this initial contract. Mint a
  dedicated Hash API key with only `write:authoring` and `write:workflow`, and a
  dedicated tenant-bound BrightCRM lifecycle key with only `esign:lifecycle`.
- For BrightCRM, use `CREATE_ESIGN_REQUEST` and its encrypted Reactor
  connection, or a CRM automation outbox that POSTs customer data using the
  exact signed `automation-v1` contract. The legacy generic Automation
  `WEBHOOK` action is not automatically compliant and must not be treated as
  this producer unless it is extended and tested for canonical HMAC signing,
  stable IDs, durable receipts, and reconciliation. For the optional Google
  edge, restrict Apps Script editors, configure the two Script Properties with
  the exact trigger secret of at least 32 UTF-8 bytes, persist the exact prepared
  body in a durable outbox before POST, and run all embedded HMAC, strict-JSON,
  and response-Content-Type vectors after any adapter change.
- Confirm that the Sales Partner automation uses a trigger BrightCRM actually
  captures transactionally. Native capture currently covers form submissions
  and task decision/completion paths; an arbitrary lead/deal/contact trigger
  name is not activated merely by defining a rule. Use the documented external
  `automation-v1` producer path when the required source event is outside that
  native set. Configure `variable_fields` through the REST API when mappings
  beyond the visual editor's current controls are required.
- Treat ingress `202` as queued only. Persist `run_id`, reconcile the original
  event through the signed status capability, and mark success only for terminal
  `succeeded` with a valid safe Hash result. Apply an operator-owned polling
  deadline and dead-letter everything that exceeds it.
- In a non-customer environment, execute the complete create/send/open/sign/
  complete lifecycle and prove BrightCRM operation and deal projection. Then
  inject failure after ingress acceptance, after Hash commits but before the
  Step ends, before the producer stores `run_id`, and before lifecycle
  correlation exists. Kill/restart a worker during retries. Every replay must
  converge on one Hash document, one invitation sequence, one CRM operation,
  and the correct final lifecycle state; total retry attempts must remain
  bounded across restarts.
- Exercise a workflow release while an old run is queued. The old run must use
  its pinned digest; if those validly pinned bytes are unavailable, it must stay
  visibly blocked and recoverable until they are restored. An invalid persisted
  version/digest identity must fail terminally. It must never silently execute
  the replacement version. Repeat for a restarted run and a DLQ redrive.
  Complete a timed Reactor restore and the Hash coupled restore drill, record
  actual recovery results, and obtain the applicable privacy/legal approval
  before go-live.
