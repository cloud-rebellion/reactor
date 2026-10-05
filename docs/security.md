# Security

Five layers of defence around the credentials the AI references but
never sees.

## Layer 1: at rest

`internal/vault/` stores every credential AES-256-GCM with PBKDF2-SHA256
600k iterations, 32-byte salt, 12-byte nonce, version byte for
transparent re-encrypt on master-key rotation. The master key is the
only thing protecting the blob; **loss of the master key is total,
unrecoverable loss of every credential.**

There is no recovery mechanism. Earlier versions of this document
promised a "BIP39 24-word recovery encoded on init"; that was never
implemented and no mnemonic is ever shown. `reactor init` writes 32
random bytes to `<state>/master.key` (mode 0600) and prints only the
path. **Back that file up out of band before you store anything in the
vault**, and see docs/operations.md for the rotation window
(`REACTOR_MASTER_KEY_PREVIOUS`).

Migration 0060 adds application-level encryption for **new run trigger
metadata and the exact trigger input bytes**. The journal uses one random,
stable 32-byte data key wrapped under the master key in the database. Each
field has a fresh AES-256-GCM nonce and authenticated tenant, run, and field
identity. SQLite and PostgreSQL store a versioned envelope; workers and
explicitly authorized MCP input reads restore the original bytes only after
authentication. A database trigger rejects plaintext run inserts after the
wrapped data key is initialized, including inserts from older binaries.
Version-zero historical run rows remain plaintext until an explicit backfill.
An encrypted row cannot be read without the matching master key or an
authorized previous key during rotation; a missing or tampered envelope fails
closed. Preserve a consistent database backup **and** its matching master key:
the wrapped data key is not recoverable from the database alone.

Migration 0061 also encrypts **new step output and error fields** under that
same wrapped data key. The authenticated identity includes tenant, run, step
name, call ordinal, attempt, and field. Replay authenticates the complete
output before returning its original JSON bytes; an explicit MCP output page
authenticates the bounded complete envelope before exposing a character
slice. The 1 MiB step-field limit matches the child wire-frame limit. SQLite
and PostgreSQL triggers reject old-binary plaintext inserts and outcome
updates after key initialization. Schema rollback refuses while encrypted
step rows or an active journal key exist.

Migration 0063 encrypts **new dead-letter error and payload copies** under the
same wrapped key. Authentication binds tenant, run, DLQ row, step name, call
ordinal, attempt, failure order, and field. Tenant-scoped inventory reads use
plaintext byte-length receipts without loading the envelope; an explicit
bounded detail read authenticates the complete value before returning it.
Redrive authenticates the selected encrypted row before granting another
attempt. When a keyed legacy row with nullable attempt identity is promoted,
its envelopes are re-sealed under the exact attempt in that same transaction.
New DLQ fields are limited to 1 MiB each; old-writer inserts and plaintext
updates are rejected after first-key initialization on both engines.

Migration 0064 encrypts **new persisted run-log lines**, including artifact
availability markers, under the same wrapped journal key. Authentication binds
tenant, run, line sequence, kind, and field; only an authorized keyed read
restores the text. New lines are capped at the in-memory ring's 8 MiB line
limit. A bounded MCP read uses plaintext byte-length receipts to omit an
oversized line before loading its envelope. Both engines reject old-binary
plaintext inserts after key initialization and refuse schema rollback while
the key or encrypted log rows exist. Historical log lines remain plaintext.
After keyed startup, `reactor payload backfill-run-logs` can seal a bounded,
restartable batch of historical version-zero lines without changing their
exact read bytes, order, kind, or timestamps. It does not run automatically;
an oversized or malformed historical line stops its batch without a partial
commit and needs operator review. Database backups made before backfill retain
the plaintext history. Migration 0072 adds a partial index over remaining
version-zero log rows so repeated bounded batches do not rescan converted
history; the migration itself does not encrypt any data. If a PostgreSQL
concurrent index build is interrupted, verify `pg_index.indisvalid` before
backfilling; an invalid same-name index must be dropped concurrently before
the migration is retried.

Migration 0066 encrypts **new command-run parent errors and step/attempt
stdout, stderr, and errors** under the same wrapped journal key. Each field is
authenticated with tenant, run, step sequence, attempt, and field identity;
current-step and attempt copies use separate envelopes. SQL bounds envelopes
before journal reads, and explicit diagnostic pages authenticate the complete
output before returning a byte slice. Database triggers reject old-binary
plaintext output/error writes after key initialization, including updates to
legacy rows, and reject downgrades of encrypted fields. Historical version-zero
command-run fields remain plaintext until an explicit backfill. The migration
does not re-encrypt them. Authorized diagnostic export and dashboard reads
still return decrypted, redacted execution output; encryption at rest is not
an output-disclosure policy. The command runner redacts exact credential
values from streaming and final output, but transformed or partial values may
evade that scrubber and remain visible in authorized output views.

Migration 0067 seals **new keyed signal tokens and delivery payloads**. Token
lookup uses a digest while the recoverable token remains encrypted; payload
and token reads authenticate their tenant, run, schedule, and field identity.
Historical version-zero signal rows remain plaintext. Migration 0068 seals
**new notification-channel configuration** in a JSON envelope bound to tenant,
channel, and kind. Version-one configuration reads authenticate and size-bound
the value before handing it to the notifier; legacy version-zero reads are
size-bound but cannot authenticate their plaintext. MCP channel inventory selects
metadata only. Both migrations reject old-binary plaintext writes after key
initialization and refuse rollback while the key or encrypted rows exist.
Historical version-zero notification configs remain plaintext, and 0068 does
not backfill them. An oversized legacy config stays available through metadata
inventory but fails closed on a full configuration read. Migration 0070 seals
**new keyed command-automation definitions** with tenant, automation ID, and
exact version as authenticated identity. The version index reads SHA-256 and
plaintext-size receipts without loading encrypted command text; exact-version
review, export, and runner admission open and authenticate the definition.
Old-binary plaintext definition writes are rejected after key initialization.
Historical version-zero command definitions remain plaintext and readable;
0070 does not backfill them. Migration 0071 supports an explicit, bounded
`reactor payload backfill-command-definitions` operation after keyed startup.
It seals byte-exact historical definitions and preserves their established
review digest; it does not run automatically. Legacy rows not yet processed,
and database backups taken before backfill, remain plaintext.

This is partial execution-data protection. Historical version-zero run, step,
dead-letter, run-log, command-run, signal, notification-channel, and command
definition rows remain plaintext in the database and backups.
The application must not
advertise complete payload encryption until those sinks are converted and
old rows are backfilled. Database, volume, backup, access, and retention
controls remain part of the customer data boundary. The default MCP run
view continues to redact trigger data; explicit data-export scope is still
required to reveal exact input and step output bytes.

## Layer 2: MCP surface keeps credentials opaque

`internal/mcp/mcp.go` exposes credential metadata, scoped authoring and
dispatch operations, and bounded audit views. Credential blobs are never
serialized; `RotationTargets` are stripped before send because `secret_id`
cross-references would be a metadata leak. There is no
`get_credential_value` tool. The AI can orchestrate a workflow that has an
explicit grant, but it cannot ask MCP for plaintext credentials.

## Layer 3: Secret type redacts every accidental sink

`internal/vault/secret.go` -- the `Secret` type's `String`, `GoString`,
`MarshalJSON`, `MarshalText`, `LogValue` all return `[REDACTED]`. The
only reveal path is `.Reveal() []byte`, a single greppable call.
`slog.Info("got", "key", sec)` prints `[REDACTED]` even if the
workflow author messes up.

## Layer 4: AI references by id

The codegen system prompt teaches `vault.MustGet(id)`. The JSON schema
slot for triggers carries `secret_id` not the value. AI gets the slot,
never the secret.

Before an external codegen request, Reactor scrubs recognizable credential
and personal-data patterns from the operator brief, environment lens, runtime
graph, knowledge excerpts, and validation feedback. This is pattern-based
redaction, not encryption of the prompt or a guarantee for arbitrary customer
payloads. Do not paste raw secrets or production records into an authoring
brief. The dashboard and opt-in MCP data-export reads can still expose values
that a workflow or command chose to emit. Default MCP workflow-run,
dead-letter, and command-run views show status and redacted size receipts.
Command stdout, stderr, and errors require the separate DataExport diagnostic
read. That read returns bounded base64 pages of persisted bytes and fails
closed if its redacted access audit cannot be saved. Pattern scrubbing on
writes does not guarantee that opaque customer data, or older imported rows,
are safe to show to an AI. A per-workflow execution redaction policy remains
open.

Codegen sends prompts and its model API key only to an HTTPS model endpoint;
literal loopback HTTP is allowed for a local gateway or test, and redirects
are refused.

The reactor lint blocks direct filesystem/process access (`os`, `os/exec`), raw
network transports (`net`, `net/http`, `net/smtp`, `net/rpc`, `crypto/tls`),
`syscall`, `unsafe`, and `math/rand`, plus (in the build allowlist) `C`,
`plugin`, and `os/signal`. It also rejects standard-library wrappers that can
open arbitrary files (`io/ioutil`, `go/parser`, `text/template`,
`html/template`, and debug object readers) or raw sockets (`log/syslog`), so a
workflow cannot bypass the direct-package checks by importing an indirect API.

Workflow code uses Reactor inputs, the grant-checked vault broker, and SDKs
for external access. In a workflow subprocess, `sdk/http` and the default
Hash/BrightCRM e-sign clients block private, link-local, metadata, and redirect
destinations by default using connect-time checks; a reviewed source may opt
into private networks explicitly. `sdk/http` requires an exact reviewed origin
pin before sending Bearer or static-header credentials, rejects recognized
query credential keys without a pin, and refuses redirects even when a custom
client is injected. Provider-specific query-key names and the trusted pin's
selection remain operator review concerns. Injected custom HTTP transports
remain the caller's responsibility. Run the daemon as a dedicated unprivileged
user with a `0700` state directory.

## Layer 5: run-time fetch is brokered + ACL'd

`internal/runtime/supervisor/supervisor.go:handleSecretFetch` --
workflow subprocess sends `secret_fetch{id}` over the pipe; the host
resolves `workflow_id` and tenant from the durable run identity, checks
same-tenant ownership and `workflow_secret_grants`, and denies with `NotFound`
on miss. A successful vault or legacy OAuth token resolution writes a
`runtime_secret_access_audit` receipt before any value is sent over the pipe.
If that write fails, the host sends `NotFound` without value bytes. The
subprocess never holds DB credentials. The receipt transaction locks the
exact unexpired distributed lease generation, then the run row, before it
checks `running` and no cancellation request. A local supervisor may write a
receipt only while the run has no lease. Reaping, finalization, and accepted
cancellation therefore cannot change the authority under an in-flight receipt
transaction. A fresh state check immediately before a raw child reply, and
before and after a brokered GET, catches changes committed since the receipt.
There is still a short time-of-check gap after each committed check: a lease
may expire or cancellation may commit before bytes reach the child or an HTTP
request leaves the host. An HTTP request already sent cannot be rolled back;
worker heartbeat cancellation and process isolation remain necessary.
Revoking a workflow grant or changing a reviewed policy is checked again
before egress and before reply, but cannot unsend an in-flight external GET.
Salesforce connections registered under the canonical `salesforce`
provider ID cannot use raw `SecretFetch`, even with a grant or the permissive
ACL setting. New custom provider aliases using known
Salesforce OAuth hosts are rejected; legacy alias connections are checked
against their current provider endpoints before any raw token release.
Canonical Salesforce connections use the host connector broker for GET
requests under `/services/data/`: it validates the current
tenant-scoped token and org origin together, requires an explicit grant and
durable per-account permit, and returns a bounded response without sending the
token to the workflow process. Reviewed generic OAuth connections use the same
host-owned transport with a fixed operator-approved public HTTPS origin and
path prefix. New generic connections start broker-only pending review;
existing generic rows retain explicit legacy raw mode. New canonical Google
and Microsoft mail connections are broker-only. `email.SendConnected` sends a
structured message from a durable Step through one fixed provider POST on the
host; the workflow process never receives the OAuth token. The host requires
an explicit workflow grant, matching tenant, live run and lease, current
connection, canonical OAuth endpoints, and send-only requested plus granted
scopes. It rechecks authority before egress and response release, caps the
provider request at 256 KiB and response at 8 KiB, refuses redirects, and uses
durable per-connection and tenant/provider permits. It records a once-only
intent before POST for at most one brokered send per run/Step ordinal. The
intent stores the non-secret provider and connection IDs for later
reconciliation; it never stores the message, recipient, or token. Authors
must place any other side effects in separate Steps; the host does not inspect
arbitrary code inside a Step for those effects.
A confirmed acceptance can be returned on an authorized replay without another
POST; uncertain outcomes return a permanent
`ambiguous` error with provider-reconciliation guidance before manual redrive.
There is no automatic host retry of a provider POST.
The read-only `reactor_list_uncertain_mail_sends` HTTP MCP tool and the admin
dashboard's Mail send reconciliation page show a tenant-scoped, bounded queue
of admitted intents across runs. The queue includes the run, Step, admission
time, and non-secret provider/connection IDs; it excludes message content,
recipients, tokens, request digests, and provider message IDs. Cursor paging
reflects the current queue, not a historical snapshot. Ordinary run-history
retention preserves terminal runs with unresolved admitted sends; a confirmed
provider API acceptance makes the run eligible for normal retention. Explicit
tenant erasure still removes those runs and receipts. An admitted intent is
**not** proof that the provider sent or accepted a message; operators must
check the provider before any manual redrive.

With the separate `--mcp-allow-mail-reconciliation` scope, an authenticated
admin can call `reactor_resolve_mail_send` for one exact tenant/run/intent/
ordinal/target after checking the provider and waiting for the run to become
terminal and release its worker lease. The call stores an immutable
operator finding and a SHA-256 digest of evidence held outside Reactor.
`provider_accepted` and `provider_rejected` require a provider record or audit;
`closed_unverified` records an explicit manual decision without a provider
truth claim. The finding does not convert the original admitted intent into a
confirmed send, does not permit automatic replay, and does not expose the
message, recipient, token, provider message ID, or raw evidence. The resolved
item leaves the queue, remains visible in `reactor_list_run_mail_sends`, and
becomes eligible for normal run retention; tenant erasure also deletes the
receipt. Reactor records the operator's assertion and evidence fingerprint but
cannot verify the provider record itself.

A broker-only connection can never be downgraded to raw mode, even if its policy row is removed. Generic
policy edits and token reconnects are rechecked before
egress and response release; the value-free runtime audit records the policy
version. Custom-domain or proxy aliases that do not use
recognizable Salesforce hostnames still need review. The workflow can read
and process returned data; the broker does not constrain its later data egress.
Grandfathered connections, including existing `legacy_raw`/`email_adapter`
rows, still release raw access tokens to workflow code after their grant check
until approved workflows migrate. A workflow-supplied `sdk/http`
credential-origin pin does not itself provide a host-owned egress boundary.
The audit stores only the tenant, workflow, run, secret reference, kind,
optional broker policy revision, and timestamp; it stores no token,
fingerprint, or payload. Receipts are deleted with their parent run during
retention or tenant run-history erasure.

Credential resolution is available only in `live` execution mode. Dry-run
workflow tests and historical replay receive `NotFound` for vault and OAuth
references, even if the workflow has a grant. Use non-secret fixtures when
testing a workflow that normally calls an external application.

Empty grants deny by default. The explicit legacy escape hatch
`--vault-acl-permissive` or `REACTOR_VAULT_ACL_PERMISSIVE=1` allows same-tenant
fetches only while the grant table is empty; the runtime audit still applies.

## Process isolation

The workflow subprocess runs under:

- **prlimit** (Linux): RLIMIT_CPU, RLIMIT_NOFILE, and RLIMIT_NPROC.
  Defaults: 60 CPU-seconds / 256 open files / 64 processes. Resident memory
  is enforced by cgroup v2 `memory.max` when configured; RLIMIT_AS is not used
  because it prevents Go children from starting reliably.
- **cgroup v2** (Linux, opt-in via `--cgroup-root /sys/fs/cgroup`):
  `memory.max` + `pids.max` preset; child clones into the cgroup at
  clone3 time so the prlimit race window doesn't matter for memory +
  pid bounds. Set `--require-workflow-cgroup` (or
  `REACTOR_REQUIRE_WORKFLOW_CGROUP=1`) when workflows are treated as hostile:
  a run then fails closed unless the host can place it in a cgroup and expose
  `cgroup.kill`, which the supervisor uses to terminate descendants during
  cleanup. Without the requirement, an unavailable cgroup is an explicit
  resource-limit fallback and does not provide descendant containment.
- **Parent lifetime** (Linux): the workflow receives `SIGKILL` if the daemon
  exits unexpectedly, so it cannot continue operating against a closed journal
  or stale host state. Non-Linux deployments still require an outer process
  supervisor for this crash-recovery boundary.

Its environment is an explicit system-variable allowlist. `HOME` and the
daemon's launch-directory `PWD` are omitted; `PWD`, `TMPDIR`, `TMP`, and
`TEMP` are replaced with the fresh scratch directory for that run. This keeps
the workflow from using a shared host temporary directory to inspect files
left by the daemon or another run. `REACTOR_MASTER_KEY`, the database URL, API
keys, and other daemon secrets are never inherited or accepted through
test/extra environment overrides. Extra environment values are limited to
the internal `FF_TEST_*` instrumentation namespace and the `REACTOR_MODE`
dry-run marker.
Workflow credentials arrive only through the grant-checked secret broker.
Each run also starts in a fresh private temporary working directory, so
relative paths cannot reach the daemon's launch directory. Workflow stderr is
forwarded with a 256 KiB per-run cap and is discarded after the cap while the
child remains unblocked.

macOS / FreeBSD: prlimit no-op; rely on the outer container or VM.

The canonical HTTP daemon startup path also enforces the local filesystem
boundary: `--root` must be a real directory (not a symlink) with no group or
other permissions; use mode `0700`. A key loaded through `--master-key-file`
or the default `master.key` must be a regular non-symlink file with no group or
other permissions; use mode `0600`. This prevents an accidentally shared state directory or
key file from being accepted by the service. It does not replace deployment
isolation: a workflow process runs under the daemon's service account, so
same-UID filesystem and descendant-process access still require a dedicated
container, cgroup delegation, or stronger host sandbox when workflows are
treated as hostile code.

The checked-in systemd unit intentionally keeps `ProtectControlGroups=true`
and leaves strict per-workflow cgroups disabled, because a unit cannot create
child cgroups without an operator-reviewed delegation. On a Linux host that
has approved cgroup v2 delegation, use the drop-in in `deploy/README.md` and
set both `REACTOR_CGROUP_ROOT` and `REACTOR_REQUIRE_WORKFLOW_CGROUP=1`; the
strict startup check refuses the latter without an explicit root. Verify the
actual service cgroup and `cgroup.kill` support after restart. This remains a
resource and descendant fence. A dedicated container or VM with egress policy
is still required for a complete hostile-code boundary.

## Network

- HTTPS via `--tls-cert` / `--tls-key`, or behind a reverse proxy that
  sets `X-Forwarded-Proto: https`. Forwarded headers from non-loopback proxy
  peers require an exact `REACTOR_TRUSTED_PROXY_CIDRS` allowlist entry.
- SecurityHeaders middleware: CSP (`script-src 'self'`, which is what the
  dashboard's Cytoscape island under `/assets/` needs; inline scripts stay
  blocked, so DAG data rides a `<script type="application/json">` island
  rather than an inline block), X-Frame-Options
  DENY, X-Content-Type-Options nosniff, Referrer-Policy
  strict-origin-when-cross-origin, Permissions-Policy that nukes
  camera/mic/geo, HSTS when TLS.
- BasicAuth (constant-time SHA-256 + constant-time username compare;
  set REACTOR_BASIC_AUTH_USER + REACTOR_BASIC_AUTH_PASSWORD_SHA256).
- Per-IP token-bucket rate limiter (60 burst / 10 sustained by default,
  tunable via REACTOR_RATE_BURST / REACTOR_RATE_REFILL).
- Failed password and MFA attempts are tracked per client/account for 15 minutes
  in a bounded in-process table. Keys are hashed before storage; old entries
  expire, and new identities are denied while the table is full. This is a
  per-daemon guard, so multi-replica ingress also needs a shared edge limit.

## Audit

Credential management actions write `credential_audit` rows. The dashboard's
`/audit` aggregates these across credentials; per-credential audits show on
`/credentials/{id}`. Actor types include:

- `seed` -- migration-time seeding
- `operator` + `*.cli` action -- CLI command (`create.cli` from
  `reactor vault add`, `grant.cli`, `revoke.cli`). `actor_id` carries
  `$USER` when the environment provides it.
- `operator` + `*.dashboard` action -- dashboard interaction
- `scheduler` -- automatic rotation tick

Runtime credential-access receipts for vault credentials and OAuth connections use
the separate `runtime_secret_access_audit` table because OAuth IDs are not rows
in `credentials`. Each authorized resolution writes one durable receipt before
the child receives a legacy raw value or a Salesforce host-brokered request
proceeds. Denied lookups do not disclose values and are
logged; they do not create successful-access receipts. Operators inspect this
ledger through the bounded, tenant-scoped
`reactor_list_runtime_secret_access_audit` MCP read tool or tenant-filtered
SQL. The dashboard `/audit` page does not include these rows yet.
