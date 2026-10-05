# Architecture

One Go binary. Inside that one binary, several long-running goroutines plus per-workflow subprocesses spawned on demand.

## Daemon process layout

```text
reactor serve
 |
 +-- HTTP server (chi router)
 |   +-- /                  home with KPI tiles (runs, avg duration, time saved)
 |   +-- /runs/...          run list, detail, /tail SSE for log streaming
 |   +-- /credentials/...   list, detail, add/rotate/grant/revoke
 |   +-- /workflows/...     detail, source/dag edit, triggers, upload, chain
 |   +-- /notifications/... Slack + webhook + email channel CRUD
 |   +-- /knowledge/...     corpus browse + write
 |   +-- /audit             aggregated credential audit
 |   +-- /generate          AI codegen prompt bar (gated on ANTHROPIC_API_KEY)
 |   +-- /mcp               Streamable HTTP MCP transport
 |   +-- /command-webhook/{tok} command-automation ingress (HMAC verified)
 |   +-- /metrics           Prometheus text exposition
 |   +-- /webhook/{tok}     dispatcher entry point (HMAC verified)
 |   +-- /signal/{tok}      AwaitSignal delivery (capability token)
 |   +-- /dlq               bounded dead-letter triage page
 |   +-- /dlq/{id}/retry    one-click failed-DLQ retry
 |   +-- /login + /logout   session-cookie auth
 |   +-- /tokens            per-user API tokens (Bearer auth)
 |   +-- /users             admin-only user management
 |   +-- /docs              embedded markdown viewer
 |
 +-- cron driver            polling reconcile + (postgres) LISTEN/NOTIFY
 +-- command schedule      fires receipt-bound command automation schedules
 +-- scheduler              fires due Sleep/AwaitSignal schedules
 +-- rotation runner        hourly tick + manual rotate via dashboard
 +-- post-mortem gen        optional failed_dlq AI egress; explicit opt-in + key
 +-- notifier               fires Slack + webhook + email alerts on terminal
 +-- per-run subprocs       spawned by supervisor; one per dispatched run
```

Every long-running goroutine runs under `runDaemonComponent` with a deferred panic recovery + slog Error so a single subsystem crash logs loudly instead of killing the daemon silently.

## Per-run lifecycle

1. **Trigger arrives.** Workflow webhook receiver (`POST /webhook/{token}`), command webhook receiver (`POST /command-webhook/{token_id}`), cron driver tick, command schedule tick, manual dispatch via `POST /workflows/{slug}/run`, or chain trigger fired from another workflow's terminal event.
2. **Dispatch.** `dispatcher.Dispatch` resolves the current workflow version to its immutable SHA-256 artifact, verifies the bytes, and creates the run with `workflow_version` plus `workflow_artifact_sha256` in the same INSERT. It then spawns a `supervisor.Supervisor` (or leaves the row queued in distributed mode). The dispatch fires `IncRunsStarted` on the metrics counter.
3. **Supervise.** `supervisor.Run` exec's the verified content-addressed binary at the tenant-owned `<root>/workflows/<slug>/artifacts/sha256/<digest>/workflow` path, or at the hashed `<root>/workflows/tenants/<tenant-hash>/<slug>/artifacts/sha256/<digest>/workflow` path for a same-slug tenant. The mutable `workflow` path in either namespace is compatibility/status state and is never selected for a pinned run. On Linux it applies cgroup v2 limits + prlimit before the child gets to user code; on macOS it uses prlimit only.
4. **Pipe.** The supervisor talks to the child over a JSON-lines pipe. Frames: `Hello`, `StepStart/End/Reply`, `Sleep`, `AwaitSignal`, `SignalDeliver`, `SecretFetch/Reply`, `Log`, `Cancel`, `Error`. Sleep up to `SuspendThreshold` (default 30s) blocks; longer sleeps suspend the run + write a schedules row, the scheduler re-spawns at wake using the recorded `wake_at` (not the workflow body's recomputed value).
5. **Journal.** Every Step boundary writes to the steps table. A restart-mid-run replays `Run()` from the top; the journal's `FindCachedOutputForInput` short-circuits previously-succeeded steps so closures don't re-execute. The `input_hash` filter catches workflow-author changes to a Step's input shape (input drift triggers re-execution in live mode and `ErrReplayDivergence` in replay mode).
6. **Terminal.** `supervisor.Run` returns `succeeded`, `failed`, `failed_dlq`, or `suspended`. Terminal status and a `terminal_effects` receipt commit together. The dispatcher's `OnTerminal` hook closes `runlogs.Buffer`, sends notifications, fires workflow-complete chains through the trusted terminal admission path, then acknowledges the receipt. The leader retries unacknowledged receipts after a crash with at-least-once semantics. The metrics `IncRunsTerminal` bumps the right gauge.

## Wire protocol

See `sdk/wire/wire.go` for the frame struct definitions. The supervisor is the authority; the workflow subprocess asks for journal cache hits + secret reads + sleep wakeups, the host replies. No persistent state in the subprocess: it holds the closure state + the in-flight Step return value, nothing more.

`internal/runtime/wire` is a type-alias shim over `sdk/wire` so internal callers (dispatcher, supervisor, MCP server, journal helpers, tests) keep their existing import path while out-of-module workflow authors land on the stable `sdk/wire` surface.

## State directory layout

`<root>` defaults to `~/.reactor`:

```text
master.key                # 32-byte hex; required to start the daemon
reactor.db                # sqlite (or use a postgres URL via REACTOR_DB_URL)
reactor.env               # operator-generated; systemd/shell env assignments
workflows/                # one subdir per registered workflow
  <slug>/
    .tenant-owner          # immutable tenant binding for the executable namespace
    workflow              # mutable compatibility pointer; never used for pinned execution
    candidate.sha256      # atomic pointer to the latest split CLI build candidate
    artifacts/sha256/
      <digest>/workflow   # immutable exact bytes retained for queued/resumed/DLQ runs
  tenants/                # same-slug tenant-isolated namespaces
    <tenant-hash>/<slug>/
      .tenant-owner
      workflow
      candidate.sha256
      artifacts/sha256/<digest>/workflow
knowledge/                # markdown corpus, frontmatter at the top
  <topic>/<id>.md
graph.json                # serialised runtime graph (cache only)
```

Artifact publication copies to a private staging file, fsyncs it, atomically
links the completed bytes at the digest path without overwriting, verifies an
already-present winner, and fsyncs the full freshly-created directory hierarchy
plus both publication levels. Registration appends the version transactionally;
compatibility activation then re-locks the workflow row and proceeds only if
that exact version+digest is still current. Split `workflow register` reads the
immutable `candidate.sha256` reference (or an explicit `--artifact-sha256`),
never the mutable compatibility copy. Run
execution re-hashes the artifact on every resolution. Artifact cleanup must not
remove any digest referenced by a queued, running, suspended, or DLQ run; the
current release performs no automatic artifact garbage collection.

The `.tenant-owner` manifest is created before a new executable namespace is
compiled and is never rewritten for another tenant. Existing pre-manifest
directories can only be claimed when the journal proves the same tenant already
owns the slug. A same-slug workflow in another tenant uses the hashed
`tenants/<tenant-hash>/<slug>` namespace, so candidate/source/compatibility
state cannot overwrite the legacy owner. A digest alone never carries tenant
identity; authenticated namespace reclamation remains required after deletion.

The split CLI registration path is kept disabled because it imports an
artifact without retaining the complete source manifest. MCP/dashboard builds
retain and validate source before an operator can enable execution.

### Migration 0031 cutover

Pre-0031 `workflow_versions` and runs intentionally receive NULL artifact pins:
a migration cannot prove which bytes a mutable historical path represented.
Before reopening ingress, rebuild and re-register every enabled workflow so its
current version owns a full artifact digest. Drain and review every old queued,
running, or suspended run; resume/redrive fails closed instead of guessing the
current binary. Use a stop-ingress → drain → migrate → rebuild/register → smoke
test → reopen sequence for this compatibility boundary.

## Auth + session flow

Three credential shapes resolve in priority order on every request:

1. **`reactor_sess` cookie** → `auth.Store.ResolveSession`. Hashed lookup; the row stores sha256(cookie value) so a database snapshot does not yield session theft.
2. **`Authorization: Bearer <token>`** → `auth.Store.ResolveAPIToken`. Same hashing strategy.
3. **`Authorization: Basic <user>:<pw>`** → `auth.Store.Authenticate` against the users table, with a fallback to the env-var BasicAuth when no users exist yet.

The session middleware short-circuits the legacy BasicAuth middleware when it resolves a user, so the two compose cleanly. Unauthenticated requests redirect to `/login?next=<path>` for HTML clients, `401` for JSON. Public routes (`/healthz`, `/readyz`, `/login`, `/webhook/*`, `/command-webhook/*`, `/signal/*`, `/assets/*`, `/docs/*`) bypass auth. `/mcp` is authenticated and admin-gated; only its CSRF check is exempt because MCP clients send JSON-RPC bodies rather than browser form submissions.

See [Teams, users, sessions, API tokens](/docs/teams).

## Security floor (post-audit)

The audit pass that landed before F1/F2/F3 closed every gap that mattered for v0.2:

- **CSRF**: Origin/Referer gate on every state-changing POST.
- **Slug validation**: every `chi.URLParam("slug")` site validated against `^[a-z][a-z0-9-]*$` before joining into a filesystem path.
- **tar.gz upload cap**: 64 MiB extraction via `io.LimitedReader` + path traversal blocked via `filepath.Rel` + `O_EXCL` on writes.
- **BasicAuth fail-closed**: 503 when credentials are empty unless `--insecure-no-auth` is explicit.
- **Rate limiter eviction**: idle buckets dropped after 10 minutes, hard cap at 50,000 entries.
- **Webhook secret flash**: HMAC shared secrets surfaced via a single-use HttpOnly cookie, never via URL query strings.
- **Strict ACL by default**: empty `workflow_secret_grants` denies every fetch; the legacy permissive mode is opt-in via `REACTOR_VAULT_ACL_PERMISSIVE=1`.

See [Security threat model](/docs/security) for the full posture.

## Why one binary

Operations + ergonomics. The codegen prompt bar, the rotation engine, the dashboard, the MCP transport, the webhook + signal receivers, the notifier, and the chain firing all share the same journal + vault + auth store. Splitting them into microservices would multiply the dependency graph without buying isolation that matters for single-tenant deployments.

Multi-tenant scaling is a v0.3 question and the schema (every relevant table has `tenant_id`) is ready for it without a re-encrypt.

## Where features live in the source tree

| Surface | Package |
|---|---|
| Daemon entrypoint, flag parsing, wiring | `cmd/reactor` |
| HTTP routes + middleware + page rendering | `internal/server` |
| Dispatcher + per-run supervisor + wire | `internal/dispatcher`, `internal/runtime/supervisor`, `sdk/wire` |
| Persistent state | `internal/runtime/journal` (workflows/runs/steps/triggers/schedules/dead_letter/grants/notifications), `internal/auth` (users/sessions/api_tokens) |
| Vault | `internal/vault` (AES-GCM + PBKDF2 master key) |
| Credentials | `internal/credentials` (third-party API keys for workflow code) |
| Rotation engine | `internal/rotators` (cloudflare, github_secret, dockyard_vault, aws_iam, file_write, forgejo_secret, shared-secret) |
| Notifier | `internal/notifier` (Slack + generic webhook + email senders) |
| Codegen | `internal/codegen` (Anthropic client + prompt assembly + validator chain) |
| MCP server | `internal/mcp` |
| Knowledge corpus | `internal/knowledge` |
| Runtime graph | `internal/graph` |
| Migrations | `internal/db/migrations/{sqlite,postgres}/` |
| SDK for workflow authors | `sdk/`, `sdk/runtime`, `sdk/http`, `sdk/vault`, `sdk/wire`, `sdk/idempotency` |
| Documentation | `docs/` (embedded into the binary; rendered at `/docs`) |
