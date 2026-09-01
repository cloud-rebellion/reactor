# Changelog

All notable changes to Reactor are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added (testing)

- **Dry run / test mode.** The "Run now" form gains a "Test run" checkbox: the
  workflow executes with your sample input (in-process), but the host
  suppresses its own side effects -- no notifications, no downstream chain
  fan-out -- and exports `REACTOR_MODE=dry_run` to the subprocess so workflow
  code can mock its external calls. The dispatcher gained `DispatchTest`
  (forces local execution even in distributed mode so the mode applies);
  suppression rides a `DryRun` flag on the terminal event.

### Added (onboarding)

- **Template gallery** (`/templates`): a catalog of starter automations
  (webhook to Slack, daily summary email, form to CRM, health check, Stripe
  receipt, RSS forwarder). "Use template" feeds the brief to the AI builder,
  which generates + registers a working workflow to edit -- a starting point
  instead of a blank page. When the builder isn't configured, the briefs are
  shown to copy.

### Added (triggers)

- **Synchronous webhooks.** A webhook trigger can be marked synchronous (a
  checkbox when you create it): instead of fire-and-forget 202, the request
  waits for the run and returns JSON `{run_id, status, output}` where output is
  the last step's data -- turning a workflow into a request/response API. The
  dispatcher gained `DispatchSync` (polls the journal, so it works in local +
  distributed mode); a timeout (default 30s, max 120s) returns 202 + the run id
  to poll, a non-success run returns 502, rate-limit returns 429.

### Added (limits + compliance)

- **Per-workflow rate limiting.** A workflow can cap its runs per minute
  (`workflows.rate_limit_per_min`, 0 = unlimited, set on the workflow page).
  Enforced at dispatch by counting recent runs in the shared runs table, so the
  cap holds across instances; over-limit dispatches are refused and webhooks
  get a 429 to back off.
- **Run-data retention (opt-in).** `REACTOR_RUN_RETENTION_DAYS` (0 = keep
  forever, the default) purges finished runs + their steps/logs older than N
  days from the maintenance loop. The billing ledger (`run_usage`) is kept.
- **GDPR export + erasure.** The Tenants page can export a tenant's data as a
  JSON download (portability) and erase a tenant's run history + usage (right
  to erasure), leaving its configuration intact.

### Added (integrations)

- **OAuth2 connections.** Workflows can act as a connected third-party account
  (Google/Slack/GitHub/...) instead of users pasting raw API keys. Admins
  register a provider on `/oauth-providers` (client app + endpoints + scopes;
  secret encrypted at rest); any user connects an account on `/connections` via
  the standard consent screen (PKCE + single-use CSRF state); tokens are stored
  encrypted and refreshed automatically. A workflow fetches a fresh access token
  by referencing the credential id `oauth:<connection-id>` -- resolved on the
  host, tenant-scoped, gated by the same per-workflow secret ACL as the vault.
  No new dependency (the flow is hand-rolled on net/http). See
  `docs/connections.md`.

### Added (observability + self-healing)

- **Run-flow visualization.** A run's detail page now renders a flow diagram:
  the workflow's step graph (from dag.json) laid out top-to-bottom in
  topological order (fan-out branches share a row, joins converge), each node
  coloured by the run's actual status (succeeded / failed / running /
  suspended / pending), showing its duration, what it touches (`uses`), its
  inputs (`depends_on` lineage), and an expandable peek of the data it produced
  (`output_jsonb`) -- so you see how it ran, where the data ended up, and how
  it flowed. Server-rendered HTML + the dashboard's own CSS, no JS framework.

- **Tenant-scoped dashboard.** Dashboard users now belong to a tenant
  (`users.tenant_id`). Members see only their own tenant's workflows, runs,
  run detail, live log tail, and cancel; admins see everything. Cross-tenant
  access returns 404 so existence isn't leaked. A new `/account` page is the
  customer's read-only view of their plan, month-to-date usage, and estimated
  bill. Admins assign a user's tenant from the Users page.
- **Error log** (`/errors`): every failed execution, auto-collected with the
  failing step + error text and a link to the run, plus a recurring-failure
  summary (top failing workflows). Tenant-scoped.
- **Self-healing post-mortems** (`/postmortems`, admin): when a run fails
  permanently (DLQ), the daemon already asks Claude for a structured root
  cause + lesson + recommendation and stores it in the knowledge corpus. That
  corpus is searchable over MCP, so the next agent that builds or repairs a
  workflow reads the accumulated lessons. This page surfaces the loop.

### Added (SaaS control plane)

- **Multi-tenant fair scheduling.** Runs now carry a `tenant_id` (denormalized
  from the workflow). The worker claim is no longer global FIFO: it ranks each
  queued run by position within its tenant and serves every tenant's oldest
  run before any tenant's second, so one tenant's backlog cannot starve
  another. Single-tenant installs are unaffected (everything is the `default`
  tenant).
- **Per-tenant quotas.** A `tenants` registry holds `max_concurrent_runs`
  (enforced at claim), `max_queued_runs` + `monthly_run_quota` (enforced at
  enqueue, returning a typed `QuotaError`), and a `disabled` flag. 0 =
  unlimited; unknown tenants pass. See the Tenants admin page.
- **Usage metering.** Every terminal run writes a `run_usage` row (tenant,
  workflow, step count) with two durations: `run_seconds` (wall-clock,
  diagnostic) and `active_seconds` (billable compute = sum of step durations,
  which excludes suspended/waiting time, so a week-long sleep bills seconds not
  a week). The Tenants page shows current-month usage per tenant.
- **Billing plans + overage.** A `plans` catalog (Free/Starter/Pro/Scale
  seeded) bundles price + included executions/compute + caps + overage rates.
  Assigning a plan copies its caps onto the tenant. Hard-cap plans refuse past
  the included volume; soft-cap plans bill overage (executions per 1k, compute
  per hour) from the ledger. The Tenants page shows each tenant's estimated
  current-period bill; the Plans page manages tiers. Foundation for a payment
  processor.
- **Tenants admin page** (`/tenants`, admin-only): view quotas, live
  running/queued counts, and month-to-date usage; create/update/delete
  tenants. The `default` tenant cannot be deleted.

### Added (distributed mode)

- **Horizontal scaling on Postgres -- no Redis/NATS/k8s.** `--mode
  distributed` (or `REACTOR_MODE`) makes the daemon ENQUEUE runs (status
  `queued`); one or more `reactor worker` processes claim them off a
  shared Postgres queue via `SELECT ... FOR UPDATE SKIP LOCKED` and a
  per-run lease (the `leases` table, finally wired). Add capacity by
  running more workers; a dead worker's runs are requeued by the lease
  reaper and resume from the journal (no repeated side effects).
  Sleep/signal resumes are re-enqueued too, so suspended work also
  spreads across the fleet. Scheduler + cron + rotation are single-leader
  (Postgres advisory lock) so multiple `serve` daemons run HA without
  double-firing. Distributed mode requires Postgres; `local` mode (the
  default, single binary, SQLite or Postgres) is unchanged. See
  `docs/scaling.md`.
- **Worker autoscaler** (opt-in, `--autoscale` / `REACTOR_AUTOSCALE=1`).
  The leader spawns/stops `reactor worker` processes to track queue depth,
  with a HARD `REACTOR_AUTOSCALE_MAX` cap (default 4), paced scale-up (no
  bursting), scale-down after the queue drains, and scale-to-zero when
  idle (`REACTOR_AUTOSCALE_MIN=0`). The dashboard home shows the live fleet
  (active workers + concurrency + queue depth).
- **Pluggable autoscaler substrates** via `REACTOR_AUTOSCALE_SPAWNER`:
  `process` (default, same-host child processes), `docker` (`docker run` a
  worker container, needs `REACTOR_WORKER_IMAGE`), `kubernetes` (`kubectl
  create` a worker `Job`), and `command` (run your own
  `REACTOR_AUTOSCALE_SPAWN_CMD` / `_STOP_CMD` for Nomad, systemd, anything).
  Off-host substrates are dependency-free: Reactor shells out to your own
  docker/kubectl CLI rather than linking their SDKs. See `docs/scaling.md`.

### Changed

- **License: Apache 2.0 -> Reactor Sustainable Use License (fair-code).**
  The source stays open to read, run, and modify, and self-hosting +
  commercial use (including delivering automations for your clients) is
  free. What's newly restricted: reselling Reactor or running it as a
  hosted/managed service for third parties (a competing "Reactor cloud")
  now needs a separate commercial license. See `LICENSE`.

### Added

- **Run cancellation** from the dashboard (Cancel button on the run page),
  the CLI (`reactor cancel <run-id>`), and MCP (`reactor_cancel_run`). A
  running run's subprocess is killed; a suspended run is stopped and will
  not resume. Cross-process requests go through a `cancel_requested` flag
  the daemon's watcher honours within ~2s.
- **Persistent run logs.** A run's log tail is flushed to the DB when it
  terminates (it previously lived only in a 1000-line in-memory ring
  dropped 10 minutes after the run closed). The run detail page renders
  the persisted tail and MCP exposes `reactor_get_run_logs` so an AI can
  debug a run it triggered.
- **Per-run analytics rollup** on the dashboard home: counts by terminal
  status, avg + p95 duration over succeeded runs, and a 7-day daily-run
  mini-bar-chart.
- **Failure/success notifications** (`email_smtp`, `slack_webhook`,
  `generic_webhook` channels) routed per workflow + status, fired from the
  dispatcher's terminal path.
- **Workflow chaining**: a `workflow_complete` trigger dispatches a
  downstream workflow when a source workflow terminates with a matching
  status, with create-time cycle rejection and a runtime depth cap.
- **Teams / RBAC**: user accounts (argon2id), sessions, API tokens, and an
  admin/member role split with an admin-only route group over every
  privileged mutation.
- **In-app docs viewer** at `/docs` (goldmark, public) plus a REST API
  reference and per-feature deep-dives.

### Security & reliability (2026-06-11 audit fix pass)

- Workflow subprocesses get an explicit env allowlist (no vault master key
  / DB URL leak); codegen/upload `go build` runs hardened (CGO off,
  toolchain pinned, import allowlist, dir-wide lint).
- `/mcp` routes through SessionAuth (Bearer + per-user RBAC); webhook
  notifier SSRF guard (blocks link-local/metadata always, private by
  default); open-redirect, login brute-force, and username-enumeration
  timing fixes; session-cookie `Secure` behind a TLS proxy.
- Durable execution: scheduler resume fixed (slug/input/template +
  compare-and-set claim + terminal notifications/chains on resumed runs);
  SQLite opened WAL + busy_timeout; stale-run reaper at startup.
- Enabled flag enforced on every dispatch path; Postgres BOOLEAN binding
  fixed; webhook dedup rolled back on dispatch failure; panic recovery in
  the dispatcher + notifier; dispatcher concurrency cap; email SMTP
  deadline; p95 off-by-one fixed; `DeleteWorkflow` cleans orphan chain
  triggers; retention sweeps wired; `errorPage` no longer leaks `err`.
- Completed the `FF_*` -> `ARACHNE_*` env migration (legacy names kept as
  fallback) with a pre-commit guard; codegen default model bumped to
  `claude-opus-4-8`.

- **`reactor setup` one-command first-boot wizard.** Combines `init` +
  `migrate` + the BasicAuth hashing step + writes a sourceable
  `<root>/reactor.env` so the operator's next action is just
  `source <root>/reactor.env && reactor serve`. Supports interactive
  prompts (password read with terminal echo off via golang.org/x/term)
  and a `--non-interactive` mode for CI. Idempotent on partial
  completion: keeps existing master.key rather than clobbering. Eight
  characters minimum password enforced inline. README + deploy/README
  updated to feature the wizard as the primary path; manual steps
  documented as the fallback.

## [0.2.0] -- 2026-05-24

### Added

- **Sprint 3 distribution + docs.**
  - Homebrew formula template at `packaging/homebrew/reactor.rb.tmpl`;
    release CI substitutes the version + sha256 values + uploads the
    rendered formula to the GitHub release.
  - nfpm config at `packaging/nfpm.yaml` + postinstall / preremove
    scripts produce `.deb` + `.rpm` packages for linux/amd64 +
    linux/arm64 on every `v*` tag.
  - New `docs/` tree: architecture, sdk reference, codegen pipeline,
    rotation catalogue, mcp transports, security model, operations
    runbook. README links into the tree as the reading entry point.
- **Sprint 1 operator polish.** DLQ retry button on `/runs/{id}`,
  knowledge corpus write UI (`/knowledge/new` + Promote / Stale /
  Supersede on the detail page), workflow upload + register form
  (`/workflows/new` accepts tar.gz, extracts, validates, builds,
  registers), global audit view at `/audit`, cron next-fire-time
  column on the triggers section.
- **Sprint 2 observability + UX.**
  - `/metrics` Prometheus text endpoint with runs/rotations/MCP/webhook
    counters + uptime + goroutine + memory gauges.
  - Postgres `LISTEN/NOTIFY` live-reload for cron triggers via new
    `reactor_triggers_changed` channel (migration 0009); polling
    reconcile stays as dropped-notification safety net. SQLite
    no-op (polling still works there).
  - SDK helpers: `sdk/http` (Client with retry+jitter+bearer+timeout
    wrappers, typed `*Error` with `IsRetryable`) + `sdk/idempotency`
    (canonical key derivation per the i_step-keys knowledge entry).
  - Three new starter templates: `stripe-webhook` (verify-then-route
    by event type), `github-pr-reviewer` (diff -> LLM -> comment), and
    `scheduled-report` (cron -> metrics -> Slack-style chat webhook).
    Each ships main.go + dag.json + README scaffolds wired through
    the new SDK helpers.

### Deferred to v0.3

- **Multi-tenant request path.** Schema has `tenant_id` from migration
  1 but every code path uses `'default'`. Wiring middleware without
  a real use case is speculative; waiting on first OSS user
  feedback on isolation requirements.

## [0.1.0] -- 2026-05-24

First public release. Self-hosted, single-binary, AI-built workflow
automation. Covers everything from the v0.1 gap audit: production-safety
floor (rlimit + cgroup v2 + panic recovery on every daemon goroutine +
default-deny secret ACL), rotation surface (cloudflare + shared-secret
+ aws-iam + manual providers, six target kinds including github_secret
+ dockyard_vault + forgejo_secret + file_write), dashboard write
surfaces (credentials CRUD + grants + triggers + codegen prompt bar),
workflow versioning history with per-run pinning, both stdio and
Streamable HTTP MCP transports, and release scaffolding (Dockerfile,
docker-compose.yml, systemd unit, GitHub Actions for test + release).

### Added

- **Cgroup v2 enforcement.** When `--cgroup-root /sys/fs/cgroup` (or
  `REACTOR_CGROUP_ROOT`) is set on Linux, each workflow subprocess
  lands in `<root>/reactor/<run_id>` with `memory.max` + `pids.max`
  preset from `ResourceLimits` via `SysProcAttr.UseCgroupFD`. The
  child is in the cgroup at clone3 time so the race window between
  `cmd.Start` and `prlimit` no longer matters for memory + pid bounds.
  Falls back to prlimit-only on cgroup v1, missing controllers, or
  permission failure (logged + warned, never fatal).
- **Workflow version history.** New `workflow_versions` table (migration
  0008). `CreateWorkflow` writes a version-1 row on initial register;
  `RecordWorkflowVersion` appends on each subsequent re-register.
  Migration 0031 binds each version and run to an immutable, full SHA-256
  content-addressed executable; queue, resume, MCP dispatch, and DLQ redrive
  resolve those exact verified bytes instead of the mutable current path.
  `runs.workflow_version` plus `workflow_artifact_sha256` keep both execution
  and the audit trail truthful after re-registration. `ListWorkflowVersions` +
  `CurrentWorkflowVersion` for dashboard / MCP surfaces.
- **Streamable HTTP MCP transport.** New `POST /mcp` route on the
  dashboard server, gated behind the existing BasicAuth + RateLimit
  middleware. Accepts single requests or batches; notifications
  (no id) return HTTP 202 with no body per the spec. Closes the
  remote-AI-client gap so cloud-hosted Claude / web IDEs / custom
  HTTP gateways can speak the same surface as `reactor mcp stdio`.
- **Multi-project pre-commit guard** (`scripts/git-hooks/pre-commit`).
  Blocks staged diffs that span more than one top-level project
  unless the commit message includes `[multi-project]` or
  `Cross-project:`. Three sessions have lost work to a `git add .`
  race between parallel agents (mithras week 2, atomicsite ship-3
  splice, reactor dashboard write surface); this gate prevents the
  fourth.
- **Dashboard write surface for credentials.** `/credentials/new` form,
  `POST /credentials`, `POST /credentials/{id}/rotate`,
  `POST /credentials/{id}/grants`, `POST /credentials/{id}/grants/{wf}/revoke`.
  A non-developer operator can add + rotate + grant credentials from
  the dashboard alone, no CLI required.
- **Dashboard write surface for triggers.** `POST /workflows/{slug}/triggers`
  (webhook or cron), `POST /workflows/{slug}/triggers/{id}/delete`. Webhook
  creation auto-mints a 32-byte HMAC secret, parks it in the vault as a
  dedicated `webhook_<slug>_<short>` credential, and one-time-flashes the
  ready-to-paste curl line on the redirect.
- **Codegen prompt bar on the home page.** When `ANTHROPIC_API_KEY` is set,
  the home page renders a brief textarea + Generate button. POST `/generate`
  runs the orchestrator -> `go build` -> `journal.CreateWorkflow` -> redirect
  to `/workflows/{slug}`. Brief-to-running-workflow in one click.
- **Server gains `Vault`, `Rotator`, `Generator`, `State`** fields so the
  daemon's existing vault store + rotation runner + Anthropic-backed codegen
  can power the write surfaces. All decoupled via minimal interfaces so
  read-only deployments don't drag in unrelated dependencies.
- **Resource limits on the workflow subprocess.** New `ResourceLimits`
  in `internal/runtime/supervisor` with v0.1 defaults (512 MiB AS, 60s
  CPU, 256 NOFILE, 64 NPROC). Applied via `prlimit(2)` on Linux right
  after `cmd.Start`; non-Linux is a build-tagged no-op.
- **Panic recovery on every daemon goroutine.** `cron.Driver.reloadLoop`
  and the per-credential rotation goroutines in `rotators.Runner.Tick`
  now defer `recover()` with `debug.Stack()`. Closes the carry-over
  from the week 11 hardening commit.
- **AWS IAM rotator (`aws-iam`).** Self-referential access-key rotation.
  The current pair signs `CreateAccessKey`; the new pair signs
  `DeleteAccessKey` for the old AccessKeyId. Required
  `meta.iam_user_name`; optional `meta.region` (default `us-east-1`)
  and `meta.delete_old` (default `true`). Stdlib SigV4, no AWS SDK.
- **`file_write` rotation target.** Atomically replaces a file
  (write-temp -> fsync -> chmod 0600 -> rename) so a crash mid-write
  leaves the previous value intact. Covers docker-compose env_file,
  systemd EnvironmentFile, and similar on-disk-secret consumers.
- **`forgejo_secret` rotation target.** PUT to
  `{repo_api}/actions/secrets/{name}` with the Gitea-compatible
  `{"data":"<value>"}` body. API token comes from vault so it can
  itself be rotated.
- **`github_secret` rotation target.** Two-step flow against the
  GitHub Actions API: GET the repo's X25519 public key, encrypt the
  new value with libsodium `crypto_box_seal` (via
  `golang.org/x/crypto/nacl/box.SealAnonymous`), then PUT
  base64(ciphertext) + key_id to `/actions/secrets/{name}` with the
  `X-GitHub-Api-Version: 2022-11-28` header.
- **`dockyard_vault` rotation target.** PUT to a Dockyard vault entry
  endpoint with `{"value":"<new>"}` and a Bearer Dockyard API token.
  Since Hephaestus reads deploy secrets from the Dockyard vault at
  build time, rotating the Dockyard entry IS the Hephaestus rotation;
  no separate Hephaestus target type needed.
- **`deploy/docker-compose.yml`** for the OSS quickstart.
- **`.github/workflows/test.yml`** template (vet + race tests + build
  + smoke). Picked up automatically when the directory is mirrored to
  a GitHub repo.
- **CHANGELOG.md** (this file).

### Changed

- README rewrite: status line, full CLI surface, rotation targets +
  providers tables, dashboard story aligned with the shipped Go-templates
  UI (the SvelteKit roadmap line is retired).

## [Pre-v0.1] -- 2026-05-21

- Graph lens, knowledge corpus, post-mortems, Go-template operator
  dashboard, scaffold CLI (`reactor new`), MCP install registration.
- Panic recovery on scheduler / rotation_runner / http_server goroutines
  via `runDaemonComponent`.

## [Pre-v0.1] -- 2026-05-10

- MVP-blockers commit: security baseline middleware (CSP, BasicAuth,
  rate-limit), HTTPS via `--tls-cert`/`--tls-key`, MCP
  `reactor_dispatch_workflow`, `reactor generate` CLI, production
  Dockerfile + hardened systemd unit, multi-arch buildx.
- Week 10 polish: graceful drain on SIGINT, `/runs` pagination + filter,
  cron live-reload (polling), MCP authoring tools behind `--allow-write`,
  rotation demo extension.
- Post-week-9 backlog: DLQ retry CLI, per-workflow secret ACL
  (`workflow_secret_grants`), `reload_endpoint` dual-phase grace,
  `reactor ps`, MCP server stdio JSON-RPC, welcome-customer-v2,
  server integration tests.
- Week 9: live daemon (`reactor serve`), dispatcher, registry, server
  HTTP routes, examples/cron-echo, `make demo`.
- Week 8: rotation engine + audit log + vault CLI; Cloudflare,
  shared-secret, manual providers; single-phase webhook delivery.
- Week 7: signal delivery + DLQ persistence + replay/lint CLIs.
- Week 6: AI codegen orchestrator (`internal/codegen/`); stdlib
  Anthropic Messages API client; tool-forced JSON schema; retry-with-
  feedback validator chain.
- Week 5: external input (`internal/runtime/webhook` + `cron`);
  Stripe / GitHub / generic HMAC verifiers; cron driver.
- Week 4: long-sleep suspend + scheduler resume. `Sleep(72h)` survives
  host restarts.
- Week 3: durable execution. Step journal, JSON-lines wire protocol,
  supervisor + dispatcher.
- Week 2: vault crypto (AES-256-GCM, PBKDF2-SHA256 600k iter), public
  SDK (`sdk/reactor.go`).
- Week 1: repo bootstrap, schema migrations, dual SQLite + Postgres
  plumbing.
