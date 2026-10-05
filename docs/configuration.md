# Reactor configuration reference

All environment variables read by the daemon. New code reads the `REACTOR_*`
prefix; the legacy `ARACHNE_*` name is still accepted as a fallback for the
core keys (DB_URL, MASTER_KEY, TLS_*, BASIC_AUTH_*, RATE_*, DRAIN_TIMEOUT,
SDK_REPLACE, MASTER_KEY_PREVIOUS) via `envFirst`.

## Security-critical

| Var | Purpose |
|---|---|
| `REACTOR_MASTER_KEY` | 64-hex (32-byte) vault master key. Overrides `--master-key-file` / `<root>/master.key`. Encrypts every stored credential; losing it loses the vault. |
| `REACTOR_MASTER_KEY_PREVIOUS` | Old master key during a rotation. Set alongside the new `REACTOR_MASTER_KEY` and the daemon lazily re-encrypts each secret under the new key on read. Remove once all secrets are read at least once. |
| `REACTOR_BASIC_AUTH_USER` | Dashboard basic-auth username. (Note: the var is `REACTOR_BASIC_AUTH_USER`, not `REACTOR_USER`.) |
| `REACTOR_BASIC_AUTH_PASSWORD_SHA256` | Dashboard basic-auth password as an argon2id PHC (preferred) or a bare hex SHA-256 (legacy). Generate with `reactor setup` / `reactor hashpw`. |
| `REACTOR_SECURE_COOKIES` | `1` forces the `Secure` flag on session and one-time flash cookies even without TLS termination in-process (set it behind an HTTPS proxy). |
| `REACTOR_TLS_CERT` / `REACTOR_TLS_KEY` | PEM paths for in-process TLS. Both or neither. |
| `REACTOR_MCP_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to call `/mcp` on a named host or behind a TLS-terminating proxy (for example `https://reactor.example.com`). Requests without `Origin` remain valid for native MCP clients; automatic same-origin fallback is limited to loopback listeners to prevent DNS rebinding. |

### Dangerous (leave unset in production)

| Var | Why |
|---|---|
| `REACTOR_INSECURE_NO_AUTH=1` | Serves the whole dashboard, INCLUDING every admin mutation, with NO authentication. The daemon logs a loud ERROR every boot when this is set. Local/dev only. Default (unset) fails closed with HTTP 503 until basic-auth is configured. |
| `REACTOR_VAULT_ACL_PERMISSIVE=1` | Turns the per-workflow secret ACL from strict-deny into allow-unless-denied within the run's tenant; combined with an empty grants table it lets every workflow read any same-tenant credential. Run identity and tenant ownership checks still apply. Prefer seeding grants (`reactor vault grant`) and leaving this unset. |
| `REACTOR_FILE_WRITE_ROOT` | Base directory that `file_write` credential-rotation targets are confined to. Unset = `file_write` delivery is disabled (refused). Set it to the narrowest possible dir. |
| `REACTOR_WEBHOOK_ALLOW_PRIVATE=1` | Lets outbound webhook/rotation clients reach loopback/RFC1918 addresses. The metadata/link-local range stays blocked regardless. Only for self-hosted internal targets. |

## Core

| Var | Purpose |
|---|---|
| `REACTOR_DB_URL` | `sqlite://<path>` (local) or `postgres://...` (distributed). |
| `REACTOR_ROOT` | State dir (`master.key`, `workflows/`, `knowledge/`); default `~/.reactor` or the container mount. |
| `REACTOR_MODE` | `local` (default, in-process SQLite) or `distributed` (Postgres pull-queue). |
| `REACTOR_DASHBOARD_URL` | Public HTTPS dashboard origin used in notifications and the fixed MCP OAuth callback (`/oauth/callback`). HTTP is accepted only for loopback development; omit it to keep MCP OAuth consent unavailable. |
| `REACTOR_GIT_BACKED` | `false` disables committing generated workflows to git (low-disk installs). |
| `REACTOR_SDK_REPLACE` | Local path the workflow-build go.mod `replace`s the SDK import to (self-host build without a published SDK module). Docker sets its bundled source path; native `.deb`/`.rpm` systemd units pin the packaged SDK at `/usr/lib/reactor-sdk`. Manual binary installs must point to matching source. |
| `ANTHROPIC_API_KEY` | Enables the dashboard codegen prompt bar. It is also required, but not sufficient, for AI post-mortems. NOT a `REACTOR_` var, and it is stripped from the workflow build env. |
| `REACTOR_AI_POSTMORTEM_ENABLED` | Exact value `true` explicitly permits failed-run diagnostics to be sent to the configured Anthropic endpoint for automatic and MCP-requested post-mortems. Default/unset is off even when `ANTHROPIC_API_KEY` exists. |
| `REACTOR_MCP_ALLOW_AUTHORING` | `1` enables authenticated HTTP MCP workflow validation and creation tools. Unset keeps the HTTP MCP surface read-only. Equivalent to `reactor serve --mcp-allow-authoring`. |
| `REACTOR_MCP_ALLOW_TRIGGERS` | `1` enables authenticated HTTP MCP trigger inspection, creation, pause/resume, deletion, and workflow-chain management. Webhook credential values remain in the vault. Equivalent to `reactor serve --mcp-allow-triggers`. |
| `REACTOR_MCP_ALLOW_NOTIFICATIONS` | `1` enables authenticated HTTP MCP attachment and detachment of existing tenant notification channels. Channel configuration remains in the daemon. Equivalent to `reactor serve --mcp-allow-notifications`. |
| `REACTOR_MCP_ALLOW_DISPATCH` | `1` enables authenticated HTTP MCP workflow dispatch and cancellation tools. Equivalent to `reactor serve --mcp-allow-dispatch`. |
| `REACTOR_MCP_ALLOW_SECRETS` | `1` enables authenticated HTTP MCP vault grant/revoke and tenant-scoped OAuth consent/disconnect tools. Equivalent to `reactor serve --mcp-allow-secrets`. |
| `REACTOR_MCP_ALLOW_KNOWLEDGE` | `1` enables authenticated HTTP MCP knowledge writes. Equivalent to `reactor serve --mcp-allow-knowledge`. |
| `REACTOR_MCP_ALLOW_DIAGNOSTICS` | `1` enables authenticated HTTP MCP post-mortem egress. Requires the explicit AI post-mortem setting and API key too. Equivalent to `reactor serve --mcp-allow-diagnostics`. |
| `REACTOR_MCP_ALLOW_DATA_LIFECYCLE` | `1` enables the authenticated HTTP MCP tenant run-history erasure tool. It still requires an exact tenant confirmation, a preview, and no queued/running/suspended runs. Equivalent to `reactor serve --mcp-allow-data-lifecycle`. |
| `REACTOR_MCP_ALLOW_MAIL_RECONCILIATION` | `1` enables authenticated admin HTTP MCP recording of an operator finding for one admitted connected-mail send. It cannot send or retry mail. Equivalent to `reactor serve --mcp-allow-mail-reconciliation`. |
| `REACTOR_MCP_ALLOW_COMMAND_EXECUTION` | `1` advertises the authenticated `reactor_run_command_automation` and `reactor_cancel_command_run` tools. Running requires the separately configured command runner; cancellation can also fence a durable queued receipt after the runner is disabled. It is separate from workflow dispatch and secrets scopes. Equivalent to `reactor serve --mcp-allow-command-execution`. |
| `REACTOR_COMMAND_RUNNER_ENABLED` | `1` opts into the command runner in `--mode local`. Startup also requires `REACTOR_COMMAND_SINGLE_TENANT=1`, a pinned `REACTOR_COMMAND_DOCKER_IMAGE`, and exact `REACTOR_COMMAND_TARGETS`; unset keeps command plans non-executable. |
| `REACTOR_COMMAND_SINGLE_TENANT` | `1` is the explicit operator assertion required by the command execution gate. Reactor refuses runner startup without it. |
| `REACTOR_COMMAND_DOCKER_BINARY` | Absolute Docker binary path for the fixed sandbox adapter (default `/usr/bin/docker`). |
| `REACTOR_COMMAND_DOCKER_IMAGE` | Required pinned image reference in `name@sha256:<64 hex>` form when the runner is enabled. Tags and implicit pulls are refused. |
| `REACTOR_COMMAND_TARGETS` | Comma-separated exact target descriptors allowed by the command runner. An empty allowlist refuses startup. |
| `REACTOR_COMMAND_RUNNER_WORKERS` | `2` fixed command-runner worker count (1..64). MCP admission never starts a process in the HTTP handler. |
| `REACTOR_COMMAND_RUNNER_QUEUE` | `16` bounded in-memory handoff capacity. Durable queued rows remain recoverable when this channel is full. |
| `REACTOR_COMMAND_RUNNER_POLL` | `1s` interval for tenant-scoped recovery of durable queued command runs after startup or backpressure. |
| `REACTOR_MCP_URL` | Default endpoint used by `reactor mcp install` (default `http://127.0.0.1:7777/mcp`). |
| `REACTOR_MCP_TOKEN` | Optional dedicated bearer token accepted by the daemon's `/mcp` route and consumed by `reactor mcp install`; real Reactor API tokens are also accepted. |
| `REACTOR_MCP_TENANT` | Tenant bound to the dedicated `REACTOR_MCP_TOKEN` identity (default `default`). |
| `REACTOR_MCP_TRUSTED_PROXY` | `1` permits a non-loopback plain HTTP listener only when an authenticated TLS-terminating proxy is directly in front of Reactor. The proxy assertion is explicit; a bearer or dashboard credential alone does not make remote plain HTTP safe. Equivalent to `reactor serve --mcp-trusted-proxy`. |
| `REACTOR_TRUSTED_PROXY_CIDRS` | Comma-separated exact proxy IPs or CIDRs allowed to supply `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` (for example `10.4.5.9`); loopback is trusted by default. Use narrow entries that exclude direct clients. Equivalent to `reactor serve --trusted-proxy-cidrs`. Independent of `REACTOR_MCP_TRUSTED_PROXY`. |

## Limits, retention, scaling

| Var | Default | Purpose |
|---|---|---|
| `REACTOR_DB_MAX_OPEN_CONNS` | `8` | Maximum open PostgreSQL connections **per Reactor process** (2..256). Applies to `serve`, `worker`, migration, and other callers of the shared database opener. SQLite keeps its separate cap of 4. |
| `REACTOR_DB_MAX_IDLE_CONNS` | `4` | Maximum idle PostgreSQL connections per process (0..`REACTOR_DB_MAX_OPEN_CONNS`); the default is clamped if the open cap is set below 4. PostgreSQL connections also have a 5-minute idle timeout and 30-minute maximum lifetime. |
| `REACTOR_MAX_CONCURRENT_RUNS` | 32 | In-process concurrency cap. |
| `REACTOR_RATE_BURST` / `REACTOR_RATE_REFILL` | 60 / 10 | Per-IP token-bucket for public endpoints. |
| `REACTOR_DRAIN_TIMEOUT` | 30 | Seconds to let in-flight workflows finish on SIGINT. |
| `REACTOR_RUN_RETENTION_DAYS` | `0` | Opt in to pruning terminal workflow and command runs older than N days; `0` retains history. |
| `REACTOR_WEBHOOK_DEDUP_RETAIN_HOURS` | 720 | Inbound-webhook dedup window. |
| `REACTOR_CGROUP_ROOT` | - | Enables per-workflow cgroup memory caps (needs host cgroup write). |
| `REACTOR_REQUIRE_WORKFLOW_CGROUP` | `0` | Refuse workflow runs unless cgroup v2 placement and `cgroup.kill` descendant cleanup are available. |
| `REACTOR_WORKER_CONCURRENCY` / `REACTOR_WORKER_IMAGE` | - | Distributed-mode worker settings. |
| `REACTOR_WORKER_ARTIFACT_ROOT` / serve `--worker-artifact-root` | unset | Daemon-visible worker artifact tree containing `workflows/` for distributed enable, preflight, and queue-admission proof. Pass the same path to manually started workers with `--artifact-root`; process and Docker autoscalers pass the configured path to their workers. Kubernetes also requires its existing PVC and read-only mount contract. When unset, the daemon cannot certify a separate worker copy. |
| `REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC` | unset | Existing read-only workflow artifact PVC required by the built-in Kubernetes autoscaler. |
| `REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI` / `REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI` | unset | Both required for Kubernetes autoscaling. Integer millicores (10–128000 each); request must not exceed limit. No CPU budget is inferred from the daemon host. |
| `REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB` / `REACTOR_AUTOSCALE_K8S_MEMORY_LIMIT_MIB` | unset | Both required for Kubernetes autoscaling. Integer MiB (128–1048576 each); request must not exceed limit. Limit must be at least `256 + 512 × REACTOR_WORKER_CONCURRENCY` MiB. |
| `REACTOR_WORKER_CONCURRENCY` | Go scheduler parallelism capped at 64 for manual/process/Docker workers; required with no default for Kubernetes | Runs admitted concurrently by each worker (1–64). Invalid values fail worker startup; Kubernetes pins the exact value in every generated Job. |
| `REACTOR_AUTOSCALE*` | - | Queue-depth autoscaler (`_MIN`, `_MAX`, `_K`, `_QUEUE_PER_WORKER`, `_SPAWNER`, `_SPAWN_CMD`, `_STOP_CMD`, `_DOCKER_ARGS`). |

Size the PostgreSQL connection budget across the whole fleet: `REACTOR_DB_MAX_OPEN_CONNS` multiplied by the peak count of `serve`, `worker`, and concurrent CLI/migration processes, plus one direct cron `LISTEN` connection on the active leader, must fit beneath the server's usable `max_connections` after reserving connections for other clients and administration. Each distributed `serve` process keeps one pooled connection while waiting for or holding its advisory lock. The built-in same-host process spawner inherits these pool variables; configure them separately for Docker or Kubernetes workers. Raising worker concurrency or the autoscaler maximum does not raise PostgreSQL's connection limit.

Run-history retention is disabled by default. When enabled, each `serve` instance
advances it once at startup and then every minute. One tick commits at most 16
transactions, each selecting at most 128 terminal workflow runs and 128 terminal
command runs, so an interrupted or backlogged sweep resumes on a later tick.
PostgreSQL serializes retention batches across replicas with a transaction
advisory lock and uses `SKIP LOCKED` when selecting runs; a busy replica skips
that tick. The `run_usage` billing ledger remains after normal retention;
tenant erasure is a separate operation that removes it. A run may have many
step, log, and audit descendants, so measure batch latency and database write
pressure on production-sized history before choosing a retention period.

## Internal (not operator-set)

`REACTOR_INPUT` (trigger payload injected into the workflow subprocess) and the
per-run `SignalKey` (delivered over the Hello frame) are set by the runtime, not
the operator.
