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

### Dangerous (leave unset in production)

| Var | Why |
|---|---|
| `REACTOR_INSECURE_NO_AUTH=1` | Serves the whole dashboard, INCLUDING every admin mutation, with NO authentication. The daemon logs a loud ERROR every boot when this is set. Local/dev only. Default (unset) fails closed with HTTP 503 until basic-auth is configured. |
| `REACTOR_VAULT_ACL_PERMISSIVE=1` | Turns the per-workflow secret ACL from strict-deny into allow-unless-denied; combined with an empty grants table it lets every workflow read every credential. Prefer seeding grants (`reactor vault grant`) and leaving this unset. |
| `REACTOR_FILE_WRITE_ROOT` | Base directory that `file_write` credential-rotation targets are confined to. Unset = `file_write` delivery is disabled (refused). Set it to the narrowest possible dir. |
| `REACTOR_WEBHOOK_ALLOW_PRIVATE=1` | Lets outbound webhook/rotation clients reach loopback/RFC1918 addresses. The metadata/link-local range stays blocked regardless. Only for self-hosted internal targets. |

## Core

| Var | Purpose |
|---|---|
| `REACTOR_DB_URL` | `sqlite://<path>` (local) or `postgres://...` (distributed). |
| `REACTOR_ROOT` | State dir (`master.key`, `workflows/`, `knowledge/`); default `~/.reactor` or the container mount. |
| `REACTOR_MODE` | `local` (default, in-process SQLite) or `distributed` (Postgres pull-queue). |
| `REACTOR_DASHBOARD_URL` | Public base URL used in notifications and OAuth redirect derivation. |
| `REACTOR_GIT_BACKED` | `false` disables committing generated workflows to git (low-disk installs). |
| `REACTOR_SDK_REPLACE` | Local path the workflow-build go.mod `replace`s the SDK import to (self-host build without a published SDK module). Set by the Dockerfile. |
| `ANTHROPIC_API_KEY` | Enables the dashboard codegen prompt bar. It is also required, but not sufficient, for AI post-mortems. NOT a `REACTOR_` var, and it is stripped from the workflow build env. |
| `REACTOR_AI_POSTMORTEM_ENABLED` | Exact value `true` explicitly permits failed-run diagnostics to be sent to the configured Anthropic endpoint for automatic and MCP-requested post-mortems. Default/unset is off even when `ANTHROPIC_API_KEY` exists. |

## Limits, retention, scaling

| Var | Default | Purpose |
|---|---|---|
| `REACTOR_MAX_CONCURRENT_RUNS` | 32 | In-process concurrency cap. |
| `REACTOR_RATE_BURST` / `REACTOR_RATE_REFILL` | 60 / 10 | Per-IP token-bucket for public endpoints. |
| `REACTOR_DRAIN_TIMEOUT` | 30 | Seconds to let in-flight workflows finish on SIGINT. |
| `REACTOR_RUN_RETENTION_DAYS` | - | Prune runs older than N days. |
| `REACTOR_WEBHOOK_DEDUP_RETAIN_HOURS` | 720 | Inbound-webhook dedup window. |
| `REACTOR_CGROUP_ROOT` | - | Enables per-workflow cgroup memory caps (needs host cgroup write). |
| `REACTOR_WORKER_CONCURRENCY` / `REACTOR_WORKER_IMAGE` | - | Distributed-mode worker settings. |
| `REACTOR_AUTOSCALE*` | - | Queue-depth autoscaler (`_MIN`, `_MAX`, `_K`, `_QUEUE_PER_WORKER`, `_SPAWNER`, `_SPAWN_CMD`, `_STOP_CMD`, `_DOCKER_ARGS`). |

## Internal (not operator-set)

`REACTOR_INPUT` (trigger payload injected into the workflow subprocess) and the
per-run `SignalKey` (delivered over the Hello frame) are set by the runtime, not
the operator.
