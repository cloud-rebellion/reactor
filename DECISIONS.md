# Reactor: Locked Decisions (v0)

> **Working codename only.** "Reactor" will be renamed before the public release.
> The Go module path `github.com/bright-interaction/reactor` and the binary name
> `reactor` are placeholders; the rename is a `go mod edit` + import sweep when
> the final name lands.

Resolutions to the 13 open questions from the implementation plan, locked before week 1.
Revisit on a major version bump only.

## Database target

**Postgres is the production target. SQLite is the dev / OSS-quickstart path.**

Postgres-first because every scaling feature of a workflow engine sits on capabilities
SQLite doesn't have:

- `SELECT ... FOR UPDATE SKIP LOCKED` for worker leasing (we use TTL row leases on SQLite)
- `LISTEN/NOTIFY` for instant scheduler reload on trigger CRUD (poll on SQLite)
- Logical replication via `pgoutput` for CDC trigger sources (poll `_changed_at` on SQLite)
- True concurrent writes via MVCC (single-writer on SQLite even in WAL mode)
- Advisory locks for cross-replica cron coordination
- Streaming replication + pgBackRest for HA

Every comparable engine (Inngest, Trigger.dev v3, Temporal, Windmill, n8n in production)
lands on Postgres. SQLite earns its keep as the laptop-local dev experience and the
"5-minute git clone" promise for OSS users; users graduate by changing `REACTOR_DB_URL`.

The schema and queries split (`internal/db/migrations/{sqlite,postgres}/`,
`internal/db/queries/{sqlite,postgres}/`) is permanent. New scale-sensitive features
get the Postgres-native implementation, then a correct-but-slower SQLite fallback,
not the other way around.

For the Bright Interaction internal v1 (replacing `automations/n8n-workflows/`),
deploy to Postgres from day one on the existing BI ops stack.

## Engine + sandbox

1. **Go toolchain**: require the pinned Go 1.26.5 toolchain on `PATH` for build-capable
   deployments. The `go.mod` toolchain directive, container, and CI use this same version.
   A future release may vendor a toolchain, but a daemon that cannot find `go` must keep
   workflow authoring disabled and direct operators to the CLI build path.
2. **Worker model**: in-process scheduler + N supervisor goroutines for v0. The `leases` table
   is in the schema from migration 1 so external workers can be added without a schema change.
3. **Replay determinism and authoring boundary**: `reactor lint` forbids
   `math/rand`, `time.Now`, direct `os`, and direct `net/http` imports outside
   the Reactor SDK. Temporal-strict by default. Workflow `sdk/http` uses the
   shared SSRF-safe transport by default; reviewed source may opt into private
   networks explicitly, while public destination policy remains operator
   responsibility (see docs/security.md Layer 4).

## Code generation + AI

4. **Workflow code at rest**: filesystem + git. Generated workflows land in
   `reactor-workflows/<slug>/` and are committed **when the directory is inside a
   git repository**. Nothing in Reactor runs `git init`, so on a default install
   the committer no-ops and `git log` is not an audit trail until an operator
   creates the repo themselves. STATUS: partially implemented.
   Opt-out via `REACTOR_GIT_BACKED=false` for low-disk installs.
5. **Dry-run sandbox**: in-process for v0. Child workflows run as subprocesses
   with resource limits; seccomp and stronger network isolation remain future
   hardening before treating Reactor as a hostile-code sandbox.

## MCP Environment Lens

6. **OpenAPI dialect**: 3.0 / 3.1 only via `kin-openapi`. Document `swagger2openapi` as the
   recommended one-liner for users with Swagger 2.0 specs.
7. **Write authorisation**: per-tool scopes (`workflow:write`, `service:write`, `trigger:write`).
   Single `write` scope is too coarse to retrofit later.
8. **Schema-diff UX**: when an OpenAPI refresh produces a new `service_versions` row, freeze
   active workflows on the old version + emit a `service.schema.changed` event so the AI can
   volunteer a migration. Never auto-migrate.

## Vault

9. **Master-key recovery**: no recovery phrase is shipped in v0.1. `reactor init` writes
   one random 32-byte key to `<state>/master.key`; operators must back it up out of band.
   A future recovery format remains a product decision and must not be described as
   available until it is implemented and tested.
10. **Default dual-validity window**: 60s. Per-rotator overrides (AWS IAM 90s, Postal 30s).
    Workflow runtime exposes `Drain()` so scheduler can extend the window up to 5 min if
    active steps still hold the credential.
11. **Audit log destination**: Postgres `credential_audit` table only for v0. The
    `audit.Writer` interface allows adding S3 / Loki tee-sinks without a code rewrite.
12. **Rotation concurrency cap**: 4 simultaneous rotations, tunable via
    `REACTOR_ROTATION_CONCURRENCY`. Prevents a misconfigured cron from rate-limiting every
    cloud provider at once.
13. **Multi-tenant identity model**: Reactor-owned master key with `tenant_id`-scoped
    decryption. v1 ships single-tenant; switching is a middleware change, not a re-encrypt.
