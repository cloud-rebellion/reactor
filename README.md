# Reactor

AI-built workflow automation. Self-hosted. Single Go binary.

You describe a workflow in natural language. An AI client (via authenticated
HTTP MCP) can inspect the permitted environment and generate reviewable Go
source wired to connection and credential references. Reactor can commit
reviewed source to Git when a repository is present; set
`REACTOR_GIT_BACKED=false` to keep an install filesystem-only. The runtime
executes approved artifacts with durable checkpoints and replay.

## Status

v0.1 internal readiness is in progress. The daemon includes scheduler, cron,
rotation, HTTP/webhook/signal receivers, dashboard, codegen, knowledge and
graph views, post-mortems, scaffold CLI, and HTTP MCP installation. The
dashboard can configure credentials and triggers and review generated flows.
Local tests cover these surfaces, but the distributed deployment, sustained
capacity, broad provider-credential isolation, and complete execution-data
encryption still require implementation and acceptance. See
[security](docs/security.md), [scaling](docs/scaling.md), and
[operations](docs/operations.md) for current
boundaries before using customer data.

## What makes this different

- **AI builds, not drags.** Claude with the MCP Environment Lens (services, credentials metadata, schemas, run history, post-mortems, knowledge corpus) is the primary builder. Reactor also renders the stored DAG and each run's data flow in the dashboard and through `reactor_get_workflow_flow`.
- **Code as artifact.** Generated Go is written to disk as real source, not JSON config, so it can be reviewed and versioned. The committer uses a detected Git repository by default; set `REACTOR_GIT_BACKED=false` to disable that side effect. It no-ops when there is no repository, and `reactor init` does not create one. MCP authoring retains the exact `main.go` and `dag.json` under the workflow and beside each immutable artifact; Git history remains an optional external review layer.
- **Durable execution.** Step journal in the database. Workflows resume after restart. `Sleep(72h)` is real. Replay any past run.
- **Self-contained vault.** AES-256-GCM, PBKDF2-SHA256 600k iterations, autorotation with zero-downtime hot-swap.
- **One binary.** Go runtime, dashboard, webhook + signal receivers, vault, scheduler, rotation engine, MCP server, all embedded. SQLite single-node or Postgres scale-out.
- **Scales horizontally on just Postgres.** `--mode distributed` enqueues runs; add `reactor worker` processes to handle more load (a Postgres `SKIP LOCKED` queue + per-run leases, no Redis/NATS/k8s). See [docs/scaling.md](docs/scaling.md).
- **No SaaS lock-in.** Fair-code (Sustainable Use License): self-hosted, your code, your data, your control plane. Free to run, modify, and use commercially, including for your clients. You just can't resell it as a competing hosted service.

## Prerequisites

- Go 1.26.5+ on `PATH` for any path that builds workflows (the daemon and MCP authoring path spawn `go build`; the Homebrew formula and Docker image supply it, while native Linux packages require a host installation)
- SQLite (bundled) or PostgreSQL 14+

## Quickstart (one-command setup)

```bash
reactor setup                  # interactive: state dir, db, admin user + password
set -a; source ~/.reactor/reactor.env; set +a  # load DB, auth, and root env
reactor serve --root ~/.reactor
open http://127.0.0.1:7777/
```

For a populated demo with two workflows + two credentials seeded:

```bash
make demo
bin/reactor serve --root /tmp/reactor-demo --db sqlite:///tmp/reactor-demo/reactor.db
open http://127.0.0.1:7777/
```

The dashboard shows workflows, recent runs with timelines and live log tail, credentials with rotation state, a DAG editor with inline validation errors, and a post-mortems index. To trigger the example workflow seed a webhook trigger row (see `examples/cron-echo/main.go`); a live trigger looks like:

```bash
curl -X POST http://127.0.0.1:7777/webhook/<token> \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=<hmac-of-body>" \
  -H "X-Webhook-Delivery: $(uuidgen)" \
  -d '{"hello":"world"}'
```

The dispatcher resolves the trigger to a workflow, spawns a supervisor (with prlimit caps on Linux), and the run shows up at `/` (the dashboard home) within a second.

## CLI surface

```
reactor setup    [--root <dir>] [--non-interactive ...]  one-command first-boot wizard
reactor init     [--root <dir>]                          bootstrap state dir + master key (subset of setup)
reactor migrate  --db <url>                              run pending schema migrations
reactor payload  backfill-command-definitions            seal one bounded batch of legacy command definitions
reactor payload  backfill-run-logs                       seal one bounded batch of legacy run logs
reactor serve    --db <url> [--addr 127.0.0.1:7777]      run the daemon (HTTP + scheduler + rotation + dashboard)
reactor workflow list/register/build                     manage workflow registrations + binaries
reactor new      <template> <name>                       scaffold a workflow from a template
reactor generate --brief <text>|--brief-file|<stdin>     AI codegen via Claude (creates + commits)
reactor replay   --db <url> <run-id>                     show timeline for a finalised run
reactor test     <recorded-run>                          replay a run through the supervisor in replay mode
reactor dlq      list/show [--json] [<id>]               dead-letter inspection
reactor dlq      retry <dlq-id>                          re-run through the canonical dispatcher gates
reactor lint     [--format text|json] <path>             lint workflow .go file or dir
reactor ps                                                read-only daemon state summary
reactor vault    add/list/audit/rotate                   credential vault + rotation
reactor vault    grant/revoke/grants                     per-workflow secret ACLs
reactor knowledge add/list/search/show/supersede/promote/stale  knowledge corpus management
reactor mcp      install --client X --url URL          register the HTTP MCP endpoint
reactor version                                           print build version
```

## Rotation targets

The rotation engine delivers new credential values to consumers via these target kinds:

| Kind              | Use case                                                                  |
| ----------------- | ------------------------------------------------------------------------- |
| `webhook`         | single-phase HMAC-signed POST; receiver atomically replaces the named key |
| `reload_endpoint` | dual-phase grace window for actively-authenticated sessions               |
| `file_write`      | atomic on-disk replacement (docker-compose env_file, systemd EnvironmentFile) |
| `github_secret`   | PUT to a GitHub Actions repository secret (libsodium sealed box)          |
| `forgejo_secret`  | PUT to a Forgejo / Gitea Actions secret via the repo API                  |
| `dockyard_vault`  | PUT to a Dockyard vault entry (covers Hephaestus deploy secrets end-to-end) |

## Rotation providers

| Provider        | Behaviour                                                                  |
| --------------- | -------------------------------------------------------------------------- |
| `cloudflare`    | Rolls a Cloudflare API token in place (PUT /user/tokens/{id}/value)        |
| `shared-secret` | Mints a fresh 32-byte random hex value (HMAC keys, inter-service tokens); requires explicit local-mint acknowledgement |
| `aws-iam`       | Self-rotates an IAM user access key pair; deletes the old key with the new |
| `manual`        | Reminder-only; audits "rotation due" without minting                       |

## Architecture decisions

Locked decisions live at [DECISIONS.md](DECISIONS.md). Highlights: Postgres-first for production (SQLite for OSS quickstart), per-workflow `go build` to a binary supervised as a subprocess with prlimit + cgroup v2 caps on Linux, code committed to `reactor-workflows/<slug>/workflow.go` with a sibling `dag.json`.

## Documentation

Deeper material lives in [docs/](docs/): [architecture](docs/architecture.md), [sdk reference](docs/sdk.md), [codegen pipeline](docs/codegen.md), [rotation catalogue](docs/rotation.md), [mcp transports](docs/mcp.md), [security model](docs/security.md), [operations runbook](docs/operations.md).

## Deployment

See [deploy/README.md](deploy/README.md) for systemd + Docker walkthroughs. [`deploy/docker-compose.yml`](deploy/docker-compose.yml) is a development-only SQLite quickstart; production bridges use the documented PostgreSQL `serve --mode distributed` plus dedicated `worker` topology. Native packages: [`packaging/`](packaging/) ships the Homebrew formula template + nfpm config the release CI uses to build `.deb` and `.rpm` artifacts on every `v*` tag.

## License

Reactor is **fair-code** ([faircode.io](https://faircode.io)), licensed under the **Reactor Sustainable Use License**. The source is open to read, run, and modify. You can self-host it on your own VPS, use it commercially for your own business, and use it to deliver automation services to your clients. You cannot resell Reactor or run it as a hosted/managed service for third parties (a competing "Reactor cloud") without a separate commercial license. See [LICENSE](LICENSE), or email tom@cloudrebellion.se.
