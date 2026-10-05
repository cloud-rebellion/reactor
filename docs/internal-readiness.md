# Internal readiness runbook

Reactor is ready for an internal single-tenant deployment when the daemon runs
as a dedicated unprivileged service account, its state directory is mode `0700`,
and dashboard authentication is configured. Keep the HTTP MCP route behind the
daemon's session or API-token authentication; it is admin-gated and read-only
unless capabilities are explicitly enabled.

Use `/readyz` for traffic admission. In addition to the database, artifact
store, and MCP checks, the daemon reports a `runtime` check that turns
unavailable when the HTTP listener, scheduler, cron, or rotation loop exits or
shutdown begins. A process started without a command runner also withdraws
runtime readiness when this tenant has an enabled command plan with an active
schedule, webhook, or terminal chain. That check is an existence query scoped
to the served tenant; it does not load command text or payload data. With a
live command runner, command execution errors remain per-trigger failures and
do not take the whole service out of readiness. A 200 response therefore means
the serve runtime is still present at that instant; `/healthz` remains a
liveness-only check.

## Start with least privilege

Use the HTTP daemon for the long-running internal service. Enable only the MCP
capabilities needed by the operator session:

```sh
reactor serve \
  --db sqlite:///var/lib/reactor/reactor.db \
  --root /var/lib/reactor \
  --mcp-allow-authoring \
  --mcp-allow-dispatch
```

Add `--mcp-allow-secrets` only when the client must grant or revoke vault
access. Add `--mcp-allow-knowledge` for corpus writes and
`--mcp-allow-diagnostics` only when AI post-mortem egress is approved. The
daemon's explicit `--mcp-allow-*` flags are the authority boundary for every
HTTP client; there is no per-client write flag to copy into a config file.

When MCP must provision an OAuth connector, set `REACTOR_DASHBOARD_URL` to the
registered public HTTPS origin and enable `--mcp-allow-secrets`. The consent
tool uses that fixed origin for `/oauth/callback`; it never accepts a callback
URL from the client. The returned authorization link is short-lived and must
be opened by a human in a browser. API-key or arbitrary secret ingress remains
outside MCP until a separate step-up secret-broker design exists.

Register the shared endpoint with the client:

```sh
reactor mcp install --client claude-code \
  --url http://127.0.0.1:7777/mcp \
  --token-env REACTOR_API_TOKEN
```

The token is used only to select an environment-backed header; its value is
never written to `.mcp.json` or printed in the generated Claude command. This
writes the project-scoped `.mcp.json` registration. The equivalent
Claude Code command is `claude mcp add reactor '<url>' --transport http
--scope project --header 'Authorization: Bearer ${REACTOR_API_TOKEN}'`.
Keep the single quotes: they preserve the environment placeholder for Claude
Code to resolve when it opens the MCP connection instead of expanding the
bearer in the invoking shell.

For Codex, use the same authenticated HTTP endpoint and an environment-backed
bearer. `--apply` adds Reactor to the Codex user configuration while preserving
other MCP servers; omit it to inspect the proposed snippet first:

```sh
reactor mcp install --client codex \
  --url http://127.0.0.1:7777/mcp \
  --token-env REACTOR_API_TOKEN --apply
reactor mcp check --url http://127.0.0.1:7777/mcp \
  --token-env REACTOR_API_TOKEN
```

Restart Codex and run `codex mcp list` after applying the config. The install
and connection check establish registration and reachability; run the MCP
authoring and dispatch acceptance below to establish tool behavior.

The old `reactor mcp stdio` command remains only for compatibility with clients
that cannot use HTTP. It is not the supported internal deployment shape.

## Author, inspect, then run

The safe MCP authoring sequence is:

1. Call `reactor_search_knowledge` and `reactor_query_graph` for prior service
   and data-handling decisions.
2. Call `reactor_validate_workflow` with the proposed Go source, optional
   helper `files` map, and DAG. A DAG is required whenever the source contains
   durable Reactor nodes so the rendered review cannot hide executable work.
   This checks DAG shape across all compiled Go files, imports, lint, `go vet`,
   and build without persisting a workflow or artifact.
3. Call `reactor_create_workflow` only after validation succeeds. Reactor
   records the DAG, immutable artifact digest, and workflow version, disabled
   for review. Disable an existing workflow before replacing its source.
4. Call `reactor_get_workflow_flow` or open the workflow dashboard page to
   inspect the normalized nodes and edges before enabling triggers.
5. Call `reactor_review_workflow`, then grant only the credential IDs the
   workflow needs with `reactor_grant_secret`; the runtime broker checks the
   workflow grant on each fetch and audits the read.
6. Call `reactor_set_workflow_state` with `state: "enabled"`,
   the `expected_state` observed from `reactor_get_workflow`, and the immutable
   `expected_version` returned by `reactor_review_workflow`. Reactor checks both
   fences atomically so a newer unreviewed revision cannot be activated.
7. Call `reactor_preflight_dispatch_workflow` and resolve any `blocked` or
   `unknown` admission state. `dispatchable_now` is a point-in-time receipt;
   it does not reserve capacity or survive a concurrent disable or shutdown.
   Then call `reactor_dispatch_workflow` for a controlled test payload with a
   stable `idempotency_key`; inspect the run status, logs, artifact digest,
   and flow before sending real events.
8. For human or external approval steps, deliver the caller-held
   `AwaitSignal` capability with `reactor_deliver_signal`. Reactor verifies the
   active tenant and never exposes signal tokens through inventory or run
   inspection.
9. When editing, pausing, or deleting a trigger, use the `revision` returned
   by `reactor_list_triggers` as `expected_revision`. A stale read is rejected
   without changing the trigger; re-read and review the intervening state
   before retrying.
10. When creating a cron, webhook, or chain trigger over HTTP, provide a stable
    `idempotency_key`. An identical retry replays the original trigger receipt;
    a changed configuration under the same key is rejected.
11. Before any tenant run-history erasure, call
    `reactor_preview_erase_tenant_data` and record its counts and `erasable`
    result. The destructive call remains separately scoped and confirmed; it
    never removes workflow or credential configuration.

Every registration surface stages the authored directory into a private build
tree before module setup, linting, and compilation. Supplied `go.mod` and
`go.sum` files are ignored there, so authoring and dashboard source trees stay
unchanged even when a build is rejected.

Authored workflows cannot import direct filesystem/process or raw network
transports such as `os`, `net`, `net/http`, `net/smtp`, `net/rpc`, or
`crypto/tls`; use Reactor inputs, the vault broker, and reviewed SDKs.
Workflow subprocesses get the SSRF-safe SDK
transport by default: private, link-local, metadata, and redirect destinations
are blocked. A reviewed source can explicitly opt into private networks, and
public destination selection still requires source and grant review. Run the
daemon with cgroup v2 limits when available. If authored code is considered
hostile, run the Linux service with delegated cgroup v2 and add
`--cgroup-root=/sys/fs/cgroup --require-workflow-cgroup`; the latter refuses
execution when descendant cleanup is unavailable. This still does not create a
network namespace, seccomp profile, or same-UID filesystem boundary, so use a
dedicated container or VM for hostile workflows.

## Acceptance evidence

Before calling an internal deployment ready, require:

- `go test ./...`, `go vet`, and `go build ./cmd/reactor` green on the exact
  source revision.
- A successful MCP authoring preflight and create operation.
- A successful MCP dispatch with the run's recorded artifact digest matching
  the registered workflow version.
- A rendered flow view showing the same nodes and edges as the validated DAG.
- A credential grant/fetch audit entry and a failed fetch for an ungranted ID.
- Authentication, backup of `<root>/master.key`, and a reversible recovery
  procedure documented for the chosen host.

Local green checks do not mean merged, deployed, or live-accepted. Record those
states separately in the release handoff.
