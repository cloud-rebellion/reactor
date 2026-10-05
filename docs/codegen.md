# Codegen

Two paths to a workflow: CLI (`reactor generate`) and dashboard
prompt bar (`POST /generate`). Both run the same orchestrator with
the same lens + validator + retry chain.

## Pipeline

1. **Brief in.** Free-text description of what the workflow should do.
2. **Lens query.** `internal/codegen.PromptLens` queries:
   - `knowledge.Store.Search` for the top 5 corpus entries matching
     the brief (full-text search; gold entries weighted higher).
   - `graph.Graph.Query` for the runtime subgraph (services,
     credentials by metadata, recent runs, dlq items) relevant to the
     brief.

   Graph rebuilds page the estate-wide credential inventory through a
   metadata-only SQL projection and index knowledge frontmatter without
   retaining markdown bodies. Provider metadata, rotation targets, and
   knowledge content therefore stay out of the topology cache and prompt
   lens unless a separate, authorized read asks for them. BM25 preparation
   also caps each untrusted graph attribute and each node's searchable text,
   so a legacy diagnostic cannot turn a graph query into an unbounded scan.

   MCP graph responses apply a second boundary: nested maps and slices are
   sorted only after their item limits are checked, sensitive keys (including
   nested errors, tokens, URLs, provider metadata, and payloads) are redacted,
   strings and nested JSON have byte/depth caps, and ordinary attributes are
   marked truncated when the per-node or per-edge budget is reached. The
   graph store deep-copies JSON-like attributes on insert and read so a
   caller cannot mutate tenant ownership or diagnostics outside the graph
   lock. The admin-only `/graph.json` route is the raw diagnostic export;
   MCP and codegen use the bounded projections.
3. **Prompt assembly.** The system prompt (embedded at
   `internal/codegen/prompts/system.md`) plus the lens output plus the
   user brief feed into `Generator.assembleUserMessage`. Hard rules are
   enforced in the system prompt: only the SDK + stdlib + small
   allowlist, idempotency keys mandatory on side-effecting steps, no
   `time.Sleep` / `math/rand` / raw panic, no em dashes.
4. **Anthropic call.** stdlib HTTP client (no SDK dep) to
   `/v1/messages`. ToolChoice forces a single `emit_workflow_files`
   call returning `{slug, version, workflow_go, dag_json,
   workflow_test_go}`.
5. **Validate.** Files land in a tempdir; the default Validator runs:
   - `go mod init` + `go vet`
   - `reactor lint` (AST checks: banned imports, banned calls, em dashes)
   - `go build`
   - the bounded DAG schema on `dag.json`, including rejection of duplicate
     object keys. This prevents Go's JSON decoder last-wins behavior from
     making the visual graph or persisted version differ from the authored
     source on direct CLI/programmatic build paths.

   > **Resolving the SDK import.** The Reactor SDK module is not published to
   > a public Go proxy. Docker bundles a source copy; native `.deb`/`.rpm`
   > releases bundle the exact SDK and local `safehttp` source at
   > `/usr/lib/reactor-sdk`, and their systemd unit pins
   > `REACTOR_SDK_REPLACE` to that directory. Manual binary or development
   > installs need `REACTOR_SDK_REPLACE=/path/to/reactor` pointing at matching
   > source. Go 1.26.5+ must be on the daemon's PATH. Builds use
   > `GOPROXY=off` and `GOTOOLCHAIN=local`; a missing local SDK or toolchain
   > cannot be downloaded during authoring.
6. **Retry on failure.** Up to MaxRetries (default 3) more rounds with
   the validator output fed back as "fix only these issues".
7. **Atomic rename.** On success, mv tempdir into
   `<workflows-dir>/<slug>/`. Committer (default `GitCommitter`) stages
   + commits with `feat(workflow): <slug> v<version>` when a repository is
   present. Set `REACTOR_GIT_BACKED=false` (or `0`/`off`) to disable that
   optional side effect.
8. **Auto build + stage** (dashboard path only). After codegen returns, the
   server builds to a private stage, publishes the exact executable under its
   SHA-256 content address, and atomically records that digest on version 1 (or
   appends the next version for an existing slug). The selected dashboard
   tenant is recorded on the workflow; an unknown tenant is rejected rather
   than silently falling back to `default`. The mutable exact digest is also
   recorded as the split-build candidate. The
   `<root>/workflows/<slug>/workflow` compatibility copy is activated only after
   the immutable artifact and database version exist, while holding the
   workflow-version row lock and only if that version is still current. A
   delayed older registration therefore cannot overwrite a newer activation.
   Dashboard-generated workflows are inserted disabled. The redirect carries
   the selected tenant and lands on `/workflows/<slug>` so an operator can
   inspect the source and visual DAG, then explicitly enable the reviewed
   artifact before dispatch.

The journal allows a slug to appear in more than one tenant. Existing
installations keep the legacy `<root>/workflows/<slug>` namespace, protected by
an immutable `.tenant-owner` manifest. When `BuildAndRegister` sees that slug
owned by another tenant, it uses a hashed tenant namespace under
`<root>/workflows/tenants/<tenant-hash>/<slug>` and writes the same owner
manifest there. Candidate pointers, retained source, compatibility binaries,
and immutable artifacts are therefore isolated per tenant while old installs
remain readable. A pre-manifest legacy directory is accepted only when an
existing same-tenant journal row provides explicit migration proof; an
unclaimed directory cannot be adopted because a digest happens to exist on
disk.

The split `workflow build` command has no tenant flag and always reserves the
default tenant; use the digest printed by that command with `workflow register`
after review. It still refuses a slug owned by another tenant because the CLI
cannot select that tenant; use MCP or the dashboard authoring path to create a
same-slug workflow in a selected tenant. Version artifacts are retained after
workflow deletion, and each owner manifest remains a fail-closed reservation;
reclaiming a deleted tenant's namespace still requires an authenticated
garbage-collection/adoption workflow.

For the split CLI path, `reactor workflow build` prints the published digest
and atomically updates `<slug>/candidate.sha256`; `workflow register` consumes
that reference by default. CLI registration is an import/staging operation: it
keeps the workflow disabled because it does not retain the complete source
manifest needed for the execution proof. Use the MCP/dashboard build path for
an executable workflow. If two people or CI jobs may build the same slug at
the same time, copy the digest printed by your build into
`workflow register --artifact-sha256 <digest>` so the session cannot select the
other build's newer candidate pointer.

## What the lens injects

Run `reactor generate --echo-prompt --brief 'send a welcome email when
a customer signs up'` and read the stderr output for the verbatim
prompt assembly. The graph slice is filtered to the brief's keyword
matches; the knowledge entries are the lens's chosen 5.

## Lint rules

`internal/codegen/lint.go` is an AST walker. Rules:

- **Banned imports:** `math/rand`, `os`, `os/exec`, `syscall`, `unsafe`,
  raw network transports (`net`, `net/http`, `net/smtp`, `net/rpc`,
  `crypto/tls`), filesystem wrappers (`io/ioutil`, `go/parser`,
  `text/template`, `html/template`, and debug object readers), and raw socket
  logging (`log/syslog`) (workflows use the reviewed SDK connectors instead).
- **Banned calls:** `time.Sleep`, `time.Now`, raw `panic(...)`.
- **Em dashes** anywhere in source.

The build path applies import and lint checks to every `.go` helper under the
workflow directory, not only `main.go`. MCP authoring can supply those helpers
and assets through its bounded `files` map; the complete staged tree is then
retained with a content manifest. Source/DAG validation uses the Go toolchain's
selected files for `go build .`, including imported local helper packages and
excluding unused packages, OS-specific files, and excluded build tags. That
selected-file list is pinned in the retained source manifest and reused at
review/dispatch without reinterpreting tags on another host. This is static
source consistency: a call in dead code can still be selected, so only runtime
step receipts establish which operations actually ran.
Native source and assembly files
(`.c`, `.cpp`, `.m`, `.s`, `.asm`, `.syso`, and related extensions) are rejected
before compilation so the authoring boundary remains Go plus the Reactor SDK.

The same lint runs on the editor save path
(`POST /workflows/{slug}/code`) so dashboard edits get the same gates.

## Failure modes

- **Anthropic 429:** the generator surfaces `IsRateLimited` on the
  typed `*APIError`. The retry loop respects this by waiting + retrying
  the same prompt rather than feeding back a "fix me" message.
- **Validator fail after MaxRetries:** the orchestrator returns the
  last validator error; the tempdir is preserved at `tmp_path` in the
  return value so an operator can debug.
- **Empty brief:** rejected before the Anthropic call.
