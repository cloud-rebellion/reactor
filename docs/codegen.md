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
   - JSON validity on dag.json

   > **Resolving the SDK import.** The Reactor SDK module is not yet
   > published to a public Go proxy, so `go build` of a generated workflow
   > can only resolve `github.com/bright-interaction/reactor/sdk/...` inside
   > the dev checkout. To build on a self-hosted box, set
   > `REACTOR_SDK_REPLACE=/path/to/reactor` (a local Reactor source
   > checkout); the scaffold then writes a `require` + `replace` so the
   > workflow builds against it. Once the module is published this becomes
   > unnecessary.
6. **Retry on failure.** Up to MaxRetries (default 3) more rounds with
   the validator output fed back as "fix only these issues".
7. **Atomic rename.** On success, mv tempdir into
   `<workflows-dir>/<slug>/`. Committer (default `GitCommitter`) stages
   + commits with `feat(workflow): <slug> v<version>`.
8. **Auto build + register** (dashboard path only). After codegen returns, the
   server builds to a private stage, publishes the exact executable under its
   SHA-256 content address, and atomically records that digest on version 1 (or
   appends the next version for an existing slug). The mutable
   exact digest is also recorded as the split-build candidate. The
   `<root>/workflows/<slug>/workflow` compatibility copy is activated only after
   the immutable artifact and database version exist, while holding the
   workflow-version row lock and only if that version is still current. A
   delayed older registration therefore cannot overwrite a newer activation.
   The operator's redirect lands on `/workflows/<slug>` with a built +
   registered workflow.

For the split CLI path, `reactor workflow build` prints the published digest
and atomically updates `<slug>/candidate.sha256`; `workflow register` consumes
that reference by default. If two people or CI jobs may build the same slug at
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

- **Banned imports:** `math/rand`, `os/exec`, `syscall`, `unsafe`,
  `net/http` (workflows use `sdk/http` instead).
- **Banned calls:** `time.Sleep`, `time.Now`, raw `panic(...)`.
- **Em dashes** anywhere in source.

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
