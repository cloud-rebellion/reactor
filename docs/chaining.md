# Workflow chaining

Run workflow B automatically whenever workflow A terminates. Chain triggers use
the existing `triggers` table; terminal side effects are recorded in the
durable `terminal_effects` receipt so a daemon crash can recover the handoff.

## Quick start

1. Open the **downstream** workflow's detail page (`/workflows/{slug}`).
2. Scroll to the **Run after another workflow** form below the cron + webhook trigger forms.
3. Enter the upstream workflow's slug as `source_slug`.
4. Pick which terminal statuses fire: default `succeeded`; broaden to `succeeded,failed,failed_dlq` to chain on failure too.
5. Click **Create chain trigger**.

The upstream workflow's detail page now shows a "Downstream workflows" section listing this chain.

## Schema

A new `kind` value on `triggers` from migration 0004 stores the chain
relationship. Migration 0038 adds one `terminal_effects` row per run so the
post-terminal handoff can recover after a host crash:

```text
kind = 'workflow_complete'
config_json = {
  "source_workflow_id": "wf_a",
  "on_statuses": "succeeded,failed_dlq"
}
```

The trigger row's `workflow_id` is the **downstream**. The upstream lives in `config_json`. Inverse navigation works in both directions:

- `Journal.ChainTriggersForSource(source_id, status)` - dispatcher's fast path on terminal events.
- `Journal.ChainTriggersDownstreamOf(source_id)` - workflow detail page's "Downstream workflows" section.
- `Journal.ChainTriggersUpstreamOf(workflow_id)` - workflow detail page's standard Triggers table renders chain rows as "after wf_src on succeeded".

## Status CSV

Same shape as notification routes ([Notifications](/docs/notifications)). Trim + lowercase + dedupe + sort on write. Empty defaults to `succeeded`. Self-loops and any cycle that would make a terminal run reach an already-visited workflow are rejected at create time.

## Payload to the downstream workflow

The dispatcher calls the trusted `DispatchTerminalChain` path where `payload` is:

```json
{
  "source_run_id": "run_5b06a401ff4bd96d",
  "source_workflow_id": "wf_a",
  "source_workflow_slug": "demo",
  "source_status": "succeeded",
  "source_trigger_kind": "webhook",
  "source_error_text": ""
}
```

The downstream workflow's body unmarshals this into its own `Input` type per the SDK contract:

```go
type Input struct {
    SourceRunID       string `json:"source_run_id"`
    SourceWorkflowSlug string `json:"source_workflow_slug"`
    SourceStatus      string `json:"source_status"`
    SourceErrorText   string `json:"source_error_text"`
}

func run(ctx context.Context, in Input) (Out, error) {
    // ...
}
```

The downstream can pull additional source state by querying the journal or making a tool call back into the dashboard's REST API ([API reference](/docs/api)).

## Fire path

When a run terminates:

1. The supervisor returns to the dispatcher with the run's status.
2. The dispatcher invokes the `OnTerminal` callback (set in `serve.go`).
3. The callback closes the log buffer (always), fires notifications (when status is terminal-class), then calls `fireChainedWorkflows`.
4. `fireChainedWorkflows` looks up matching chain triggers, marshals the payload, and calls `DispatchTerminalChain` for each downstream. Every peer is attempted; a failed handoff leaves the terminal-effect receipt retryable, while deterministic source/trigger idempotency prevents peers that already accepted their run from being duplicated on retry.
5. The callback acknowledges the `terminal_effects` receipt. The leader retries
   an unacknowledged receipt after a crash; delivery is at-least-once, so a
   downstream receiver should deduplicate by `source_run_id`.

The journal query and the fire boundary both require the source workflow, chain
trigger, and downstream workflow to carry the same tenant identity. Legacy or
imported rows that violate that relationship are omitted from the dispatch
projection, and the fire path skips any row that fails the authoritative source
run check. A malformed relationship therefore cannot turn a terminal event in
one tenant into a downstream run in another.

Chain firing is synchronous inside the inFlight goroutine, so graceful drain (`SIGINT` -> wait for in-flight runs) covers chained workflows too. Failures log and do not abort the loop; one bad downstream does not block peers, and the terminal receipt stays pending until the failed handoff is recovered.

## Diamond shapes and fan-out

A workflow can have multiple downstream chains and multiple upstream chains. `ChainTriggersForSource` returns every matching trigger in one query, so an upstream that terminates fires every downstream in parallel.

There is no built-in deduplication across two distinct chain trigger rows. A
single receipt is deduplicated by run id, while separate rows intentionally
fire separately.

## Cycle guard

`CreateChainTrigger` rejects `source_workflow_id == downstream_workflow_id` and
walks the existing active chain edges before inserting a new edge. A cycle such
as A -> B -> C -> A is rejected with no trigger row written, so a terminal run
cannot recursively re-enter an already visited workflow. Disabling an existing
edge removes it from the cycle check; reactivating a disabled chain through MCP
the dashboard, or the CLI is intentionally refused and requires creating a
fresh cycle-checked edge.
The cycle read and trigger write share a topology lock (a transaction-scoped
Postgres advisory lock or SQLite writer transaction), so concurrent authors
cannot validate two opposing edges against the same old graph.

## Operator surfaces

### `POST /workflows/{slug}/triggers` with `kind=chain`

Form fields:

| Field | Required | Default |
|---|---|---|
| `source_slug` | yes | - |
| `on_statuses` | no | `succeeded` |

Returns `404` if the source slug does not resolve. Returns `400` with the journal's error message if the create constraint failed (self-loop, empty statuses).

### Per-trigger management

Chain triggers use the standard trigger management endpoints:

- `POST /workflows/{slug}/triggers/{trigger_id}/delete` - hard delete.
- `POST /workflows/{slug}/triggers/{trigger_id}/pause` - temporarily stop firing.
- `POST /workflows/{slug}/triggers/{trigger_id}/resume` - re-enable.

There is no inline edit form for chain triggers in this release; delete and re-create to change the source or status CSV.

## Tests

- Journal: self-loop and multi-hop cycle rejection, round-trip with defaults, CSV filter, downstream + upstream view correctness.
- Dispatcher hook: every matching trigger fires, continue-past-failures, no-op on empty, nil-guards, error_text propagates into payload.
- Server: dashboard form happy path covers both views via `/workflows/{slug}` detail page, unknown source returns 404.

## Comparison with notifications

Both features key off the dispatcher's `OnTerminal` callback. The difference:

| Feature | Output | Use case |
|---|---|---|
| Notifications | Slack/email/webhook to a human | "Tell me when X breaks" |
| Chaining | Dispatch another workflow | "Run Y automatically after X" |

A workflow can have both. The dispatcher fires notifications first, then chained workflows.
