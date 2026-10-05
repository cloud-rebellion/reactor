# SDK reference

The public surface AI-generated workflows import. Every entry below has
a corresponding banned-imports lint rule (workflow code can only import
the sdk packages + stdlib + a small allowlist).

## sdk

`github.com/bright-interaction/reactor/sdk`

```go
type Workflow struct{ Slug, Version string }
type Trigger interface{ triggerMarker() }
type WebhookTrigger struct{ Path, Provider string }
type CronTrigger struct{ Spec string }
type EventTrigger struct{ EventName string }

type Flow interface {
    Step(ctx context.Context, name string, opts StepOpts, fn func(context.Context) (any, error)) (any, error)
    Sleep(ctx context.Context, name string, d time.Duration) error
    AwaitSignal(ctx context.Context, name string, timeout time.Duration) (Signal, error)
    SignalToken(name string) string
    Logger() *slog.Logger
}

type StepOpts struct {
    IdempotencyKey string
    InputHash      string
    Timeout        time.Duration
    RetryPolicy    RetryPolicy
}
type ExpBackoff struct{ Max int; Base, Cap time.Duration }

func Step[T any](flow Flow, ctx context.Context, name string, opts StepOpts, fn func(context.Context) (T, error)) (T, error)
func SideEffect[T any](flow Flow, ctx context.Context, name string, fn func() T) (T, error)
func Retryable(err error) error
func Permanent(err error) error
func IsRetryable(err error) bool
```

`Step` is the durable-execution primitive. The closure runs once per
attempt; on success the supervisor journals the output_jsonb so a
restart-mid-run replays from cache. `SideEffect` captures a
non-deterministic value once (time.Now, crypto/rand, uuid, os.Getenv)
and journals it; replay returns the cached bytes without calling the
closure again. Use `Permanent(err)` to skip retries, `Retryable(err)`
to opt back in. For steps whose closure captures business input that can
change independently of the idempotency key, pass a bounded opaque digest in
`InputHash`; Reactor folds it into the replay identity and never sends the raw
input to the host.

## Pure data and control blocks

`github.com/bright-interaction/reactor/sdk/blocks` provides the n8n-style
shapes as deterministic, non-mutating Go helpers. `Switch` and `Split` route
data, `Iterate` maps items sequentially, `Chunk` creates bounded batches,
`Aggregate` reduces a collection. `Merge` appends; `JoinByKey` provides
inner/left/right/full joins including duplicate matches; `ZipAll` keeps
unmatched positional rows; and `CrossJoin` emits all combinations. These last
three require an explicit `maxRows` bound and return an error before exposing
partial output if it would be exceeded. `MergeByKey` is the older left-join
enrichment helper where the last duplicate right key wins, while `Zip`
deliberately stops at the shorter side. `MergeMaps` overrides map keys from
left to right. `Filter`, `UniqueBy`, `GroupBy`, `SortBy`, and
`Limit` cover the common list operations.

These helpers run inside a durable `Step`; they do not silently create hidden
runtime nodes or concurrency. To make the intended inner data flow inspectable,
an author may add a `visual_flow` annotation to that step in `dag.json`:

```json
{
  "nodes": [{
    "id": "process-orders", "kind": "step",
    "visual_flow": {
      "blocks": [
        {"id": "route", "kind": "split", "label": "Ready?"},
        {"id": "each", "kind": "iterate", "label": "Each ready order"},
        {"id": "total", "kind": "aggregate"},
        {"id": "join", "kind": "merge", "mode": "append"}
      ],
      "edges": [
        {"from": "route", "to": "each", "route": "ready"},
        {"from": "route", "to": "join", "route": "skipped"},
        {"from": "each", "to": "total"},
        {"from": "total", "to": "join"}
      ]
    }
  }]
}
```

`visual_flow` works in either `steps[]` or `nodes[]` DAG encoding, only on a
`kind: "step"` node. It allows 32 blocks and 64 edges per step, with 256 blocks
and 512 edges per workflow. Block kinds are `if`, `switch`, `split`, `iterate`,
`aggregate`, `merge`, `map`, `filter`, `reduce`, `group_by`, `sort`, `limit`,
`chunk`, `flatten`, `zip`, `join`, `unique`, `coalesce`, and `custom`. Edges are
acyclic and may carry a short `route` label. The schema rejects dangling
edges, duplicate block IDs, control characters in labels, unknown fields, and
oversized annotations.

Merge blocks may declare `mode` so the customer can see the intended
operation: `append`, `inner_join`, `left_join`, `right_join`, `full_join`,
`position_keep_all`, `position_truncate`, `all_pairs`,
`left_enrich_last_right`, or `map_override`. Key-join modes may add a
non-sensitive `key` identifier. `JoinByKey`, `ZipAll`, and `CrossJoin` modes
must also declare a `max_rows` value from 1 through 100,000, matching the
literal bound in the source call. For example:

```json
{"id":"join","kind":"merge","mode":"full_join","key":"customer_id","max_rows":1000}
```

For a value-free runtime observation of this exact merge, call
`blocks.JoinByKeyObserved(ctx, "join", left, right, leftKey, rightKey,
blocks.JoinFull, 1000)` directly inside the matching `reactor.Step` closure.
The block ID, mode, and limit must be literals matching the visual declaration.
The helper reports input/output row counts and a bounded outcome to the host;
it never sends rows, key values, or error text. It requires a supervised Step
and fails closed if the host cannot persist the observation. A plain
`JoinByKey` remains available when no receipt is needed.

For an observed split, declare `{"id":"route","kind":"split"}` in the
matching step's `visual_flow` and call
`yes, no, err := blocks.SplitObserved(stepCtx, "route", rows, predicate)`
directly inside that Step closure. The block ID must be a matching literal.
The helper accepts at most 100,000 input rows, reports only input/yes/no counts,
requires a non-nil predicate, and returns after the host persists and acknowledges
the receipt. It checks cancellation before reporting and returns no branch result
if already canceled. An
unobserved `Split` remains available. The receipt does not verify the
predicate or the declared route labels. Source/DAG review rejects a direct
visual `Split` or `SplitObserved` call with a literal nil predicate; dynamically
computed predicates still require runtime validation and source inspection.

For an observed item loop, declare `{"id":"each","kind":"iterate"}` and call
`mapped, err := blocks.IterateObserved(stepCtx, "each", rows, mapFn)` directly
in the matching Step closure. For an observed fold, declare
`{"id":"total","kind":"aggregate"}` and call
`total, err := blocks.AggregateObserved(stepCtx, "total", mapped, initial,
foldFn)` there. The block IDs must be literal matches. Both accept at most
100,000 inputs and return only after the host acknowledges a receipt with
input/output counts. An aggregate reports one final accumulator even for empty
input. Neither receipt contains item values or verifies the mapping or fold.
The ordinary `Iterate` and `Aggregate` helpers remain available without an
operation receipt.

The dashboard shows these blocks inside their durable step, including routes
and an accessible text fallback. MCP flow, review, and preflight receipts return
them as `step_flows` with `provenance: "author_declared_annotation"` and
`behavior_verified: false`. At build time, Reactor checks that each `split`,
`iterate`, `aggregate`, and `merge` block has one direct call to the matching
`sdk/blocks` helper in the enclosing `Step` closure, and that every such direct
call is represented when a step declares `visual_flow`. Typed merge modes also
check the direct helper, literal join mode, and literal row bound against the
annotation. The key name and data relationship remain author-declared. An import alias is
accepted; a shadowing local variable is not. Calls hidden in a separate helper
or nested function are not static evidence for the step and must be moved into
the closure or represented as `custom` until an inspectable source mapping is
available. Other block kinds, edges, route labels, and data relationships
remain author-declared. The check does not prove that a call ran on a specific
execution. The enclosing step has the authoritative durable outcome; the
observed join, split, iterate, or aggregate adds an **SDK-reported** operation receipt, not proof against
authored Go that can forge a wire frame. The run detail and
`reactor_list_run_block_receipts` distinguish such a receipt from a block with
no SDK observation. Undeclared branch
predicates, error paths, loops, aggregation, and transforms inside Go remain
unavailable to the canvas; inspect source and step receipts for actual behavior.

## sdk/runtime

```go
func Serve[I any](w Workflow, trigger Trigger, run func(ctx context.Context, flow Flow, in I) error)
func IsDryRun() bool
```

The workflow's main() calls this. It handles the wire protocol, decodes
REACTOR_INPUT into I, and calls run with a host-backed Flow. `IsDryRun` is
true during `reactor_test_workflow`; use it to select fixtures or skip business
mutations. SDK outbound HTTP is blocked independently during that review mode.

## sdk/vault

```go
type Secret interface{ Reveal() []byte; Fingerprint() string; String() string }
func Bind(r Resolver)
func MustGet(id string) Secret
func Get(ctx context.Context, id string) (Secret, error)
```

Workflows call `vault.MustGet("stripe-key")`. The returned Secret's
String / GoString / MarshalJSON / MarshalText / LogValue all redact;
only `.Reveal() []byte` returns the plaintext. The supervisor
brokers the fetch over the pipe, checks workflow_secret_grants, and
audits every read.

## sdk/http

```go
type Client struct{ HTTPClient *http.Client; Retry Retry; Bearer, CredentialOrigin, UserAgent string; Headers map[string]string; AllowPrivateNetwork bool }
type Retry struct{ Max int; BaseDelay, MaxDelay time.Duration; Jitter, UnsafeWithIdempotencyKey bool }
type Error struct{ Status int; Body string; RetryAfter time.Duration; RetryAfterLong bool }

func (c *Client) Get(ctx context.Context, url string, out any) error
func (c *Client) GetRaw(ctx context.Context, url string) (status int, headers map[string]string, body []byte, err error)
func (c *Client) PostJSON(ctx context.Context, url string, body, out any) error
func (c *Client) PutJSON(ctx context.Context, url string, body, out any) error
func (c *Client) Put(ctx context.Context, url string, out any) error
func (c *Client) PatchJSON(ctx context.Context, url string, body, out any) error
func (c *Client) Delete(ctx context.Context, url string, out any) error
func (c *Client) Do(req *http.Request) (*http.Response, error)
var ErrDryRun error
var ErrCredentialOrigin error
var ErrRequestURL, ErrRequestBody, ErrRequestTooLarge error
var ErrRetryConfig error
var ErrResponseRead, ErrResponseTooLarge, ErrResponseDecode error
func IsDryRun() bool
func IsRetryable(err error) bool
```

Workflow-side HTTP wrapper. Exponential backoff with full jitter
(crypto/rand because math/rand is banned by the lint), bearer or static
headers, typed *Error on non-2xx with status + body, and IsRetryable matcher
(5xx, 408, 429, transport errors). JSON and raw response bodies are capped at
4 MiB; oversized responses fail explicitly instead of being truncated. When
`Bearer` or any static `Headers` are set, `CredentialOrigin` is mandatory and
must be a reviewed scheme and authority such as `https://api.hubapi.com`.
The SDK rejects a missing or mismatched pin before adding headers or dialing;
the error is permanent for Step retries and does not echo URL query data.
Default ports match their explicit forms (`https` 443, `http` 80). The SDK
also checks common query credential names, but custom names need an explicit
pin; never derive the pin from a workflow input or provider response. Injected
HTTP clients cannot follow redirects and forward credential headers. When
`Retry.Max` exceeds 1, automatic retries cover GET, HEAD, and OPTIONS after
transport failures, 408, 429, or 5xx. Mutations are never automatically retried
unless `Retry.UnsafeWithIdempotencyKey` is set and the request has a non-empty
`Idempotency-Key` header; enable this only for an operation whose provider
documents that header's deduplication contract. A Reactor Step key alone does
not make an upstream POST idempotent. Retryable request bodies must be
replayable. The client honors `Retry-After` delta-seconds or HTTP dates up to
30 seconds and returns a longer rate-limit response without retrying. `Get`
and `PostJSON` expose that response as `*Error` with `RetryAfterLong=true` for
durable rescheduling; its `RetryAfter` value is only a lower bound in that
case. A zero-value `Client` makes one attempt; configure
`Retry.Max` explicitly when desired. During `reactor_test_workflow`, `Do`
returns `ErrDryRun` before dialing; the same guard is used by the built-in
email, payment, and e-sign adapters. Workflow requests share one SSRF-safe
connection pool per approved network policy.

HTTP retries accept at most 10 total attempts. A zero delay uses the SDK
default; an explicit delay must be nonnegative, at most 30 seconds, and the
base cannot exceed its ceiling. Invalid settings return permanent
`ErrRetryConfig` before any request. Longer waits belong in a durable Step
retry rather than an occupied HTTP worker slot.

`http.FetchPages` collects a bounded batch through the same client: by default
at most 10 pages, 1,000 items, and 16 MiB, with hard ceilings of 100 pages,
10,000 items, and 64 MiB. It follows only same-origin continuation URLs and
returns no partial batch on a failed page. A provider-specific decoder must
be pure; its error text is discarded because it may contain response data or
cursor credentials. `PageBatch.NextURL` can itself contain a provider cursor,
so keep it out of logs and pass it only to the next durable Step.

`PutJSON`, `PatchJSON`, and `Delete` make ordinary REST writes available to
authored workflows without importing `net/http`. They share `PostJSON`'s
origin-pin, dry-run, typed-error, and response-bound behavior. JSON requests
are limited to 16 MiB on the wire, responses to 4 MiB; malformed request URLs
and JSON encoder errors are returned without echoing the URL or body. Empty 204/205
responses succeed even when `out` is non-nil. `Put` handles a documented
bodyless PUT. Mutations make only one attempt
unless the provider explicitly supports `Idempotency-Key` for that operation,
the client sends a distinct key, and `Retry.UnsafeWithIdempotencyKey` is set.
The standard JSON encoder can briefly allocate more than the wire cap before
writing. Enforce the workflow cgroup or host memory limit when accepting
untrusted authored input.

Salesforce and operator-reviewed generic OAuth reads use `http.ConnectorGet(ctx,
"oauth:<connection-id>", "/services/data/v60.0/...", &out)` inside a durable
Step. The workflow sends only a connection reference and relative path to the
host. The host verifies the run's tenant and grant, uses the connection's
validated Salesforce origin or the reviewed generic API origin/prefix, attaches
the fresh token, and applies durable budgets of 30 requests per minute and two
concurrent requests across workers in one tenant. Salesforce groups by a
provider-attested org key; generic connections conservatively share a
tenant/provider budget because account identity is not attested. Older
Salesforce connections without an org key must refresh or reconnect before
brokered reads work. This broker supports GET only,
returns at most 256 KiB, and has no automatic host retry. A host without the
advertised broker capability fails closed. Ordinary `Client` calls and
legacy raw-token OAuth workflows do not use these host broker budgets.

Connected Google and Microsoft mail uses `email.SendConnected(ctx,
"oauth:<connection-id>", msg)` inside a durable Step with a nonempty
`IdempotencyKey`. Use one send and no other side effects per Step. The host
fixes the provider POST endpoint, verifies the current tenant, grant, lease,
connection, and send-only
scopes, and keeps the token out of the workflow process. Gmail returns a
message ID; Microsoft Graph accepts with HTTP 202 and returns an empty ID.
The host persists a once-only send intent before egress and never retries the
provider POST automatically. An uncertain outcome is a permanent Step error
that requires provider reconciliation before manual redrive. A host without
the advertised mail broker capability fails closed.

## sdk/idempotency

```go
func Key(workflowSlug, stepName string, kv ...string) string
func KeyForPayload(workflowSlug, stepName, payloadID string) string
```

Canonical sha256 over (slug, step, sorted-kv-pairs). Use as
StepOpts.IdempotencyKey. Single-id shortcut for the common webhook case.

## sdk/esign

```go
const SpecVersion = "1.0"
const EventTypeDocumentRequested = "esignature.document.requested.v1"

func DecodeDocumentRequested(raw []byte) (DocumentRequested, error)
func (DocumentRequested) Validate() error
```

Provider-neutral e-signature request envelope used by CRM, Google Apps Script,
and standalone producers. Decoding rejects unknown fields, unsupported versions
or event types, non-string variables, invalid customer/recipient identities,
duplicate recipients, and oversized collections. Tenant, endpoint, API key,
organization, and concrete template UUID are deliberately absent from the
trusted routing contract.

## sdk/esign/hash

```go
func NewClient(baseURL, apiKey string, httpClient *http.Client) (*Client, error)
func (c *Client) CreateAndSend(ctx context.Context, idempotencyKey string, request SignatureRequest) (SignatureResult, error)
func IsRetryable(error) bool
func Recipients([]esign.Recipient) []Recipient
```

The default client uses Reactor's connect-time SSRF and DNS-rebinding guard,
refuses redirects, and bounds response bodies. An explicitly injected
`*http.Client` is preserved for tests or reviewed integrations and remains the
caller's responsibility for transport policy.

Single-attempt adapter for Hash's `POST /api/automation/v1/signature-requests`
command. It requires HTTPS outside loopback, refuses redirects, bounds response
bodies, sanitizes API errors, and never returns signer bearer links. Put it
inside one Reactor Step and use the same stable event ID for the Step and Hash
idempotency keys. Let the Step retry only transport errors, timeouts, ambiguous
2xx responses, 408, 425, 429, and 5xx; a stable 4xx response is permanent.
