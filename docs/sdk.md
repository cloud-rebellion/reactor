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
type EventTrigger struct{ Topic string }

type Flow interface { /* Step, Sleep, AwaitSignal, FetchSecret, SignalToken */ }

type StepOpts struct {
    IdempotencyKey string
    Timeout        time.Duration
    Retry          RetryPolicy
}
type ExpBackoff struct{ Base, Max time.Duration; Attempts int }

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
to opt back in.

## sdk/runtime

```go
func Serve[I any](w Workflow, run func(ctx context.Context, flow Flow, in I) (any, error))
```

The workflow's main() calls this. It handles the wire protocol, decodes
REACTOR_INPUT into I, and calls run with a host-backed Flow.

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
type Client struct{ HTTPClient *http.Client; Retry Retry; Bearer string; UserAgent string }
type Retry struct{ Max int; BaseDelay, MaxDelay time.Duration; Jitter bool }
type Error struct{ Status int; Body string }

func (c *Client) Get(ctx context.Context, url string, out any) error
func (c *Client) PostJSON(ctx context.Context, url string, body, out any) error
func (c *Client) Do(req *http.Request) (*http.Response, error)
func IsRetryable(err error) bool
```

Workflow-side HTTP wrapper. Exponential backoff with full jitter
(crypto/rand because math/rand is banned by the lint), bearer auth,
typed *Error on non-2xx with status + body, IsRetryable matcher (5xx,
408, 429, transport errors).

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

Single-attempt adapter for Hash's `POST /api/automation/v1/signature-requests`
command. It requires HTTPS outside loopback, refuses redirects, bounds response
bodies, sanitizes API errors, and never returns signer bearer links. Put it
inside one Reactor Step and use the same stable event ID for the Step and Hash
idempotency keys. Let the Step retry only transport errors, timeouts, ambiguous
2xx responses, 408, 425, 429, and 5xx; a stable 4xx response is permanent.
