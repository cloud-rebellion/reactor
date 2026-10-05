# Connector execution contracts

The service catalog supplies authoring templates, OAuth setup hints, and
example operations. It is not a list of production-certified adapters. Before
enabling a client integration, verify the provider's current authentication,
pagination, throttling, and mutation idempotency contract against its own API
documentation and exercise those paths with a provider sandbox or contract
fixture.

## Bounded paginated reads

`sdk/http.FetchPages` handles the common read-side loop while the adapter owns
the provider's response shape. The decoder returns items and the provider's
next-page reference; it may use a JSON field or a response header. Each request
uses the regular SDK timeout, SSRF, dry-run, retry, and 4 MiB response policy.
Provider-supplied next links must stay on the starting scheme and host. Userinfo,
fragments, invalid URLs, and cycles are rejected before another request sends
the client's authorization header.

```go
type Contact struct { ID string `json:"id"` }

type contactsResponse struct {
    Data []Contact `json:"data"`
    Next string    `json:"next"`
}

decode := func(raw []byte, _ map[string]string) (reactorhttp.Page[Contact], error) {
    var response contactsResponse
    if err := json.Unmarshal(raw, &response); err != nil {
        return reactorhttp.Page[Contact]{}, err
    }
    return reactorhttp.Page[Contact]{Items: response.Data, Next: response.Next}, nil
}

batch, err := reactorhttp.FetchPages(ctx, client,
    "https://api.example.test/v1/contacts?limit=100",
    reactorhttp.PageLimits{MaxPages: 5, MaxItems: 500, MaxBytes: 8 << 20},
    decode)
```

The example URL and response fields are illustrative, not a provider contract.
The zero-value limits default to 10 pages, 1,000 items, and 16 MiB of response
bodies per batch; explicit limits have hard ceilings of 100 pages, 10,000 items,
and 64 MiB. A batch returns whole pages. `Complete` means the provider gave no
next reference. Otherwise `NextURL` points to the next page and can start a
later bounded batch. If one page exceeds the remaining item or byte budget,
the call fails with `ErrPageLimit` and returns no partial data, so the adapter
must request a smaller provider page size. Non-2xx responses return the SDK's
typed `*Error`, including bounded `Retry-After` information for 429s.
For rate-sensitive providers, set `MaxPages: 1` and journal each completed
page separately; a retry after a later-page failure then does not refetch the
earlier pages.

Keep page decoders pure. A failed batch may be retried from the first page;
mutating the provider while decoding would duplicate effects. Some providers
place sensitive cursor values in a next URL. Do not log or return such URLs in
workflow outputs; design a provider-specific protected cursor path before
journaling them. The same-origin check protects against credential forwarding
to a different origin, not against every provider-specific cursor or data
handling risk.

## Writes and rate limits

An external mutation should use a stable Reactor Step idempotency key and the
provider's own deduplication mechanism when one exists. `sdk/http.Client` does
not automatically retry POST, PATCH, PUT, or DELETE unless the adapter explicitly
sets `Retry.UnsafeWithIdempotencyKey` and sends a non-empty `Idempotency-Key`
header for an operation whose provider contract guarantees that behavior.
A Step key alone does not make an external write idempotent.

For 429 responses, the SDK waits for short `Retry-After` periods within the
request context. Longer windows return a typed error with
`RetryAfterLong=true`. A Step retry policy respects short provider waits; the
host persists the short provider deadline before acknowledging the failed
attempt, so a worker restart cannot allocate the next attempt early. The host
does not spend a retry slot while waiting for that deadline. A long window
stops automatic retries and reaches the dead-letter path unless the workflow
has an explicit durable reschedule contract. Provider-specific quota headers
and shared account-level limits across workers require an adapter contract and
a durable shared budget. The Salesforce OAuth GET broker is the first such
contract. The host pairs a fresh token with its validated account origin and
the organization ID parsed from Salesforce's OAuth `id` identity URL. The
identity comes from the token exchange, never from a workflow path, MCP
argument, or connector output. The encrypted connection stores the org ID;
the budget database stores only a SHA-256 account key. Multiple connections
to the same org **within one Reactor tenant** share a durable rolling-minute
budget and 429 `Retry-After` cooldown: initially 30 requests per minute and
two concurrent requests. A connection also keeps its former per-connection
budget during the transition. A shared-budget refusal can therefore consume
a per-connection receipt without sending an upstream request; this is
conservative rather than an extra request.

Existing Salesforce connections without an OAuth identity URL can still be
listed and refreshed, but `ConnectorGet` fails closed until refresh supplies
the org ID or the operator reconnects. A refresh may update the API origin but
cannot silently change an established org ID; reconnecting is required for a
new org. The Salesforce catalog requests the `id` scope explicitly. Salesforce
documents the token response's `id` and `instance_url`
fields in its [web server OAuth flow](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_web_server_flow.htm&language=en_US&type=5)
and the [org/user identity URL format](https://developer.salesforce.com/docs/platform/mobile-sdk/guide/oauth-using-identity-urls.html).
The parser currently accepts `*.salesforce.com` identity hosts and Salesforce
15- or 18-character org/user IDs; custom Experience Cloud identity domains
need a separately reviewed policy.

This budget covers **only** host-brokered Salesforce OAuth GET requests under
`/services/data/`. It does not cover Salesforce writes, ordinary SDK HTTP,
other OAuth providers, provider traffic outside Reactor, or one Salesforce org
connected through separate Reactor tenants. This tenant boundary avoids
cross-tenant quota coupling and timing signals, but it does not enforce a
provider-global quota when clients share one Salesforce org. Mixed old/new
workers do not all enforce the org budget: finish the migration and replace
old workers before claiming the shared limit. There is no policy UI or MCP
budget management yet.
Other providers need a reviewed provider-attested account identity and a
host-brokered egress contract before using the shared permit primitive.

The SDK's default error text contains only the HTTP status or a decoder error,
not an upstream error body or a request URL with cursor/query parameters.
`*reactorhttp.Error.Body` remains available to a reviewed adapter for deliberate
classification; never copy it into logs, Step errors, or customer-facing
outputs because providers may echo credentials or customer data.
