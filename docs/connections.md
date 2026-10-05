# OAuth connections

Let workflows act as a connected third-party account (Google, Slack, GitHub,
...) without anyone pasting raw API keys. The user connects an account once via
the standard OAuth consent screen; Reactor stores the tokens encrypted and
refreshes them automatically. Salesforce reads and operator-reviewed generic
GET requests use the host connector broker, which keeps access tokens out of
workflow code. New Google and Microsoft mail connections use a fixed host-owned
send route and never release their access token to workflow code. Pre-existing
generic connections retain explicit `legacy_raw` mode; new generic connections
start `broker_only` and wait for an operator API review.

## 1. Register a provider (admin, once)

On **OAuth providers** (`/oauth-providers`, admin-only):

- Create your OAuth app in the provider's console and set its redirect /
  callback URL to the value shown on the page (`<your-host>/oauth/callback`).
- Fill in the provider id, the authorize + token URLs, the client id +
  secret, and the scopes, then enable it. Common endpoints:
  - **Google** auth `https://accounts.google.com/o/oauth2/v2/auth`, token `https://oauth2.googleapis.com/token`
  - **Slack** auth `https://slack.com/oauth/v2/authorize`, token `https://slack.com/api/oauth.v2.access`
  - **GitHub** auth `https://github.com/login/oauth/authorize`, token `https://github.com/login/oauth/access_token`

Client secrets are encrypted at rest with the master key (the same envelope
encryption the vault uses) and are never shown back. Provider URLs must be
https (http is allowed only on localhost for development).
Disabling a provider is a runtime kill switch: consent callbacks, raw token
release, brokered reads, and brokered mail sends for its connections fail until
it is re-enabled.

Token responses must be complete and at most 1 MiB. An oversized or interrupted
response is rejected before token parsing. If this happens during refresh, the
connection is marked as an error and its stored encrypted tokens are preserved;
the failed refresh returns no access token. Error messages omit response bodies.
Refreshes for the same connection are serialized, including across Postgres
workers. A refresh updates only the token row it read, so a concurrent
reconnection or deletion cannot be overwritten or recreated by a late provider
response. Reconnecting an existing provider/account name retains its connection
id and its workflow grants. An access token that is expired or inside the
60-second expiry guard without a refresh token requires reconnection; Reactor
does not return that likely-invalid token to a workflow.

## 2. Connect an account (any user)

On **Connections** (`/connections`), pick an enabled provider, name the
connection, and click Connect. You are sent to the provider's consent screen
and returned here once you approve. The connection is scoped to your tenant;
its tokens are encrypted and never displayed. The flow uses PKCE and a
single-use, expiring CSRF state.

## 3. Use it in a workflow

Reference the connection as `oauth:<connection-id>` (shown on the Connections
page). For a generic connection with an approved API policy, use the host
broker inside a durable Step:

```go
import reactorhttp "github.com/bright-interaction/reactor/sdk/http"

var result map[string]any
err := reactorhttp.ConnectorGet(ctx, "oauth:conn_AbC123", "/v1/accounts/123", &result)
```

The operator reviews the specific connection on **OAuth broker policies**
(`/oauth-broker-policies`, admin-only), entering a public HTTPS API origin and
one allowed path prefix for GET. The review records the admin, time, and
monotonic version. The workflow supplies only a path and query, never an
origin or Authorization header. The host checks the run tenant, explicit
workflow grant, live lease, current policy revision, connection status, and
durable per-connection plus tenant/provider permits before it attaches a fresh
token. Prefix checks use a path-segment boundary: `/v1/accounts` does not
allow `/v1/accounts-private`. Redirects, private-IP targets, encoded path
bytes, and responses over 256 KiB are denied. The shared generic budget is
conservative across all connections to one provider in a tenant because
generic OAuth does not prove two connections belong to the same account.

Approval permanently changes the connection to `broker_only`. Deleting its
policy or editing it incorrectly makes broker requests fail closed; it never
restores raw-token access. A new review can restore GET service with a higher
version. For a strict no-raw cutover, pause/drain active workflows and command
runs that use the connection before approval, then rebuild them to use
`ConnectorGet`. Drain old daemon/worker binaries and verify the exact deployed
image as well: pre-0062 binaries do not enforce the new mode column, and a
running child can retain a previously released token. An already framed raw
reply can race approval. Existing grandfathered connections, including
pre-existing mail rows marked `legacy_raw`/`email_adapter`, can still use the
legacy runtime token accessor while their approved workflows migrate:

```go
token, _ := secrets.Get(ctx, "oauth:conn_AbC123")
// legacy mode only; token crosses into the workflow process
```

Fresh Google/Microsoft connections are `broker_only`. Send through them inside
one durable Step with a nonempty idempotency key:

```go
id, err := email.SendConnected(ctx, "oauth:conn_AbC123", email.Message{
    From: "me@example.com", To: []string{"customer@example.com"},
    Subject: "Welcome", Text: "Thanks for signing up.",
})
```

Gmail returns a message ID; Microsoft Graph accepts with HTTP 202 and no ID.
The child sends a structured message and connection reference. The host fixes
the HTTPS provider endpoint and POST method, attaches the token, requires the
run tenant and explicit workflow grant, and rechecks the live run, lease,
connection, canonical OAuth endpoints, and send-only requested and granted
scopes before egress. It uses durable per-connection and tenant/provider
permits, limits the provider request to 256 KiB and response to 8 KiB, and
does not follow redirects. The quick-add presets omit Gmail read and Microsoft
Mail.Read scopes. An endpoint edit, scope expansion, broad returned grant, or
revocation denies the broker. New arbitrary provider aliases are broker-only.

The host records one durable send intent per run and Step ordinal immediately
before POST. A retry or replay of a confirmed send returns its recorded result
without a second POST. An unconfirmed intent is ambiguous and never sends
again. An uncertain outcome is a permanent Step error with
`ambiguous` status; reconcile in the provider before manual redrive or a new
run. Use **one send and no other side effects per Step**. A Step idempotency key
and the intent protect replay within one run, not repeated upstream events in
separate runs. Previously
compiled raw-token mail workflows need rebuilding to use `SendConnected` for
fresh broker-only connections. Existing `legacy_raw`/`email_adapter` rows keep
their current raw-token behavior until those approved workflows migrate.
For a retained run, `reactor_list_run_mail_sends` shows bounded, tenant-scoped
intent metadata, including the non-secret provider and connection ID recorded
before egress. Older intents without those routing IDs show
`target_recorded: false`. `admitted` means provider acceptance is unknown; `confirmed`
means the provider API accepted the request, not that delivery succeeded. The
MCP view omits recipients, content, tokens, hashes, and provider message IDs.
An operator may record a separate `resolution` on an admitted intent using
`reactor_resolve_mail_send` after provider inspection. It keeps the original
`admitted` status, never sends mail, and never turns a manual finding into a
provider callback. The unresolved queue excludes resolved intents; the
per-run receipt still shows the decision and time without the underlying
evidence or actor identity.
An empty list means no intent was recorded for that retained run. Run retention
or tenant erasure deletes the intents with the run, after which the tool returns
run-not-found rather than an empty list.
The same per-workflow secret ACL (`workflow_secret_grants`) that gates vault
credentials gates `oauth:` ids, and the lookup is scoped to the run's tenant,
so a workflow can only use its own tenant's connections. Connections registered
under the canonical `salesforce` provider ID require an explicit grant even
when the legacy permissive ACL setting is enabled.

Salesforce returns an `instance_url` with its OAuth token. Reactor validates a
bare HTTPS origin under `salesforce.com` and retains it inside the encrypted
connection payload. The internal `oauth.Store.SalesforceAPIOrigin` accessor
returns only that origin for a connection in the requested tenant; it never
returns a token. If a refresh omits `instance_url`, Reactor keeps the previously
validated origin; a new valid origin replaces it. Invalid origins fail the
exchange without replacing the existing encrypted token. Older connections
without this metadata need a refresh that supplies `instance_url`, or a
reconnection, before the accessor can return an origin. Salesforce documents
the field in its
[web server flow](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_web_server_flow.htm&type=5)
and [refresh flow](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_refresh_token_flow.htm&type=5).

The broker also requires Salesforce's OAuth `id` identity URL, from which it
validates the org ID. Reactor keeps that ID inside the encrypted connection
and stores only a hashed shared budget key. A refresh that omits `id` retains
an established org ID; one that reports a different org ID is rejected until
the operator reconnects. Older connections without this metadata cannot use
the broker until a refresh supplies it or they reconnect. Salesforce documents
the [identity URL format](https://developer.salesforce.com/docs/platform/mobile-sdk/guide/oauth-using-identity-urls.html).

For reads from connections registered under the canonical `salesforce`
provider ID, use `sdk/http.ConnectorGet` with a provider-relative path:

```go
import reactorhttp "github.com/bright-interaction/reactor/sdk/http"

var result map[string]any
err := reactorhttp.ConnectorGet(ctx, "oauth:conn_AbC123", "/services/data/v60.0/sobjects/Account/001...", &result)
```

The host checks the run's tenant, workflow grant, and connection provider,
then resolves the current encrypted token and validated origin together. It
attaches the token to one HTTPS Salesforce org request; the child chooses only
the `/services/data/` path and query. Redirects and private-IP connections are
blocked, response bodies are capped at 256 KiB, and durable permits limit this
path to 30 requests/minute and 2 in-flight requests both per connection and
per Salesforce org within a Reactor tenant. Separate connections to the same
org share the org permit and cooldown.
HTTP 429 `Retry-After` starts a shared cooldown. No token, provider error body,
or full request URL is returned in broker errors. Only **GET** is supported
today; writes, pagination policies, and provider-specific retry semantics still
need reviewed adapters. This catalog entry is an authoring template, not a
certified connector. Custom Salesforce API domains outside `*.salesforce.com`
require a separately reviewed policy.

Raw `secrets.Get(ctx, "oauth:<salesforce-connection-id>")` fails closed at
the host boundary, including for already granted workflows. Existing Salesforce
workflows that fetch the token must migrate to `ConnectorGet` and rebuild their
workflow artifact before they can resume Salesforce reads. Salesforce writes
cannot be migrated to this GET-only path yet. Generic OAuth writes still use
legacy raw tokens. The shipped Gmail/Outlook connected-account sends use
`email.SendConnected`; the older token-taking adapters remain for grandfathered
workflows. Pre-0062 generic connections also retain raw mode until each is
explicitly reviewed.
The MCP `reactor_list_oauth_connections` inventory returns bounded, token-free
mode and review-version metadata so an AI author can distinguish pending,
approved, and legacy connections; it does not itself approve an origin or
guarantee a live run can execute. New custom provider aliases using known
Salesforce OAuth hosts (`*.salesforce.com`, `*.my.site.com`, or `*.force.com`)
are rejected; legacy aliases using those endpoints cannot return a raw token.
Custom Salesforce domains and proxies are not identified by this host check,
and aliases cannot use the canonical Salesforce broker. Review and migrate
them before treating the broker route as tenant-wide protection.
The broker controls where it attaches the token, but workflow code still sees
the returned data and can send that data through other permitted HTTP paths.
Review history is tied to a connection and is deleted when the connection is
deleted, including tenant erasure. Runtime policy-use receipts carry the
review version and follow run-retention/erasure rules. They contain no tokens,
provider response body, or full path. A policy edit committed after the final
host check can race an in-flight GET; a sent request cannot be recalled.
