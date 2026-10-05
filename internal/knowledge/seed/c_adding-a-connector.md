---
id: c_adding-a-connector
topic: connectors
title: Adding a new connector (the universal bridge)
created_by: seed
sources: []
tags: [connectors, catalog, oauth, http, bridge, playbook]
gold: true
citation_count: 0
---

# Adding a new connector (the universal bridge)

Reactor's connector layer is data plus a generic bridge, not one Go client per
service. Adding a connection is almost always a catalog entry, not new code.
The bridge has three generic pieces that already work for any service:

- **Credential resolution**: `vault.MustGet("<key>")` for API keys,
  `vault.MustGet("oauth:<connection-id>")` for OAuth tokens (auto-refreshed).
- **OAuth flow** (`internal/oauth`): a provider-agnostic authorize-code + PKCE
  consent loop. Quirks are declarative (see below), not branches in the flow.
- **HTTP** (`sdk/http`): one client for any REST API, with `Bearer` plus a
  `Headers` map for every other auth shape.

## To add a service

1. Add one `Service` struct literal to `internal/catalog/catalog.go`:
   `ID, Name, Category, Auth (oauth|api_key), BaseURL, AuthScheme, KeyName,
   KeyHint, Docs, Ops`. That alone gives it AI prefill + the auto-add UI.
2. If it does OAuth, set `AuthURL`, `TokenURL`, `Scopes`. Now it appears on the
   Integrations page with a Connect button (once an admin pastes the client
   id/secret). A service can keep `Auth: api_key` AND set these to offer both.
3. Declare any OAuth quirks on the same entry, no flow code needed:
   - `TokenAuthStyle: "basic"` when the provider wants client creds as an HTTP
     Basic header on the token request (Pipedrive, Notion).
   - `AuthParams: {"owner": "user"}` for extra authorize-URL params (Notion).

## Auth shapes for the workflow's own calls

The generated workflow authenticates with `sdk/http`:

- Bearer: `&ahttp.Client{Bearer: string(vault.MustGet("name").Reveal()), CredentialOrigin: "https://<reviewed-provider-host>"}`.
- Anything else (raw token, API-key header, Basic, version pin): the `Headers`
  map (see [[c_generic-api]]). Query-param keys go on the URL. Set
  `CredentialOrigin` from reviewed provider configuration for every
  credential-bearing request; the SDK refuses a missing or mismatched pin.

## The ceiling (where the AI writes code)

A flat catalog entry covers REST + Bearer/Basic/header/query + standard OAuth,
which is the large majority. The tail still needs the AI to compose a few lines:
**signed JWT** auth (Ghost), **GraphQL** bodies (monday, Linear), and
**per-account dynamic hosts** (Shopify, self-hosted WordPress/Strapi/Drupal,
Salesforce instance_url, Zoho region) where the base URL comes from a reviewed
account setting or a provider response. Reactor retains a validated Salesforce
instance origin in its encrypted OAuth connection. The first host broker binds
Salesforce OAuth tokens to that origin for GET requests under `/services/data/`
using `sdk/http.ConnectorGet`; raw Salesforce token fetches fail closed. Other
providers and Salesforce writes still need equivalent reviewed broker paths.
A catalog entry alone is not a client-ready adapter.
