---
id: c_generic-api
topic: connectors
title: Integrate any catalog service (CRM, project management, ...) via sdk/http
created_by: seed
sources: []
tags: [connectors, crm, project-management, http, oauth, api-key, idempotency]
gold: true
citation_count: 0
---

# Integrate any catalog service via sdk/http

Most services do not need a dedicated SDK package. The Environment context
lists, for every connected service, its base URL, auth scheme, and example
operations. Confirm provider details against the linked docs before using
`sdk/http`. Prefer a dedicated package (`sdk/email`,
`sdk/stripe`, `sdk/mollie`) when one is listed.

## The pattern

```go
import ahttp "github.com/bright-interaction/reactor/sdk/http"

_, err := reactor.Step(flow, ctx, "create-contact", reactor.StepOpts{
    IdempotencyKey: "hubspot-contact:" + in.Email, // writes are side effects
    Timeout:        30 * time.Second,
}, func(ctx context.Context) (map[string]any, error) {
    // API-key service: the key is a static vault credential by name.
    c := &ahttp.Client{
        Bearer: string(vault.MustGet("hubspot-key").Reveal()),
        CredentialOrigin: "https://api.hubapi.com", // reviewed provider origin
    }
    body := map[string]any{"properties": map[string]any{"email": in.Email}}
    var out map[string]any
    if err := c.PostJSON(ctx, "https://api.hubapi.com/crm/v3/objects/contacts", body, &out); err != nil {
        return nil, err
    }
    return out, nil
})
```

## Auth shapes (from the catalog)

- **Bearer key**: `&ahttp.Client{Bearer: string(vault.MustGet("<key-name>").Reveal()), CredentialOrigin: "https://<reviewed-provider-host>"}`.
- **OAuth connection**: same, but `vault.MustGet("oauth:<connection-id>")` (the
  host refreshes it for you).
- **Query-param key** (Trello): set `CredentialOrigin` from a reviewed provider
  origin, append the key and token to the request URL, and do not set Bearer.
- **HTTP Basic** (Jira, Close): set it via the client's Headers map:
  `&ahttp.Client{CredentialOrigin: "https://<reviewed-provider-host>", Headers: map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+key))}}`.
- **Custom header** (ClickUp `Authorization: <token>` with no Bearer prefix,
  Storyblok, Shortcut `Shortcut-Token`) and **version pins** (Notion
  `Notion-Version`): use the Headers map too:
  `&ahttp.Client{CredentialOrigin: "https://api.notion.com", Headers: map[string]string{"Authorization": token, "Notion-Version": "2022-06-28"}}`.
  Values in Headers win over the Bearer default, so mix and match freely.

For ordinary REST mutations use `PostJSON` to create, `PutJSON` to replace or
upsert, `Put` for a documented bodyless PUT, `PatchJSON` to update selected
fields, and `Delete` to remove. They
accept reviewed provider URLs and inherit the same credential-origin pin,
response limit, dry-run block, and retry policy. Pass `nil` as Delete's output
when the provider returns 204 without JSON. A JSON body has a 16 MiB limit;
responses have a 4 MiB limit. You do not need to import `net/http`.

## Rules

- Every create/update/delete is a side effect: set a deterministic Step
  `IdempotencyKey` (see [[i_step-keys]]).
- Mutation HTTP calls make one attempt by default. Enable the client's
  `Retry.UnsafeWithIdempotencyKey` only after confirming that the exact provider
  operation deduplicates `Idempotency-Key`; set a distinct key in `Client.Headers`
  for each operation. A Step key alone does not provide upstream deduplication.
- Classify failures: wrap transient ones with `reactor.Retryable`, permanent
  4xx (bad input, auth) with `reactor.Permanent`. `ahttp.IsRetryable(err)` helps.
- Never log the key. `Reveal()` is the only place the plaintext appears, and
  only at run time.
- The SDK rejects a missing or mismatched `CredentialOrigin` before sending a
  credential-bearing request. Use the exact reviewed scheme and authority;
  never derive the pin or destination from webhook input or provider data.
- Confirm version- or instance-specific details (Salesforce instance_url, Jira
  domain, Zoho region) against the service's docs link in the Environment.
