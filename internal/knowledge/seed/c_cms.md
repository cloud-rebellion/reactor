---
id: c_cms
topic: connectors
title: Publish to a CMS (WordPress, Webflow, Contentful, ...)
created_by: seed
sources: [https://developer.wordpress.org/rest-api/, https://www.contentful.com/developers/docs/references/content-management-api/]
tags: [cms, wordpress, webflow, contentful, connectors, side-effects]
gold: true
citation_count: 0
---

# Publish to a CMS

CMS connectors are in the service catalog (Environment context) with their base
URL, auth, and operations. Call them through `sdk/http` from inside a Step with
an `IdempotencyKey` (creating a post or entry is a side effect). A few have auth
shapes worth calling out:

## WordPress (the common one): HTTP Basic with an Application Password

WordPress uses Basic auth, not a Bearer token. The credential is stored as
`username:application-password`; send it as a Basic header:

```go
import ahttp "github.com/bright-interaction/reactor/sdk/http"

_, err := reactor.Step(flow, ctx, "create-post", reactor.StepOpts{
    IdempotencyKey: "wp-post:" + in.Slug, Timeout: 30 * time.Second,
}, func(ctx context.Context) (map[string]any, error) {
    creds := string(vault.MustGet("wordpress-key").Reveal()) // "user:app-password"
    c := &ahttp.Client{
        CredentialOrigin: "https://your-reviewed-site.example", // operator-owned configuration
        Headers: map[string]string{
            "Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(creds)),
        },
    }
    var out map[string]any
    if err := c.PostJSON(ctx, "https://your-reviewed-site.example/wp-json/wp/v2/posts", body, &out); err != nil {
        return nil, err
    }
    return out, nil
})
```

## Bearer-token CMSes (Webflow, Contentful, Sanity, Strapi, DatoCMS)

Use `&ahttp.Client{Bearer: string(vault.MustGet("<key-name>").Reveal()), CredentialOrigin: "https://<reviewed-provider-host>"}`, then
`PostJSON`, `PutJSON`, `PatchJSON`, or `Delete` according to the documented
provider operation. Notes:
- **Contentful**: create uses `PutJSON` to an entry id with header
  `X-Contentful-Content-Type`; new entries are drafts, publish with a second
  PUT to `.../published` carrying `X-Contentful-Version`; use `Put` if the
  documented operation expects an empty request body.
- **DatoCMS** also needs header `X-Api-Version: 3`.

## Other auth shapes

- **Storyblok**: `Authorization: <management-token>` (no Bearer prefix).
- **Ghost**: sign a short-lived HS256 JWT from the Admin API key `id:secret`,
  send `Authorization: Ghost <jwt>`.
- **Wix**: `Authorization: <api-key>` plus a `wix-site-id` header.
- **Drupal (JSON:API)**: Basic or OAuth, and set
  `Accept: application/vnd.api+json`.

## Rules

- Creating or publishing content is a side effect: deterministic
  `IdempotencyKey` (see [[i_step-keys]]); a key derived from the post slug is the
  canonical shape.
- Base hosts are often site- or project-specific (WordPress, Sanity, Strapi,
  Drupal, Ghost). Take each exact origin from reviewed operator configuration,
  not from workflow input or an upstream response. Pin the same origin on the
  SDK client. Confirm details against the docs link in the Environment.
- See [[c_generic-api]] for the general auth-shape patterns.
