# Documentation

Reactor ships every doc with the binary. The dashboard renders them at `/docs`; you can also read them on disk under `docs/*.md`.

## Start here

- **[Architecture](/docs/architecture)** - what the daemon is, what runs where, per-run lifecycle, where features live in the source tree.
- **[Dashboard pages + endpoints](/docs/dashboard)** - every page in the dashboard with auth, request shapes, status codes.
- **[REST API reference](/docs/api)** - the canonical HTTP API: auth modes, endpoint catalogue, error responses, sample curl flow.
- **[MCP server + tool reference](/docs/mcp)** - canonical Streamable HTTP transport, compatibility stdio notes, and all tools with input schema + payload examples.

## Features

- **[Notifications](/docs/notifications)** - Slack + generic JSON webhook + SMTP email senders, per-workflow routing, per-channel test button.
- **[Workflow chaining](/docs/chaining)** - fire workflow B when workflow A terminates; payload shape; fanout + diamond patterns.
- **[Hash e-signature bridge](/docs/hash-esign-bridge)** - standalone and CRM webhook architecture, canonical event, Google Apps Script edge adapter, and launch requirements.
- **[Teams, users, sessions, API tokens](/docs/teams)** - auth schema, password hashing, session middleware, RBAC, mint/revoke flow.

## Operating reactor

- **[Operations runbook](/docs/operations)** - quickstart, backup/restore, database migration to Postgres, scaling notes.
- **[Internal readiness runbook](/docs/internal-readiness)** - least-privilege MCP setup, authoring sequence, and acceptance evidence.
- **[Security threat model](/docs/security)** - secret handling, MCP boundary, supervisor sandbox, audit posture.
- **[Credential rotation](/docs/rotation)** - six supported rotation targets (cloudflare, github_secret, dockyard_vault, aws_iam, file_write, forgejo_secret), rotation runner schedule.

## SDK + codegen

- **[SDK reference](/docs/sdk)** - the public surface workflow authors import: `sdk`, `sdk/runtime`, `sdk/http`, `sdk/vault`, `sdk/wire`, `sdk/idempotency`.
- **[Connector execution contracts](/docs/integration-contracts)** - bounded pagination, safe continuation URLs, provider rate limits, and write idempotency.
- **[Codegen pipeline](/docs/codegen)** - Anthropic prompt assembly, lens-aware context, validator chain, retry policy.

## Editing docs

Drop a new `.md` file into `reactor/docs/`. The dashboard picks it up on the next daemon restart (the files are embedded into the binary via `embed.FS`). Add the slug to `docsOrder` and `docTitles` in `internal/server/docs.go` to control its position in the left-rail.

Markdown features supported (via [goldmark](https://github.com/yuin/goldmark) with GFM):

- Tables, strikethrough, task lists, auto-linking
- Fenced code blocks with language hints
- Hard line breaks (one newline becomes `<br>`)
- Heading auto-IDs (for anchor links within a page)
