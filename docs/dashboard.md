# Dashboard pages + endpoints

The dashboard is server-rendered HTML reachable from a browser. Every page in this reference lists the URL, who can see it, and the form fields it accepts. For programmatic clients (CI, scripts), see the [REST API reference](/docs/api).

## Top nav

| Link | URL | Visible to |
|---|---|---|
| Home | `/` | everyone signed in |
| Runs | `/runs` | everyone signed in |
| Credentials | `/credentials` | everyone signed in |
| Notifications | `/notifications` | everyone signed in |
| Knowledge | `/knowledge` | everyone signed in (only if knowledge corpus is wired) |
| Audit | `/audit` | everyone signed in |
| Docs | `/docs` | everyone (no sign-in required) |
| Tokens | `/tokens` | everyone signed in |
| Users | `/users` | admin role only |
| Sign out | `/logout` | everyone signed in |
| Health | `/healthz` | everyone (no sign-in required) |

## Authentication

The dashboard accepts three credential shapes in priority order:

1. **Session cookie** `reactor_sess`. HttpOnly, SameSite=Strict, 7-day TTL. Minted by `POST /login`.
2. **Bearer token** `Authorization: Bearer rtr_<base64>`. Minted at `/tokens`; same permissions as the issuing user.
3. **HTTP Basic** `Authorization: Basic <user>:<pass>`. Falls through to the users table; the legacy env-var `REACTOR_BASIC_AUTH_USER` + `REACTOR_BASIC_AUTH_PASSWORD_SHA256` is the boot fallback when no users exist.

Unauthenticated requests redirect to `/login?next=<path>` for HTML clients and return `401 Unauthorized` for JSON clients.

## Home page (`/`)

The landing page. If no workflows are registered yet, the daemon redirects to `/onboarding`.

**Headline rollup** (operator-felt KPIs, computed live):

- Total runs
- Succeeded (with success-rate sub-line)
- Failed (includes DLQ)
- Avg duration + p95 over succeeded runs
- Time saved (sum of `estimated_minutes_saved_per_run x succeeded` across all workflows)

Below the tiles: a 7-day SVG mini-chart with per-bar run counts, a "Time saved by workflow" details panel sorted by impact descending, the workflow list with deploy/run buttons, and the 20 most recent runs.

When `ANTHROPIC_API_KEY` is set the page also shows a **codegen prompt bar**: type a brief, click Generate, the orchestrator runs `go vet` + `reactor lint` + `go build` with retries, commits to git, builds the binary, and registers the workflow. Synchronous (15-45 seconds typical).

## Runs (`/runs`, `/runs/{id}`, `/runs/{id}/tail`)

**`/runs`** - filterable list with `?workflow_id=`, `?status=`, `?limit=` (1-200, default 50), `?offset=`. Renders 1 page per `limit`; prev/next pager.

**`/runs/{id}`** - per-run timeline: metadata table (workflow, trigger, status, started/finished), DLQ retry button when status is `failed_dlq` and a DLQ row exists, steps table with per-step output JSONB or error text.

**`/runs/{id}/tail`** - Server-Sent Events stream of the run's log lines. Subscribe with `EventSource("/runs/run_xxx/tail")`. Close happens automatically when the run hits a terminal status (the runlogs buffer grace window is 10 minutes after Close so a late subscriber still sees the tail).

## Credentials (`/credentials`, `/credentials/{id}`)

**`/credentials`** - list with rotation state, last-rotated timestamp, last-rotation-error pill, "Granted to" column (number of workflows authorised to fetch each credential under the strict-deny ACL). Add-credential CTA when a vault is wired.

**`/credentials/new`** - `POST /credentials` form. Provider dropdown (`shared-secret` / `cloudflare` / `aws-iam` / `manual`); value field is encrypted on write.

**`/credentials/{id}`** - credential detail with audit log + lifecycle forms:

| Form | URL | What |
|---|---|---|
| Rotate now | `POST /credentials/{id}/rotate` | Triggers the provider's mint -> deliver -> audit pipeline. Idempotent. |
| Manual update | `POST /credentials/{id}/value` | Replaces the stored value with a new one (operator just rotated upstream). Encrypted on write; bumps `last_rotated_at`. |
| Grant | `POST /credentials/{id}/grants` | Authorise a workflow slug to fetch this credential. Strict ACL default means workflows cannot fetch until granted. |
| Revoke | `POST /credentials/{id}/grants/{workflow_id}/revoke` | Inverse of Grant. |

## Workflows (`/workflows/new`, `/workflows/{slug}`)

**`/workflows/new`** - `POST /workflows`. Multipart form: `slug` text field + `tarball` file (`.tar.gz` containing a directory with `main.go` and optional `dag.json`). The handler extracts under a `LimitReader` (64 MiB cap), validates entry paths via `filepath.Rel`, runs the same `go vet` + `reactor lint` + `go build` chain the codegen prompt uses, then inserts the workflow.

**`/workflows/{slug}`** - workflow detail page. Sections (top to bottom):

| Section | URL | What |
|---|---|---|
| Top metadata | (read-only) | slug, id, binary status |
| Run now | `POST /workflows/{slug}/run` | Manual dispatch with optional JSON payload textarea. |
| Lifecycle | `POST /workflows/{slug}/{enable,disable,delete}` | Delete is admin-only (returns 403 for members); refuses if any runs are running/suspended. |
| Time saved | `POST /workflows/{slug}/minutes-saved` | Operator-declared baseline that drives the home dashboard "Time saved" tile. |
| Triggers | `POST /workflows/{slug}/triggers` | kind=webhook (needs vault) / cron / chain. Per-row pause/resume/delete and an inline cron edit form. |
| Notifications | `POST /workflows/{slug}/notifications` | Attach an existing channel from `/notifications` to fire on chosen statuses. |
| Downstream workflows | (read-only) | List of chain triggers pointing at this workflow. |
| DAG | (read-only) | Cytoscape visualisation of `dag.json`. |
| Code + DAG editor | `POST /workflows/{slug}/{code,dag}` | Save runs the validator chain; failure renders 422 with the validator's message. |

Webhook creation reveals the generated HMAC key and its non-secret backing
credential ID only in the single-use, no-store result after creation. The
credential ID links directly to its **Manual update** form. For `hash-v1`, Hash
creates the authoritative endpoint secret: register the Reactor URL in Hash,
capture Hash's one-time 64-byte ASCII-hex value, and replace the temporary
Reactor value through that link before sending a test event. Secrets never
belong in URLs, workflow source, or logs.

## Notifications (`/notifications`)

`/notifications` lists channels + add form. Three kinds:

- `slack_webhook` - Block Kit message with optional "Open run" button. Config: `{"url": "https://hooks.slack.com/..."}`.
- `generic_webhook` - JSON POST of the full event (run_id, workflow_slug, status, error_text, dashboard_url, ...). Config: `{"url": "https://...", "headers": {"X-Auth-Token": "..."}}`.
- `email_smtp` - STARTTLS by default on port 587. Config: `{"host", "port", "username", "password", "from", "to"}`.

`POST /notifications/{id}/test` fires a synthetic alert through the channel so the operator can verify connectivity before a real run fails.

`POST /notifications/{id}/delete` refuses (409 Conflict) when any workflow route still references the channel; detach the per-workflow routes first.

See [`Notifications`](/docs/notifications) for the full payload reference.

## Knowledge (`/knowledge`, `/knowledge/{id}`)

Knowledge corpus search + read. `POST /knowledge` adds an entry; `/knowledge/{id}/{promote,stale,supersede}` manage lifecycle. Used by the codegen orchestrator to inject relevant prior art into prompts.

## Audit (`/audit`)

Aggregated credential audit log across every credential, newest first, capped at 500 rows. Read-only.

## Tokens (`/tokens`)

Each signed-in user sees their own API tokens. Mint by name; the raw token is
shown exactly once on the post-mint redirect. The shared flash row is encrypted,
atomically consumed, and decryptable only with the short-lived HttpOnly cookie,
so the redirect works across replicas without placing the token in the cookie
or database plaintext. `POST /tokens/{id}/revoke` marks the row revoked; the row
stays so the audit trail of "this token did X" survives.

See [`Teams, users, sessions, API tokens`](/docs/teams) for the full RBAC model.

## Users (`/users`, admin-only)

List + manage every user account. Per-row actions: toggle role (admin/member), disable/enable, delete. `guardLastAdminFor` refuses any action that would leave the daemon with zero active admins (HTTP 409 Conflict with remediation hint).

## Docs (`/docs`, `/docs/{page}`)

This documentation viewer. Every markdown file in the binary's embedded `docs/` directory renders here. Public (no sign-in required) so an operator on the login page can still read the docs.

## Health (`/healthz`)

Tiny JSON: `{"ok": true, "version": "..."}`. Always reachable without auth. Liveness probes and load balancers point here.

## Metrics (`/metrics`)

Prometheus text exposition format. Authentication is required (mounted under the standard auth chain). Gauges:

- `reactor_runs_{started,succeeded,failed,dlq}_total`
- `reactor_rotations_{run,error}_total`
- `reactor_mcp_calls_total`
- `reactor_webhook_calls_total`
- `reactor_uptime_seconds`
- `reactor_goroutines`
- `reactor_memory_{alloc,sys}_bytes`
- `reactor_memory_gc_cycles_total`

## Status codes the dashboard uses

| Code | Meaning |
|---|---|
| 200 | Page rendered. |
| 303 | Form POST succeeded, redirect to a result page. |
| 400 | Form validation failed (bad slug shape, missing required field). |
| 401 | Not signed in (JSON clients). HTML clients see a 303 to `/login`. |
| 403 | Signed in but lacking the role (member trying to delete a workflow). |
| 404 | URL path resolved a slug that does not exist (workflow, run, channel). |
| 409 | Refused due to a precondition: workflow has active runs, channel has routes, last admin. |
| 422 | Form validation failed (workflow code did not pass the validator chain; signup form rejected by length / charset rules). |
| 503 | Capability not wired (notifier nil, vault nil for webhook trigger creation, generator nil for `/generate`). |

## Static assets (`/assets/*`)

Public; serves the cytoscape JS bundle and the DAG render glue from the binary. Cached by the browser; safe to behind a CDN.
