# Teams, users, sessions, API tokens

The dashboard supports per-operator login + admin/member roles + personal API tokens for programmatic clients. This is **phase 1** of the teams roadmap: per-team workflow ownership comes in phase 2.

## Quick start

After `reactor setup`, an admin user is seeded into the users table with the username and password you provided. Open the dashboard and sign in at `/login`. From there:

- Create more users at `/users` (admin only).
- Mint API tokens at `/tokens` (every user, own tokens only).
- Sign out via the top-nav link or `POST /logout`.

The legacy env-var BasicAuth fallback (`REACTOR_BASIC_AUTH_USER` + `REACTOR_BASIC_AUTH_PASSWORD_SHA256`) keeps working when no users exist in the database, so existing deployments do not break on upgrade.

## Schema

Migration 0012 adds three tables.

### `users`

| Column | Type | Notes |
|---|---|---|
| id | text PK | `usr_<hex>` |
| username | text UNIQUE | operator-chosen |
| password_phc | text | argon2id PHC string (or legacy lowercase hex SHA-256) |
| role | text CHECK | `admin` \| `member` |
| disabled | bool | session middleware refuses disabled users |
| created_at / updated_at | timestamp | |
| last_login_at | timestamp | bumped on every successful login |

### `sessions`

| Column | Type | Notes |
|---|---|---|
| id_hash | text PK | sha256 hex of the cookie value the browser sends back |
| user_id | text FK CASCADE | |
| created_at | timestamp | |
| expires_at | timestamp | hard deadline; middleware sweeps expired rows on resolve |
| last_seen_at | timestamp | bumped on every request |
| user_agent | text | snapshotted at login |
| ip | text | snapshotted at login |

Storing the **hash** of the cookie value (not the raw value) means a database snapshot does not yield session theft.

### `api_tokens`

| Column | Type | Notes |
|---|---|---|
| id | text PK | `tok_<hex>` |
| user_id | text FK CASCADE | |
| name | text | operator-chosen, displayed in the dashboard |
| token_hash | text UNIQUE | sha256 hex of the raw token |
| created_at | timestamp | |
| last_used_at | timestamp | bumped on every successful resolve |
| expires_at | timestamp NULL | optional |
| revoked | bool | row stays so audit trail of "this token did X" survives |

The raw token is shown to the user **exactly once** at mint time via the flash
store. In normal deployments the short-lived payload is AES-GCM encrypted in
the shared journal so a POST and its redirect GET may land on different
replicas. The database holds only ciphertext and a digest; the random HttpOnly,
SameSite=Strict cookie contains the one-time decryption capability. Set
`REACTOR_SECURE_COOKIES=1` behind HTTPS termination.

## Password hashing

`auth.HashPassword` uses argon2id (`golang.org/x/crypto/argon2.IDKey`) with OWASP-recommended defaults:

- Memory: 64 MiB (`m=65536`)
- Iterations: 3 (`t=3`)
- Parallelism: 2 (`p=2`)
- Salt: 16 random bytes
- Hash: 32 bytes

Stored as a PHC string: `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>`.

`auth.VerifyPassword` sniffs the stored field shape:

- `$argon2id$...` → argon2id verify with constant-time hash compare.
- Lowercase hex of length 64 → legacy SHA-256 hex compare (for migrating env-var BasicAuth setups).
- Anything else → reject.

## Session middleware

`SessionAuth` runs BEFORE the legacy `BasicAuth` middleware. Resolution order:

1. **Cookie** `reactor_sess` → `Store.ResolveSession`. On success, stash the user on the request context.
2. **`Authorization: Bearer <token>`** → `Store.ResolveAPIToken`.
3. **`Authorization: Basic <user>:<pw>`** → `Store.Authenticate` against the users table.
4. **No identity resolved** + no users in DB → pass through so the legacy env-var BasicAuth still handles fresh boots.
5. **Users exist** + no identity → `303 See Other` to `/login?next=<path>` for HTML clients; `401 Unauthorized` for JSON clients.

The legacy `BasicAuth` middleware short-circuits when a session-resolved user is already on the request context. The two middlewares compose cleanly.

Exempt paths (always pass through): `/healthz`, `/login`, `/webhook/*`, `/signal/*`, `/assets/*`, `/mcp*`.

## Roles

Two roles ship in phase 1:

| Role | What |
|---|---|
| `admin` | Manages `/users`, deletes workflows, deletes credentials, all member capabilities. |
| `member` | Reads + edits workflows, credentials, knowledge, notifications, triggers. Cannot delete workflows or manage users. |

The `requireAdmin` helper writes a `403 Forbidden` when a non-admin hits an admin-only endpoint.

### `guardLastAdminFor`

Demoting, disabling, or deleting the last active admin would lock the daemon. The dashboard refuses with `409 Conflict` and the message `cannot remove the last active admin; promote another user first`.

## Sessions

Cookies are HttpOnly + SameSite=Strict. 7-day TTL. The middleware bumps `last_seen_at` on every successful resolve; expired rows are swept on resolve plus by a periodic background task (`Store.SweepExpiredSessions`).

`POST /logout` destroys the row + clears the cookie. Disabling a user destroys all their sessions atomically so the dashboard does not stay reachable to a just-revoked operator.

## API tokens

Mint at `/tokens`:

```text
POST /tokens
form: name=ci-deploy
```

Returns `303 See Other` + a one-time flash capability cookie. The cookie never
contains the raw API token. The next GET `/tokens` atomically consumes and
decrypts the shared flash row, then renders the raw token in a callout exactly
once:

```text
Token minted. Copy it now; it will not be shown again. Use it as:
Authorization: Bearer rtr_YOUR_TOKEN_HERE
```

Tokens have the same role/permissions as the issuing user. `POST /tokens/{id}/revoke` marks the row revoked; the audit trail survives.

For Bearer use, see the [REST API reference](/docs/api).

## Setup wizard integration

`reactor setup --non-interactive --admin-user X --admin-password Y` does three things:

1. Writes the `reactor.env` file with `REACTOR_BASIC_AUTH_USER` + `REACTOR_BASIC_AUTH_PASSWORD_SHA256` (legacy fallback).
2. Runs migrations.
3. Calls `seedFirstAdmin`: idempotently inserts (or upserts the password of) the named user with `role=admin`.

Re-running setup recovers a forgotten admin password without disturbing other users.

## Future (phase 2)

- Per-team workflow + credential ownership (every row gains an effective `team_id`, currently hardcoded to `'default'`).
- Team management UI (create/delete teams, invite users to teams, per-team admin role).
- SSO/OIDC integration (mapped to user rows on first sign-in).
- Refresh tokens for browser clients (today's 7-day session is hard expiry).

Phase 1 ships identity + auth + RBAC against the existing single-tenant data model; phase 2 is the data-model rewrite.

## Tests

- 10 auth-package tests: CreateUser + Authenticate happy path, short-password rejection, UNIQUE rejection, session lifecycle + expiry sweep, disabled-user rejection, role + admin count, API token mint + list + resolve + revoke, legacy sha256 + argon2id round-trips.
- 6 server tests: unauth redirects to /login, login mints a session cookie with HttpOnly+SameSite=Strict, Bearer auth succeeds, RBAC member 403 vs admin 303 for workflow delete, logout clears the cookie.
