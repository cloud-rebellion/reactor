# Rotation

The rotation engine drives the "mint a new credential -> deliver it
everywhere -> audit" pipeline. Two configurable axes: providers (what
mints the new value) and targets (where the new value gets pushed).

## Providers

A Provider mints a fresh credential value. Implementations live in
`internal/rotators/`. Register with `rotators.Register(p)`.

| Name             | Auto-rotate? | Meta required        | Notes                                          |
| ---------------- | ------------ | -------------------- | ---------------------------------------------- |
| `cloudflare`     | yes          | (token verifies self)| PUT /user/tokens/{id}/value rolls in place    |
| `shared-secret`  | yes          | explicit local-mint acknowledgement | 32 random bytes, hex-encoded (HMAC keys); replaces the stored value locally |
| `aws-iam`        | yes          | `iam_user_name`      | Self-rotating access key pair; stdlib SigV4   |
| `manual`         | no           | none                 | Audits "rotation due"; operator rotates       |

## Targets

A Target tells the engine where to deliver the new value after the
provider mints it. Configured per-credential in the rotation_targets
JSON column.

| Kind              | Use case                                                                       |
| ----------------- | ------------------------------------------------------------------------------ |
| `webhook`         | Single-phase HMAC-signed POST; receiver atomically replaces the named key      |
| `reload_endpoint` | Dual-phase grace window for actively-authenticated sessions                    |
| `file_write`      | Atomic on-disk replacement (docker-compose env_file, systemd EnvironmentFile)  |
| `github_secret`   | PUT to GitHub Actions repo secret (libsodium sealed box against the repo key)  |
| `forgejo_secret`  | PUT to Forgejo / Gitea Actions secret via the repo API                         |
| `dockyard_vault`  | PUT to a Dockyard vault entry; covers Hephaestus deploy secrets end-to-end     |

## Adding a new provider

1. Implement `rotators.Provider` (Name, CanAutoRotate, Rotate, Validate).
2. Register from `init()` in `internal/rotators/provider.go`.
3. Add to the dashboard's `/credentials/new` form provider dropdown.
4. Add a row to the README rotation providers table.

## Adding a new target

1. Add a case to the `Deliver` switch in
   `internal/rotators/delivery.go` plus a `deliverXxx` function
   following the existing webhook / forgejo_secret shape (read the
   target.URL + target.SecretID from vault + POST + audit).
2. Add a row to the docs/rotation.md table + the README.
3. Write a happy-path test against an `httptest.NewServer` fake.

## Manual rotation

Dashboard: `/credentials/{id}` -> "Rotate now" button. Roll-at-source
providers call `rotators.Runner.RotateOne(ctx, id)`. A local-mint provider
shows a required acknowledgement checkbox and calls the explicit
`RotateOneWithLocalMintAck` path; without that acknowledgement the stored
value is not changed. Creating an auto-rotating local-mint credential stores
the same acknowledgement in provider metadata so later scheduler ticks do
not silently turn an externally issued key into a new random value.

CLI: `reactor vault rotate <id>`. Add `--allow-local-mint` for a one-off
explicit approval when the credential has no stored acknowledgement. When
creating a scheduled local-mint credential, `reactor vault add` likewise
requires `--allow-local-mint`; an unacknowledged local-mint credential may be
stored for reference, but the Runner refuses to replace its value.

## Grant ACL

A workflow's `vault.MustGet(id)` call goes through the supervisor's
SecretFetch handler, which checks the per-workflow grant in
`workflow_secret_grants`. Default-deny on empty table since v0.1;
the opt-out flag `--vault-acl-permissive` (or
`REACTOR_VAULT_ACL_PERMISSIVE=1`) restores the v0 behaviour for
migration scenarios.
