# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Email the
maintainers at security@brightinteraction.com with:

- a description of the issue and its impact,
- steps to reproduce (a minimal workflow or request is ideal),
- the commit or release you tested against.

You will get an acknowledgement within 3 business days. We aim to ship a
fix or a documented mitigation within 30 days, and we will credit you in
the release notes unless you ask us not to.

## Supported versions

Reactor is pre-1.0. Security fixes land on `main` and in the next tagged
release. There is no backport guarantee for older tags yet.

## Security model

Reactor runs operator-authored and AI-generated workflow code, so the
trust boundaries matter:

- **Vault.** Credentials are encrypted at rest. The daemon holds the
  master key; workflow subprocesses never receive it. A workflow fetches a
  secret only over the wire protocol's `secret_fetch` frame, which is
  gated by a per-workflow grant ACL. Subprocess environments are built
  from an explicit allowlist, so `REACTOR_MASTER_KEY` and `REACTOR_DB_URL`
  are never inherited.
- **Build sandbox.** Generated/uploaded workflow code is statically
  checked against an import allowlist (approved standard-library packages
  plus the Reactor SDK). Filesystem, process, and raw-network wrappers such as
  `io/ioutil`, `go/parser`, `text/template`, debug object readers, and
  `log/syslog` are denied as well as their direct transports. It is compiled
  with `CGO_ENABLED=0` and a pinned toolchain before it can run.
- **RBAC.** The dashboard distinguishes admin and member roles. Every
  privileged mutation (workflow code, credentials, triggers, notification
  channels, codegen, uploads) is admin-only.
- **Network.** The webhook notifier refuses to connect to link-local and
  cloud-metadata addresses, and to loopback/private ranges unless
  `REACTOR_WEBHOOK_ALLOW_PRIVATE=1` is set. Webhook ingestion is HMAC
  verified; signal delivery uses a 128-bit capability token.
- **Transport.** Run behind a TLS-terminating proxy and set
  `REACTOR_SECURE_COOKIES=1` (or an `https://` dashboard URL) so the
  session cookie carries the `Secure` flag.

## Hardening checklist for operators

- Set `REACTOR_BASIC_AUTH_*` or create users; never run `--insecure-no-auth`
  in production.
- Keep `REACTOR_VAULT_ACL_PERMISSIVE` unset (strict deny on an empty grant
  table).
- Put the daemon behind TLS and a reverse proxy; do not expose the raw
  port.
- Grant each workflow only the credentials it needs.
