# Contributing to Reactor

Thanks for helping improve Reactor. It is a single Go module with no
required external services for development (SQLite is the default engine).

## Development setup

```bash
git clone <repo> reactor && cd reactor
go build ./...
go test ./...
```

Go 1.26.5 is required. There is no frontend build step: the dashboard is
server-rendered Go.

## Gates (run before every PR)

```bash
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

`staticcheck ./...` is encouraged. CI runs the same gates across all
packages.

## Code style

- Use `slog` for logging, never `log` or `fmt.Println` in library code.
- Return errors, do not panic in request/dispatch paths.
- Prefer table-driven tests.
- Parameterise SQL; never concatenate user input into a query.
- Read environment variables with the new `REACTOR_*` prefix via
  `envFirst("REACTOR_X", "ARACHNE_X")` (new primary, legacy fallback); do
  not add new `os.Getenv("ARACHNE_...")` or `os.Getenv("FF_...")` reads (a
  pre-commit guard blocks them; `FF_TEST_*` test instrumentation is exempt).
- No em dashes in code or prose.

## Security-sensitive changes

If your change touches the vault, the workflow subprocess environment, the
codegen build path, RBAC, or the webhook/SSRF surface, call it out in the
PR description and add a regression test. See `SECURITY.md` for the trust
model.

## Commits

Conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`,
`test:`). Keep commits small and focused. Squash noise before review.

## Licensing of contributions

Reactor is fair-code under the Reactor Sustainable Use License (see
`LICENSE`), not an OSI "open source" license: you can self-host and use it
commercially, including for your clients, but you can't resell it or run it
as a competing hosted service. By submitting a contribution you agree that
it is licensed under the same terms and that the Licensor (Bright
Interaction) may also include it in commercially-licensed distributions.
This keeps a single, relicensable codebase. For anything the license does
not permit, email tom@cloudrebellion.se.

## Running a workflow locally

```bash
reactor setup --root /tmp/reactor-dev --non-interactive \
  --db sqlite:///tmp/reactor-dev/reactor.db --admin-user dev --admin-password devdevdev
set -a; source /tmp/reactor-dev/reactor.env; set +a
reactor serve --root /tmp/reactor-dev
```

Then open http://127.0.0.1:7777/ and use the dashboard to generate or
upload a workflow.
