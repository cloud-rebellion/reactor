#!/usr/bin/env bash
# Every check CI runs, in one script you can also run yourself:
#
#   bash scripts/ci.sh
#
# Run it before opening a pull request and CI will not tell you anything new.
#
# WHY THE LOGIC LIVES HERE AND NOT IN .github/workflows/ci.yml
#
# Two reasons, and the second is not obvious.
#
# 1. A contributor can run it. A check that only exists inside a workflow file is a
#    check you cannot reproduce locally, so you discover it after pushing.
#
# 2. It keeps .github/workflows/ci.yml STABLE, which is what makes automated
#    publishing possible at all. This repository is a filtered mirror, published by a
#    job authenticated with a repository deploy key (see scripts/split-public-repo.sh
#    upstream). GitHub does not allow a deploy key, or an OAuth token without the
#    `workflow` scope, to create or update anything under .github/workflows/. So every
#    time a CI step changed, the publish was rejected at the FINAL push, after every
#    gate had already passed, with a raw git error that read like a mystery. With the
#    steps in this script, changing a check touches scripts/ci.sh (an ordinary file the
#    deploy key may write) and the workflow file stays untouched, so the publish goes
#    through.
#
# The consequence to remember: editing .github/workflows/ci.yml is now a rare,
# deliberate act (an action version bump, a trigger change) that needs a push from a
# credential with the `workflow` scope. Editing THIS file needs nothing special.
set -uo pipefail

# Resolve the module root from the script's own location rather than from the caller's
# working directory. The same file lives at reactor/scripts/ci.sh in the private
# monorepo and at scripts/ci.sh in the published mirror, and "one directory up from
# this script" is the module root in both, with no dependency on git or on where you
# invoked it from.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.." || exit 1
[ -f go.mod ] || { echo "error: expected go.mod next to scripts/; is this file still in reactor/scripts/?" >&2; exit 1; }

FAILED=()
SKIPPED=()
# Exit code 99 means "this check did not run". It is distinct from pass and from fail
# on purpose: a skipped security scan that prints ok is worse than no scan at all,
# because it looks like evidence.
step() {
  local name="$1" rc; shift
  printf '\n=== %s ===\n' "$name"
  "$@"; rc=$?
  case "$rc" in
    0)  printf 'ok: %s\n' "$name" ;;
    99) printf 'SKIPPED: %s\n' "$name"; SKIPPED+=("$name") ;;
    *)  printf 'FAIL: %s\n' "$name" >&2; FAILED+=("$name") ;;
  esac
}

# Are we in the published mirror, or in the private monorepo the mirror is cut from?
# The secret scan below has to mean different things in the two places, and getting
# that wrong makes it either useless upstream or toothless downstream.
#
# SECURITY-AUDIT-2026-07-07.md is the private deep-audit report. It names internal
# infrastructure, so scripts/split-public-repo.sh lists it in STRIP_PATHS and removes
# it from every published commit: present means upstream, absent means mirror.
# The second test is belt and braces. If reactor is plainly a subdirectory of a larger
# repository then we are upstream whatever the marker says, so renaming or retiring the
# audit report can never silently point the history scan at the whole monorepo.
IN_MIRROR=1
[ -f SECURITY-AUDIT-2026-07-07.md ] && IN_MIRROR=0
GIT_TOP="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$GIT_TOP" ] && [ "$GIT_TOP" != "$PWD" ] && IN_MIRROR=0

# gofmt is not a style opinion here, it is the only formatting the Go tooling agrees on,
# and CONTRIBUTING.md already tells contributors this exact command must print nothing.
# Run the same command the docs promise, so the doc and the gate cannot drift.
gofmt_check() {
  local unformatted
  unformatted="$(gofmt -l .)"
  if [ -n "$unformatted" ]; then
    echo "These files are not gofmt'd:" >&2
    echo "$unformatted" >&2
    echo "Fix them with: gofmt -w \$(gofmt -l .)" >&2
    return 1
  fi
  echo "every Go file is already in canonical gofmt form"
}

# `go build ./...` proves every package COMPILES. It does not prove the binary WORKS.
# A broken migration, a bad default path or a nil map in command wiring only shows up
# when something runs the thing, and none of the package tests exec the real CLI. This
# is the shortest path that starts the binary, writes a master key, migrates a real
# SQLite database through every migration and reads it back.
cli_smoke() {
  local dir rc=0 log
  dir="$(mktemp -d)" || return 1
  log="$dir/smoke.log"
  {
    go build -o "$dir/reactor" ./cmd/reactor &&
      "$dir/reactor" version &&
      "$dir/reactor" init --root "$dir/state" &&
      "$dir/reactor" migrate --db "sqlite://$dir/state/reactor.db" &&
      "$dir/reactor" ps --db "sqlite://$dir/state/reactor.db"
  } >"$log" 2>&1 || rc=1
  if [ "$rc" -ne 0 ]; then
    echo "the CLI failed a bare init/migrate/ps cycle:" >&2
    tail -40 "$log" >&2
  else
    echo "binary builds, initialises a root, migrates a fresh SQLite db and reports on it"
  fi
  rm -rf "$dir"
  return "$rc"
}

# Reactor's environment prefix migrated FF_ -> ARACHNE_ -> REACTOR_, and the middle
# step was left half-done once already: some reads kept the old name, so a value set
# under the new prefix was silently ignored at runtime. New code reads the current
# prefix, with the legacy name only ever as a fallback STRING passed to a helper:
#
#   envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL")   // fine, that is the fallback
#   os.Getenv("ARACHNE_DB_URL")                    // not fine, that is a legacy read
#
# The monorepo's pre-commit hook enforces this, but a hook is not part of the published
# payload and only ever sees STAGED files. Running it here means the rule travels with
# the repository a contributor actually clones, and it is checked over the whole tree
# rather than one diff.
#
# FF_TEST_* is exempt: it is supervisor test instrumentation injected through the
# child-process env allowlist on purpose, not configuration.
legacy_env_prefixes() {
  local hits
  hits="$(git ls-files '*.go' | xargs grep -nE 'os\.(Getenv|LookupEnv)\("(FF_|ARACHNE_)' 2>/dev/null | grep -v 'FF_TEST_')"
  if [ -n "$hits" ]; then
    echo "Legacy env prefix read(s). Use envFirst(\"REACTOR_X\", \"ARACHNE_X\") instead:" >&2
    echo "$hits" >&2
    return 1
  fi
  echo "no os.Getenv/LookupEnv reads of the retired FF_ or ARACHNE_ prefixes"
}

# The scanners are used if they are on PATH and installed on demand otherwise, which
# needs network. Set REACTOR_CI_SKIP_SCANNERS=1 to skip them when offline. They then
# report SKIPPED rather than passing quietly, for the reason in step() above.
scan() {
  local name="$1" mod="$2" bin; shift 2
  if [ "${REACTOR_CI_SKIP_SCANNERS:-0}" = "1" ]; then
    echo "not run: REACTOR_CI_SKIP_SCANNERS=1"
    return 99
  fi
  bin="$(command -v "$name" 2>/dev/null)"
  if [ -z "$bin" ]; then
    go install "$mod" >/dev/null 2>&1 || { echo "could not install $name (offline?)" >&2; return 1; }
    bin="$(go env GOPATH)/bin/$name"
  fi
  "$bin" "$@"
}

step "build"  go build ./...
step "vet"    go vet ./...
step "gofmt"  gofmt_check
# RUN the tests, do not merely compile them. The label matters: this project's mirror
# gate once said "tests compile: OK" while executing `go test -run=^$`, which builds
# every _test.go and runs none of them, and that was believed for months. -count=1
# defeats the result cache so a green line always means the tests executed in THIS run.
#
# -race because the supervisor, scheduler and dispatcher are the whole product and they
# are concurrent; a data race there is a corrupted run journal, not a flake.
#
# -timeout=15m because the supervisor package really does compile a workflow binary and
# spawn it as a child process per test. Keep the legacy test.yml wrapper on this
# same package budget. Package and test concurrency are bounded because workflows
# inherit the runner UID: unbounded package fan-out exhausted fork/thread headroom.
# This retains every package/test and race instrumentation; individual lifecycle
# deadlines and the workflow's own task/resource limits remain unchanged.
step "test suite (compiled AND run, race detector on)" env GOMAXPROCS=2 GOFLAGS=-p=1 go test ./... -race -count=1 -timeout=15m -p=1 -parallel=2
step "cli smoke test (init, migrate, ps against a throwaway sqlite db)" cli_smoke
step "no retired FF_/ARACHNE_ env reads" legacy_env_prefixes
# In the mirror, every published commit is this project's, so scanning the full history
# is exactly right and is the last gate before a credential becomes world-readable.
# Upstream, the history belongs to a whole monorepo of unrelated projects, so a full scan
# reports hundreds of findings that have nothing to do with Reactor and would train
# everyone to ignore the check. There the working tree is what matters, and
# scripts/split-public-repo.sh scans the real filtered payload's full history separately
# before it pushes.
if [ "$IN_MIRROR" = "1" ]; then
  step "secret scan (full history)" \
    scan gitleaks github.com/zricethezav/gitleaks/v8@latest \
    detect --source . --config .gitleaks.toml --no-banner --redact
else
  step "secret scan (working tree; the publish pipeline scans the filtered history)" \
    scan gitleaks github.com/zricethezav/gitleaks/v8@latest \
    detect --source . --config .gitleaks.toml --no-git --no-banner --redact
fi
step "vulnerability scan" scan govulncheck golang.org/x/vuln/cmd/govulncheck@latest ./...

printf '\n'
if [ ${#SKIPPED[@]} -ne 0 ]; then
  printf 'ci: %d check(s) DID NOT RUN: %s\n' "${#SKIPPED[@]}" "${SKIPPED[*]}" >&2
fi
if [ ${#FAILED[@]} -ne 0 ]; then
  # Report EVERY failure, not just the first. A run that stops at the first problem
  # costs a full round trip per issue.
  printf 'ci: %d check(s) failed: %s\n' "${#FAILED[@]}" "${FAILED[*]}" >&2
  exit 1
fi
if [ ${#SKIPPED[@]} -ne 0 ]; then
  echo "ci: every check that RAN passed, but some did not run (see above)"
  exit 0
fi
echo "ci: all checks passed"
