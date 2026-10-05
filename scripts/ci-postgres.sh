#!/usr/bin/env bash
# PostgreSQL integration gate. Run against a dedicated, throwaway test database:
#
#   REACTOR_TEST_POSTGRES_URL='postgres://reactor_test:reactor_test@127.0.0.1:5432/reactor_ci_test?sslmode=disable' \
#     bash scripts/ci-postgres.sh
#
# The CI workflow supplies an isolated PostgreSQL service. Keep the bounded
# queue probe separate from the other tests so its idle-queue precondition is
# meaningful, and never aim this script at shared or production data.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

if [[ ! "${REACTOR_TEST_POSTGRES_URL:-}" =~ ^postgres(ql)?://[^/@]+@(127\.0\.0\.1|localhost):[0-9]+/[A-Za-z0-9_]*test[A-Za-z0-9_]*(\?.*)?$ ]]; then
  echo 'REACTOR_TEST_POSTGRES_URL must name a loopback PostgreSQL database containing "test"' >&2
  exit 1
fi

echo 'Applying every embedded PostgreSQL migration to the dedicated test database'
go run ./cmd/reactor migrate --db "$REACTOR_TEST_POSTGRES_URL"

echo 'Running PostgreSQL journal, queue, admission, and tenant-cap contracts'
go test ./internal/runtime/journal -run Postgres -count=1 -timeout=5m -v

echo 'Running authenticated HTTP MCP to separate distributed worker acceptance'
go test -p 2 ./cmd/reactor -run '^TestPostgresHTTPMCPDistributedWorkerLifecycle$' -count=1 -timeout=3m -v

echo 'Running the fixed-size PostgreSQL queue plan and lease probe on the idle test queue'
REACTOR_TEST_POSTGRES_QUEUE_PROBE=1 \
  go test ./internal/runtime/journal -run '^TestPostgresQueueClaimBoundedProbe$' -count=1 -timeout=3m -v
