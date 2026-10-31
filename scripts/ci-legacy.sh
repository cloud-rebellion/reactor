#!/usr/bin/env bash
# The legacy test workflow keeps its explicit govulncheck and CLI-smoke steps.
# These are its original vet, executed race suite and binary build, under the
# same isolated CI account used by the canonical test entrypoint.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
go vet ./...
env GOMAXPROCS=2 GOFLAGS=-p=1 go test -race -count=1 -timeout=15m -p=1 -parallel=1 ./...
go build -o bin/reactor ./cmd/reactor
