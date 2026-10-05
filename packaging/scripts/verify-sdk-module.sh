#!/bin/sh
# Prove that the staged native-package SDK builds without a Go proxy, then
# compile a real workflow using the same require + replace shape as Reactor.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <staged-sdk-module-directory>" >&2
    exit 2
fi

case "$1" in
    /*) module_dir=$1 ;;
    *) module_dir=$PWD/$1 ;;
esac
if [ ! -f "$module_dir/go.mod" ] || [ ! -f "$module_dir/LICENSE" ] || [ ! -d "$module_dir/sdk" ] || [ ! -d "$module_dir/internal/safehttp" ]; then
    echo "staged SDK module is incomplete: $module_dir" >&2
    exit 1
fi

module_cache=$(mktemp -d)
workflow_dir=$(mktemp -d)
trap 'rm -rf -- "$module_cache" "$workflow_dir"' EXIT HUP INT TERM
# A fresh module cache proves the packaged source does not depend on a warm
# checkout/cache or a network proxy. Keep the host's normal Go build cache.
export GOMODCACHE="$module_cache"
export CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOENV=off GOFLAGS=-mod=mod
(
    cd "$module_dir"
    go build ./sdk/... ./internal/safehttp
)

cat > "$workflow_dir/main.go" <<'GO'
package main

import (
    "context"

    reactor "github.com/bright-interaction/reactor/sdk"
    reactorhttp "github.com/bright-interaction/reactor/sdk/http"
    "github.com/bright-interaction/reactor/sdk/runtime"
)

var workflow = reactor.Workflow{Slug: "package-smoke", Version: "0.1.0"}
var trigger = reactor.WebhookTrigger{Path: "/webhook/package-smoke", Provider: "generic"}

func run(_ context.Context, _ reactor.Flow, _ struct{}) error {
    _ = reactorhttp.ConnectorGet
    return nil
}

func main() { runtime.Serve(workflow, trigger, run) }
GO
(
    cd "$workflow_dir"
    go mod init reactor-workflow/package-smoke
    go mod edit -require=github.com/bright-interaction/reactor@v0.0.0 \
        -replace="github.com/bright-interaction/reactor=$module_dir"
    go vet ./...
    go build -buildvcs=false -o "$workflow_dir/workflow" .
    GOOS=linux GOARCH=arm64 go build -buildvcs=false -o "$workflow_dir/workflow-linux-arm64" .
)
