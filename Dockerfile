# syntax=docker/dockerfile:1
#
# Reactor daemon image. Two-stage build: a golang builder compiles the
# binary, and the runtime ALSO carries the Go toolchain + the Reactor SDK
# source so the deployed daemon can compile operator/AI-generated
# workflows in place. Building workflows in-container is not optional: it
# is Reactor's headline feature ("describe a workflow, the AI builds it").
# A toolchain-free distroless runtime makes the dashboard codegen + upload
# paths fail at `go build`, leaving workflows stuck in "missing" status.
#
# The in-container build is HERMETIC and offline by construction:
#   - GOPROXY=off            -> no network fetch is ever attempted
#   - REACTOR_SDK_REPLACE    -> the unpublished SDK import resolves to the
#                               bundled /opt/reactor-src copy (initModule
#                               wires a go.mod replace before building)
#   - warmed GOMODCACHE      -> the SDK's transitive deps are pre-downloaded
#   - CGO_ENABLED=0 + the codegen import allowlist (stdlib + SDK only) are
#     the safety layer that keeps `go build` from running hostile code.
#
# Multi-arch: BUILDPLATFORM runs Go; TARGETPLATFORM is the run target.
# The runtime toolchain is the runtime image's native arch, so workflows
# compile natively at run time (no cross-compile at runtime).
#
# Build single-arch (host):
#   docker build -t reactor:latest .
#
# Run (Linux local-only path; host networking preserves a loopback bind):
#   docker run -d --name reactor --network host \
#     -v reactor-state:/var/lib/reactor \
#     -e REACTOR_DB_URL=sqlite:///var/lib/reactor/reactor.db \
#     -e REACTOR_BASIC_AUTH_USER=admin \
#     -e REACTOR_BASIC_AUTH_PASSWORD_SHA256=<sha256-hex> \
#     reactor:latest serve --root /var/lib/reactor --addr 127.0.0.1:7777

# Keep this in lockstep with ciGoToolchain in hephaestus/userworkflows/ci_go.go.
# It was once golang:1.26.4-alpine while CI compiled and govulnchecked reactor
# inside 1.26.5, which was pinned precisely to pick up the crypto/tls fix for
# GO-2026-5856 (ECH privacy leak). So govulncheck was scanning a patched stdlib
# that the shipped binary did not have: the gate was GREEN on a CVE that was live
# in production. Note the asymmetry, because it is why this hid for so long: a CI
# image OLDER than this stage fails loudly red, a NEWER one fails silently green.
# The 1.26.6 pin here is the same lockstep rule applied again, for the seven
# stdlib advisories (GO-2026-6089/6088/5972/5026 and three more) that 1.26.5
# carries and 1.26.6 fixes.
# The runtime stage below is also golang-alpine (the daemon compiles user
# workflows at runtime); it does NOT build this binary, and mistaking it for the
# builder is exactly how the drift stayed invisible.
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
        -ldflags="-s -w -X main.Version=${VERSION}" \
        -o /out/reactor ./cmd/reactor

# Warm a MINIMAL module cache holding exactly what compiling a WORKFLOW
# needs, not the daemon's ~470MB full dep cache. A workflow imports only
# stdlib + the SDK (enforced by the codegen import allowlist) and the SDK is
# stdlib-only, so this captures just the module-graph metadata (a few MB).
# Mimics the daemon's initModule + go build so the runtime resolves a
# workflow build offline (GOPROXY=off). Future-proof: if the SDK ever gains a
# dep, this step downloads it automatically.
RUN mkdir -p /wfcache /wfwarm \
    && cp examples/cron-echo/main.go /wfwarm/main.go \
    && cd /wfwarm \
    && GOMODCACHE=/wfcache go mod init reactor-workflow/warm \
    && GOMODCACHE=/wfcache go mod edit -require=github.com/bright-interaction/reactor@v0.0.0 -replace=github.com/bright-interaction/reactor=/src \
    && GOMODCACHE=/wfcache GOFLAGS=-mod=mod CGO_ENABLED=0 go build -o /dev/null .

# Runtime: golang-alpine so the daemon has a Go toolchain to compile
# workflows. Slightly larger than distroless, but the alternative is a
# product whose core feature cannot run in production.
FROM golang:1.26.6-alpine
RUN apk add --no-cache ca-certificates git \
    && adduser -D -u 65532 reactor
COPY --from=build /out/reactor /usr/local/bin/reactor
# SDK source: generated workflows import the (unpublished) module
# github.com/bright-interaction/reactor; initModule rewrites that import to
# this local copy via a go.mod replace so the workflow links the same SDK.
COPY --from=build /src /opt/reactor-src
# Minimal module cache (workflow-build deps only; see the warm step above),
# so the in-container workflow build resolves offline with GOPROXY=off.
COPY --from=build /wfcache /go/pkg/mod
ENV REACTOR_SDK_REPLACE=/opt/reactor-src \
    GOTOOLCHAIN=local \
    GOPROXY=off \
    GOFLAGS=-mod=mod \
    GOCACHE=/var/lib/reactor/.gocache \
    GOMODCACHE=/go/pkg/mod
# nonroot owns the state dir (master.key, db, build cache live here) and the
# SDK source (go build may touch go.sum); the module cache is world-readable.
RUN mkdir -p /var/lib/reactor/.gocache \
    && chown -R reactor:reactor /var/lib/reactor /opt/reactor-src \
    && chmod 0700 /var/lib/reactor /var/lib/reactor/.gocache \
    && chmod -R a+rX /go/pkg/mod
VOLUME ["/var/lib/reactor"]
EXPOSE 7777
USER reactor
ENTRYPOINT ["/usr/local/bin/reactor"]
CMD ["serve", "--addr", "127.0.0.1:7777"]
