# Deploying Reactor

This page is a single-node installation walkthrough. Its Docker, Compose, and
systemd examples use SQLite and are suitable for development or a local
evaluation. They are **not** a production recipe for the Hash e-signature
bridge, which requires an estate-owned PostgreSQL distributed topology with at
least one `serve` process and one `worker` process. Deploy the separate
`artifact-publisher` role as well when workers use a distinct artifact volume.
See
[`docs/scaling.md`](../docs/scaling.md) for the runtime topology and
[`docs/hash-esign-bridge.md`](../docs/hash-esign-bridge.md) for the bridge
cutover gates. Reactor does not currently ship a turnkey production Compose
manifest for that topology.

## Docker

The commands in this section demonstrate a local, single-node SQLite install.
The plain-HTTP `docker run` and Compose examples use host networking so Reactor
can bind `127.0.0.1` inside the container; use Linux or Docker Desktop with its
host-networking feature enabled. On other hosts, run the binary directly or
configure an HTTPS container endpoint using the second example below. Do not
switch these examples back to a bridge-published wildcard plain-HTTP listener:
Reactor refuses that exposure at startup.

```bash
# Single-arch (host CPU):
docker build -t reactor:latest .

# Multi-arch via buildx (linux/amd64 + linux/arm64). Required if you
# build on Apple Silicon / ARM dev box but deploy to x86 servers,
# or vice versa. --push uploads each platform variant to your registry.
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t registry.example.com/reactor:latest --push .

# First boot: init + migrate inside the volume.
docker run --rm \
  -v reactor-state:/var/lib/reactor \
  reactor:latest init --root /var/lib/reactor

docker run --rm \
  -v reactor-state:/var/lib/reactor \
  reactor:latest migrate --db sqlite:///var/lib/reactor/reactor.db

# Steady state: run the daemon. On Linux, use host networking for this
# loopback-only HTTP example; Reactor refuses a wildcard plain-HTTP MCP bind.
# Set REACTOR_BASIC_AUTH_USER +
# REACTOR_BASIC_AUTH_PASSWORD_SHA256 so the status pages aren't open.
docker run -d --name reactor \
  --init \
  --network host \
  -v reactor-state:/var/lib/reactor \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 1g --pids-limit 512 \
  -e REACTOR_DB_URL=sqlite:///var/lib/reactor/reactor.db \
  -e REACTOR_BASIC_AUTH_USER=admin \
  -e REACTOR_BASIC_AUTH_PASSWORD_SHA256=$(printf '%s' 'changeme' | sha256sum | awk '{print $1}') \
  reactor:latest serve --root /var/lib/reactor --addr 127.0.0.1:7777

curl -u admin:changeme http://127.0.0.1:7777/
```

For a bridge-published or remote endpoint, use HTTPS (or a directly
authenticated TLS-terminating proxy) and bind the daemon explicitly to its
private network interface. Mount a cert + key and pass the flags:

```bash
docker run -d --name reactor \
  --init \
  -p 7777:7777 \
  -v reactor-state:/var/lib/reactor \
  -v /etc/letsencrypt/live/reactor.example.com:/etc/tls:ro \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 1g --pids-limit 512 \
  -e REACTOR_DB_URL=sqlite:///var/lib/reactor/reactor.db \
  reactor:latest serve \
    --root /var/lib/reactor \
    --addr 0.0.0.0:7777 \
    --tls-cert /etc/tls/fullchain.pem \
    --tls-key  /etc/tls/privkey.pem
```

## systemd

The unit below is likewise a single-node example. Do not use it as the only
process for a production Hash bridge.

Native `.deb`/`.rpm` releases include the exact release's workflow SDK source
at `/usr/lib/reactor-sdk`; the packaged unit pins `REACTOR_SDK_REPLACE` to that
root-owned, read-only module. Install Go 1.26.5 or newer for the host
architecture at `/usr/local/go/bin/go` or `/usr/bin/go` before starting MCP or
dashboard authoring. Reactor's workflow compiler sets `GOPROXY=off` and
`GOTOOLCHAIN=local`, so it cannot fetch a missing SDK or toolchain at request
time. The release package job verifies an SDK-importing workflow with an empty
module cache and the staged source read-only. The package does not include the
Go toolchain; an installed binary without Go can run existing artifacts but
cannot author new Go workflows.
The vendor unit at `/lib/systemd/system/reactor.service` is replaced on package
upgrade, so put host-specific settings in
`/etc/systemd/system/reactor.service.d/*.conf` and reload systemd after changes.
The first upgrade from older Reactor packages needs an operator check: their
old removal hook can stop and disable the unit even during an upgrade. After
upgrading, review `systemctl is-enabled reactor` and `systemctl is-active
reactor`, then explicitly re-enable/start the unit if it was previously meant
to run. The updated removal hook leaves the unit alone on subsequent upgrades.

The packaged unit deliberately keeps `ProtectControlGroups=true` and does not
claim per-workflow cgroup isolation. On Linux hosts where authored workflows
are treated as hostile, install a reviewed drop-in after confirming the service
cgroup path and systemd version:

```ini
# /etc/systemd/system/reactor.service.d/workflow-cgroup.conf
[Service]
Delegate=yes
ProtectControlGroups=false
Environment=REACTOR_CGROUP_ROOT=/sys/fs/cgroup/system.slice/reactor.service
Environment=REACTOR_REQUIRE_WORKFLOW_CGROUP=1
```

Then run `systemctl daemon-reload && systemctl restart reactor` and verify the
service cgroup is delegated before dispatching. This gives the supervisor
per-run `memory.max`, `pids.max`, and `cgroup.kill` enforcement when the host
supports them; it is still an outer resource/descendant fence, not a complete
same-UID hostile-code sandbox. Use a dedicated container or VM with reviewed
egress policy when workflow code must be treated as hostile.

```bash
# 1. Install the binary.
sudo install -m 0755 bin/reactor /usr/bin/reactor
# When installing a binary manually instead of the .deb/.rpm, stage the SDK
# from the same source revision used to build that binary. Packages already
# include this module; do not restage an installed package.
sudo packaging/scripts/stage-sdk-module.sh /usr/lib/reactor-sdk

# Check the host toolchain and the release-matched SDK module.
go version
test -f /usr/lib/reactor-sdk/go.mod

# 2. Create the system user + state dir.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --home-dir /var/lib/reactor reactor
sudo install -d -m 0700 -o reactor -g reactor /var/lib/reactor

# 3. Run the setup wizard (interactive) OR pass --non-interactive for CI.
sudo -u reactor /usr/bin/reactor setup \
  --root /var/lib/reactor \
  --non-interactive --admin-user admin --admin-password "$ADMIN_PASSWORD"
# Setup writes /var/lib/reactor/reactor.env (mode 0600, owned by reactor).
# The packaged unit loads this same file with EnvironmentFile=.
# containing REACTOR_DB_URL + REACTOR_BASIC_AUTH_USER + REACTOR_BASIC_AUTH_PASSWORD_SHA256.

# 4. (Optional) Add rate-limit overrides to the env file.
sudo tee -a /var/lib/reactor/reactor.env >/dev/null <<EOF
REACTOR_RATE_BURST=120
REACTOR_RATE_REFILL=20
EOF

# 5. Install the unit (it references /var/lib/reactor/reactor.env).
sudo install -m 0644 deploy/reactor.service /etc/systemd/system/reactor.service
sudo systemctl daemon-reload
sudo systemctl enable --now reactor

# 6. Verify.
sudo systemctl status reactor
curl -u admin:"$ADMIN_PASSWORD" http://127.0.0.1:7777/healthz
```

The packaged unit binds the local dashboard and HTTP MCP endpoint to
`127.0.0.1:7777`. A local reverse proxy can reach this listener directly.
For a proxy on another host, bind Reactor to an exact private address, restrict
the listener at the firewall to the proxy's source IP, and use the reviewed
`--mcp-trusted-proxy` assertion (or configure in-process TLS). The assertion
permits non-loopback plain HTTP at startup; it does not enforce the firewall.

The pre-setup-wizard manual path (separate `reactor init` + `reactor
migrate` + hand-rolled `sha256sum` for the password hash) still works;
the wizard is just a one-command shortcut.

## Behind a reverse proxy

When fronted by Caddy / Nginx / Traefik that already terminates TLS,
omit the `--tls-cert` / `--tls-key` flags. The proxy needs to set
`X-Forwarded-Proto: https` so Reactor emits HSTS on responses. Loopback proxy
peers are trusted by default. For a proxy at `10.4.5.9`, set
`REACTOR_TRUSTED_PROXY_CIDRS=10.4.5.9` (or `--trusted-proxy-cidrs 10.4.5.9`)
so Reactor accepts its forwarded client IP, scheme, and host. Prefer exact
`/32` or `/128` proxy peers. A broad CIDR that
also contains direct clients lets those clients spoof forwarded headers.
Configure the proxy to replace incoming forwarded headers, or append the
actual client IP to `X-Forwarded-For` before proxying.

Tighten `REACTOR_RATE_BURST` + `REACTOR_RATE_REFILL` against the source-IP
distribution your proxy passes in `X-Forwarded-For`.

## Backups

For the SQLite example, take a quiesced copy of the state directory. For a
PostgreSQL deployment, the state directory is **not** the entire backup target:
take a database-native consistent backup/PITR stream as well as a protected copy
of Reactor's state and release artifacts.

- `master.key` (mode 0600). Without this no credentials can be decrypted.
- `reactor.db` for SQLite, or a separately verified PostgreSQL backup.
- `workflows/`, their reviewed source/DAG, release identity, and checksums. Do
  not assume a later rebuild is byte-for-byte or behaviorally identical.

A state-directory archive alone is not sufficient for distributed production.
Store the database recovery point, matching master key, workflow artifacts, and
configuration as one documented recovery generation in separate protected
storage. Restore it into isolation and prove that the vault decrypts and a
pinned workflow can resume before accepting the backup or a release cutover.
