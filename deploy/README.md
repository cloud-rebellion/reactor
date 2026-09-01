# Deploying Reactor

This page is a single-node installation walkthrough. Its Docker, Compose, and
systemd examples use SQLite and are suitable for development or a local
evaluation. They are **not** a production recipe for the Hash e-signature
bridge, which requires an estate-owned PostgreSQL distributed topology with at
least one `serve` process and one `worker` process. See
[`docs/scaling.md`](../docs/scaling.md) for the runtime topology and
[`docs/hash-esign-bridge.md`](../docs/hash-esign-bridge.md) for the bridge
cutover gates. Reactor does not currently ship a turnkey production Compose
manifest for that topology.

## Docker

The commands in this section demonstrate a local, single-node SQLite install.

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

# Steady state: run the daemon. Set REACTOR_BASIC_AUTH_USER +
# REACTOR_BASIC_AUTH_PASSWORD_SHA256 so the status pages aren't open.
docker run -d --name reactor \
  -p 127.0.0.1:7777:7777 \
  -v reactor-state:/var/lib/reactor \
  -e REACTOR_DB_URL=sqlite:///var/lib/reactor/reactor.db \
  -e REACTOR_BASIC_AUTH_USER=admin \
  -e REACTOR_BASIC_AUTH_PASSWORD_SHA256=$(printf '%s' 'changeme' | sha256sum | awk '{print $1}') \
  reactor:latest

curl -u admin:changeme http://127.0.0.1:7777/
```

For HTTPS, mount a cert + key and pass the flags:

```bash
docker run -d --name reactor \
  -p 7777:7777 \
  -v reactor-state:/var/lib/reactor \
  -v /etc/letsencrypt/live/reactor.example.com:/etc/tls:ro \
  -e REACTOR_DB_URL=sqlite:///var/lib/reactor/reactor.db \
  reactor:latest serve \
    --root /var/lib/reactor \
    --tls-cert /etc/tls/fullchain.pem \
    --tls-key  /etc/tls/privkey.pem
```

## systemd

The unit below is likewise a single-node example. Do not use it as the only
process for a production Hash bridge.

```bash
# 1. Install the binary.
sudo install -m 0755 bin/reactor /usr/local/bin/reactor

# 2. Create the system user + state dir.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --home-dir /var/lib/reactor reactor
sudo install -d -m 0700 -o reactor -g reactor /var/lib/reactor

# 3. Run the setup wizard (interactive) OR pass --non-interactive for CI.
sudo -u reactor /usr/local/bin/reactor setup \
  --root /var/lib/reactor \
  --non-interactive --admin-user admin --admin-password "$ADMIN_PASSWORD"
# Setup writes /var/lib/reactor/reactor.env (mode 0600, owned by reactor)
# containing REACTOR_DB_URL + REACTOR_BASIC_AUTH_USER + REACTOR_BASIC_AUTH_PASSWORD_SHA256.

# 4. (Optional) Add rate-limit overrides to the env file.
sudo tee -a /var/lib/reactor/reactor.env >/dev/null <<EOF
export REACTOR_RATE_BURST=120
export REACTOR_RATE_REFILL=20
EOF

# 5. Install the unit (the unit references /var/lib/reactor/reactor.env).
sudo install -m 0644 deploy/reactor.service /etc/systemd/system/reactor.service
sudo systemctl daemon-reload
sudo systemctl enable --now reactor

# 6. Verify.
sudo systemctl status reactor
curl -u admin:"$ADMIN_PASSWORD" http://127.0.0.1:7777/healthz
```

The pre-setup-wizard manual path (separate `reactor init` + `reactor
migrate` + hand-rolled `sha256sum` for the password hash) still works;
the wizard is just a one-command shortcut.

## Behind a reverse proxy

When fronted by Caddy / Nginx / Traefik that already terminates TLS,
omit the `--tls-cert` / `--tls-key` flags. The proxy needs to set
`X-Forwarded-Proto: https` so Reactor emits HSTS on responses; the
trusted-proxy logic in `internal/server/middleware.go` accepts the
header from loopback / RFC1918 ranges only.

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
