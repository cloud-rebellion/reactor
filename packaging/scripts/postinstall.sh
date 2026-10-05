#!/bin/sh
# Post-install script for reactor .deb / .rpm.
#
# Creates a system user + state directory, then leaves the daemon
# disabled so the operator runs `reactor setup` first to mint a master
# key, run migrations, and configure authentication. We deliberately do
# NOT auto-enable because setup requires an operator-provided password and
# the daemon refuses to start without a master key.
set -eu

if ! getent passwd reactor >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --home-dir /var/lib/reactor reactor
fi

install -d -m 0700 -o reactor -g reactor /var/lib/reactor
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

upgrade=false
case "${1:-}" in
    configure)
        if [ -n "${2:-}" ]; then
            upgrade=true
        fi
        ;;
    2) upgrade=true ;;
esac

if [ "$upgrade" = true ]; then
    cat <<EOF

Reactor upgraded. The vendor unit and release-matched SDK module were updated.
Check systemctl is-enabled reactor and systemctl is-active reactor. If this is
the first upgrade from an older package, its old removal hook may have stopped
and disabled the unit; restore its previous intended state manually.
Go 1.26.6+ must remain available at /usr/local/go/bin/go or /usr/bin/go for
MCP/dashboard workflow authoring. See /usr/share/doc/reactor/DEPLOY.md.
EOF
    exit 0
fi

cat <<EOF

Reactor installed. Next step:

  sudo -u reactor reactor setup --root /var/lib/reactor

This writes the master key, runs migrations, and creates
/var/lib/reactor/reactor.env with REACTOR_BASIC_AUTH_USER +
REACTOR_BASIC_AUTH_PASSWORD_SHA256. Then start the unit:

  sudo systemctl enable --now reactor

See /usr/share/doc/reactor/DEPLOY.md for the full walkthrough.
MCP/dashboard workflow authoring also needs Go 1.26.6+ installed at
/usr/local/go/bin/go or /usr/bin/go. The matching SDK module is included at
/usr/lib/reactor-sdk; workflow builds will not fetch missing tools online.
EOF
