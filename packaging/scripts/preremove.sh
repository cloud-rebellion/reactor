#!/bin/sh
# Pre-remove script for reactor .deb / .rpm.
# Stops the daemon on an actual erase, never on an upgrade. Leaves the state dir + user behind
# so an apt purge can be re-installed without losing the master key
# (purge with apt purge --auto-remove + manually rm -rf if you really
# mean it).
set -eu

# Debian prerm receives `upgrade <new-version>` or `remove`; RPM preun
# receives `1` on upgrade and `0` on erase. Unknown actions fail open for
# service continuity rather than disabling a live unit unexpectedly.
case "${1:-}" in
    remove|0) ;;
    upgrade|1) exit 0 ;;
    *) exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop reactor 2>/dev/null || true
    systemctl disable reactor 2>/dev/null || true
fi
