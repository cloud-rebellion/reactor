#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "$fixture_dir"' EXIT HUP INT TERM

cat > "$fixture_dir/systemctl" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$REACTOR_TEST_SYSTEMCTL_LOG"
SH
chmod +x "$fixture_dir/systemctl"

for action in upgrade 1 unknown; do
    REACTOR_TEST_SYSTEMCTL_LOG="$fixture_dir/calls" PATH="$fixture_dir:$PATH" \
        sh "$repo_root/packaging/scripts/preremove.sh" "$action"
    if [ -e "$fixture_dir/calls" ]; then
        echo "preremove touched systemd for upgrade or unknown action: $action" >&2
        exit 1
    fi
done

for action in remove 0; do
    REACTOR_TEST_SYSTEMCTL_LOG="$fixture_dir/calls" PATH="$fixture_dir:$PATH" \
        sh "$repo_root/packaging/scripts/preremove.sh" "$action"
    expected='stop reactor
disable reactor'
    if [ "$(cat "$fixture_dir/calls")" != "$expected" ]; then
        echo "preremove did not stop and disable for erase action: $action" >&2
        exit 1
    fi
    rm "$fixture_dir/calls"
done
