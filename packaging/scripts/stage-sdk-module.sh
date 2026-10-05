#!/bin/sh
# Stage only the source imported by authored workflows. The native package
# ships this exact release's SDK beside the binary without the daemon's
# unrelated dependencies or mutable build artifacts.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <new-sdk-module-directory>" >&2
    exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
module_dir=$1
if [ -e "$module_dir" ]; then
    echo "SDK module destination already exists: $module_dir" >&2
    exit 1
fi

mkdir -p "$module_dir/internal"
cp -R "$repo_root/sdk" "$module_dir/sdk"
cp -R "$repo_root/internal/safehttp" "$module_dir/internal/safehttp"
cp "$repo_root/packaging/sdk-module.mod" "$module_dir/go.mod"
cp "$repo_root/LICENSE" "$module_dir/LICENSE"
# The installed module lives on systemd's read-only filesystem. Verify builds
# against that same shape, including with a fresh module cache.
chmod -R a+rX,a-w "$module_dir"
