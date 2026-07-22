#!/usr/bin/env sh
# Verify a daemonless Docker archive produced by the GitLab rootless BuildKit gate.
set -eu

archive=${1:?usage: verify_container_archive.sh IMAGE_ARCHIVE}

archive_dir=$(mktemp -d)
rootfs_dir=$(mktemp -d)
cleanup() {
    rm -rf "$archive_dir" "$rootfs_dir"
}
trap cleanup EXIT HUP INT TERM

tar -xf "$archive" -C "$archive_dir"
manifest="$archive_dir/manifest.json"
test -s "$manifest"

config_rel=$(sed -n 's/.*"Config"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n 1)
test -n "$config_rel"
config="$archive_dir/$config_rel"
test -s "$config"

grep -Eq '"User"[[:space:]]*:[[:space:]]*"app"' "$config"
grep -Eq '"Cmd"[[:space:]]*:[[:space:]]*\[[[:space:]]*"python"[[:space:]]*,[[:space:]]*"-m"[[:space:]]*,[[:space:]]*"agentforge\.web"[[:space:]]*\]' "$config"
grep -q '/health' "$config"

layers=$(sed -n 's/.*"Layers"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' "$manifest" \
    | tr ',' '\n' \
    | tr -d '" \t\r')
test -n "$layers"
for layer in $layers; do
    test -s "$archive_dir/$layer"
    tar -xf "$archive_dir/$layer" -C "$rootfs_dir"
done

test -f "$rootfs_dir/app/alembic.ini"
test -f "$rootfs_dir/app/migrations/env.py"
test -f "$rootfs_dir/app/console/index.html"
test -d "$rootfs_dir/app/console/assets"
test -d "$rootfs_dir/usr/local/lib/python3.12/site-packages/agentforge"
test ! -e "$rootfs_dir/usr/local/bin/node"
test ! -e "$rootfs_dir/usr/local/bin/npm"

if find "$rootfs_dir/app/console" -type f -name '*.map' -print -quit | grep -q .; then
    echo "runtime archive contains a source map" >&2
    exit 1
fi
if find "$rootfs_dir/app/console" -type f -name '*.ts' -print -quit | grep -q .; then
    echo "runtime archive contains TypeScript source" >&2
    exit 1
fi
if find "$rootfs_dir/app/console" -type f -name '*.tsx' -print -quit | grep -q .; then
    echo "runtime archive contains TSX source" >&2
    exit 1
fi
