#!/usr/bin/env bash
# Verify that the final image contains deployable artifacts without Node/dev output.
set -euo pipefail

image=${1:?usage: verify_runtime_image.sh IMAGE}

user=$(docker image inspect --format '{{.Config.User}}' "$image")
if [[ "$user" != "app" ]]; then
    echo "runtime image must declare the non-root app user" >&2
    exit 1
fi

command=$(docker image inspect --format '{{json .Config.Cmd}}' "$image")
if [[ "$command" != '["python","-m","agentforge.web"]' ]]; then
    echo "runtime image has an unexpected default process" >&2
    exit 1
fi

docker run --rm --entrypoint sh "$image" -c '
    set -eu
    test "$(id -u)" != 0
    test -f /app/alembic.ini
    test -f /app/migrations/env.py
    test -f /app/console/index.html
    test -d /app/console/assets
    ! command -v node >/dev/null 2>&1
    ! command -v npm >/dev/null 2>&1
    ! find /app/console -type f -name "*.map" -print -quit | grep -q .
    ! find /app/console -type f \( -name "*.ts" -o -name "*.tsx" \) -print -quit | grep -q .
    test "$(alembic heads | wc -l | tr -d " ")" = "1"
'
