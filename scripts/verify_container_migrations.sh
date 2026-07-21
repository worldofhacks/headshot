#!/usr/bin/env bash
# Exercise clean and 0003 -> 0004 -> integrated-head migrations inside the final image.
set -euo pipefail

image=${1:?usage: verify_container_migrations.sh IMAGE}
: "${CLEAN_DATABASE_URL:?CLEAN_DATABASE_URL is required}"
: "${UPGRADE_DATABASE_URL:?UPGRADE_DATABASE_URL is required}"

network_mode=${DOCKER_NETWORK_MODE:-host}

alembic_in_image() {
    local database_url=$1
    shift
    docker run --rm \
        --network "$network_mode" \
        --env DATABASE_URL="$database_url" \
        --entrypoint alembic \
        "$image" "$@"
}

assert_current() {
    local database_url=$1
    local expected=$2
    local actual
    actual=$(alembic_in_image "$database_url" current | awk 'NR == 1 {print $1}')
    if [[ "$actual" != "$expected" ]]; then
        echo "unexpected Alembic revision: expected $expected, got ${actual:-none}" >&2
        exit 1
    fi
}

heads=$(docker run --rm --entrypoint alembic "$image" heads | awk '{print $1}')
if [[ -z "$heads" || "$heads" == *$'\n'* ]]; then
    echo "the integrated migration graph must have exactly one head" >&2
    exit 1
fi

alembic_in_image "$CLEAN_DATABASE_URL" upgrade head
assert_current "$CLEAN_DATABASE_URL" "$heads"

alembic_in_image "$UPGRADE_DATABASE_URL" upgrade 0003
assert_current "$UPGRADE_DATABASE_URL" "0003"
alembic_in_image "$UPGRADE_DATABASE_URL" upgrade 0004
assert_current "$UPGRADE_DATABASE_URL" "0004"
alembic_in_image "$UPGRADE_DATABASE_URL" upgrade head
assert_current "$UPGRADE_DATABASE_URL" "$heads"
