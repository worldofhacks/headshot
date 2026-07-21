#!/usr/bin/env bash
# Start the final Web image on a non-default PORT and exercise public/fallback boundaries.
set -euo pipefail

image=${1:?usage: smoke_runtime_container.sh IMAGE}
port=${AGENTFORGE_SMOKE_PORT:-18080}
network_mode=${DOCKER_NETWORK_MODE:-bridge}
smoke_host=${AGENTFORGE_SMOKE_HOST:-127.0.0.1}
container_name="agentforge-web-smoke-$$"

cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

network_args=(--network "$network_mode")
if [[ "$network_mode" != "host" ]]; then
    network_args+=(--publish "${port}:${port}")
fi

docker run --rm -d \
    --name "$container_name" \
    "${network_args[@]}" \
    --env PORT="$port" \
    --env AGENTFORGE_ENVIRONMENT=local \
    "$image" >/dev/null

ready=0
for _ in $(seq 1 30); do
    if curl --fail --silent "http://${smoke_host}:${port}/health" >/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if [[ "$ready" != "1" ]]; then
    docker logs "$container_name" >&2 || true
    echo "Web container did not serve liveness on the assigned PORT" >&2
    exit 1
fi

# Missing DB/auth configuration must never look ready.
ready_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    "http://${smoke_host}:${port}/ready")
if [[ "$ready_status" != "503" ]]; then
    echo "unconfigured container must fail readiness closed (got $ready_status)" >&2
    exit 1
fi

# A direct console route receives the fixed SPA shell; an API miss never does.
curl --fail --silent --show-error \
    --header 'Accept: text/html' \
    "http://${smoke_host}:${port}/live" | grep -q '<div id="root"></div>'
api_body=$(mktemp)
api_status=$(curl --silent --output "$api_body" --write-out '%{http_code}' \
    "http://${smoke_host}:${port}/api/v1/not-a-route")
if [[ "$api_status" == "200" ]] || grep -q '<div id="root"></div>' "$api_body"; then
    rm -f "$api_body"
    echo "an unknown API route received the SPA fallback" >&2
    exit 1
fi
rm -f "$api_body"
