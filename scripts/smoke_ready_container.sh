#!/usr/bin/env bash
# Prove the packaged Web becomes ready with a migrated DB and offline fixture auth config.
set -euo pipefail

image=${1:?usage: smoke_ready_container.sh IMAGE}
: "${READY_DATABASE_URL:?READY_DATABASE_URL is required}"

port=${AGENTFORGE_READY_SMOKE_PORT:-18081}
network_mode=${DOCKER_NETWORK_MODE:-host}
smoke_host=${AGENTFORGE_SMOKE_HOST:-127.0.0.1}
container_name="agentforge-ready-smoke-$$"

cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Generate a 2048-bit public fixture key entirely in memory. The private half never leaves
# this short-lived process and neither half represents a Clerk credential.
jwt_key=$(docker run --rm --entrypoint python "$image" -c '
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
print(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(), end="")
')
encoded_fapi=$(printf 'clerk.example.com$' | base64 | tr -d '\n')
fixture_publishable="pk_test_${encoded_fapi}"

network_args=(--network "$network_mode")
if [[ "$network_mode" != "host" ]]; then
    network_args+=(--publish "${port}:${port}")
fi

docker run --rm -d \
    --name "$container_name" \
    "${network_args[@]}" \
    --env PORT="$port" \
    --env AGENTFORGE_ENVIRONMENT=local \
    --env DATABASE_URL="$READY_DATABASE_URL" \
    --env CLERK_PUBLISHABLE_KEY="$fixture_publishable" \
    --env CLERK_JWT_KEY="$jwt_key" \
    --env CLERK_AUTHORIZED_PARTIES=http://localhost:5173 \
    --env CLERK_REQUIRED_ORG_ID=org_headshotfixture \
    "$image" >/dev/null

for attempt in $(seq 1 30); do
    http_code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
        "http://${smoke_host}:${port}/ready" || true)
    if [[ "$http_code" == "200" ]]; then
        exit 0
    fi
    if [[ "$attempt" == "30" ]]; then
        docker logs "$container_name" >&2 || true
        echo "configured Web container did not become ready (last status ${http_code:-none})" >&2
        exit 1
    fi
    sleep 1
done
