#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
keycloak_image='quay.io/keycloak/keycloak@sha256:98fab020a3a490aba0978f237e2a06cd0ea42bf149c6cf10f11c0aaf27728ff2'
expected_version="26.3.2"
fixture="${root}/oidc/testdata/keycloak-26.3.2-realm.json"
run_directory="$(mktemp -d)"
token_file="${run_directory}/id-token"
container="golib-oidc-keycloak-${$}-${RANDOM}"

cleanup() {
    docker rm -f "${container}" >/dev/null 2>&1 || true
    find "${run_directory}" -depth -delete
}
trap cleanup EXIT

command -v docker >/dev/null || {
    printf 'Docker is required for OIDC Keycloak interoperability\n' >&2
    exit 1
}

docker run --detach --name "${container}" --publish 127.0.0.1::8080 \
    --mount "type=bind,src=${fixture},dst=/opt/keycloak/data/import/realm.json,readonly" \
    --env KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    --env KC_BOOTSTRAP_ADMIN_PASSWORD=interoperability-admin \
    "${keycloak_image}" start-dev --import-realm --hostname-strict=false >/dev/null
port="$(docker port "${container}" 8080/tcp | tail -1 | sed 's/.*://')"
issuer="http://127.0.0.1:${port}/realms/oidc-hardening"
ready=false
for _ in {1..120}; do
    if curl --fail --silent --show-error \
        "${issuer}/.well-known/openid-configuration" >/dev/null 2>&1; then
        ready=true
        break
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "${container}" 2>/dev/null || true)" != "true" ]]; then
        break
    fi
    sleep 1
done
if [[ "${ready}" != "true" ]]; then
    docker logs "${container}" >&2 || true
    printf 'Keycloak did not become ready\n' >&2
    exit 1
fi

reported_version="$(docker exec "${container}" /opt/keycloak/bin/kc.sh --version)"
if [[ "${reported_version}" != *"${expected_version}"* ]]; then
    printf 'unexpected Keycloak version: %s\n' "${reported_version}" >&2
    exit 1
fi

token_response="$(curl --fail --silent --show-error \
    --request POST "${issuer}/protocol/openid-connect/token" \
    --data-urlencode grant_type=password \
    --data-urlencode client_id=oidc-client \
    --data-urlencode username=alice \
    --data-urlencode password=interoperability-password \
    --data-urlencode scope=openid)"
id_token="$(jq -er '.id_token | strings | select(length > 0)' <<<"${token_response}")"
umask 077
printf '%s\n' "${id_token}" >"${token_file}"
unset token_response id_token

OIDC_INTEROP_ISSUER="${issuer}" \
OIDC_INTEROP_TOKEN_FILE="${token_file}" \
OIDC_INTEROP_CLIENT_ID=oidc-client \
GOCACHE="${run_directory}/go-cache" \
GOWORK=off \
go test ./... -tags=integration \
    -run '^(TestGoogleProviderMetadataSnapshot|TestRepresentativeProviderMetadataProfiles|TestKeycloakProviderIssuedIDToken)$' \
    -count=1

printf 'Keycloak interoperability passed: version=%s image=%s\n' \
    "${expected_version}" "${keycloak_image}"
