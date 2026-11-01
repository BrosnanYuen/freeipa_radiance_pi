#!/usr/bin/env bash
# Copy the IPA client CA and default.conf out of the running server container
# into the host staging area. The one-off bootstrap container mounts these so
# its `ipa` CLI can verify the server certificate and find the realm; neither
# file is a secret (the CA is public and default.conf holds no credentials).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=".env"
[ -f "$ENV_FILE" ] || ENV_FILE=".env.example"

set -a
# shellcheck disable=SC1090
. "./$ENV_FILE"
set +a

COMPOSE=(docker compose --env-file "$ENV_FILE")
IPA_ID="$("${COMPOSE[@]}" ps -q ipa | head -n1)"
if [ -z "$IPA_ID" ]; then
    echo "copy-ipa-client-config: the ipa service is not running" >&2
    exit 2
fi

mkdir -p run/ipa-client
docker cp "$IPA_ID:/etc/ipa/ca.crt" run/ipa-client/ca.crt
chmod 644 run/ipa-client/ca.crt

if ! docker cp "$IPA_ID:/etc/ipa/default.conf" run/ipa-client/ipa-default.conf 2>/dev/null; then
    realm="${REALM:-IPA.TEST}"
    domain="${IPA_DOMAIN:-ipa.test}"
    kdc="${KDC_HOST:-ipa.ipa.test}"
    basedn="dc=$(printf '%s' "$domain" | sed 's/\\./,dc=/g')"
    cat > run/ipa-client/ipa-default.conf <<EOF
[global]
host = $kdc
realm = $realm
domain = $domain
basedn = $basedn
EOF
fi
chmod 644 run/ipa-client/ipa-default.conf
echo "copy-ipa-client-config: staged CA and default.conf" >&2
