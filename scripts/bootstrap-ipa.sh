#!/usr/bin/env bash
# Run (or re-run) the one-off IPA bootstrap. Requires the IPA service to be up.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=".env"
[ -f "$ENV_FILE" ] || ENV_FILE=".env.example"

[ -s run/krb5.conf ] || { echo "bootstrap-ipa: run scripts/up.sh first" >&2; exit 2; }
[ -s run/ipa-data/certs/radiance.csr ] || { echo "bootstrap-ipa: missing CSR; run scripts/gen-cert.sh" >&2; exit 2; }

./scripts/copy-ipa-client-config.sh
docker compose --env-file "$ENV_FILE" --profile bootstrap run --rm -T bootstrap
