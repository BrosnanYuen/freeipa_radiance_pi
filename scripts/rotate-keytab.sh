#!/usr/bin/env bash
# Rotate HTTP/radiance.ipa.test's keytab (new kvno) and restart the edge.
# The old keytab stops authorizing once Apache restarts.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=".env"
[ -f "$ENV_FILE" ] || ENV_FILE=".env.example"

docker compose --env-file "$ENV_FILE" --profile bootstrap run --rm -T \
    --entrypoint /bin/bash bootstrap -lc '
      set -euo pipefail
      kinit admin < /run/secrets/ipa_admin_password
      ipa-getkeytab -s ipa.ipa.test -p HTTP/radiance.ipa.test \
        -k /data/keytabs/radiance.new \
        -e aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96
      chmod 600 /data/keytabs/radiance.new
      mv /data/keytabs/radiance.new /data/keytabs/radiance.keytab
      kdestroy
    '

docker compose --env-file "$ENV_FILE" restart radiance-edge
echo "rotate-keytab: new keytab installed; the edge is restarting" >&2
