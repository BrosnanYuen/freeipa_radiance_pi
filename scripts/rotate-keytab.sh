#!/usr/bin/env bash
# Rotate HTTP/radiance.ipa.test's keytab (new kvno) and recreate the gateway.
# The old keytab stops authorizing once the gateway restarts. A cached service
# ticket minted under the old key also fails; clients must log in again.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

require_docker
"${COMPOSE[@]}" --profile bootstrap run --rm -T --entrypoint /bin/bash bootstrap -lc '
    set -euo pipefail
    kinit admin < /run/secrets/ipa_admin_password
    ipa-getkeytab -s ipa.ipa.test -p HTTP/radiance.ipa.test \
        -k /data/keytabs/radiance.new \
        -e aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96
    chmod 600 /data/keytabs/radiance.new
    mv /data/keytabs/radiance.new /data/keytabs/radiance.keytab
    kdestroy
' || die "ipa-getkeytab failed; the keytab was not replaced"

log "keytab rotated; recreating the gateway"
recreate_gateway_stack 120 || die "the gateway did not become healthy after keytab rotation"
if ! verify_gateway_auth; then
    log "WARNING: authenticated check failed after keytab rotation; cached client tickets may need re-login"
fi
log "keytab rotation complete; clients must run pi-krb login again"
