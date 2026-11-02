#!/usr/bin/env bash
# Rotate the gateway TLS key and certificate.
#
# A fresh RSA key and CSR are created inside the bootstrap container (so the
# root-owned /data volume is writable), the new certificate is issued by the
# IPA CA, and the gateway is recreated. The old certificate is revoked and its
# private key is shredded only after the new TLS listener verifies. On any
# failure the previous key/cert pair is restored.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

require_docker
hostname="${RADIANCE_HOSTNAME:-radiance.ipa.test}"

old_serial_hex="$("${COMPOSE[@]}" exec -T radiance-gateway \
    openssl x509 -in /certs/radiance.crt -noout -serial 2>/dev/null |
    tr -d '\r' | cut -d= -f2)"
old_serial_dec=""
if [[ "$old_serial_hex" =~ ^[0-9A-Fa-f]+$ ]]; then
    old_serial_dec=$((16#$old_serial_hex))
fi

log "requesting a new TLS certificate for ${hostname}"
"${COMPOSE[@]}" --profile bootstrap run --rm -T --entrypoint /bin/bash bootstrap -lc '
    set -euo pipefail
    cd /data/certs
    trap "rm -f radiance.key.new radiance.csr.new radiance.crt.new" EXIT
    openssl req -new -newkey rsa:3072 -nodes \
        -keyout radiance.key.new -out radiance.csr.new \
        -subj "/CN='"$hostname"'" \
        -addext "subjectAltName=DNS:'"$hostname"'" \
        -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
    chmod 600 radiance.key.new
    kinit -f admin < /run/secrets/ipa_admin_password >/dev/null
    serial="$(ipa cert-request --principal=HTTP/'"$hostname"' \
        --profile=caIPAserviceCert --chain radiance.csr.new |
        sed -n "s/.*Serial number: *\([0-9][0-9]*\).*/\1/p" | tail -n1)"
    [ -n "$serial" ] || { echo "no serial in the cert-request output" >&2; exit 3; }
    ipa cert-show "$serial" --out=radiance.crt.new --chain >/dev/null
    [ "$(grep -c "BEGIN CERTIFICATE" radiance.crt.new)" -ge 1 ] || {
        echo "cert-show produced no certificate" >&2; exit 4; }
    new_mod="$(openssl x509 -in radiance.crt.new -noout -modulus | openssl sha256)"
    key_mod="$(openssl rsa -in radiance.key.new -noout -modulus 2>/dev/null | openssl sha256)"
    [ -n "$new_mod" ] && [ "$new_mod" = "$key_mod" ] || {
        echo "new certificate does not match the new key" >&2; exit 5; }
    cp -p radiance.key radiance.key.prev
    cp -p radiance.crt radiance.crt.prev
    mv radiance.key.new radiance.key
    mv radiance.csr.new radiance.csr
    mv radiance.crt.new radiance.crt
    chmod 600 radiance.key radiance.key.prev
    chmod 644 radiance.crt radiance.crt.prev
    kdestroy
    echo "issued serial: $serial"
' || die "certificate request failed; the previous key/cert pair is untouched"

log "recreating the gateway with the new certificate"
if ! recreate_gateway_stack 120; then
    log "gateway did not become healthy; restoring the previous certificate"
    "${COMPOSE[@]}" --profile bootstrap run --rm -T --entrypoint /bin/bash bootstrap -lc '
        cd /data/certs
        [ -f radiance.key.prev ] && mv radiance.key.prev radiance.key
        [ -f radiance.crt.prev ] && mv radiance.crt.prev radiance.crt
        chmod 600 radiance.key; chmod 644 radiance.crt
    ' || true
    recreate_gateway_stack 120 || true
    die "certificate rotation failed; the previous certificate was restored"
fi

if ! command -v openssl >/dev/null 2>&1; then
    log "openssl unavailable; skipping the TLS verification"
else
    if ! openssl s_client -connect 127.0.0.1:8443 -servername "$hostname" \
        -verify_hostname "$hostname" -CAfile run/ipa-data/certs/ca.crt \
        -verify_return_error </dev/null >/dev/null 2>&1; then
        log "TLS verification failed; restoring the previous certificate"
        "${COMPOSE[@]}" --profile bootstrap run --rm -T --entrypoint /bin/bash bootstrap -lc '
            cd /data/certs
            mv radiance.key.prev radiance.key
            mv radiance.crt.prev radiance.crt
            chmod 600 radiance.key; chmod 644 radiance.crt
        ' || true
        recreate_gateway_stack 120 || true
        die "certificate rotation failed; the previous certificate was restored"
    fi
fi

new_serial_hex="$("${COMPOSE[@]}" exec -T radiance-gateway \
    openssl x509 -in /certs/radiance.crt -noout -serial 2>/dev/null |
    tr -d '\r' | cut -d= -f2)"
if [ "$new_serial_hex" = "$old_serial_hex" ]; then
    die "the served certificate serial did not change (still ${old_serial_hex})"
fi
log "new certificate serial: ${new_serial_hex:-unknown}"

if ! verify_gateway_auth; then
    log "authenticated request failed after the certificate change"
    die "certificate is served but authentication failed; inspect the gateway logs"
fi

if [ -n "$old_serial_dec" ]; then
    log "revoking the previous certificate (serial ${old_serial_dec})"
    if ! "${COMPOSE[@]}" --profile bootstrap run --rm -T --entrypoint /bin/bash bootstrap -lc '
        kinit -f admin < /run/secrets/ipa_admin_password >/dev/null
        ipa cert-revoke '"$old_serial_dec"' --revocation-reason=4 >/dev/null
        kdestroy
    '; then
        log "WARNING: could not revoke the previous certificate; revoke serial ${old_serial_dec} manually"
    fi
fi

# The old key is no longer needed; do not leave it on disk.
"${COMPOSE[@]}" --profile bootstrap run --rm -T --entrypoint /bin/bash bootstrap -lc '
    cd /data/certs
    [ -f radiance.key.prev ] && shred -u radiance.key.prev
    rm -f radiance.crt.prev
' || log "WARNING: could not remove the previous key/cert backup"

log "TLS key and certificate rotated"
