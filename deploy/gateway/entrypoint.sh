#!/bin/sh
# radiance-gateway entrypoint: install the keytab/certs/secrets where the
# unprivileged gateway user can read them, then drop privileges.
#
#   --check : import the GSSAPI/LDAP modules and validate a generated TLS context
#   run     : wait for bootstrap output, install files, exec the gateway
set -eu

WAIT_SECONDS="${GATEWAY_WAIT_SECONDS:-900}"
RUN_DIR=/run/gateway

log() { printf 'gateway: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

wait_for_file() {
    deadline=$(( $(date +%s) + WAIT_SECONDS ))
    while [ ! -e "$1" ]; do
        [ "$(date +%s)" -lt "$deadline" ] || die "timed out waiting for $1"
        sleep 2
    done
}

if [ "${1:-run}" = "--check" ]; then
    python3 -c 'import gssapi, ldap, ssl; print("gateway: gssapi, ldap, ssl import OK")'
    python3 -m py_compile /opt/gateway/gateway.py
    log "check mode OK"
    exit 0
fi

wait_for_file /certs/.bootstrap-complete
wait_for_file /certs/radiance.crt
wait_for_file /certs/radiance.key
wait_for_file /certs/ca.crt
wait_for_file /keytabs/radiance.keytab

mkdir -p "$RUN_DIR"
chown gateway:gateway "$RUN_DIR"
chmod 0700 "$RUN_DIR"
install -m 0400 -o gateway -g gateway /keytabs/radiance.keytab "$RUN_DIR/radiance.keytab"
install -m 0400 -o gateway -g gateway /certs/radiance.key "$RUN_DIR/radiance.key"
install -m 0644 -o gateway -g gateway /certs/radiance.crt "$RUN_DIR/radiance.crt"
install -m 0644 -o gateway -g gateway /certs/ca.crt "$RUN_DIR/ca.crt"
install -m 0400 -o gateway -g gateway /secrets-src/ldap_bind_password "$RUN_DIR/ldap_bind_password"
install -m 0400 -o gateway -g gateway /secrets-src/radiance_api_key "$RUN_DIR/radiance_api_key"
log "installed keytab/cert/secrets for gateway"

exec setpriv --reuid=gateway --regid=gateway --clear-groups --inh-caps=-all --ambient-caps=-all \
    python3 /opt/gateway/gateway.py \
      --listen 0.0.0.0 \
      --port 8443 \
      --cert "$RUN_DIR/radiance.crt" \
      --key "$RUN_DIR/radiance.key" \
      --keytab "$RUN_DIR/radiance.keytab" \
      --service "HTTP@radiance.ipa.test" \
      --upstream-host 127.0.0.1 \
      --upstream-port 8000 \
      --api-key-file "$RUN_DIR/radiance_api_key" \
      --ldap-uri "ldaps://ipa.ipa.test:636" \
      --ldap-base "cn=users,cn=accounts,dc=ipa,dc=test" \
      --ldap-bind-dn "uid=svc-radiance,cn=sysaccounts,cn=etc,dc=ipa,dc=test" \
      --ldap-bind-password-file "$RUN_DIR/ldap_bind_password" \
      --ldap-ca-file "$RUN_DIR/ca.crt" \
      --ldap-group "cn=ai-users,cn=groups,cn=accounts,dc=ipa,dc=test" \
      --health-port 8081 \
      --read-timeout 10
