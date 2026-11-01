#!/usr/bin/env bash
# radiance edge entrypoint.
#
#   --check : render the vhost with throwaway secrets/cert and run apachectl -t
#   run     : wait for bootstrap output, install the keytab for www-data, render
#             the vhost, validate it, and exec Apache in the foreground.
set -euo pipefail

APACHE_CONF="/run/apache2/radiance.conf"
RENDER="/opt/edge/render.py"
TEMPLATE="/opt/edge/vhost.conf.tmpl"
WAIT_SECONDS="${EDGE_WAIT_SECONDS:-900}"

log() { printf 'edge: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

wait_for_file() {
    local path="$1" deadline=$((SECONDS + WAIT_SECONDS))
    while [ ! -e "$path" ]; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            die "timed out after ${WAIT_SECONDS}s waiting for $path"
        fi
        sleep 2
    done
}

mkdir -p "$APACHE_RUN_DIR" /run/radiance /var/lock/apache2
chmod 0755 /var/lock/apache2
# Send Apache's early/global error log to the container's stderr.
ln -sf /proc/self/fd/2 "$APACHE_RUN_DIR/error.log"

install_keytab() {
    local source="$1"
    [ -s "$source" ] || die "keytab $source is missing or empty"
    # Remove a previous copy first: without CAP_FOWNER, `install` cannot chmod
    # an existing file owned by www-data. (The container also gets FOWNER.)
    rm -f /run/radiance/radiance.keytab
    install -m 0400 -o www-data -g www-data "$source" /run/radiance/radiance.keytab
    log "installed keytab 0400 www-data"
}

render() {
    local ldap_file="$1" api_file="$2"
    "$RENDER" \
        --template "$TEMPLATE" \
        --out "$APACHE_CONF" \
        --ldap-password-file "$ldap_file" \
        --api-key-file "$api_file"
    chmod 0600 "$APACHE_CONF"
}

if [ "${1:-run}" = "--check" ]; then
    log "check mode: rendering a throwaway configuration"
    mkdir -p /certs /keytabs
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj "/CN=radiance.ipa.test" \
        -keyout /certs/radiance.key -out /certs/radiance.crt >/dev/null 2>&1
    cp /certs/radiance.crt /certs/ca.crt
    # Non-empty so the readiness check is exercised; not parsed by
    # mod_auth_gssapi during `apachectl -t`.
    printf 'check-mode-keytab\n' > /keytabs/radiance.keytab
    install_keytab /keytabs/radiance.keytab
    install -m 0644 -o root -g root /certs/ca.crt /run/radiance/ca.crt
    printf '%s\n' "0123456789abcdef0123456789abcdef" > /run/apache2/check-ldap
    printf '%s\n' "fedcba9876543210fedcba9876543210" > /run/apache2/check-api
    render /run/apache2/check-ldap /run/apache2/check-api
    apache2 -t
    log "check mode OK"
    exit 0
fi

wait_for_file /certs/.bootstrap-complete
wait_for_file /certs/radiance.crt
wait_for_file /certs/radiance.key
wait_for_file /certs/ca.crt
wait_for_file /keytabs/radiance.keytab

install_keytab /keytabs/radiance.keytab
# mod_ldap runs as www-data and must read the CA per request; /certs itself is
# 0700 root, so expose a readable copy on the tmpfs run directory.
install -m 0644 -o root -g root /certs/ca.crt /run/radiance/ca.crt
render /secrets-src/ldap_bind_password /secrets-src/radiance_api_key

apache2 -t
log "starting Apache"
exec apache2 -D FOREGROUND
