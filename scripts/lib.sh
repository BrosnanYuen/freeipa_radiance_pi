#!/usr/bin/env bash
# Shared helpers for the host-side rotation and smoke scripts.
# Source it; do not execute it directly:  . "$(dirname "$0")/lib.sh"
#
# Secrets are never passed on a command line. Password material travels on
# stdin or through a file descriptor only, and secrets are rewritten in place so
# that a bind-mounted file (gateway) sees the new value after a restart.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

ENV_FILE="${ENV_FILE:-.env}"
if [ ! -f "$ENV_FILE" ]; then
    ENV_FILE=".env.example"
fi
COMPOSE=(docker compose --env-file "$ENV_FILE")

log() { printf '%s: %s\n' "$(basename "$0")" "$*" >&2; }
die() {
    log "ERROR: $*"
    exit 1
}

require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker is required"
    docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
}

secret_value() {
    local path="$1"
    [ -s "$path" ] || die "missing or empty secret: $path"
    # Command substitution strips the trailing newline. Keep it that way:
    # `ldapwhoami -y` does not strip a newline from a password file.
    local value
    value="$(cat "$path")"
    [ -n "$value" ] || die "empty secret: $path"
    printf '%s' "$value"
}

require_owned_secret() {
    local path="$1"
    [ -f "$path" ] || die "missing secret: $path"
    if [ ! -O "$path" ] && [ "$(id -u)" != "0" ]; then
        die "cannot update $path: owned by UID $(stat -c %u "$path"), running as UID $(id -u)"
    fi
}

write_secret_inplace() {
    local path="$1" value="$2" mode="$3" uid gid
    [ -f "$path" ] || die "missing secret: $path"
    [ -n "$value" ] || die "refusing to write an empty secret to $path"
    uid="$(stat -c %u "$path")"
    gid="$(stat -c %g "$path")"
    # Atomic rename would leave a bind-mounted consumer on the old inode.
    chmod u+w "$path" 2>/dev/null || die "cannot make $path writable"
    if ! printf '%s\n' "$value" >"$path"; then
        chmod "$mode" "$path" 2>/dev/null || true
        die "could not write $path"
    fi
    chmod "$mode" "$path"
    if [ "$(id -u)" = "0" ]; then
        chown "$uid:$gid" "$path" || die "could not restore ownership on $path"
    fi
}

service_running() {
    "${COMPOSE[@]}" ps --services --filter status=running 2>/dev/null | grep -qx "$1"
}

wait_for_gateway_health() {
    local timeout="${1:-90}" i
    for ((i = 0; i < timeout; i++)); do
        if "${COMPOSE[@]}" exec -T radiance-gateway \
            curl -fsS http://127.0.0.1:8081/healthz >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Recreate the gateway and whichever engine shares its network namespace. A
# restart alone is not enough: the sidecar's namespace belongs to the old
# container.
recreate_gateway_stack() {
    local timeout="${1:-90}"
    "${COMPOSE[@]}" up -d --force-recreate --no-deps radiance-gateway \
        || die "could not recreate radiance-gateway"
    if service_running mock-radiance; then
        "${COMPOSE[@]}" up -d --force-recreate --no-deps mock-radiance \
            || die "could not recreate mock-radiance"
    elif service_running radiance; then
        "${COMPOSE[@]}" up -d --force-recreate --no-deps radiance \
            || die "could not recreate radiance"
    fi
    if ! wait_for_gateway_health "$timeout"; then
        "${COMPOSE[@]}" logs --tail=50 radiance-gateway >&2 || true
        die "gateway did not become healthy within ${timeout}s"
    fi
}

wait_for_engine() {
    local timeout="${1:-120}" i
    for ((i = 0; i < timeout; i++)); do
        if "${COMPOSE[@]}" exec -T radiance-gateway \
            curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Optional end-to-end check with the test user. Skips (with a warning) when the
# host lacks kinit/curl or the realm cannot be reached; the container path is
# optional for the rotation scripts.
verify_gateway_auth() {
    local tmp cc code
    if ! command -v kinit >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
        log "kinit/curl unavailable; skipping authenticated check"
        return 0
    fi
    [ -s run/krb5.conf ] && [ -s run/ipa-data/certs/ca.crt ] || {
        log "run/krb5.conf or the CA is missing; skipping authenticated check"
        return 0
    }
    local bind_addr
    bind_addr="$(sed -n "s/^BIND_ADDR=//p" "$ENV_FILE" 2>/dev/null | tail -n1)"
    case "$bind_addr" in
        ""|0.0.0.0) bind_addr=127.0.0.1 ;;
    esac
    tmp="$(mktemp -d)"
    sed 's/ipa\.ipa\.test/127.0.0.1/g' run/krb5.conf >"$tmp/krb5.conf"
    cc="$tmp/cc"
    if ! secret_value secrets/pi_password | \
        KRB5_CONFIG="$tmp/krb5.conf" KRB5CCNAME="FILE:$cc" kinit -F pi >/dev/null 2>&1; then
        log "kinit pi failed; skipping authenticated check"
        rm -rf "$tmp"
        return 0
    fi
    code="$(KRB5_CONFIG="$tmp/krb5.conf" KRB5CCNAME="FILE:$cc" \
        curl -sS -o /dev/null -w '%{http_code}' --negotiate -u : \
        --cacert run/ipa-data/certs/ca.crt \
        --resolve "radiance.ipa.test:8443:${bind_addr}" \
        https://radiance.ipa.test:8443/v1/models 2>/dev/null)"
    rm -rf "$tmp"
    if [ "$code" != "200" ]; then
        log "authenticated /v1/models returned ${code:-no response}"
        return 1
    fi
    return 0
}
