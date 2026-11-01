#!/usr/bin/env bash
# Bring up the radiance-krb stack.
#
#   ./scripts/up.sh          IPA + edge + mock radiance + shim  (no GPU needed)
#   ./scripts/up.sh --gpu    IPA + edge + real radiance  + shim
#
# Idempotent: secrets, the key/CSR and the runtime directories are created only
# when missing; the realm is installed by the FreeIPA image on first start.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="mock"
while [ $# -gt 0 ]; do
    case "$1" in
        --gpu) MODE="gpu" ;;
        --mock) MODE="mock" ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "up.sh: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

log() { printf 'up: %s\n' "$*" >&2; }
die() { printf 'up: ERROR: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v openssl >/dev/null || die "openssl is required"
command -v python3 >/dev/null || die "python3 is required"

if [ ! -f .env ]; then
    cp .env.example .env
    log "created .env from .env.example — review UIDs/GIDs and RADIANCE_MODELS"
fi
set -a
# shellcheck disable=SC1091
. ./.env
set +a

: "${FREEIPA_IMAGE:?set FREEIPA_IMAGE in .env}"
: "${RADIANCE_IMAGE:?set RADIANCE_IMAGE in .env}"
: "${RADIANCE_SECCOMP:?set RADIANCE_SECCOMP in .env}"
: "${PI_UID:?set PI_UID in .env}"
: "${PI_GID:?set PI_GID in .env}"
: "${RADIANCE_UID:?set RADIANCE_UID in .env}"
: "${RADIANCE_GID:?set RADIANCE_GID in .env}"

# Resolve the seccomp profile to an absolute path: Docker resolves it on the host.
RADIANCE_SECCOMP="$(realpath -m "$RADIANCE_SECCOMP")"
export RADIANCE_SECCOMP
[ -f "$RADIANCE_SECCOMP" ] || die "seccomp profile not found: $RADIANCE_SECCOMP"

COMPOSE=(docker compose --env-file .env)

umask 077
mkdir -p secrets run/ccache run/pi-agent run/ipa-data/certs run/ipa-data/keytabs \
    run/ipa-client work
chmod 700 secrets run work
chmod 700 run/ccache run/pi-agent run/ipa-client
# After the first IPA start, root owns these inside the container.
chmod 700 run/ipa-data/certs run/ipa-data/keytabs 2>/dev/null || true

gen_secret() {
    local file="$1" bytes="$2"
    if [ ! -s "$file" ]; then
        openssl rand -hex "$bytes" > "$file"
        log "generated $file"
    fi
    chmod 600 "$file"
}

gen_secret secrets/ipa_admin_password 24
gen_secret secrets/ipa_dm_password 24
gen_secret secrets/pi_password 16
gen_secret secrets/mallory_password 16
gen_secret secrets/ldap_bind_password 24
gen_secret secrets/radiance_api_key 32

# The engine runs as RADIANCE_UID and must read only this key: 0400.
if [ "$(id -u)" = "0" ] || [ "$(id -u)" = "$RADIANCE_UID" ]; then
    chown "$RADIANCE_UID:$RADIANCE_GID" secrets/radiance_api_key 2>/dev/null || \
        log "warning: could not chown radiance_api_key to ${RADIANCE_UID}:${RADIANCE_GID}"
else
    log "warning: run up.sh as root or as UID ${RADIANCE_UID} so the engine can read the API key"
fi
chmod 400 secrets/radiance_api_key

# The Pi containers run as PI_UID; only their state dirs need that ownership.
if [ "$(id -u)" = "0" ]; then
    chown -R "$PI_UID:$PI_GID" run/ccache run/pi-agent work
elif [ "$(id -u)" = "$PI_UID" ]; then
    :
else
    log "warning: run/ccache, run/pi-agent and work/ are not owned by ${PI_UID}:${PI_GID}"
fi

python3 scripts/render_krb5_conf.py \
    --realm "${REALM:-IPA.TEST}" \
    --kdc "${KDC_HOST:-ipa.ipa.test}" \
    --domain "${IPA_DOMAIN:-ipa.test}" \
    --out run/krb5.conf \
    || die "could not render run/krb5.conf"

# The options file is only needed by the first install. After that the realm's
# CA exists and the root-owned data volume must not be written from the host.
if [ ! -s run/ipa-data/ipa-server-install-options ] && \
   [ ! -f run/ipa-data/etc/ipa/ca.crt ]; then
    python3 scripts/render_install_options.py \
        --template deploy/ipa/install-options.tmpl \
        --out run/ipa-data/ipa-server-install-options \
        --secret-dir secrets \
        --realm "${REALM:-IPA.TEST}" \
        --domain "${IPA_DOMAIN:-ipa.test}" \
        || die "could not render install options"
fi

./scripts/gen-cert.sh || die "could not generate the TLS key/CSR"

wait_healthy() {
    local service="$1" timeout="${2:-900}" elapsed=0 id status
    while :; do
        id="$("${COMPOSE[@]}" ps -q "$service" 2>/dev/null | head -n1)" || true
        [ -n "$id" ] || die "service $service is not running"
        status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || true)"
        case "$status" in
            healthy) return 0 ;;
            exited|dead)
                "${COMPOSE[@]}" logs --tail=40 "$service" >&2 || true
                die "service $service entered state $status"
                ;;
        esac
        if [ "$elapsed" -ge "$timeout" ]; then
            "${COMPOSE[@]}" logs --tail=60 "$service" >&2 || true
            die "timed out after ${timeout}s waiting for $service (state: ${status:-unknown})"
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done
}

log "starting FreeIPA (first install can take 10-15 minutes)"
"${COMPOSE[@]}" up -d ipa
wait_healthy ipa 1800

log "staging the IPA client CA and default.conf for the bootstrap container"
./scripts/copy-ipa-client-config.sh || die "could not stage the IPA client configuration"

if [ -s run/ipa-data/ipa-server-install-options ]; then
    # The image has already consumed it; it contains both installer passwords.
    # The data volume is root-owned inside the container, so shred there.
    IPA_ID="$("${COMPOSE[@]}" ps -q ipa | head -n1)"
    docker exec "$IPA_ID" shred -u /data/ipa-server-install-options 2>/dev/null || \
        docker exec "$IPA_ID" rm -f /data/ipa-server-install-options 2>/dev/null || \
        log "warning: could not remove the installer options file"
    log "shredded the installer options file"
fi

log "running the one-off IPA bootstrap"
"${COMPOSE[@]}" --profile bootstrap run --rm -T bootstrap

log "starting the Kerberos edge"
"${COMPOSE[@]}" up -d radiance-edge
wait_healthy radiance-edge 900

if [ "$MODE" = "gpu" ]; then
    log "starting radiance (GPU); this can take a while to load the model"
    "${COMPOSE[@]}" --profile gpu up -d radiance
    wait_healthy radiance 1800
else
    log "starting mock-radiance (no GPU)"
    "${COMPOSE[@]}" --profile test-fast up -d mock-radiance
    wait_healthy mock-radiance 120
fi

log "starting the credential agent and the Pi client containers"
"${COMPOSE[@]}" --profile client up -d radiance-shim pi-login pi-client
wait_healthy radiance-shim 120

cat >&2 <<'EOF'

Stack is up. Next:

  docker compose --profile client run --rm pi-login pi-krb login
  docker compose --profile client run --rm pi-login pi-krb status
  docker compose --profile client run --rm pi-client pi-krb run --model radiance-krb/qwen3.8-27b

For a host-run Pi, see docs/RUNBOOK.md (the container path is the tested one).
EOF
