#!/usr/bin/env bash
# Host-mode Pi smoke test: Pi runs on the host (pinned npm release via npx),
# talks to a loopback-published shim, and the shim holds the ccache and does
# Negotiate to the gateway.
#
#   ./scripts/host-pi-smoke.sh [--turns N] [--port 18088]
#
# Requires: a running stack with a valid run/ccache/krb5cc (run `pi-krb login`
# first), Docker, npx, and the radiance-krb-pi:local image.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

turns=10
port=18088
while [ $# -gt 0 ]; do
    case "$1" in
    --turns)
        shift
        turns="${1:-}"
        ;;
    --port)
        shift
        port="${1:-}"
        ;;
    -h | --help)
        sed -n '2,12p' "$0"
        exit 0
        ;;
    *)
        die "unknown argument: $1"
        ;;
    esac
    shift
done
case "$turns" in
"" | *[!0-9]*) die "--turns must be a positive integer" ;;
esac
[ "$turns" -ge 1 ] || die "--turns must be at least 1"

command -v npx >/dev/null 2>&1 || die "npx is required for host-mode Pi"
command -v curl >/dev/null 2>&1 || die "curl is required"
require_docker
service_running radiance-gateway || die "radiance-gateway is not running"
docker image inspect radiance-krb-pi:local >/dev/null 2>&1 ||
    die "radiance-krb-pi:local is missing; run ./scripts/up.sh"

ccache="$ROOT/run/ccache/krb5cc"
token="$ROOT/run/pi-agent/shim-token"
ca="$ROOT/run/ipa-data/certs/ca.crt"
[ -s "$ccache" ] || die "missing ccache $ccache; run pi-krb login"
[ -s "$token" ] || die "missing shim token $token; start radiance-shim first"
[ -s "$ca" ] || die "missing IPA CA $ca"
KRB5CCNAME="FILE:$ccache" klist -s 2>/dev/null ||
    die "the ccache has no valid ticket; run pi-krb login"

set -a
# shellcheck disable=SC1090
. "./$ENV_FILE"
set +a
pi_version="${PI_VERSION:-1.4.0}"
model="${RADIANCE_SERVED_NAME:-qwen3.8-27b}"

network="$(
    "${COMPOSE[@]}" ps -q radiance-shim | head -n1 |
        xargs -r docker inspect -f \
            '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}' |
        grep 'krb-net$' | head -n1
)"
[ -n "$network" ] || die "could not find the shim's krb-net; is radiance-shim running?"

name="radiance-host-pi-shim-$$"
tmp="$(mktemp -d)"
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT

log "starting a loopback shim on 127.0.0.1:${port} (network ${network})"
docker run -d --rm --name "$name" \
    --user "$(id -u):$(id -g)" \
    --network "$network" \
    -p "127.0.0.1:${port}:8088" \
    --read-only --tmpfs /tmp \
    --cap-drop ALL --security-opt no-new-privileges:true \
    -v "$ccache:/creds/krb5cc:ro" \
    -v "$ROOT/run/pi-agent:/agent" \
    -v "$ROOT/run/krb5.conf:/etc/krb5.conf:ro" \
    -v "$ca:/certs/ca.crt:ro" \
    -e KRB5CCNAME=FILE:/creds/krb5cc \
    -e KRB5_CONFIG=/etc/krb5.conf \
    --entrypoint radiance-krb-shim radiance-krb-pi:local \
    --listen 0.0.0.0:8088 \
    --edge https://radiance.ipa.test:8443 \
    --service HTTP/radiance.ipa.test \
    --ca /certs/ca.crt \
    --token-file /agent/shim-token >/dev/null

for ((i = 0; i < 60; i++)); do
    if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null ||
    die "host shim did not become healthy"

python3 - "$tmp" "$port" "$token" <<'PY'
import json
import sys
from pathlib import Path

out, port, token = sys.argv[1], sys.argv[2], sys.argv[3]
models = {
    "providers": {
        "radiance-krb": {
            "name": "radiance (Kerberos)",
            "baseUrl": f"http://127.0.0.1:{port}/v1",
            "api": "openai-completions",
            "apiKey": f"!cat {token}",
            "authHeader": True,
            "models": [
                {
                    "id": "qwen3.8-27b",
                    "name": "Qwen3.8 27B (radiance)",
                    "reasoning": False,
                    "input": ["text"],
                    "contextWindow": 8192,
                    "maxTokens": 1024,
                    "cost": {
                        "input": 0,
                        "output": 0,
                        "cacheRead": 0,
                        "cacheWrite": 0,
                    },
                }
            ],
        }
    }
}
Path(out, "models.json").write_text(json.dumps(models, indent=2), encoding="utf-8")
PY

log "running ${turns} host-mode turn(s) with Pi ${pi_version} (model ${model})"
for ((turn = 1; turn <= turns; turn++)); do
    args=(--print "host-mode turn ${turn}: reply with one short sentence.")
    if [ "$turn" -gt 1 ]; then
        args+=(--continue)
    fi
    PI_CODING_AGENT_DIR="$tmp" \
        npx -y "@earendil-works/pi-coding-agent@${pi_version}" \
        "${args[@]}" \
        --model "radiance-krb/${model}" >/dev/null ||
        die "Pi failed on turn ${turn}"
    log "turn ${turn}/${turns} ok"
done

log "host-mode Pi completed ${turns} turn(s) through the loopback shim"
