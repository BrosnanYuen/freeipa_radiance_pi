#!/usr/bin/env bash
# Create the radiance TLS private key and CSR on the host. The bootstrap
# container signs the CSR with the FreeIPA CA and writes radiance.crt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SERVER_NAME="${RADIANCE_HOSTNAME:-radiance.ipa.test}"
CERT_DIR="${CERT_DIR:-run/ipa-data/certs}"
KEY="$CERT_DIR/radiance.key"
CSR="$CERT_DIR/radiance.csr"

umask 077
mkdir -p "$CERT_DIR" 2>/dev/null || true
# The IPA data volume becomes root-owned after the first start; an existing
# key/CSR needs no write, so a failed chmod must not abort a rerun.
chmod 700 "$CERT_DIR" 2>/dev/null || true

if [ ! -s "$KEY" ]; then
    echo "gen-cert: generating $KEY" >&2
    openssl req -new -newkey rsa:3072 -nodes \
        -keyout "$KEY" -out "$CSR" \
        -subj "/CN=$SERVER_NAME" \
        -addext "subjectAltName=DNS:$SERVER_NAME" \
        -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
else
    if [ ! -s "$CSR" ]; then
        echo "gen-cert: regenerating $CSR from existing key" >&2
        openssl req -new -key "$KEY" -out "$CSR" \
            -subj "/CN=$SERVER_NAME" \
            -addext "subjectAltName=DNS:$SERVER_NAME" \
            -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
    fi
fi

# The IPA data volume is root-owned after the realm exists, and a rotated TLS
# key is written by the bootstrap container as root. chmod on a file this user
# does not own fails, even when the mode is already correct; only tighten files
# we own (or when running as root).
if [ -O "$KEY" ] || [ "$(id -u)" = "0" ]; then
    chmod 600 "$KEY"
else
    echo "gen-cert: $KEY is not owned by this user; leaving its mode unchanged" >&2
fi
if [ -O "$CSR" ] || [ "$(id -u)" = "0" ]; then
    chmod 644 "$CSR"
else
    echo "gen-cert: $CSR is not owned by this user; leaving its mode unchanged" >&2
fi
echo "gen-cert: key and CSR ready for $SERVER_NAME" >&2
