#!/usr/bin/env bash
# Entrypoint for the one-off bootstrap container.
# The Python implementation is importable and unit-tested; this wrapper only
# fixes PATH/HOME for the FreeIPA image and execs it.
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="${HOME:-/tmp}"
export KRB5_CONFIG="${KRB5_CONFIG:-/etc/krb5.conf}"
export KRB5CCNAME="${KRB5CCNAME:-FILE:/tmp/krb5cc_bootstrap}"

exec python3 /bootstrap/bootstrap.py "$@"
