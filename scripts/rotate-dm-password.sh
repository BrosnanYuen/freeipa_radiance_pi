#!/usr/bin/env bash
# Rotate the Directory Manager password.
#
# Directory Manager is only used by the installer, but it remains a
# long-lived realm credential. The change is applied through the local ldapi
# socket with SASL EXTERNAL (the container's root maps to cn=Directory
# Manager), so neither the old nor the new password appears in argv. The new
# password is verified with a fresh LDAPS bind before it is written to secrets/.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

require_docker
secret_file="secrets/ipa_dm_password"
require_owned_secret "$secret_file"
old="$(secret_value "$secret_file")"
new="$(openssl rand -hex 24)"
[ -n "$new" ] || die "could not generate a new password"

instance="$("${COMPOSE[@]}" exec -T ipa dsctl -l 2>/dev/null | head -n1 | tr -d '\r')"
[ -n "$instance" ] || die "could not determine the 389-ds instance name"
uri="ldapi://%2Frun%2F${instance}.socket"

apply_rootpw() {
    # LDIF on stdin: the password is never an argv element.
    printf 'dn: cn=config\nchangetype: modify\nreplace: nsslapd-rootpw\nnsslapd-rootpw: %s\n' "$1" |
        "${COMPOSE[@]}" exec -T -e LDAPTLS_CACERT=/etc/ipa/ca.crt ipa \
            ldapmodify -Y EXTERNAL -H "$uri" >/dev/null
}

verify_bind() {
    # `-y /dev/stdin` avoids argv; the value must not carry a trailing newline.
    printf '%s' "$1" | "${COMPOSE[@]}" exec -T -e LDAPTLS_CACERT=/etc/ipa/ca.crt ipa \
        ldapwhoami -x -H ldaps://ipa.ipa.test:636 \
        -D "cn=Directory Manager" -y /dev/stdin 2>/dev/null |
        grep -qi '^dn: cn=directory manager'
}

log "rotating the Directory Manager password via ${uri}"
apply_rootpw "$new" || die "could not apply the new Directory Manager password"

if ! verify_bind "$new"; then
    log "new password did not bind; restoring the old password"
    apply_rootpw "$old" || die "CRITICAL: could not restore the old Directory Manager password"
    verify_bind "$old" || die "CRITICAL: Directory Manager bind is broken; use ldapi EXTERNAL to reset it"
    die "Directory Manager rotation failed; the old password was restored and the secret is unchanged"
fi

write_secret_inplace "$secret_file" "$new" 600
log "Directory Manager password rotated; the new value is in $secret_file"

if verify_bind "$old"; then
    log "WARNING: the old Directory Manager password still binds; investigate before relying on rotation"
fi
