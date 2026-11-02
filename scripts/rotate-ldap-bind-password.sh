#!/usr/bin/env bash
# Rotate the LDAP bind password for uid=svc-radiance,cn=sysaccounts,cn=etc.
#
# The gateway renders this password into the vhost at start, so the gateway (and the
# engine that shares its namespace) is recreated afterwards. If the new
# password cannot authenticate through the gateway, the sysaccount password and
# the secret are rolled back.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

require_docker
secret_file="secrets/ldap_bind_password"
require_owned_secret "$secret_file"
old="$(secret_value "$secret_file")"
admin="$(secret_value secrets/ipa_admin_password)"
new="$(openssl rand -hex 24)"
[ -n "$new" ] || die "could not generate a new password"
sysaccount_dn="uid=svc-radiance,cn=sysaccounts,cn=etc,dc=ipa,dc=test"

set_sysaccount_password() {
    printf '%s\n%s\n' "$admin" "$1" | "${COMPOSE[@]}" exec -T ipa \
        env KRB5CCNAME=/tmp/krb5cc_sysaccount_rotate bash -c '
            set -euo pipefail
            read -r admin
            read -r new
            printf "%s\n" "$admin" | kinit -f admin >/dev/null
            printf "%s\n%s\n" "$new" "$new" | ipa sysaccount-mod svc-radiance --password >/dev/null
            kdestroy
        '
}

verify_bind() {
    printf '%s' "$1" | "${COMPOSE[@]}" exec -T -e LDAPTLS_CACERT=/etc/ipa/ca.crt ipa \
        ldapwhoami -x -H ldaps://ipa.ipa.test:636 -D "$sysaccount_dn" \
        -y /dev/stdin 2>/dev/null | grep -qi '^dn: uid=svc-radiance'
}

log "rotating the svc-radiance LDAP bind password"
set_sysaccount_password "$new" || die "could not reset the sysaccount password"

if ! verify_bind "$new"; then
    log "new password did not bind; restoring the old password"
    set_sysaccount_password "$old" || die "CRITICAL: could not restore the sysaccount password"
    die "sysaccount rotation failed; the old password was restored and the secret is unchanged"
fi

# In-place write so the bind-mounted gateway secret changes too.
write_secret_inplace "$secret_file" "$new" 600
log "recreating the gateway with the new bind password"
if ! recreate_gateway_stack 120 || ! verify_gateway_auth; then
    log "gateway verification failed; rolling back the sysaccount password"
    set_sysaccount_password "$old" || die "CRITICAL: rollback password change failed"
    write_secret_inplace "$secret_file" "$old" 600
    recreate_gateway_stack 120 || die "CRITICAL: gateway did not recover after rollback"
    die "LDAP bind password rotation failed and was rolled back"
fi
log "LDAP bind password rotated; the gateway authenticated a pi request"
