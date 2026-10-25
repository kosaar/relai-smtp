#!/usr/bin/env bash
# =============================================================================
#  Fournisseur simulé — TEST UNIQUEMENT.
#   - compte SASL du relai (secrets relay_smtp_username / relay_smtp_password) ;
#   - BAL Dovecot de PROVIDER_MAILBOXES (mot de passe : secret mailbox_password) ;
#   - lance Dovecot et Postfix au premier plan ; le conteneur s'arrête si l'un
#     des deux s'arrête.
#  La PKI (/pki) est générée par le service one-shot « pki » (gen-test-pki).
# =============================================================================
set -Eeuo pipefail

die() { echo "provider: FATAL: $*" >&2; exit 1; }
read_secret() { local f=$1; [[ -r $f ]] || die "secret $f manquant"; local v; v=$(<"$f"); printf '%s' "${v%$'\n'}"; }

MAILBOXES=${PROVIDER_MAILBOXES:-alice@example.com bob@example.com carol@example.com supervision@example.com ext@partner.test}
for f in ca.crt provider.crt provider.key; do [[ -s /pki/$f ]] || die "/pki/$f absent (service pki non exécuté ?)"; done

# --- Compte SASL du relai -------------------------------------------------------
user=$(read_secret "${PROVIDER_SASL_USERNAME_FILE:-/run/secrets/relay_smtp_username}")
pass=$(read_secret "${PROVIDER_SASL_PASSWORD_FILE:-/run/secrets/relay_smtp_password}")
rm -f /etc/sasldb2
printf '%s' "$pass" | saslpasswd2 -p -c -f /etc/sasldb2 -u provider.test "$user"
chown root:postfix /etc/sasldb2
chmod 0640 /etc/sasldb2
echo "provider: compte SASL '${user}' créé (realm provider.test)"

# --- BAL ------------------------------------------------------------------------
mbpass=$(read_secret "${PROVIDER_MAILBOX_PASSWORD_FILE:-/run/secrets/mailbox_password}")
uid=$(id -u vmail) gid=$(id -g vmail)
: >/etc/dovecot/users
: >/etc/postfix/vmailbox
declare -A domains=()
for mb in $MAILBOXES; do
    [[ $mb =~ ^[a-z0-9._-]+@([a-z0-9.-]+)$ ]] || die "adresse de BAL invalide : $mb"
    domains[${BASH_REMATCH[1]}]=1
    printf '%s:{PLAIN}%s:%s:%s::/var/vmail/%s/%s::\n' "$mb" "$mbpass" "$uid" "$gid" \
        "${mb#*@}" "${mb%@*}" >>/etc/dovecot/users
    printf '%s OK\n' "$mb" >>/etc/postfix/vmailbox
done
chown root:dovecot /etc/dovecot/users
chmod 0640 /etc/dovecot/users
postconf -e "virtual_mailbox_domains = ${!domains[*]}"
echo "provider: BAL ${MAILBOXES}"

postfix check
doveconf -n >/dev/null

dovecot -F & dpid=$!
postfix start-fg & ppid=$!
trap 'kill -TERM "$dpid" "$ppid" 2>/dev/null || true' TERM INT
rc=0
wait -n "$dpid" "$ppid" || rc=$?
kill -TERM "$dpid" "$ppid" 2>/dev/null || true
wait || true
exit "$rc"
