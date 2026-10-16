#!/usr/bin/env bash
# Faux MTA — TEST UNIQUEMENT.
#  - génère (si absente) une AC de test + un certificat serveur "fake-mta" dans
#    /pki (volume partagé : le relai y lit ca.crt pour vérifier le serveur) ;
#  - crée le compte SASL attendu à partir des secrets de test ;
#  - lance Postfix au premier plan.
set -Eeuo pipefail

die() { echo "fake-mta: FATAL: $*" >&2; exit 1; }

read_secret() { local f=$1; [[ -r $f ]] || die "secret $f manquant"; local v; v=$(<"$f"); printf '%s' "${v%$'\n'}"; }

if [[ ! -s /pki/fake-mta.crt ]]; then
    echo "fake-mta: génération de la PKI de test (AC auto-signée + certificat fake-mta)"
    umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -sha256 \
        -subj "/CN=Test CA (smtp-relay tests)" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout /pki/ca.key -out /pki/ca.crt 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=fake-mta" \
        -keyout /pki/fake-mta.key -out /pki/fake-mta.csr 2>/dev/null
    printf 'subjectAltName=DNS:fake-mta\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' >/pki/ext.cnf
    openssl x509 -req -in /pki/fake-mta.csr -CA /pki/ca.crt -CAkey /pki/ca.key -CAcreateserial \
        -days 30 -sha256 -extfile /pki/ext.cnf -out /pki/fake-mta.crt 2>/dev/null
    rm -f /pki/fake-mta.csr /pki/ext.cnf /pki/ca.key /pki/ca.srl
    chmod 0644 /pki/ca.crt /pki/fake-mta.crt
    chmod 0600 /pki/fake-mta.key
fi

user=$(read_secret "${FAKE_MTA_USERNAME_FILE:-/run/secrets/relay_smtp_username}")
pass=$(read_secret "${FAKE_MTA_PASSWORD_FILE:-/run/secrets/relay_smtp_password}")
rm -f /etc/sasldb2
printf '%s' "$pass" | saslpasswd2 -p -c -f /etc/sasldb2 -u provider.test "$user"
chown root:postfix /etc/sasldb2
chmod 0640 /etc/sasldb2
echo "fake-mta: compte SASL '${user}' créé (realm provider.test)"

chown capture:capture /var/mail/captured
postfix check
exec "$@"
