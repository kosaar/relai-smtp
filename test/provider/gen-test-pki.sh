#!/usr/bin/env bash
# =============================================================================
#  PKI de TEST — génère une AC auto-signée et les certificats serveur de la
#  stack de test dans /pki (volume partagé, monté en lecture seule ailleurs) :
#    ca.crt                      AC de test (seul fichier à faire confiance)
#    provider.{crt,key}          fournisseur simulé (SMTP 587 + IMAPS 993)
#    smtp-relay.{crt,key}        relai (soumission 587 ; aussi relay-badcreds)
#    keydir.{crt,key}            annuaire de clés (HTTPS, lot 2)
#  La clé de l'AC est détruite après usage. Les clés privées sont lisibles par
#  tous : elles sont partagées entre conteneurs d'UID différents (test seulement).
#  Idempotent : ne fait rien si la PKI existe déjà.
# =============================================================================
set -Eeuo pipefail

PKI=${PKI_DIR:-/pki}
DAYS=${PKI_DAYS:-30}

# name -> SAN
declare -A SANS=(
    [provider]="DNS:provider,DNS:smtp.provider.test,DNS:imap.provider.test"
    [smtp-relay]="DNS:smtp-relay,DNS:relay,DNS:relay-badcreds"
    [keydir]="DNS:keydir,DNS:openpgpkey.example.com"
)

complete=1
for name in ca "${!SANS[@]}"; do [[ -s $PKI/$name.crt ]] || complete=0; done
if (( complete )); then
    echo "gen-test-pki: PKI déjà présente dans $PKI"
    exit 0
fi

echo "gen-test-pki: génération de la PKI de test dans $PKI (validité ${DAYS} j)"
umask 022
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

openssl req -x509 -newkey rsa:3072 -nodes -days "$DAYS" -sha256 \
    -subj "/CN=Test CA (smtp-relay tests)" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$tmp/ca.key" -out "$tmp/ca.crt" 2>/dev/null

for name in "${!SANS[@]}"; do
    openssl req -newkey rsa:3072 -nodes -sha256 -subj "/CN=${name}" \
        -keyout "$tmp/$name.key" -out "$tmp/$name.csr" 2>/dev/null
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n' \
        "${SANS[$name]}" >"$tmp/$name.ext"
    openssl x509 -req -in "$tmp/$name.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial \
        -days "$DAYS" -sha256 -extfile "$tmp/$name.ext" -out "$tmp/$name.crt" 2>/dev/null
    install -m 0644 "$tmp/$name.crt" "$tmp/$name.key" "$PKI/"
    echo "gen-test-pki: certificat ${name} (${SANS[$name]})"
done
# L'AC est publiée en dernier : sa présence signale une PKI complète.
install -m 0644 "$tmp/ca.crt" "$PKI/ca.crt"
