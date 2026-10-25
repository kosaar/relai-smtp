#!/usr/bin/env bash
# =============================================================================
#  Entrypoint de l'annuaire de clés (keydir).
#  En root : copie le certificat et la clé TLS (secrets) dans un tmpfs lisible
#  par le seul utilisateur keydir, prépare le volume de données, puis lance le
#  serveur sous l'utilisateur non privilégié keydir, sans aucune capacité.
# =============================================================================
set -Eeuo pipefail
die() { printf '%s keydir-entrypoint: FATAL: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }

secret_path() {  # secret_path <VAR> <défaut> : <VAR>_FILE > /run/secrets/<nom>
    local file_var="${1}_FILE"
    local file=${!file_var:-$2}
    [[ -r $file ]] || die "${1} manquant : fournir le secret ${2} (ou ${file_var})."
    printf '%s' "$file"
}

cert=$(secret_path KEYDIR_TLS_CERT /run/secrets/keydir_tls_cert)
key=$(secret_path KEYDIR_TLS_KEY /run/secrets/keydir_tls_key)
install -d -o keydir -g keydir -m 0700 /run/keydir/tls
install -o keydir -g keydir -m 0600 "$cert" /run/keydir/tls/cert.pem
install -o keydir -g keydir -m 0600 "$key" /run/keydir/tls/key.pem
install -d -o keydir -g keydir -m 0700 /var/lib/keydir /tmp/keydir
chown -R keydir:keydir /var/lib/keydir

export KEYDIR_TLS_CERT=/run/keydir/tls/cert.pem KEYDIR_TLS_KEY=/run/keydir/tls/key.pem KEYDIR_TMP=/tmp/keydir
exec setpriv --reuid=keydir --regid=keydir --init-groups --inh-caps=-all "$@"
