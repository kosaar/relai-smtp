#!/usr/bin/env bash
# =============================================================================
#  Entrypoint de la passerelle (milter).
#  En root : copie la clé HMAC (secret gateway_hmac_key, pseudonymisation des
#  identifiants de message) dans un tmpfs lisible par le seul utilisateur
#  gateway, puis lance le milter sous cet utilisateur, sans aucune capacité.
# =============================================================================
set -Eeuo pipefail
die() { printf '%s gateway-entrypoint: FATAL: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }

key=${GATEWAY_HMAC_KEY_FILE:-/run/secrets/gateway_hmac_key}
[[ -r $key ]] || die "clé HMAC manquante : fournir le secret gateway_hmac_key (ou GATEWAY_HMAC_KEY_FILE)."
install -d -o gateway -g gateway -m 0700 /run/gateway
install -o gateway -g gateway -m 0400 "$key" /run/gateway/hmac_key

export GATEWAY_HMAC_KEY_FILE=/run/gateway/hmac_key
exec setpriv --reuid=gateway --regid=gateway --init-groups --inh-caps=-all "$@"
