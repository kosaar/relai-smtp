#!/usr/bin/env bash
# Recharge la liste blanche SANS redémarrer le conteneur ni perdre de mail.
# Usage : docker compose exec relay relay-reload-allowlist
#
# Relit ALLOWED_CLIENT_IPS_FILE (fichier monté, modifiable à chaud) et la
# variable ALLOWED_CLIENT_IPS du conteneur (figée à sa création : pour la
# changer, utiliser "docker compose up -d", qui recrée le conteneur).
# Si la nouvelle liste est vide ou invalide, l'ancienne reste en vigueur.
set -Eeuo pipefail
# shellcheck source=relay-lib.sh
source /usr/local/lib/relay-lib.sh
die() { log "ERREUR: $*" >&2; log "Liste blanche inchangée." >&2; exit 1; }

build_allowlist
old=$(postconf -h mynetworks)
postconf -e "mynetworks = ${MYNETWORKS}"
postfix reload
log "Liste blanche rechargée."
log "  avant : ${old}"
log "  après : ${MYNETWORKS}"
