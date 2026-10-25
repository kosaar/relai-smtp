#!/usr/bin/env bash
# =============================================================================
#  Tests d'intégration et de bout en bout du relai SMTP.
#  Stack : docker-compose.yml + docker-compose.test.yml (vrais logiciels, sans mock).
#
#  Usage : tests/run-tests.sh                 # construit, teste, nettoie
#          SUITES="00 01" tests/run-tests.sh  # sélection de suites (préfixes)
#          KEEP=1 tests/run-tests.sh          # conserve la stack pour inspection
#          SKIP_BUILD=1 tests/run-tests.sh    # images déjà construites (CI)
#  Code de sortie : 0 si tous les tests sont PASS, 1 sinon.
#
#  Les suites (tests/suites/NN-*.sh) sont sourcées dans l'ordre, sur une seule
#  stack ; chacune la laisse dans un état sain pour la suivante.
# =============================================================================
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
WORK=tests/.work
PROJECT=smtp-relay-test
COMPOSE=(docker compose -p "$PROJECT" --env-file tests/test.env -f docker-compose.yml -f docker-compose.test.yml)
TOKEN=$(date +%s)-$RANDOM
export WORK PROJECT TOKEN

# shellcheck source=tests/lib.sh
. tests/lib.sh

# --- Sélection des suites --------------------------------------------------------
declare -a SUITE_FILES=()
for f in tests/suites/[0-9][0-9]-*.sh; do
    n=$(basename "$f"); n=${n%%-*}
    if [[ -z ${SUITES:-} || " ${SUITES} " == *" ${n} "* ]]; then SUITE_FILES+=("$f"); fi
done
(( ${#SUITE_FILES[@]} )) || { echo "Aucune suite ne correspond à SUITES='${SUITES:-}'" >&2; exit 2; }

cleanup() {
    local rc=$?
    if (( rc != 0 )); then   # journaux de tous les conteneurs, pour diagnostic (artefact CI)
        mkdir -p tests/.logs
        for svc in $(dc ps -a --services 2>/dev/null); do
            dc logs --no-color --timestamps "$svc" >"tests/.logs/${svc}.log" 2>&1 || true
        done
        info "Journaux des conteneurs dans tests/.logs/"
    fi
    if [[ ${KEEP:-0} == 1 ]]; then
        info "KEEP=1 : stack conservée. Nettoyage : ${COMPOSE[*]} down -v"
    else
        info "Nettoyage (docker compose down -v)"
        dc down -v --remove-orphans >/dev/null 2>&1 || true
        rm -rf "$WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT

# --- Préparation : secrets de test générés à la volée ----------------------------
info "Génération des secrets de test dans ${WORK}/secrets"
rm -rf "$WORK" tests/.logs
mkdir -p "$WORK/secrets"
chmod 700 "$WORK"
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
printf 'relay-test' >"$WORK/secrets/relay_smtp_username"
printf '%s' "$(rand 24)" >"$WORK/secrets/relay_smtp_password"
printf '%s' "wrong-$(rand 16)" >"$WORK/secrets/relay_smtp_password_bad"
printf '%s' "$(rand 24)" >"$WORK/secrets/mailbox_password"
printf '%s' "$(rand 48)" >"$WORK/secrets/gateway_hmac_key"
# Inventaire de test (modifiable par les suites) et un secret par application.
mkdir -p "$WORK/config" "$WORK/secrets/apps"
cp tests/fixtures/applications.toml "$WORK/config/applications.toml"
while read -r app; do
    printf '%s' "$(rand 24)" >"$WORK/secrets/apps/$app"
done < <(sed -n 's/^\[applications\.\([a-z0-9-]*\)\]$/\1/p' tests/fixtures/applications.toml)
# Lisibles par le démon Docker (bind mounts) et par la passerelle (non root).
find "$WORK/config" "$WORK/secrets" -type d -exec chmod 755 {} +
find "$WORK/config" "$WORK/secrets" -type f -exec chmod 644 {} +

if [[ ${SKIP_BUILD:-0} == 1 ]]; then
    info "SKIP_BUILD=1 : utilisation des images déjà présentes"
else
    info "Construction des images (base Ubuntu)"
    # Nouvelles tentatives : le registre peut limiter le débit (HTTP 429).
    for attempt in 1 2 3; do
        dc build --quiet && break
        (( attempt < 3 )) || exit 1
        info "Échec de la construction, nouvelle tentative dans $((attempt * 20)) s"
        sleep $((attempt * 20))
    done
fi
dc down -v --remove-orphans >/dev/null 2>&1 || true

info "Démarrage de la stack de test"
if ! dc up -d --wait --wait-timeout 180; then
    dc ps -a || true
    dc logs --no-color --tail 50 || true
    echo "La stack de test n'a pas démarré." >&2
    exit 1
fi

# Destinataires des tests : chacun a une clé validée sur l'annuaire (sans clé,
# la passerelle refuse le destinataire). carol@example.com n'en a volontairement pas.
info "Clés des destinataires : alice@example.com, bob@example.com, ext@partner.test"
for email in alice@example.com bob@example.com ext@partner.test; do
    provision_key "$email" || { echo "Impossible de publier la clé de ${email}." >&2; exit 1; }
done

for f in "${SUITE_FILES[@]}"; do
    # shellcheck source=/dev/null
    . "$f"
done

# --- Bilan -----------------------------------------------------------------------
echo
info "Bilan : ${PASS} PASS, ${FAIL} FAIL"
printf '  %s\n' "${RESULTS[@]}"
(( FAIL == 0 ))
