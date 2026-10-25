# shellcheck shell=bash
# =============================================================================
#  Fonctions communes aux suites de tests (sourcé par tests/run-tests.sh).
#  Variables attendues : COMPOSE (tableau), TOKEN, WORK.
# =============================================================================

if [[ -t 1 ]]; then G=$'\e[32m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G='' R='' B='' N=''; fi
PASS=0 FAIL=0
declare -a RESULTS=()

info()  { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
suite() { echo; info "Suite $*"; }
pass()  { PASS=$((PASS + 1)); RESULTS+=("${G}PASS${N}  $1"); printf '  %sPASS%s  %s\n' "$G" "$N" "$1"; }
fail()  { FAIL=$((FAIL + 1)); RESULTS+=("${R}FAIL${N}  $1"); printf '  %sFAIL%s  %s\n' "$R" "$N" "$1"; [[ -z ${2:-} ]] || printf '        %s\n' "${2:0:600}"; }
note()  { printf '        %s\n' "${1:0:220}"; }

dc()   { "${COMPOSE[@]}" "$@"; }
logs() { dc logs --no-color --no-log-prefix "$1" 2>/dev/null; }
cid()  { dc ps -q "$1"; }

# wait_for <timeout_s> <commande...> : réessaie la commande jusqu'au succès.
wait_for() {
    local t=$1; shift
    local end=$((SECONDS + t))
    until "$@" >/dev/null 2>&1; do
        (( SECONDS < end )) || return 1
        sleep 1
    done
}

# wait_healthy <service> [timeout_s]
wait_healthy() {
    wait_for "${2:-90}" is_healthy "$1"
}
is_healthy() { [[ $(docker inspect -f '{{.State.Health.Status}}' "$(cid "$1")" 2>/dev/null) == healthy ]]; }

# smtp <service client> <options swaks...> : exécute swaks depuis un client.
smtp() { local c=$1; shift; dc exec -T "$c" swaks --timeout 20 "$@" 2>&1; }

# --- Soumission au relai (587) ---------------------------------------------------
# app_password <application> : mot de passe SMTP de test de l'application.
app_password() { cat "$WORK/secrets/apps/$1"; }

# submit <client> <login> <sujet> [options swaks...] : soumission 587 en STARTTLS
# (certificat de smtp-relay vérifié par l'AC de test) + AUTH PLAIN de <login>.
# Par défaut : MAIL FROM et From: = <login>@example.com, destinataire alice.
# Les options suivantes (--from, --to, --server, --h-From…) remplacent ces valeurs.
submit() {
    local c=$1 login=$2 subj=$3; shift 3
    smtp "$c" --server smtp-relay --port 587 \
        --tls --tls-verify --tls-ca-path /pki/ca.crt \
        --auth PLAIN --auth-user "$login" --auth-password "$(app_password "$login")" \
        --from "${login}@example.com" --to alice@example.com \
        --header "Subject: ${subj}" --body "Test ${subj}" "$@"
}

# --- Clés des destinataires ---------------------------------------------------------
# provision_key <adresse> : le poste génère sa paire de clés (RNP), la dépose sur
# l'annuaire en HTTPS, puis l'administrateur la valide (empreinte du poste).
provision_key() {
    local email=$1 fpr out
    fpr=$(dc exec -T workstation keys gen "$email") || return 1
    out=$(dc exec -T workstation bash -c "keys export ${email} | keys deposit ${email}") || return 1
    [[ $out == *HTTP_CODE=202* ]] || { echo "$out" >&2; return 1; }
    dc exec -T keydir keydir-admin approve "$email" "$fpr" >/dev/null
}

# --- BAL du fournisseur, relevées en IMAPS depuis le poste de travail ------------
# Le motif est cherché dans le message brut puis dans sa partie déchiffrée (RNP,
# trousseaux du poste pour cette adresse).
# mb_fetch <bal> <motif> [attente_s] : message brut contenant <motif> (code 1 si absent).
mb_fetch() { dc exec -T workstation mailbox fetch "$1" --match "$2" --wait "${3:-0}"; }
# mb_plain <bal> <motif> [attente_s] : partie déchiffrée du message contenant <motif>.
mb_plain() { dc exec -T workstation mailbox fetch "$1" --match "$2" --wait "${3:-0}" --decrypted; }
mb_has()   { mb_fetch "$1" "$2" "${3:-0}" >/dev/null; }
mb_count() { dc exec -T workstation mailbox count "$1" ${2:+--match "$2"}; }
# Partie en-têtes d'un message brut (stdin), CR retirés.
headers_of() { tr -d '\r' | sed -n '1,/^$/p'; }

# --- Démarrage refusé ------------------------------------------------------------
# start_must_fail <libellé> <motif attendu> <args docker run (avant l'image)...> -- <image>
# Lance un conteneur jetable et vérifie qu'il s'arrête avec un code ≠ 0 et <motif>.
start_must_fail() {
    local label=$1 expect=$2; shift 2
    local args=() image c code=running out
    while [[ $1 != -- ]]; do args+=("$1"); shift; done
    image=$2
    c=$(docker run -d --network none "${args[@]}" "$image")
    for _ in $(seq 1 20); do
        if [[ $(docker inspect -f '{{.State.Running}}' "$c") == false ]]; then
            code=$(docker inspect -f '{{.State.ExitCode}}' "$c"); break
        fi
        sleep 1
    done
    out=$(docker logs "$c" 2>&1)
    docker rm -f "$c" >/dev/null
    if [[ $code != running && $code != 0 ]] && grep -qF -- "$expect" <<<"$out"; then
        pass "${label} : démarrage refusé (exit ${code})"
        note "log: $(grep -m1 FATAL <<<"$out")"
    else
        fail "${label} : le conteneur n'a pas refusé de démarrer (état: ${code})" "$(tail -3 <<<"$out")"
    fi
}
