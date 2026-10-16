#!/usr/bin/env bash
# =============================================================================
#  Tests d'intégration du relai SMTP (stack docker-compose.yml + .test.yml).
#  Usage : tests/run-tests.sh            # construit, teste, nettoie
#          KEEP=1 tests/run-tests.sh     # conserve la stack pour inspection
#          SKIP_BUILD=1 tests/run-tests.sh # images déjà construites (CI)
#  Code de sortie : 0 si tous les tests sont PASS, 1 sinon.
# =============================================================================
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
WORK=tests/.work
PROJECT=smtp-relay-test
COMPOSE=(docker compose -p "$PROJECT" --env-file tests/test.env -f docker-compose.yml -f docker-compose.test.yml)
RELAY_IP=10.0.1.5
BADCREDS_IP=10.0.1.6
TOKEN=$(date +%s)-$RANDOM
SENDER=noreply@example.com

if [[ -t 1 ]]; then G=$'\e[32m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G= R= B= N=; fi
PASS=0 FAIL=0
declare -a RESULTS=()

info() { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
pass() { PASS=$((PASS + 1)); RESULTS+=("${G}PASS${N}  $1"); printf '  %sPASS%s  %s\n' "$G" "$N" "$1"; }
fail() { FAIL=$((FAIL + 1)); RESULTS+=("${R}FAIL${N}  $1"); printf '  %sFAIL%s  %s\n' "$R" "$N" "$1"; [[ -z ${2:-} ]] || printf '        %s\n' "$2"; }

dc() { "${COMPOSE[@]}" "$@"; }
logs() { dc logs --no-color --no-log-prefix "$1" 2>/dev/null; }

# wait_for <timeout_s> <commande...> : réessaie la commande jusqu'au succès.
wait_for() {
    local t=$1; shift
    local end=$((SECONDS + t))
    until "$@" >/dev/null 2>&1; do
        (( SECONDS < end )) || return 1
        sleep 1
    done
}

cleanup() {
    local rc=$?
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
rm -rf "$WORK"
mkdir -p "$WORK/secrets"
chmod 700 "$WORK"
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
printf 'relay-test' >"$WORK/secrets/relay_smtp_username"
printf '%s' "$(rand 24)" >"$WORK/secrets/relay_smtp_password"
printf '%s' "wrong-$(rand 16)" >"$WORK/secrets/relay_smtp_password_bad"
chmod 644 "$WORK"/secrets/*   # lisibles par le démon Docker (bind mount)

if [[ ${SKIP_BUILD:-0} == 1 ]]; then
    info "SKIP_BUILD=1 : utilisation des images déjà présentes"
else
    info "Construction des images (base Debian)"
    dc build --quiet
fi
dc down -v --remove-orphans >/dev/null 2>&1 || true

info "Démarrage de la stack de test"
if ! dc up -d --wait --wait-timeout 120; then
    dc ps -a || true
    dc logs --no-color --tail 50 || true
    echo "La stack de test n'a pas démarré." >&2
    exit 1
fi

# send <service client> <serveur> <sujet> [options swaks...]
send() {
    local client=$1 server=$2 subject=$3; shift 3
    dc exec -T "$client" swaks --server "$server" --port 25 --timeout 20 \
        --header "Subject: ${subject}" --body "Test ${subject}" "$@" 2>&1
}
captured_file() {  # nom du fichier capturé par le faux MTA contenant <motif>
    dc exec -T fake-mta sh -c "grep -l -F -- \"\$1\" /var/mail/captured/*.eml 2>/dev/null | head -1" _ "$1"
}
has_capture() { [[ -n $(captured_file "$1") ]]; }

echo
info "Exécution des tests"

# --- T1 / T2 : IP déclarées -> mail reçu par le faux MTA -------------------------
for app in gitlab jenkins; do
    subj="t-${app}-${TOKEN}"
    out=$(send "client-${app}" "$RELAY_IP" "$subj" \
        --helo "${app}.ci.internal" --from "${app}@ci.internal" \
        --h-From "\"$(tr '[:lower:]' '[:upper:]' <<<"${app:0:1}")${app:1}\" <${app}@ci.internal>" \
        --to "dev-team@customer.test") && rc=0 || rc=$?
    if (( rc == 0 )) && wait_for 30 has_capture "Subject: ${subj}"; then
        pass "T1/T2 [$app] IP déclarée : mail accepté par le relai et reçu par le MTA fournisseur"
    else
        fail "T1/T2 [$app] IP déclarée : mail non reçu (swaks rc=$rc)" "$(tail -3 <<<"$out")"
    fi
done

# --- T3 : IP non déclarée -> rejet + trace dans les logs -------------------------
subj="t-unknown-${TOKEN}"
out=$(send client-unknown "$RELAY_IP" "$subj" --helo unknown.ci.internal \
    --from "app@unknown.internal" --to "dev-team@customer.test") && rc=0 || rc=$?
if (( rc != 0 )) && grep -q '554 5.7.1' <<<"$out"; then
    pass "T3a IP non déclarée (10.0.1.30) : envoi refusé par le relai (554 5.7.1)"
else
    fail "T3a IP non déclarée : l'envoi n'a pas été refusé (swaks rc=$rc)" "$(tail -3 <<<"$out")"
fi
relay_rejected() { logs relay | grep -qE 'NOQUEUE: reject: RCPT from [^ ]*\[10\.0\.1\.30\].*Client host rejected: Access denied'; }
if wait_for 10 relay_rejected; then
    line=$(logs relay | grep -E 'NOQUEUE: reject: RCPT from [^ ]*\[10\.0\.1\.30\]' | tail -1)
    pass "T3b rejet tracé dans les logs (IP source + motif)"
    printf '        log: %s\n' "${line:0:220}"
else
    fail "T3b rejet absent des logs du relai"
fi
sleep 3
if has_capture "Subject: ${subj}"; then
    fail "T3c le mail de l'IP non déclarée a été délivré !"
else
    pass "T3c aucun mail de l'IP non déclarée n'a atteint le MTA fournisseur"
fi

# --- T4 : expéditeur réécrit -----------------------------------------------------
f=$(captured_file "Subject: t-gitlab-${TOKEN}")
if [[ -n $f ]]; then
    msg=$(dc exec -T fake-mta cat "$f")
    hdr=$(sed -n '1,/^\r\{0,1\}$/p' <<<"$msg")
    rp=$(grep -i -m1 '^Return-Path:' <<<"$hdr" | tr -d '\r')
    from=$(grep -i -m1 '^From:' <<<"$hdr" | tr -d '\r')
    if [[ $rp == "Return-Path: <${SENDER}>" ]]; then
        pass "T4a enveloppe (MAIL FROM) réécrite : ${rp}"
    else
        fail "T4a enveloppe non réécrite" "$rp"
    fi
    if [[ $from == *"<${SENDER}>"* && $from != *ci.internal* ]]; then
        pass "T4b en-tête From réécrit (nom affiché conservé) : ${from}"
    else
        fail "T4b en-tête From non réécrit" "$from"
    fi
else
    fail "T4 message GitLab introuvable : impossible de vérifier l'expéditeur"
fi

# --- T5 : relai -> MTA chiffré (TLS vérifié) et authentifié (SASL) ----------------
rlogs=$(logs relay)
tls=$(grep -E 'Verified TLS connection established to fake-mta\[10\.0\.2\.10\]:587: TLSv1\.[23]' <<<"$rlogs" | tail -1 || true)
if [[ -n $tls ]]; then
    pass "T5a TLS >= 1.2 avec certificat vérifié (relai)"
    printf '        log: %s\n' "${tls:0:220}"
else
    fail "T5a pas de connexion TLS vérifiée dans les logs du relai"
fi
sent=$(grep -E 'relay=fake-mta\[10\.0\.2\.10\]:587, .*status=sent' <<<"$rlogs" | tail -1 || true)
[[ -n $sent ]] && pass "T5b livraison confirmée par le relai (status=sent)" \
               || fail "T5b aucune ligne status=sent vers fake-mta"
auth=$(logs fake-mta | grep -E 'client=[^ ]*\[10\.0\.2\.5\], sasl_method=(PLAIN|LOGIN), sasl_username=relay-test' | tail -1 || true)
if [[ -n $auth ]]; then
    pass "T5c authentification SASL du relai acceptée par le MTA fournisseur"
    printf '        log: %s\n' "${auth:0:220}"
else
    fail "T5c pas de trace d'authentification SASL côté MTA fournisseur"
fi
if [[ -n ${msg:-} ]] && grep -qE '\(using TLSv1\.[23] ' <<<"$msg" && grep -q 'Authenticated sender: relay-test' <<<"$msg"; then
    pass "T5d en-tête Received du message : TLS + 'Authenticated sender'"
else
    fail "T5d en-tête Received sans preuve TLS/SASL"
fi

# --- T6 : mauvais identifiants -> non délivré, reste en file (et y survit) --------
subj="t-badcreds-${TOKEN}"
out=$(send client-gitlab "$BADCREDS_IP" "$subj" --helo gitlab.ci.internal \
    --from "gitlab@ci.internal" --to "dev-team@customer.test") && rc=0 || rc=$?
(( rc == 0 )) || fail "T6 le relai (mauvais identifiants) n'a pas accepté le mail (rc=$rc)" "$(tail -3 <<<"$out")"
auth_failed() { logs relay-badcreds | grep -q 'SASL authentication failed'; }
if wait_for 40 auth_failed; then
    pass "T6a échec d'authentification SASL tracé dans les logs"
    printf '        log: %s\n' "$(logs relay-badcreds | grep 'SASL authentication failed' | tail -1 | cut -c1-220)"
else
    fail "T6a pas d'erreur d'authentification SASL dans les logs"
fi
in_queue() { dc exec -T relay-badcreds postqueue -j 2>/dev/null | grep -q '"queue_name": *"deferred".*dev-team@customer.test'; }
if wait_for 20 in_queue; then
    pass "T6b message conservé dans la file d'attente (deferred)"
else
    fail "T6b message absent de la file deferred" "$(dc exec -T relay-badcreds postqueue -p 2>&1 | tail -5)"
fi
if has_capture "Subject: ${subj}"; then
    fail "T6c le mail a été délivré malgré de mauvais identifiants !"
else
    pass "T6c message non délivré au MTA fournisseur"
fi
dc restart relay-badcreds >/dev/null 2>&1
if wait_for 60 in_queue; then
    pass "T6d message toujours en file après redémarrage du conteneur (volume persistant)"
else
    fail "T6d message perdu après redémarrage"
fi

# --- T7 : refus de démarrage si la liste blanche est vide / invalide -------------
image=$(docker inspect -f '{{.Config.Image}}' "$(dc ps -q relay)")
start_must_fail() {  # <libellé> <valeur ALLOWED_CLIENT_IPS> <motif attendu dans les logs>
    local label=$1 value=$2 expect=$3 cid code=running out
    cid=$(docker run -d --network none \
        -e ALLOWED_CLIENT_IPS="$value" -e SENDER_DOMAIN=example.com -e RELAY_HOST=smtp.example-provider.com \
        -e RELAY_SMTP_USERNAME=u -e RELAY_SMTP_PASSWORD=p "$image")
    for _ in $(seq 1 15); do
        if [[ $(docker inspect -f '{{.State.Running}}' "$cid") == false ]]; then
            code=$(docker inspect -f '{{.State.ExitCode}}' "$cid"); break
        fi
        sleep 1
    done
    out=$(docker logs "$cid" 2>&1)
    docker rm -f "$cid" >/dev/null
    if [[ $code != running && $code != 0 ]] && grep -q "$expect" <<<"$out"; then
        pass "T7 ${label} : démarrage refusé (exit ${code})"
        printf '        log: %s\n' "$(grep -m1 FATAL <<<"$out" | cut -c1-220)"
    else
        fail "T7 ${label} : le conteneur n'a pas refusé de démarrer (état: ${code})" "$(tail -3 <<<"$out")"
    fi
}
start_must_fail "liste vide"              ""              "ALLOWED_CLIENT_IPS (ou ALLOWED_CLIENT_IPS_FILE) est vide"
start_must_fail "liste invalide (CIDR)"   "10.0.1.0/24"   "pas de CIDR"
start_must_fail "liste invalide (IP)"     "10.0.1.10,999.1.1.1" "n'est pas une adresse IPv4 ou IPv6"

# --- T8 : healthcheck -------------------------------------------------------------
status=$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q relay)")
if [[ $status == healthy ]]; then
    pass "T8 healthcheck du relai : healthy"
else
    fail "T8 healthcheck du relai : ${status}"
fi

# --- Bilan -----------------------------------------------------------------------
echo
info "Bilan : ${PASS} PASS, ${FAIL} FAIL"
printf '  %s\n' "${RESULTS[@]}"
(( FAIL == 0 ))
