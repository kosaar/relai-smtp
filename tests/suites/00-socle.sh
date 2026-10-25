# shellcheck shell=bash
# =============================================================================
#  Suite 00 — socle : relai -> fournisseur (TLS vérifié + SASL), BAL relue en
#  IMAPS, file persistante, refus de démarrage, healthcheck.
# =============================================================================
suite "00 — socle (relai, fournisseur, BAL)"

RELAY_IP=10.0.1.5
BADCREDS_IP=10.0.1.6
SENDER=noreply@example.com
RCPT=alice@example.com

# send25 <client> <serveur> <sujet> [options swaks...] : soumission port 25 (avant lot 1).
send25() {
    local client=$1 server=$2 subject=$3; shift 3
    smtp "$client" --server "$server" --port 25 \
        --header "Subject: ${subject}" --body "Test ${subject}" "$@"
}

# --- T1 / T2 : IP déclarées -> message livré dans la BAL, relu en IMAPS ----------
for app in gitlab jenkins; do
    subj="t-${app}-${TOKEN}"
    out=$(send25 "client-${app}" "$RELAY_IP" "$subj" \
        --helo "${app}.ci.internal" --from "${app}@ci.internal" \
        --h-From "\"$(tr '[:lower:]' '[:upper:]' <<<"${app:0:1}")${app:1}\" <${app}@ci.internal>" \
        --to "$RCPT") && rc=0 || rc=$?
    if (( rc == 0 )) && mb_has "$RCPT" "Subject: ${subj}" 40; then
        pass "T1/T2 [$app] IP déclarée : message accepté, livré dans la BAL et relu en IMAPS"
    else
        fail "T1/T2 [$app] IP déclarée : message absent de la BAL (swaks rc=$rc)" "$(tail -3 <<<"$out")"
    fi
done

# --- T3 : IP non déclarée -> rejet + trace dans les logs -------------------------
subj="t-unknown-${TOKEN}"
out=$(send25 client-unknown "$RELAY_IP" "$subj" --helo unknown.ci.internal \
    --from "app@unknown.internal" --to "$RCPT") && rc=0 || rc=$?
if (( rc != 0 )) && grep -q '554 5.7.1' <<<"$out"; then
    pass "T3a IP non déclarée (10.0.1.30) : envoi refusé par le relai (554 5.7.1)"
else
    fail "T3a IP non déclarée : l'envoi n'a pas été refusé (swaks rc=$rc)" "$(tail -3 <<<"$out")"
fi
relay_rejected() { logs relay | grep -qE 'NOQUEUE: reject: RCPT from [^ ]*\[10\.0\.1\.30\].*Client host rejected: Access denied'; }
if wait_for 10 relay_rejected; then
    pass "T3b rejet tracé dans les logs (IP source + motif)"
    note "log: $(logs relay | grep -E 'NOQUEUE: reject: RCPT from [^ ]*\[10\.0\.1\.30\]' | tail -1)"
else
    fail "T3b rejet absent des logs du relai"
fi
sleep 3
if mb_has "$RCPT" "Subject: ${subj}"; then
    fail "T3c le message de l'IP non déclarée a été livré !"
else
    pass "T3c aucun message de l'IP non déclarée dans la BAL"
fi

# --- T4 : expéditeur réécrit -----------------------------------------------------
msg=$(mb_fetch "$RCPT" "Subject: t-gitlab-${TOKEN}" || true)
if [[ -n $msg ]]; then
    hdr=$(headers_of <<<"$msg")
    rp=$(grep -i -m1 '^Return-Path:' <<<"$hdr" || true)
    from=$(grep -i -m1 '^From:' <<<"$hdr" || true)
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

# --- T5 : relai -> fournisseur chiffré (TLS vérifié) et authentifié (SASL) -------
rlogs=$(logs relay)
tls=$(grep -E 'Verified TLS connection established to provider\[10\.0\.2\.10\]:587: TLSv1\.[23]' <<<"$rlogs" | tail -1 || true)
if [[ -n $tls ]]; then
    pass "T5a TLS >= 1.2 avec certificat vérifié (relai)"
    note "log: $tls"
else
    fail "T5a pas de connexion TLS vérifiée dans les logs du relai"
fi
sent=$(grep -E 'relay=provider\[10\.0\.2\.10\]:587, .*status=sent' <<<"$rlogs" | tail -1 || true)
[[ -n $sent ]] && pass "T5b livraison confirmée par le relai (status=sent)" \
               || fail "T5b aucune ligne status=sent vers provider"
auth=$(logs provider | grep -E 'client=[^ ]*\[10\.0\.2\.5\], sasl_method=(PLAIN|LOGIN), sasl_username=relay-test' | tail -1 || true)
if [[ -n $auth ]]; then
    pass "T5c authentification SASL du relai acceptée par le fournisseur"
    note "log: $auth"
else
    fail "T5c pas de trace d'authentification SASL côté fournisseur"
fi
if [[ -n $msg ]] && grep -qE '\(using TLSv1\.[23] ' <<<"$msg" && grep -q 'Authenticated sender: relay-test' <<<"$msg"; then
    pass "T5d en-tête Received du message : TLS + 'Authenticated sender'"
else
    fail "T5d en-tête Received sans preuve TLS/SASL"
fi
lmtp=$(logs provider | grep -E "lmtp\(${RCPT}\).*saved mail to INBOX" | tail -1 || true)
[[ -n $lmtp ]] && pass "T5e livraison LMTP dans la BAL Dovecot tracée par le fournisseur" \
               || fail "T5e pas de livraison LMTP tracée par Dovecot"

# --- T6 : mauvais identifiants -> non délivré, reste en file (et y survit) --------
subj="t-badcreds-${TOKEN}"
out=$(send25 client-gitlab "$BADCREDS_IP" "$subj" --helo gitlab.ci.internal \
    --from "gitlab@ci.internal" --to "$RCPT") && rc=0 || rc=$?
(( rc == 0 )) || fail "T6 le relai (mauvais identifiants) n'a pas accepté le message (rc=$rc)" "$(tail -3 <<<"$out")"
auth_failed() { logs relay-badcreds | grep -q 'SASL authentication failed'; }
if wait_for 40 auth_failed; then
    pass "T6a échec d'authentification SASL tracé dans les logs"
    note "log: $(logs relay-badcreds | grep 'SASL authentication failed' | tail -1)"
else
    fail "T6a pas d'erreur d'authentification SASL dans les logs"
fi
in_queue() { dc exec -T relay-badcreds postqueue -j 2>/dev/null | grep -q "\"queue_name\": *\"deferred\".*${RCPT}"; }
if wait_for 20 in_queue; then
    pass "T6b message conservé dans la file d'attente (deferred)"
else
    fail "T6b message absent de la file deferred" "$(dc exec -T relay-badcreds postqueue -p 2>&1 | tail -5)"
fi
if mb_has "$RCPT" "Subject: ${subj}"; then
    fail "T6c le message a été livré malgré de mauvais identifiants !"
else
    pass "T6c message non livré dans la BAL"
fi
dc restart relay-badcreds >/dev/null 2>&1
if wait_for 60 in_queue; then
    pass "T6d message toujours en file après redémarrage du conteneur (volume persistant)"
else
    fail "T6d message perdu après redémarrage"
fi

# --- T7 : refus de démarrage si la liste blanche est vide / invalide -------------
image=$(docker inspect -f '{{.Config.Image}}' "$(cid relay)")
t7() {  # <libellé> <valeur ALLOWED_CLIENT_IPS> <motif attendu>
    start_must_fail "T7 $1" "$3" -e ALLOWED_CLIENT_IPS="$2" -e SENDER_DOMAIN=example.com \
        -e RELAY_HOST=smtp.example-provider.com -e RELAY_SMTP_USERNAME=u -e RELAY_SMTP_PASSWORD=p -- "$image"
}
t7 "liste vide"            ""                    "ALLOWED_CLIENT_IPS (ou ALLOWED_CLIENT_IPS_FILE) est vide"
t7 "liste invalide (CIDR)" "10.0.1.0/24"         "pas de CIDR"
t7 "liste invalide (IP)"   "10.0.1.10,999.1.1.1" "n'est pas une adresse IPv4 ou IPv6"

# --- T8 : healthcheck -------------------------------------------------------------
status=$(docker inspect -f '{{.State.Health.Status}}' "$(cid relay)")
if [[ $status == healthy ]]; then
    pass "T8 healthcheck du relai : healthy"
else
    fail "T8 healthcheck du relai : ${status}"
fi
