# shellcheck shell=bash
# =============================================================================
#  Suite 00 — socle : relai -> fournisseur (TLS vérifié + SASL), BAL relue en
#  IMAPS, liste blanche IP, file persistante, healthcheck. Les refus de
#  démarrage (inventaire invalide) sont dans la suite 01 (IT1.9).
# =============================================================================
suite "00 — socle (relai, fournisseur, BAL)"

RCPT=alice@example.com

# --- T1 / T2 : applications déclarées -> message livré dans la BAL, relu en IMAPS
for app in gitlab jenkins; do
    subj="t-${app}-${TOKEN}"
    out=$(submit "client-${app}" "$app" "$subj" --to "$RCPT") && rc=0 || rc=$?
    if (( rc == 0 )) && mb_has "$RCPT" "Subject: ${subj}" 40; then
        pass "T1/T2 [$app] message soumis (587), livré dans la BAL et relu en IMAPS"
    else
        fail "T1/T2 [$app] message absent de la BAL (swaks rc=$rc)" "$(tail -3 <<<"$out")"
    fi
done

# --- T3 : IP non déclarée -> rejet dès la connexion + trace dans les logs --------
subj="t-unknown-${TOKEN}"
out=$(smtp client-unknown --server smtp-relay --port 587 --from "gitlab@example.com" \
    --to "$RCPT" --header "Subject: ${subj}") && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '554[- ]5\.7\.1' <<<"$out"; then
    pass "T3a IP non déclarée (10.0.1.30) : connexion refusée par le relai (554 5.7.1)"
else
    fail "T3a IP non déclarée : la connexion n'a pas été refusée (swaks rc=$rc)" "$(tail -3 <<<"$out")"
fi
relay_rejected() { logs relay | grep -qE 'NOQUEUE: reject: CONNECT from [^ ]*\[10\.0\.1\.30\].*Client host rejected: Access denied'; }
if wait_for 10 relay_rejected; then
    pass "T3b rejet tracé dans les logs (IP source + motif)"
    note "log: $(logs relay | grep -E 'NOQUEUE: reject: CONNECT from [^ ]*\[10\.0\.1\.30\]' | tail -1)"
else
    fail "T3b rejet absent des logs du relai"
fi
sleep 3
if mb_has "$RCPT" "Subject: ${subj}"; then
    fail "T3c le message de l'IP non déclarée a été livré !"
else
    pass "T3c aucun message de l'IP non déclarée dans la BAL"
fi

# --- T4 : expéditeur conservé (plus de réécriture : adresse liée au login) -------
msg=$(mb_fetch "$RCPT" "Subject: t-gitlab-${TOKEN}" || true)
if [[ -n $msg ]]; then
    hdr=$(headers_of <<<"$msg")
    rp=$(grep -i -m1 '^Return-Path:' <<<"$hdr" || true)
    from=$(grep -i -m1 '^From:' <<<"$hdr" || true)
    if [[ $rp == "Return-Path: <gitlab@example.com>" && $from == "From: gitlab@example.com" ]]; then
        pass "T4 enveloppe et From: = adresse de l'application (gitlab@example.com)"
    else
        fail "T4 expéditeur inattendu" "${rp} / ${from}"
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
out=$(submit client-gitlab gitlab "$subj" --server relay-badcreds --to "$RCPT") && rc=0 || rc=$?
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

# --- T8 : healthcheck -------------------------------------------------------------
status=$(docker inspect -f '{{.State.Health.Status}}' "$(cid relay)")
if [[ $status == healthy ]]; then
    pass "T8 healthcheck du relai : healthy"
else
    fail "T8 healthcheck du relai : ${status}"
fi
