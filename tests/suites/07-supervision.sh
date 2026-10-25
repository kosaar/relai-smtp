# shellcheck shell=bash
# =============================================================================
#  Suite 07 — supervision (F4) et RGPD (D11).
#  Exporteur Prometheus du relai (relay-run + relay-exporter, port 9154) :
#  compteurs tirés des journaux Postfix, file d'attente, sonde TLS du
#  smarthost, métriques des clés recopiées depuis l'annuaire. Puis contrôle
#  qu'aucun objet ni corps de message n'apparaît dans les journaux.
# =============================================================================
suite "07 — supervision et RGPD"

# --- IT7.1 : compteurs de refus faute de clé, d'échecs d'authentification, de blocages
before=$(metrics) || before=""
S_NOKEY='relay_nokey_rejects_total{recipient="carol@example.com"}'
S_REJ='relay_rejects_total{app="gitlab",reason="no_key",class="permanent"}'
S_AUTH='relay_auth_failures_total{app="jenkins"}'
S_CONTENT='relay_content_blocks_total{app="gitlab",rule="private-key"}'
out_a=$(submit client-gitlab gitlab "it71a-${TOKEN}" --to carol@example.com) && rc_a=0 || rc_a=$?
printf -v bad_pw 'faux-%s' "$(rand 16)"
out_b=$(smtp client-jenkins --server smtp-relay --port 587 --tls --tls-verify --tls-ca-path /pki/ca.crt \
    --auth PLAIN --auth-user jenkins --auth-password "$bad_pw" \
    --from jenkins@example.com --to alice@example.com) && rc_b=0 || rc_b=$?
tests/tools/content-msg.py privkey "it71c-${TOKEN}" "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ${RANDOM}" \
    | put_file client-gitlab /tmp/it71c.eml
out_c=$(send_eml client-gitlab gitlab /tmp/it71c.eml alice@example.com) && rc_c=0 || rc_c=$?
counters_up() {
    local now s
    now=$(metrics) || return 1
    for s in "$S_NOKEY" "$S_REJ" "$S_AUTH" "$S_CONTENT"; do
        (( $(metric "$now" "$s") >= $(metric "$before" "$s") + 1 )) || return 1
    done
}
replies_ok() {
    (( rc_a != 0 && rc_b != 0 && rc_c != 0 )) \
        && grep -qE '550[- ]5\.7\.1 No valid OpenPGP key for <carol@example\.com>' <<<"$out_a" \
        && grep -qE '535[- ]5\.7\.8' <<<"$out_b" \
        && grep -qE '550[- ]5\.7\.1 Message blocked by content policy \(rule private-key\)' <<<"$out_c"
}
if [[ -n $before ]] && replies_ok && wait_for 20 counters_up; then
    after=$(metrics)
    pass "IT7.1 compteurs incrémentés : refus faute de clé (carol, $(metric "$after" "$S_NOKEY")), échec d'authentification (jenkins, $(metric "$after" "$S_AUTH")), blocage de contenu (private-key, $(metric "$after" "$S_CONTENT"))"
else
    fail "IT7.1 compteurs non incrémentés (rc=${rc_a}/${rc_b}/${rc_c})" \
        "$(metrics 2>&1 | grep -E '^relay_(nokey|auth|content|rejects)' | tr '\n' ' ')"
fi

# --- IT7.2 : fournisseur arrêté : file non vide, âge > 0, smarthost injoignable --------
id=it72-${TOKEN}
dc stop provider >/dev/null 2>&1
submit client-gitlab gitlab "$id" >/dev/null && rc=0 || rc=$?
queue_alert() {
    local m
    m=$(metrics) || return 1
    awk '$1 ~ /^relay_queue_messages\{/ { n += $2 } $1 == "relay_queue_oldest_message_age_seconds" { age = $2 }
         $1 == "relay_smarthost_up" { up = $2 } $1 == "relay_queue_scrape_ok" { ok = $2 }
         END { exit !(ok == 1 && n >= 1 && age > 0 && up == 0) }' <<<"$m"
}
if (( rc == 0 )) && wait_for 45 queue_alert; then
    m=$(metrics)
    pass "IT7.2a fournisseur arrêté : $(awk '$1 ~ /^relay_queue_messages\{/ { n += $2 } END { print n }' <<<"$m") message(s) en file, plus ancien : $(metric "$m" relay_queue_oldest_message_age_seconds) s, relay_smarthost_up=0"
else
    fail "IT7.2a métriques de file ou de joignabilité incorrectes (rc=$rc)" \
        "$(metrics 2>&1 | grep -E '^relay_(queue|smarthost)' | tr '\n' ' ')"
fi
dc start provider >/dev/null 2>&1
wait_healthy provider 90 || fail "IT7.2 fournisseur non sain après redémarrage"
dc exec -T relay postqueue -f >/dev/null 2>&1 || true
queue_back() {
    local m
    m=$(metrics) || return 1
    awk '$1 ~ /^relay_queue_messages\{/ { n += $2 } $1 == "relay_smarthost_up" { up = $2 }
         END { exit !(n == 0 && up == 1) }' <<<"$m"
}
if mb_has alice@example.com "Subject: ${id}" 90 && wait_for 30 queue_back; then
    m=$(metrics)
    pass "IT7.2b fournisseur relancé : message livré, file vide, relay_smarthost_up=1 ; différés comptés ($(grep -E '^relay_deferrals_total\{app="gitlab"' <<<"$m" | tr '\n' ' '))"
else
    fail "IT7.2b retour à la normale non constaté" "$(metrics 2>&1 | grep -E '^relay_(queue|smarthost)' | tr '\n' ' ')"
fi

# --- IT7.3 : date d'expiration du certificat du smarthost ------------------------------
# shellcheck disable=SC2016  # développé par le sh du conteneur
want=$(dc exec -T provider sh -c 'date -u -d "$(openssl x509 -in /pki/provider.crt -noout -enddate | cut -d= -f2)" +%s' 2>/dev/null || true)
m=$(metrics)
got=$(metric "$m" relay_smarthost_certificate_expiry_timestamp_seconds)
if [[ -n $want && $got == "$want" && $(metric "$m" relay_smarthost_tls_verified) == 1 ]]; then
    pass "IT7.3 expiration du certificat du smarthost = celle du certificat de test ($(date -u -d "@${got}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$got")), certificat vérifié"
else
    fail "IT7.3 expiration du certificat incorrecte (attendu ${want:-?}, obtenu ${got})"
fi

# --- IT7.4 : clé expirant dans 10 jours : signalée, puis révoquée ----------------------
email=expire10j@example.com
fpr=$(ws keys gen-gpg "$email" 10d 2>/dev/null || true)
dep=$(ws bash -c "keys export-gpg ${email} | keys deposit ${email}" 2>&1 || true)
dc exec -T keydir keydir-admin approve "$email" "$fpr" >/dev/null 2>&1 || true
S_SOON="keydir_key_expiring_soon{email=\"${email}\"}"
S_EXP="keydir_key_expiry_timestamp_seconds{email=\"${email}\"}"
m=$(metrics)
exp_ts=$(metric "$m" "$S_EXP")
now=$(date +%s)
if [[ -n $fpr && $dep == *HTTP_CODE=202* && $(metric "$m" "$S_SOON") == 1 ]] \
    && (( exp_ts > now + 9 * 86400 && exp_ts <= now + 10 * 86400 + 3600 )) \
    && (( $(metric "$m" keydir_keys_expiring_soon) >= 1 )) && [[ $(metric "$m" relay_keydir_metrics_up) == 1 ]]; then
    pass "IT7.4a clé de ${email} expirant dans 10 jours : signalée « proche de l'expiration » (seuil $(metric "$m" keydir_expiry_warning_days) j)"
else
    fail "IT7.4a clé proche de l'expiration non signalée (dépôt : ${dep##*$'\n'}, exp=${exp_ts})" \
        "$(grep -E '^keydir_' <<<"$m" | tr '\n' ' ')"
fi
dc exec -T keydir keydir-admin revoke "$email" >/dev/null 2>&1 || true
m=$(metrics)
if [[ $(metric "$m" "keydir_key_revoked{email=\"${email}\"}") == 1 && $(metric "$m" "$S_SOON") == 0 ]]; then
    pass "IT7.4b clé révoquée par l'administrateur : signalée révoquée (keydir_keys_revoked=$(metric "$m" keydir_keys_revoked)), plus « proche de l'expiration »"
else
    fail "IT7.4b révocation non signalée" "$(grep -E '^keydir_key' <<<"$m" | tr '\n' ' ')"
fi

# --- IT7.5 : aucun objet ni corps dans les journaux d'aucun conteneur ------------------
id=it75-${TOKEN}
printf -v body_marker 'corps-confidentiel-%s' "$(rand 12)"
submit client-gitlab gitlab "$id Objet confidentiel" --body "$body_marker" >/dev/null && rc=0 || rc=$?
# Témoin : les marqueurs sont bien dans le message livré (partie déchiffrée).
plain=$(mb_plain alice@example.com "Subject: ${id}" 60 || true)
leaks=""
nsvc=0
for svc in $(dc ps -a --services 2>/dev/null); do
    nsvc=$((nsvc + 1))
    l=$(logs "$svc")
    for marker in "$TOKEN" "$body_marker" "Objet confidentiel" "Contenu secret" "infra-secrete" "PRIVATE KEY"; do
        n=$(grep -c -F -- "$marker" <<<"$l" || true)
        (( n == 0 )) || leaks+="${svc}:${marker}(${n}) "
    done
done
if (( rc == 0 && nsvc >= 5 )) && [[ -z $leaks && $plain == *"$body_marker"* ]]; then
    pass "IT7.5 journaux des ${nsvc} conteneurs : aucun objet ni corps de message de test (marqueurs des suites 00 à 07)"
else
    fail "IT7.5 contenu de message dans les journaux ou témoin non livré (rc=$rc) : ${leaks:-aucune fuite}"
fi
