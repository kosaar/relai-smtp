# shellcheck shell=bash
# =============================================================================
#  Suite 03 — passerelle de chiffrement : clé du destinataire au RCPT TO (WKD
#  de l'annuaire), chiffrement PGP/MIME avec en-têtes protégés (GnuPG),
#  déchiffrement sur le poste avec RNP (bibliothèque de Thunderbird), échec
#  fermé (destinataire sans clé, passerelle ou annuaire arrêtés), file chiffrée.
# =============================================================================
suite "03 — passerelle de chiffrement OpenPGP"

NEUTRAL="Message chiffré"
TTL_WAIT=7   # cache des clés de la passerelle en test : 5 s
ws() { dc exec -T workstation "$@"; }

# send_eml <client> <login> <fichier .eml du client> <destinataires> [options swaks…]
send_eml() {
    local c=$1 login=$2 file=$3 to=$4; shift 4
    smtp "$c" --server smtp-relay --port 587 --tls --tls-verify --tls-ca-path /pki/ca.crt \
        --auth PLAIN --auth-user "$login" --auth-password "$(app_password "$login")" \
        --from "${login}@example.com" --to "$to" --data "@${file}" --suppress-data "$@"
}
# mkmsg_in <client> <id> <options mkmsg…> : /tmp/<id>.eml et /tmp/<id>.json dans le client,
# copie du manifeste dans $WORK/<id>.json
mkmsg_in() {
    local c=$1 id=$2; shift 2
    dc exec -T "$c" mkmsg --out "/tmp/${id}.eml" --manifest "/tmp/${id}.json" "$@" >/dev/null \
        && dc exec -T "$c" cat "/tmp/${id}.json" >"$WORK/${id}.json"
}
# received <bal> <motif> <id> : message brut gardé dans /tmp/<id>.eml du poste,
# résumé (pgpmime summary) dans $WORK/<id>.summary.json
received() {
    ws bash -c "mailbox fetch '$1' --match '$2' --wait 60 >/tmp/$3.eml" \
        && ws bash -c "pgpmime summary --mailbox '$1' </tmp/$3.eml" >"$WORK/$3.summary.json"
}
# roundtrip <id du résumé> [id du manifeste] : compare reçu et envoyé
roundtrip() { python3 tests/tools/compare-roundtrip.py "$WORK/$1.summary.json" "$WORK/${2:-$1}.json" "$NEUTRAL"; }
qid_of() { { grep -oE 'queued as [0-9A-F]+' <<<"$1" || true; } | awk '{print $3}' | tail -1; }
in_queue_for() { dc exec -T relay postqueue -j 2>/dev/null | grep -q "\"address\": *\"$1\""; }

# --- IT3.1 : E2E GitLab -> alice, chiffré, déchiffré par RNP à l'identique ----------
id=it31-${TOKEN}
mkmsg_in client-gitlab "$id" --from gitlab@example.com --to alice@example.com \
    --subject "${id} Pipeline #42 échoué sur main" --text "Corps confidentiel ${id}-corps : jeton de déploiement à renouveler." \
    --attach rapport.bin:20000 --attach trace.bin:150000
out=$(send_eml client-gitlab gitlab "/tmp/${id}.eml" alice@example.com) && rc=0 || rc=$?
if (( rc == 0 )) && received alice@example.com "$id" "$id" && res=$(roundtrip "$id"); then
    pass "IT3.1a E2E GitLab -> alice : PGP/MIME, objet neutre, déchiffré par RNP : ${res}"
else
    fail "IT3.1a message absent ou différent après déchiffrement (swaks rc=$rc)" "${res:-$(tail -3 <<<"$out")}"
fi
leaks=$(ws grep -c -e "$id" -e "Pipeline #42" -e "confidentiel" "/tmp/${id}.eml" || true)
# Lignes base64 des pièces jointes du message d'origine (fichier en CRLF).
b64=$(dc exec -T client-gitlab bash -c "tr -d '\r' </tmp/${id}.eml | grep -E '^[A-Za-z0-9+/]{76}\$' | head -40" || true)
b64_leaks=$( [[ -n $b64 ]] && ws grep -c -F -f - "/tmp/${id}.eml" <<<"$b64" || true)
if [[ $leaks == 0 && $b64_leaks == 0 && $(grep -c . <<<"$b64") -ge 40 ]]; then
    pass "IT3.1b message brut en BAL : aucun fragment de l'objet, du corps ni des pièces jointes (40 lignes base64 testées)"
else
    fail "IT3.1b fragments du message d'origine dans le message brut (texte : ${leaks}, base64 : ${b64_leaks})"
fi
enc_log=$(logs gateway | grep -E "encrypt .*login=gitlab rcpts=1 " | tail -1 || true)
[[ -n $enc_log ]] && pass "IT3.1c chiffrement journalisé par la passerelle (métadonnées)" && note "log: ${enc_log}" \
                  || fail "IT3.1c aucune trace de chiffrement dans les logs de la passerelle"

# --- IT3.2 : la clé de bob ne déchiffre pas le message d'alice --------------------
if ! ws bash -c "pgpmime decrypt --mailbox bob@example.com </tmp/${id}.eml" >/dev/null 2>&1; then
    pass "IT3.2 la clé de bob ne déchiffre pas le message d'alice"
else
    fail "IT3.2 le message d'alice est déchiffrable avec la clé de bob !"
fi

# --- IT3.3 : carol (sans clé) refusée au RCPT TO, rien en file ni en BAL --------------
subj="it33-${TOKEN}"
out=$(submit client-gitlab gitlab "$subj" --to carol@example.com) && rc=0 || rc=$?
gw_nokey() { logs gateway | grep -qE 'reject .*stage=rcpt .*reason=no-key code=550 rcpt=carol@example.com'; }
if (( rc != 0 )) && grep -qE '550[- ]5\.7\.1 .*No valid OpenPGP key for <carol@example\.com>' <<<"$out" && wait_for 5 gw_nokey; then
    pass "IT3.3a carol (sans clé) : 550 5.7.1 au RCPT TO, refus journalisé"
else
    fail "IT3.3a carol non refusée (rc=$rc)" "$(grep -E 'RCPT|550|250' <<<"$out" | tail -4)"
fi
sleep 2
if ! in_queue_for carol@example.com && [[ $(mb_count carol@example.com) == 0 ]]; then
    pass "IT3.3b rien en file ni dans la BAL de carol"
else
    fail "IT3.3b un message pour carol est en file ou en BAL"
fi

# --- IT3.4 : alice + carol : carol refusée, alice livrée chiffrée -------------------
subj="it34-${TOKEN}"
out=$(submit client-gitlab gitlab "$subj" --to alice@example.com,carol@example.com) && rc=0 || rc=$?
if grep -qE '550[- ]5\.7\.1 .*<carol@example\.com>' <<<"$out" && grep -q 'queued as' <<<"$out" \
    && mb_has alice@example.com "Subject: ${subj}" 40; then
    pass "IT3.4a alice + carol : carol refusée (550), message accepté et livré chiffré à alice"
else
    fail "IT3.4a envoi partiel incorrect (rc=$rc)" "$(grep -E 'RCPT|550|250|queued' <<<"$out" | tail -5)"
fi
sleep 2
[[ $(mb_count carol@example.com) == 0 ]] && pass "IT3.4b rien dans la BAL de carol" \
                                         || fail "IT3.4b carol a reçu un message"

# --- IT3.5 : alice + bob : un seul message, déchiffrable par chacun, clés masquées --
id=it35-${TOKEN}
mkmsg_in client-jenkins "$id" --from jenkins@example.com --to "alice@example.com, bob@example.com" \
    --subject "${id} Build #7 réussi" --text "Résultat ${id}" --attach build.log:4096
out=$(send_eml client-jenkins jenkins "/tmp/${id}.eml" alice@example.com,bob@example.com) && rc=0 || rc=$?
ok=1
for who in alice bob; do
    received "${who}@example.com" "$id" "${id}-${who}" && roundtrip "${id}-${who}" "$id" >/dev/null || { ok=0; note "échec : ${who}"; }
done
(( ok )) && pass "IT3.5a alice et bob déchiffrent chacun le message avec leur propre clé" \
         || fail "IT3.5a déchiffrement impossible pour un destinataire (swaks rc=$rc)" "$(tail -3 <<<"$out")"
same=$(ws bash -c "diff <(sed -n '/BEGIN PGP MESSAGE/,/END PGP MESSAGE/p' /tmp/${id}-alice.eml) <(sed -n '/BEGIN PGP MESSAGE/,/END PGP MESSAGE/p' /tmp/${id}-bob.eml) >/dev/null && echo same" || true)
keyids=$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["keyids"]))' "$WORK/${id}-alice.summary.json" 2>/dev/null || true)
keyid1=$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["keyids"]))' "$WORK/it31-${TOKEN}.summary.json" 2>/dev/null || true)
if [[ $same == same && $(wc -w <<<"$keyids") == 2 && $keyids != *0000000000000000* && $keyid1 == 0000000000000000 ]]; then
    pass "IT3.5b un seul message chiffré pour les deux ; identifiants de clés masqués pour un destinataire unique (IT3.1), visibles à plusieurs (RNP n'essaie que le premier destinataire masqué)"
else
    fail "IT3.5b structure inattendue (identique : ${same:-non}, keyids : ${keyids} ; destinataire unique : ${keyid1})"
fi

# --- IT3.6 : clé révoquée ou expirée : refus après expiration du cache ---------------
subj="it36a-${TOKEN}"
submit client-gitlab gitlab "$subj" --to bob@example.com >/dev/null && accepted_before=1 || accepted_before=0
ws bash -c 'keys revcert bob@example.com | keys deposit bob@example.com' >/dev/null
sleep "$TTL_WAIT"
out=$(submit client-gitlab gitlab "it36b-${TOKEN}" --to bob@example.com) && rc=0 || rc=$?
gw_revoked() { logs gateway | grep -qE 'reject .*stage=rcpt .*reason=key-revoked code=550 rcpt=bob@example.com'; }
if (( accepted_before )) && (( rc != 0 )) && grep -qE '550[- ]5\.7\.1' <<<"$out" && wait_for 5 gw_revoked; then
    pass "IT3.6a clé de bob révoquée (certificat déposé) : refusée (550, key-revoked) après expiration du cache"
else
    fail "IT3.6a clé révoquée encore utilisée (avant : ${accepted_before}, rc=$rc)" "$(tail -3 <<<"$out")"
fi
fpr_c=$(ws keys gen-gpg carol@example.com seconds=30 || true)
ws bash -c 'keys export-gpg carol@example.com | keys deposit carol@example.com' >/dev/null
dc exec -T keydir keydir-admin approve carol@example.com "$fpr_c" >/dev/null
started=$SECONDS
submit client-gitlab gitlab "it36c-${TOKEN}" --to carol@example.com >/dev/null && accepted_before=1 || accepted_before=0
sleep $(( 30 + TTL_WAIT - (SECONDS - started) ))
out=$(submit client-gitlab gitlab "it36d-${TOKEN}" --to carol@example.com) && rc=0 || rc=$?
gw_expired() { logs gateway | grep -qE 'reject .*stage=rcpt .*reason=key-expired code=550 rcpt=carol@example.com'; }
if (( accepted_before )) && (( rc != 0 )) && grep -qE '550[- ]5\.7\.1' <<<"$out" && wait_for 5 gw_expired; then
    pass "IT3.6b clé de carol expirée (validité 30 s) : acceptée avant, refusée (550, key-expired) après"
else
    fail "IT3.6b clé expirée encore utilisée (avant : ${accepted_before}, rc=$rc)" "$(tail -3 <<<"$out")"
fi
provision_key bob@example.com   # nouvelle clé pour bob (les suites suivantes en ont besoin)
sleep "$TTL_WAIT"
subj="it36e-${TOKEN}"
if submit client-gitlab gitlab "$subj" --to bob@example.com >/dev/null && mb_has bob@example.com "Subject: ${subj}" 40; then
    pass "IT3.6c nouvelle clé de bob validée : envoi de nouveau accepté et déchiffrable"
else
    fail "IT3.6c envoi à bob impossible après publication de sa nouvelle clé"
fi

# --- IT3.7 : passerelle arrêtée -> 451, rien de livré ; relancée -> renvoi réussi ---
subj="it37-${TOKEN}"
dc stop gateway >/dev/null 2>&1
out=$(submit client-gitlab gitlab "$subj") && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '^<\*\* 4[0-9]{2}[- ]4\.[0-9]\.[0-9]' <<<"$out" && ! grep -q 'queued as' <<<"$out"; then
    pass "IT3.7a passerelle arrêtée : erreur temporaire, l'application réessaiera"
    note "réponse : $(grep -m1 -E '^<\*\* 4' <<<"$out")"
else
    fail "IT3.7a passerelle arrêtée : réponse inattendue (rc=$rc)" "$(grep -E '^<' <<<"$out" | tail -3)"
fi
dc start gateway >/dev/null 2>&1
wait_healthy gateway 60 || fail "IT3.7 passerelle non saine après redémarrage"
mb_has alice@example.com "Subject: ${subj}" && fail "IT3.7b message livré alors que la passerelle était arrêtée !" \
                                            || pass "IT3.7b rien n'a été livré pendant l'arrêt"
out=$(submit client-gitlab gitlab "$subj") && rc=0 || rc=$?
(( rc == 0 )) && mb_has alice@example.com "Subject: ${subj}" 40 \
    && pass "IT3.7c passerelle relancée : le renvoi réussit, message livré chiffré" \
    || fail "IT3.7c renvoi en échec après relance (rc=$rc)" "$(tail -3 <<<"$out")"

# --- IT3.8 : annuaire arrêté, cache vide -> 451, rien de livré -----------------------
subj="it38-${TOKEN}"
dc stop keydir >/dev/null 2>&1
sleep "$TTL_WAIT"
out=$(submit client-gitlab gitlab "$subj") && rc=0 || rc=$?
gw_unavail() { logs gateway | grep -qE 'reject .*stage=rcpt .*reason=keydir-unreachable code=451 rcpt=alice@example.com'; }
if (( rc != 0 )) && grep -qE '451[- ]4\.7\.1 .*Key directory unavailable' <<<"$out" && wait_for 5 gw_unavail; then
    pass "IT3.8a annuaire arrêté, cache expiré : 451 4.7.1 au RCPT TO (jamais d'envoi en clair)"
else
    fail "IT3.8a annuaire arrêté : réponse inattendue (rc=$rc)" "$(grep -E '^<' <<<"$out" | tail -3)"
fi
dc start keydir >/dev/null 2>&1
wait_healthy keydir 60 || fail "IT3.8 annuaire non sain après redémarrage"
mb_has alice@example.com "Subject: ${subj}" && fail "IT3.8b message livré malgré l'annuaire arrêté !" \
                                            || pass "IT3.8b rien n'a été livré"

# --- IT3.9 : après rotation, seul le nouveau trousseau déchiffre -----------------------
provision_key alice@example.com
sleep "$TTL_WAIT"
id=it39-${TOKEN}
submit client-gitlab gitlab "$id" >/dev/null
prev=$(ws bash -c 'ls -d ~/.rnp/alice@example.com.* | sort | tail -1' || true)
if ws bash -c "mailbox fetch alice@example.com --match 'Subject: ${id}' --wait 40 >/tmp/${id}.eml" \
    && ws bash -c "pgpmime decrypt --home ~/.rnp/alice@example.com </tmp/${id}.eml" >/dev/null \
    && ! ws bash -c "pgpmime decrypt --home '${prev}' </tmp/${id}.eml" >/dev/null 2>&1; then
    pass "IT3.9 après rotation : message déchiffrable avec la nouvelle clé, pas avec l'ancienne"
else
    fail "IT3.9 rotation non prise en compte (ancien trousseau : ${prev})"
fi

# --- IT3.10 : destinataire externe ----------------------------------------------------
id=it310-${TOKEN}
mkmsg_in client-glpi "$id" --from glpi@example.com --to ext@partner.test --subject "${id} Ticket #1234" \
    --text "Ticket ${id}" --attach capture.bin:30000
out=$(send_eml client-glpi glpi "/tmp/${id}.eml" ext@partner.test) && rc=0 || rc=$?
if (( rc == 0 )) && received ext@partner.test "$id" "$id" && res=$(roundtrip "$id"); then
    pass "IT3.10a destinataire externe avec clé validée (ext@partner.test) : livré chiffré, ${res}"
else
    fail "IT3.10a envoi externe en échec (rc=$rc)" "${res:-$(tail -3 <<<"$out")}"
fi
out=$(submit client-glpi glpi "it310b-${TOKEN}" --to nobody@partner.test) && rc=0 || rc=$?
(( rc != 0 )) && grep -qE '550[- ]5\.7\.1 .*<nobody@partner\.test>' <<<"$out" \
    && pass "IT3.10b destinataire externe sans clé : 550 5.7.1" \
    || fail "IT3.10b destinataire externe sans clé accepté (rc=$rc)" "$(tail -3 <<<"$out")"

# --- IT3.11 : fournisseur arrêté : la file ne contient que du chiffré -----------------
id=it311-${TOKEN}
dc stop provider >/dev/null 2>&1
out=$(submit client-youtrack youtrack "$id" --body "Contenu secret ${id}-corps") && rc=0 || rc=$?
qid=$(qid_of "$out")
q=$( [[ -n $qid ]] && dc exec -T relay postcat -q "$qid" 2>&1 || true)
if (( rc == 0 )) && [[ -n $qid && $q == *"-----BEGIN PGP MESSAGE-----"* && $q != *"$id"* ]] \
    && grep -q 'multipart/encrypted' <<<"$q"; then
    pass "IT3.11a fournisseur arrêté, message ${qid} en file : postcat ne montre que du PGP/MIME (ni objet ni corps)"
else
    fail "IT3.11a contenu en clair dans la file ou message absent (rc=$rc, qid=${qid:-?})" "$(grep -m3 -E 'Subject|secret' <<<"$q")"
fi
dc start provider >/dev/null 2>&1
wait_healthy provider 90 || fail "IT3.11 fournisseur non sain après redémarrage"
dc exec -T relay postqueue -f >/dev/null 2>&1 || true
if mb_has alice@example.com "Subject: ${id}" 90; then
    pass "IT3.11b fournisseur relancé : le message en file est livré et déchiffrable"
else
    fail "IT3.11b message en file non livré après relance du fournisseur"
fi

# --- IT3.12 : objet UTF-8, pièces jointes binaires, taille proche du maximum ----------
id=it312-${TOKEN}
mkmsg_in client-gitlab "$id" --from gitlab@example.com --to alice@example.com \
    --subject "${id} Été — 測試 ✓ ünïcödé" --text "Accents : éàù — 漢字 — emoji ✓ ${id}" \
    --attach "données binaires.bin:3700000" --attach "nul.bin:0" --attach "petit.bin:1"
size=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["size"])' "$WORK/${id}.json" 2>/dev/null || true)
out=$(send_eml client-gitlab gitlab "/tmp/${id}.eml" alice@example.com) && rc=0 || rc=$?
if (( rc == 0 )) && received alice@example.com "$id" "$id" && res=$(roundtrip "$id"); then
    pass "IT3.12 objet UTF-8 (RFC 2047), pièces jointes binaires, ${size} octets (limite 5242880) : ${res}"
else
    fail "IT3.12 aller-retour inexact (${size} octets, swaks rc=$rc)" "${res:-$(grep -E '^<' <<<"$out" | tail -3)}"
fi
