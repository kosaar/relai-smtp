# shellcheck shell=bash
# =============================================================================
#  Suite 06 — contrôle du contenu sortant (D8) : règles de
#  config/content-rules.toml appliquées par la passerelle avant chiffrement,
#  au texte décodé (corps, pièces jointes base64). Refus 550 5.7.1 avec
#  l'identifiant de règle, rien de livré, journaux sans contenu.
# =============================================================================
suite "06 — contrôle du contenu sortant"

# content_case <cas> <id> [secret] : construit le message et le soumet (GitLab -> alice).
content_case() {
    tests/tools/content-msg.py "$1" "$2" "${3:-}" | put_file client-gitlab "/tmp/$2.eml"
    send_eml client-gitlab gitlab "/tmp/$2.eml" alice@example.com
}
# blocked <id> <règle> <secret> <sortie swaks> <rc> : refus, rien de livré, logs sans contenu.
blocked() {
    local id=$1 rule=$2 secret=$3 out=$4 rc=$5 logs
    logs=$(logs gateway; logs relay)
    if (( rc == 0 )) || ! grep -qE "550[- ]5\.7\.1 Message blocked by content policy \(rule ${rule}\)" <<<"$out"; then
        echo "réponse inattendue (rc=${rc}) : $(grep -E '^<' <<<"$out" | tail -2)"; return 1
    fi
    grep -qE "reject .*stage=data .*login=gitlab reason=content:${rule} code=550" <<<"$logs" \
        || { echo "refus non journalisé"; return 1; }
    [[ -z $secret ]] || ! grep -qF -- "$secret" <<<"$logs" || { echo "contenu dans les journaux !"; return 1; }
    ! mb_has alice@example.com "Subject: ${id}" 5 || { echo "message livré !"; return 1; }
}

# --- IT6.1 : bloc de clé privée dans le corps ---------------------------------------
id=it61-${TOKEN}
key_body="b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAt${TOKEN//-/}"
out=$(content_case privkey "$id" "$key_body") && rc=0 || rc=$?
if why=$(blocked "$id" private-key "$key_body" "$out" "$rc"); then
    pass "IT6.1 bloc « BEGIN OPENSSH PRIVATE KEY » : 550 5.7.1 (rule private-key), rien de livré, journaux sans contenu"
else
    fail "IT6.1 clé privée non bloquée correctement : ${why}"
fi

# --- IT6.2 : jeton dans une pièce jointe encodée en base64 -----------------------------
id=it62-${TOKEN}
printf -v gl_token 'glpat-%s' "$(rand 20)"   # printf : pas de SIGPIPE (pipefail)
out=$(content_case token "$id" "$gl_token") && rc=0 || rc=$?
if [[ $(tests/tools/content-msg.py token "$id" "$gl_token" | grep -c -F -- "$gl_token" || true) == 0 ]] \
    && why=$(blocked "$id" gitlab-token "$gl_token" "$out" "$rc"); then
    pass "IT6.2 jeton GitLab dans une pièce jointe base64 (absent du message brut) : détecté après décodage, refusé (rule gitlab-token)"
else
    fail "IT6.2 jeton en pièce jointe non bloqué correctement : ${why:-jeton visible en clair dans le message de test}"
fi

# --- IT6.3 : pièce jointe exécutable -----------------------------------------------------
id=it63-${TOKEN}
out=$(content_case exe "$id") && rc=0 || rc=$?
if why=$(blocked "$id" forbidden-extension "" "$out" "$rc"); then
    pass "IT6.3 pièce jointe outil.exe : refusée (rule forbidden-extension)"
else
    fail "IT6.3 pièce jointe .exe non bloquée correctement : ${why}"
fi

# --- IT6.4 : message sain livré ; règles invalides : démarrage refusé -------------------
id=it64-${TOKEN}
out=$(content_case clean "$id") && rc=0 || rc=$?
if (( rc == 0 )) && plain=$(mb_plain alice@example.com "Subject: ${id}" 60) && grep -q 'filename="rapport.pdf"' <<<"$plain"; then
    pass "IT6.4a message sain (texte, PDF joint) : livré chiffré et déchiffrable"
else
    fail "IT6.4a message sain non livré (rc=$rc)" "$(tail -3 <<<"$out")"
fi
gw_image=$(docker inspect -f '{{.Config.Image}}' "$(cid gateway)")
rules_dir="$PWD/$WORK/rules"
mkdir -p "$rules_dir"
cp "$WORK/secrets/gateway_hmac_key" "$rules_dir/hmac_key"
printf 'version = 1\n[[patterns]]\nid = "casse"\nregex = "(non fermée"\n' >"$rules_dir/bad.toml"
chmod -R a+rX "$rules_dir"
start_must_fail "IT6.4b règles de contenu invalides (regex)" "('casse') : regex invalide" \
    -v "$PWD/$WORK/config:/etc/relay:ro" -v "$rules_dir:/rules:ro" -e GATEWAY_CONTENT_RULES_FILE=/rules/bad.toml \
    -v "$rules_dir/hmac_key:/run/secrets/gateway_hmac_key:ro" -- "$gw_image"
start_must_fail "IT6.4b règles de contenu absentes" "illisibles" \
    -v "$PWD/$WORK/config:/etc/relay:ro" -e GATEWAY_CONTENT_RULES_FILE=/rules/absent.toml \
    -v "$rules_dir/hmac_key:/run/secrets/gateway_hmac_key:ro" -- "$gw_image"
