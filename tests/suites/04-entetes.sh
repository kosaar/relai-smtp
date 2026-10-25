# shellcheck shell=bash
# =============================================================================
#  Suite 04 — nettoyage des en-têtes (D9) : en-têtes extérieurs en liste
#  blanche, en-têtes internes (X-GitLab-*, Received d'origine…) seulement dans
#  la partie chiffrée, identifiants de message pseudonymisés par HMAC (fils
#  conservés), aucun Received ne révèle la topologie interne.
# =============================================================================
suite "04 — nettoyage des en-têtes"

ALLOWED='^(from|to|cc|date|subject|mime-version|content-type|message-id|in-reply-to|references|reply-to|auto-submitted)$'
# Marqueurs de topologie interne : VLAN Applications et backend, noms internes.
INTERNAL='10\.0\.1\.|10\.0\.3\.|internal\.lan|gitlab-web|client-|gateway|_private|_backend'
PSEUDO='^<[0-9a-f]{32}@example\.com>$'

# relay_headers / all_headers <fichier brut> : en-têtes extérieurs dépliés.
relay_headers() { tests/tools/outer-headers.py relay <"$1"; }
all_headers()   { tests/tools/outer-headers.py all <"$1"; }
hval() { sed -n "s/^$2: //Ip" <"$1" | head -1; }   # hval <fichier d'en-têtes> <nom>

# notif <id> <en-têtes supplémentaires…> : notification GitLab (fichier .eml du client)
notif() {
    local id=$1; shift
    {
        printf 'From: GitLab <gitlab@example.com>\r\nTo: alice@example.com\r\n'
        printf 'Subject: %s Pipeline #4242 failed\r\n' "$id"
        printf 'Date: %s\r\n' "$(date -uR)"
        local h; for h in "$@"; do printf '%s\r\n' "$h"; done
        printf 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
        printf 'Notification %s : le pipeline a échoué (corps UTF-8).\r\n' "$id"
    } | put_file client-gitlab "/tmp/${id}.eml"
}

# --- IT4.1 : liste blanche ; en-têtes internes seulement dans la partie chiffrée ------
id=it41-${TOKEN}
notif "$id" \
    "Message-ID: <pipeline_4242.${id}@gitlab-web-01.internal.lan>" \
    "Received: from gitlab-web-01.internal.lan (gitlab-web-01.internal.lan [10.0.1.10])" \
    "	by gitlab-mta.internal.lan (Postfix) with ESMTP id 4F2A; $(date -uR)" \
    "X-GitLab-Project: infra-secrete" \
    "X-GitLab-Pipeline-Id: 4242" \
    "X-Mailer: GitLab Mailer" \
    "X-Originating-IP: [10.0.1.10]" \
    "User-Agent: GitLab/17.0" \
    "Auto-Submitted: auto-generated" \
    "Reply-To: GitLab <gitlab@example.com>"
out=$(send_eml client-gitlab gitlab "/tmp/${id}.eml" alice@example.com) && rc=0 || rc=$?
raw41=$WORK/${id}.raw
if (( rc == 0 )) && mb_fetch alice@example.com "Subject: ${id}" 60 >"$raw41"; then
    relay_headers "$raw41" >"$WORK/${id}.relay"
    extra=$(cut -d: -f1 "$WORK/${id}.relay" | tr 'A-Z' 'a-z' | grep -vE "$ALLOWED" | sort -u | tr '\n' ' ' || true)
    leaks=$(grep -oE "$INTERNAL|X-GitLab|X-Mailer|User-Agent|infra-secrete" "$WORK/${id}.relay" | sort -u | tr '\n' ' ' || true)
    body_leak=$(grep -c -E 'X-GitLab|infra-secrete|internal\.lan' "$raw41" || true)
    if [[ -z $extra && -z $leaks && $body_leak == 0 ]]; then
        pass "IT4.1a en-têtes extérieurs ⊆ liste blanche ($(cut -d: -f1 "$WORK/${id}.relay" | tr '\n' ' ')) ; aucune IP 10.0.x interne, aucun nom interne, aucun X-GitLab-*"
    else
        fail "IT4.1a en-têtes extérieurs hors liste blanche ou fuite (hors liste : ${extra:-aucun} ; fuites : ${leaks:-aucune} ; message brut : ${body_leak})"
    fi
    mid=$(hval "$WORK/${id}.relay" Message-ID)
    [[ $mid =~ $PSEUDO && $(hval "$WORK/${id}.relay" Auto-Submitted) == auto-generated \
        && $(hval "$WORK/${id}.relay" Reply-To) == *gitlab@example.com* ]] \
        && pass "IT4.1b Message-ID pseudonymisé (${mid}), Auto-Submitted et Reply-To conservés" \
        || fail "IT4.1b Message-ID non pseudonymisé ou en-tête autorisé perdu" "$(cat "$WORK/${id}.relay")"
else
    fail "IT4.1a notification non livrée (rc=$rc)" "$(tail -3 <<<"$out")"
    fail "IT4.1b notification non livrée"
fi
plain=$(mb_plain alice@example.com "Subject: ${id}" 0 || true)
if grep -q '^X-GitLab-Project: infra-secrete' <<<"$plain" && grep -q '^X-GitLab-Pipeline-Id: 4242' <<<"$plain" \
    && grep -q "^Message-ID: <pipeline_4242.${id}@gitlab-web-01.internal.lan>" <<<"$plain" \
    && grep -q '^Received: from gitlab-web-01.internal.lan' <<<"$plain" && grep -q '^X-Mailer: GitLab Mailer' <<<"$plain"; then
    pass "IT4.1c partie déchiffrée : X-GitLab-*, X-Mailer, Received et Message-ID d'origine présents"
else
    fail "IT4.1c en-têtes d'origine absents de la partie déchiffrée" "$(headers_of <<<"$plain" | head -20)"
fi

# --- IT4.2 : fil de discussion conservé (References pseudonymisés identiques) ---------
ida=it42a-${TOKEN} idb=it42b-${TOKEN} idc=it42c-${TOKEN}
root="<issue_77.${TOKEN}@gitlab-web-01.internal.lan>"
notif "$ida" "Message-ID: ${root}"
out=$(send_eml client-gitlab gitlab "/tmp/${ida}.eml" alice@example.com) && rca=0 || rca=$?
# La pseudonymisation ne dépend que de la clé HMAC : identique après redémarrage.
dc restart gateway >/dev/null 2>&1
wait_healthy gateway 60 || fail "IT4.2 passerelle non saine après redémarrage"
notif "$idb" "Message-ID: <note_1.${TOKEN}@gitlab-web-01.internal.lan>" "In-Reply-To: ${root}" \
    "References: ${root}"
out=$(send_eml client-gitlab gitlab "/tmp/${idb}.eml" alice@example.com) && rcb=0 || rcb=$?
notif "$idc" "Message-ID: <issue_78.${TOKEN}@gitlab-web-01.internal.lan>"
send_eml client-gitlab gitlab "/tmp/${idc}.eml" alice@example.com >/dev/null || true
if (( rca == 0 && rcb == 0 )) && mb_fetch alice@example.com "Subject: ${ida}" 60 >"$WORK/${ida}.raw" \
    && mb_fetch alice@example.com "Subject: ${idb}" 60 >"$WORK/${idb}.raw" \
    && mb_fetch alice@example.com "Subject: ${idc}" 60 >"$WORK/${idc}.raw"; then
    for i in "$ida" "$idb" "$idc"; do relay_headers "$WORK/${i}.raw" >"$WORK/${i}.relay"; done
    mida=$(hval "$WORK/${ida}.relay" Message-ID)
    midb=$(hval "$WORK/${idb}.relay" Message-ID)
    midc=$(hval "$WORK/${idc}.relay" Message-ID)
    irt=$(hval "$WORK/${idb}.relay" In-Reply-To)
    refs=$(hval "$WORK/${idb}.relay" References)
    if [[ $mida =~ $PSEUDO && $irt == "$mida" && $refs == "$mida" && $midb =~ $PSEUDO \
          && $midb != "$mida" && $midc != "$mida" ]]; then
        pass "IT4.2a réponse : In-Reply-To et References = Message-ID pseudonymisé du premier message (${mida}), même après redémarrage ; autre fil distinct"
    else
        fail "IT4.2a fil rompu" "A=${mida} B=${midb} C=${midc} In-Reply-To=${irt} References=${refs}"
    fi
    plainb=$(mb_plain alice@example.com "Subject: ${idb}" 0 || true)
    grep -qF "References: ${root}" <<<"$plainb" && grep -qF "In-Reply-To: ${root}" <<<"$plainb" \
        && pass "IT4.2b partie déchiffrée : References et In-Reply-To d'origine conservés" \
        || fail "IT4.2b références d'origine absentes de la partie déchiffrée" "$(headers_of <<<"$plainb" | head -12)"
else
    fail "IT4.2a messages du fil non livrés (rc=${rca}/${rcb})" "$(tail -3 <<<"$out")"
    fail "IT4.2b messages du fil non livrés"
fi

# --- IT4.3 : aucun Received ne révèle la topologie interne ---------------------------
if [[ -s $raw41 ]]; then
    relay_rcv=$(grep -ci '^Received:' "$WORK/${id}.relay" || true)
    all_rcv=$(all_headers "$raw41" | grep -i '^Received:' || true)
    foreign=$(grep -viE 'by (provider|smtp\.provider\.test) ' <<<"$all_rcv" || true)
    internal=$(grep -oE "$INTERNAL" <<<"$all_rcv" | sort -u | tr '\n' ' ' || true)
    if [[ $relay_rcv == 0 && -n $all_rcv && -z $foreign && -z $internal ]]; then
        pass "IT4.3 aucun Received transmis par le relai ($(grep -c . <<<"$all_rcv") ajouté(s) par le fournisseur, sans IP ni nom interne)"
    else
        fail "IT4.3 Received révélant la topologie interne (relai : ${relay_rcv}, marqueurs : ${internal:-aucun})" "$all_rcv"
    fi
    # Le relai retire bien son propre Received en sortie (smtp_header_checks).
    note "relai : $(dc exec -T relay postconf -h smtp_header_checks 2>/dev/null)"
else
    fail "IT4.3 pas de message à analyser (IT4.1 en échec)"
fi

# --- IT4.4 : clé de pseudonymisation absente ou trop courte : démarrage refusé -------
gw_image=$(docker inspect -f '{{.Config.Image}}' "$(cid gateway)")
hk="$PWD/$WORK/hmac"
mkdir -p "$hk" && printf 'trop-courte' >"$hk/short" && chmod -R a+rX "$hk"
start_must_fail "IT4.4 passerelle, secret gateway_hmac_key absent" "clé HMAC manquante" \
    -v "$PWD/$WORK/config:/etc/relay:ro" -- "$gw_image"
start_must_fail "IT4.4 passerelle, secret gateway_hmac_key trop court" "au moins 32 caractères" \
    -v "$PWD/$WORK/config:/etc/relay:ro" -v "$hk/short:/run/secrets/gateway_hmac_key:ro" -- "$gw_image"
