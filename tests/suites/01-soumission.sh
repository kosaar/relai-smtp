# shellcheck shell=bash
# =============================================================================
#  Suite 01 — contrat d'entrée : soumission 587 (STARTTLS >= 1.2 + SASL par
#  application), liaison login <-> IP <-> expéditeur, port 25 fermé,
#  inventaire (refus de démarrage, ajout d'une application).
# =============================================================================
suite "01 — soumission 587 et identité par application"

RCPT=alice@example.com
CA=(--tls-ca-path /pki/ca.crt)

# --- IT1.1 : chaque application s'authentifie en STARTTLS (certificat vérifié) ---
for app in gitlab jenkins glpi youtrack; do
    subj="it11-${app}-${TOKEN}"
    out=$(submit "client-${app}" "$app" "$subj") && rc=0 || rc=$?
    msg=$( (( rc == 0 )) && mb_fetch "$RCPT" "Subject: ${subj}" 40 || true)
    hdr=$(headers_of <<<"$msg")
    if [[ -n $msg ]] && grep -qx "Return-Path: <${app}@example.com>" <<<"$hdr" \
        && grep -qx "From: ${app}@example.com" <<<"$hdr"; then
        pass "IT1.1 [${app}] STARTTLS vérifié + AUTH : message livré dans la BAL (enveloppe et From: = ${app}@example.com)"
    else
        fail "IT1.1 [${app}] message non livré ou expéditeur inattendu (swaks rc=$rc)" "$(tail -4 <<<"$out")"
    fi
done
rlogs=$(logs relay)
missing=""
for app in gitlab jenkins glpi youtrack; do
    grep -qE "client=[^ ]*\[10\.0\.1\.[0-9]+\], sasl_method=PLAIN, sasl_username=${app}\$" <<<"$rlogs" || missing+=" $app"
done
tls_in=$(grep -E 'TLS connection established from [^ ]*\[10\.0\.1\.10\]: TLSv1\.[23]' <<<"$rlogs" | tail -1 || true)
if [[ -z $missing && -n $tls_in ]]; then
    pass "IT1.1 logs du relai : TLS >= 1.2 et login SASL de chaque application"
    note "log: ${tls_in}"
else
    fail "IT1.1 logs du relai incomplets (logins absents :${missing:- aucun}, TLS: ${tls_in:-absent})"
fi

# --- IT1.2 : sans STARTTLS, AUTH non proposé et envoi refusé (530 5.7.0) ---------
out=$(smtp client-gitlab --server smtp-relay --port 587 --quit-after EHLO) && rc=0 || rc=$?
if (( rc == 0 )) && grep -q 'STARTTLS' <<<"$out" && ! grep -qE '250[- ]AUTH' <<<"$out"; then
    pass "IT1.2a sans STARTTLS : EHLO propose STARTTLS mais pas AUTH"
else
    fail "IT1.2a EHLO en clair inattendu (rc=$rc)" "$(grep -E '250' <<<"$out" | tr '\n' ' ')"
fi
subj="it12-${TOKEN}"
out=$(smtp client-gitlab --server smtp-relay --port 587 --from gitlab@example.com --to "$RCPT" \
    --header "Subject: ${subj}") && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '530[- ]5\.7\.0 Must issue a STARTTLS command first' <<<"$out"; then
    pass "IT1.2b sans STARTTLS : MAIL FROM refusé (530 5.7.0)"
else
    fail "IT1.2b envoi en clair non refusé (rc=$rc)" "$(tail -3 <<<"$out")"
fi
out=$(smtp client-gitlab --server smtp-relay --port 587 --auth PLAIN --auth-user gitlab \
    --auth-password "$(app_password gitlab)" --from gitlab@example.com --to "$RCPT") && rc=0 || rc=$?
if (( rc != 0 )) && ! grep -q '^ ~> AUTH' <<<"$out" && ! grep -q '235 ' <<<"$out"; then
    pass "IT1.2c sans STARTTLS : authentification impossible (mot de passe jamais envoyé en clair)"
else
    fail "IT1.2c AUTH tenté ou accepté en clair (rc=$rc)" "$(tail -3 <<<"$out")"
fi

# --- IT1.3 : TLS 1.1 refusé, TLS 1.2 et 1.3 acceptés (certificat vérifié) --------
s_client() {  # s_client <options openssl…>
    dc exec -T client-gitlab openssl s_client -connect smtp-relay:587 -starttls smtp \
        -servername smtp-relay "$@" </dev/null 2>&1
}
out=$(s_client -tls1_1 -cipher 'DEFAULT@SECLEVEL=0') && rc=0 || rc=$?
if (( rc != 0 )) && grep -q 'alert protocol version' <<<"$out" && grep -q 'Cipher is (NONE)' <<<"$out"; then
    pass "IT1.3a client limité à TLS 1.1 : poignée de main refusée"
    note "openssl: $(grep -m1 -o 'tlsv1 alert protocol version.*' <<<"$out")"
else
    fail "IT1.3a TLS 1.1 accepté (rc=$rc)" "$(grep -E 'alert|New,' <<<"$out" | tr '\n' ' ')"
fi
for v in 1_2 1_3; do
    out=$(s_client "-tls${v}" -CAfile /pki/ca.crt -verify_return_error -verify_hostname smtp-relay) && rc=0 || rc=$?
    if (( rc == 0 )) && grep -qE "TLSv${v/_/\\.}" <<<"$out" && grep -q 'Verify return code: 0 (ok)' <<<"$out"; then
        pass "IT1.3b TLS ${v/_/.} accepté, certificat smtp-relay vérifié par l'AC"
    else
        fail "IT1.3b TLS ${v/_/.} refusé ou certificat non vérifié (rc=$rc)" "$(grep -E 'Verify return|Protocol|New,' <<<"$out" | tr '\n' ' ')"
    fi
done

# --- IT1.4 : mauvais mot de passe -> 535, échec journalisé, rien de livré ---------
subj="it14-${TOKEN}"
out=$(submit client-gitlab gitlab "$subj" --auth-password "wrong-password-$RANDOM") && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '535[- ]5\.7\.8' <<<"$out"; then
    pass "IT1.4a mauvais mot de passe : 535 5.7.8"
else
    fail "IT1.4a mauvais mot de passe non refusé (rc=$rc)" "$(tail -3 <<<"$out")"
fi
auth_failed() { logs relay | grep -qE 'warning: [^ ]*\[10\.0\.1\.10\]: SASL PLAIN authentication failed: .*sasl_username=gitlab'; }
if wait_for 10 auth_failed; then
    pass "IT1.4b échec journalisé avec l'IP et le login"
    note "log: $(logs relay | grep -E 'SASL PLAIN authentication failed' | tail -1)"
else
    fail "IT1.4b échec d'authentification absent des logs"
fi

# --- IT1.5 : sans authentification (après STARTTLS) -> refusé ---------------------
subj="it15-${TOKEN}"
out=$(smtp client-gitlab --server smtp-relay --port 587 --tls --tls-verify "${CA[@]}" \
    --from gitlab@example.com --to "$RCPT" --header "Subject: ${subj}") && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '553[- ]5\.7\.1 <gitlab@example\.com>: Sender address rejected: not logged in' <<<"$out"; then
    pass "IT1.5a sans AUTH, adresse d'une application : refusé (553 5.7.1 not logged in)"
else
    fail "IT1.5a envoi sans AUTH non refusé (rc=$rc)" "$(tail -3 <<<"$out")"
fi
out=$(smtp client-gitlab --server smtp-relay --port 587 --tls --tls-verify "${CA[@]}" \
    --from someone@example.com --to "$RCPT" --header "Subject: ${subj}") && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '554[- ]5\.7\.1 <someone@example\.com>: Sender address rejected: Access denied' <<<"$out"; then
    pass "IT1.5b sans AUTH, autre adresse : refusé (554 5.7.1)"
else
    fail "IT1.5b envoi sans AUTH non refusé (rc=$rc)" "$(tail -3 <<<"$out")"
fi

# --- IT1.6 : usurpation d'expéditeur ----------------------------------------------
subj="it16a-${TOKEN}"
out=$(submit client-gitlab gitlab "$subj" --from jenkins@example.com) && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '553[- ]5\.7\.1 <jenkins@example\.com>: Sender address rejected: not owned by user gitlab' <<<"$out"; then
    pass "IT1.6a login gitlab, MAIL FROM jenkins@ : 553 5.7.1"
else
    fail "IT1.6a enveloppe usurpée non refusée (rc=$rc)" "$(tail -3 <<<"$out")"
fi
it16() {  # it16 <id> <motif journalisé> <libellé> <options swaks…>
    local id=$1 reason=$2 label=$3; shift 3
    local subj="it16${id}-${TOKEN}" out rc
    out=$(submit client-gitlab gitlab "$subj" "$@") && rc=0 || rc=$?
    if (( rc != 0 )) && grep -qE '550[- ]5\.7\.1' <<<"$out"; then
        pass "IT1.6${id} ${label} : 550 5.7.1 (passerelle)"
    else
        fail "IT1.6${id} ${label} : non refusé (rc=$rc)" "$(tail -3 <<<"$out")"
    fi
    gw_logged() { logs gateway | grep -qE "reject .*stage=data client=10\.0\.1\.10 login=gitlab reason=${reason} code=550"; }
    wait_for 5 gw_logged || fail "IT1.6${id} motif ${reason} absent des logs de la passerelle"
}
it16 b from-mismatch      "enveloppe correcte, From: jenkins@"            --h-From "Jenkins <jenkins@example.com>"
it16 c from-multiple      "deux en-têtes From:"                          --add-header "From: gitlab@example.com"
it16 d from-display-spoof "nom affiché contenant une autre adresse"      --h-From '"jenkins@example.com" <gitlab@example.com>'
sleep 2
leaked=0
for id in a b c d; do mb_has "$RCPT" "Subject: it16${id}-${TOKEN}" && leaked=1; done
(( leaked == 0 )) && pass "IT1.6e aucun message usurpé dans la BAL" || fail "IT1.6e un message usurpé a été livré !"
if logs gateway | grep -q 'Jenkins <jenkins'; then
    fail "IT1.6f la passerelle journalise le contenu des en-têtes"
else
    pass "IT1.6f journaux de la passerelle sans contenu d'en-tête (motif seulement)"
fi

# --- IT1.7 : port 25 fermé ----------------------------------------------------------
out=$(dc exec -T client-gitlab bash -c 'timeout 5 bash -c "exec 3<>/dev/tcp/smtp-relay/25" 2>&1') && rc=0 || rc=$?
if (( rc != 0 )) && grep -qi 'refused' <<<"$out"; then
    pass "IT1.7 port 25 du relai : connexion refusée"
else
    fail "IT1.7 port 25 joignable ou état inattendu (rc=$rc)" "$out"
fi

# --- IT1.8 : identifiants valides hors liste blanche -> refusé --------------------
subj="it18-${TOKEN}"
out=$(submit client-unknown gitlab "$subj") && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '554[- ]5\.7\.1' <<<"$out" && ! grep -q '^ ~> AUTH' <<<"$out"; then
    pass "IT1.8a identifiants gitlab depuis une IP non déclarée : refusé dès la connexion (554 5.7.1)"
else
    fail "IT1.8a identifiants valides acceptés hors liste blanche (rc=$rc)" "$(tail -3 <<<"$out")"
fi
out=$(submit client-jenkins gitlab "$subj") && rc=0 || rc=$?
gw_ip() { logs gateway | grep -qE 'reject .*stage=mail client=10\.0\.1\.20 login=gitlab reason=client-ip-mismatch'; }
if (( rc != 0 )) && grep -qE '550[- ]5\.7\.1' <<<"$out" && wait_for 5 gw_ip; then
    pass "IT1.8b identifiants gitlab depuis l'hôte de Jenkins : refusé (550 5.7.1, IP non liée au login)"
else
    fail "IT1.8b identifiants gitlab acceptés depuis l'IP de Jenkins (rc=$rc)" "$(tail -3 <<<"$out")"
fi
sleep 2
mb_has "$RCPT" "Subject: ${subj}" && fail "IT1.8c message livré malgré le refus !" \
                                  || pass "IT1.8c aucun message livré"

# --- IT1.9 : inventaire invalide -> démarrage refusé (FATAL) ----------------------
relay_image=$(docker inspect -f '{{.Config.Image}}' "$(cid relay)")
gateway_image=$(docker inspect -f '{{.Config.Image}}' "$(cid gateway)")
bad="$PWD/$WORK/bad"
mkdir -p "$bad/secrets"
for app in gitlab jenkins; do cp "$WORK/secrets/apps/$app" "$bad/secrets/"; done
bad_inventory() {  # bad_inventory <cas> <contenu TOML> : crée $bad/<cas>/applications.toml
    mkdir -p "$bad/$1"
    printf 'sender_domain = "example.com"\n%s\n' "$2" >"$bad/$1/applications.toml"
    chmod -R a+rX "$bad"
}
app_toml() { printf '[applications.%s]\naddress = "%s"\nclient_ips = ["%s"]\n%s\n' "$@"; }
bad_inventory doublon "$(app_toml gitlab gitlab@example.com 10.0.1.10 ''; app_toml jenkins gitlab@example.com 10.0.1.20 '')"
bad_inventory secret  "$(app_toml gitlab gitlab@example.com 10.0.1.10 ''; app_toml glpi glpi@example.com 10.0.1.40 '')"
bad_inventory domaine "$(app_toml gitlab gitlab@example.com 10.0.1.10 ''; app_toml jenkins jenkins@other.test 10.0.1.20 '')"
bad_inventory quota   "$(app_toml gitlab gitlab@example.com 10.0.1.10 'quota_per_hour = 0')"
it19() {  # it19 <cas> <motif attendu>
    start_must_fail "IT1.9 relai, $1" "$2" -v "$bad/$1:/etc/relay:ro" -v "$bad/secrets:/run/secrets/apps:ro" \
        -e RELAY_HOST=provider -e RELAY_SMTP_USERNAME=u -e RELAY_SMTP_PASSWORD=p -- "$relay_image"
}
it19 doublon "l'adresse 'gitlab@example.com' est déjà attribuée à l'application 'gitlab'"
it19 secret  "application 'glpi' : secret /run/secrets/apps/glpi absent"
it19 domaine "l'adresse 'jenkins@other.test' n'appartient pas à sender_domain 'example.com'"
it19 quota   "quota_per_hour=0 invalide"
cp "$WORK/secrets/gateway_hmac_key" "$bad/hmac_key" && chmod a+r "$bad/hmac_key"
start_must_fail "IT1.9 passerelle, adresse en double" "déjà attribuée à l'application 'gitlab'" \
    -v "$bad/doublon:/etc/relay:ro" -v "$bad/hmac_key:/run/secrets/gateway_hmac_key:ro" -- "$gateway_image"

# --- IT1.10 : ajout d'une application (entrée + secret) puis redémarrage ----------
subj="it110-before-${TOKEN}"
out=$(submit client-new newapp "$subj" --auth-password "not-yet-declared-password") && rc=0 || rc=$?
if (( rc != 0 )) && grep -qE '554[- ]5\.7\.1' <<<"$out"; then
    pass "IT1.10a application non encore déclarée (10.0.1.50) : refusée"
else
    fail "IT1.10a application non déclarée acceptée (rc=$rc)" "$(tail -3 <<<"$out")"
fi
app_toml newapp newapp@example.com 10.0.1.50 'description = "Application ajoutée par IT1.10"' >>"$WORK/config/applications.toml"
printf '%s' "$(rand 24)" >"$WORK/secrets/apps/newapp"
chmod 644 "$WORK/secrets/apps/newapp"
dc restart gateway relay >/dev/null 2>&1
if wait_healthy gateway 60 && wait_healthy relay 90; then
    pass "IT1.10b relai et passerelle redémarrés avec le nouvel inventaire"
    note "log: $(logs relay | grep 'inventaire valide' | tail -1 | cut -c1-200)"
else
    fail "IT1.10b relai ou passerelle non sains après redémarrage" "$(logs relay | tail -5)"
fi
subj="it110-new-${TOKEN}"
out=$(submit client-new newapp "$subj") && rc=0 || rc=$?
if (( rc == 0 )) && mb_has "$RCPT" "Subject: ${subj}" 40; then
    pass "IT1.10c la nouvelle application envoie : message livré"
else
    fail "IT1.10c la nouvelle application ne peut pas envoyer (rc=$rc)" "$(tail -3 <<<"$out")"
fi
ok=1
for app in gitlab jenkins glpi youtrack; do
    subj="it110-${app}-${TOKEN}"
    submit "client-${app}" "$app" "$subj" >/dev/null && mb_has "$RCPT" "Subject: ${subj}" 40 || { ok=0; note "échec : ${app}"; }
done
(( ok )) && pass "IT1.10d les applications existantes ne sont pas affectées (4/4 livrées)" \
         || fail "IT1.10d une application existante a été affectée par l'ajout"
