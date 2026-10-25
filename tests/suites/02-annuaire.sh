# shellcheck shell=bash
# =============================================================================
#  Suite 02 — annuaire de clés (keydir) : dépôt HTTPS depuis le poste (clé
#  générée par RNP), validation par l'administrateur, publication WKD (URL
#  calculée par gpg-wks-client, clé relue par GnuPG), refus motivés, rotation,
#  révocation, TLS, persistance.
#  État laissé pour les suites suivantes : clés validées pour alice@ (après
#  rotation), bob@ et ext@partner.test (privées dans le poste, RNP) ; aucune
#  clé pour carol@.
# =============================================================================
suite "02 — annuaire de clés publiques (keydir)"

ws()    { dc exec -T workstation "$@"; }
admin() { dc exec -T keydir keydir-admin "$@"; }
# deposit <adresse> <commande produisant la clé> : sortie de « keys deposit »
deposit() { local email=$1; shift; ws bash -c "$* | keys deposit ${email}"; }
http_code() { sed -n 's/^HTTP_CODE=//p' <<<"$1"; }
json_state() { head -1 <<<"$1" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null; }
wkd_fpr() { ws keys wkd-show "$1" 2>/dev/null | awk '{print $1}'; }

# Clés publiées au démarrage (run-tests.sh) : alice@, bob@, ext@partner.test.
fpr_alice=$(ws keys fpr alice@example.com)

# --- IT2.1 : clé générée par RNP, déposée en HTTPS : en attente, absente du WKD ---
fpr_frank=$(ws keys gen frank@example.com)
out=$(deposit frank@example.com keys export frank@example.com)
st=$(ws keys status frank@example.com)
wkd_out=$(ws keys wkd frank@example.com 2>&1 >/dev/null) && wkd_rc=0 || wkd_rc=$?
if [[ $(http_code "$out") == 202 && $(json_state "$st") == pending && $st == *"$fpr_frank"* ]] \
    && (( wkd_rc == 1 )) && [[ $wkd_out == *"HTTP 404"* ]]; then
    pass "IT2.1 clé RNP de frank déposée en HTTPS (certificat vérifié) : état « pending », WKD 404"
    note "empreinte (RNP) : ${fpr_frank}"
else
    fail "IT2.1 dépôt inattendu (dépôt : $(http_code "$out"), état : $(json_state "$st"), WKD : ${wkd_out})" "$out"
fi

# --- IT2.2 : validation par l'administrateur (empreinte comparée hors bande) -----
out=$(admin approve frank@example.com 0000000000000000000000000000000000000000 2>&1) && rc=0 || rc=$?
if (( rc != 0 )) && [[ $out == *"aucune clé en attente"* ]] && [[ -z $(wkd_fpr frank@example.com) ]]; then
    pass "IT2.2a validation avec une empreinte différente : refusée, rien de publié"
else
    fail "IT2.2a validation avec une mauvaise empreinte acceptée (rc=$rc)" "$out"
fi
admin approve frank@example.com "$fpr_frank" >/dev/null
show=$(ws keys wkd-show frank@example.com || true)
if [[ $(awk '{print $1}' <<<"$show") == "$fpr_frank" && $(awk '{print $3}' <<<"$show") == frank@example.com ]]; then
    pass "IT2.2b après validation, le WKD sert la clé : empreinte identique à celle du poste (GnuPG lit la clé RNP)"
    note "WKD : $(ws keys wkd-url frank@example.com)"
else
    fail "IT2.2b le WKD ne sert pas la clé attendue" "attendu ${fpr_frank}, obtenu : ${show}"
fi
ok=1
for email in alice@example.com bob@example.com ext@partner.test; do
    [[ $(wkd_fpr "$email") == "$(ws keys fpr "$email")" ]] || { ok=0; note "écart : ${email}"; }
done
(( ok )) && pass "IT2.2c clés d'alice, bob et ext@partner.test (second domaine) servies par le WKD, identiques à celles du poste" \
         || fail "IT2.2c une clé publiée au démarrage n'est pas servie correctement"

# --- IT2.3 : dépôts refusés (motif explicite, état inchangé) -----------------------
it23() {  # it23 <libellé> <adresse> <motif attendu> <commande produisant le contenu>
    local label=$1 email=$2 expect=$3; shift 3
    local out
    out=$(deposit "$email" "$@")
    if [[ $(http_code "$out") == 422 && $out == *"$expect"* ]]; then
        pass "IT2.3 ${label} : refusé (422)"
        note "$(head -1 <<<"$out")"
    else
        fail "IT2.3 ${label} : non refusé ou motif inattendu (HTTP $(http_code "$out"))" "$out"
    fi
}
it23 "sans sous-clé de chiffrement" alice@example.com "aucune sous-clé de chiffrement" keys bad nosub alice@example.com
it23 "clé expirée"                  alice@example.com "clé expirée"                   keys bad expired alice@example.com
it23 "RSA 1024"                     alice@example.com "RSA 1024"                      keys bad rsa1024 alice@example.com
ws keys gen-rsa rsa2048@example.com 2048 >/dev/null
it23 "RSA 2048 (défaut de RNP)"     rsa2048@example.com "RSA 2048"                    keys export rsa2048@example.com
it23 "UID différent"                carol@example.com "aucune identité (UID) valide pour carol@example.com" keys export bob@example.com
it23 "contenu invalide"             alice@example.com "contenu illisible"             echo "ceci n est pas une cle"
it23 "domaine non géré"             alice@other.test "domaine 'other.test' non géré"  keys export alice@example.com
ws keys gen-rsa erin@example.com 3072 >/dev/null
out=$(deposit erin@example.com keys export erin@example.com)
[[ $(http_code "$out") == 202 ]] && pass "IT2.3 RSA 3072 : accepté (en attente)" \
                                 || fail "IT2.3 RSA 3072 refusé" "$out"
st=$(ws keys status carol@example.com)
if [[ $(wkd_fpr alice@example.com) == "$fpr_alice" && $(json_state "$st") == none ]]; then
    pass "IT2.3 après les refus : clé d'alice inchangée, carol toujours sans clé"
else
    fail "IT2.3 un dépôt refusé a modifié l'annuaire" "$st"
fi

# --- IT2.4 : rotation -----------------------------------------------------------
fpr_alice2=$(ws keys gen alice@example.com)
out=$(deposit alice@example.com keys export alice@example.com)
before=$(wkd_fpr alice@example.com)
admin approve alice@example.com "$fpr_alice2" >/dev/null
after=$(wkd_fpr alice@example.com)
states=$(admin list | awk -v a="$fpr_alice" -v b="$fpr_alice2" '$3==a{x=$2} $3==b{y=$2} END{print x, y}')
if [[ $(http_code "$out") == 202 && $before == "$fpr_alice" && $after == "$fpr_alice2" && $states == "superseded approved" ]]; then
    pass "IT2.4 rotation : l'ancienne clé reste servie jusqu'à la validation, puis le WKD ne sert que la nouvelle"
else
    fail "IT2.4 rotation incorrecte (avant : ${before}, après : ${after}, états : ${states})"
fi
# shellcheck disable=SC2016  # développé dans le conteneur
npub=$(ws bash -c 'h=$(mktemp -d); keys wkd alice@example.com | gpg --homedir "$h" --batch --with-colons --show-keys 2>/dev/null' | grep -c '^pub' || true)
if [[ $npub == 1 ]]; then
    pass "IT2.4 le WKD ne sert qu'une seule clé (la nouvelle)"
else
    fail "IT2.4 le WKD sert ${npub} clé(s) pour alice"
fi

# --- IT2.5 : certificat de révocation appliqué immédiatement, sans validation -----
f_dave=$(ws keys gen dave@example.com)
deposit dave@example.com keys export dave@example.com >/dev/null
admin approve dave@example.com "$f_dave" >/dev/null
valid_before=$(ws keys wkd-show dave@example.com | awk '{print $2}')
out=$(deposit dave@example.com keys revcert dave@example.com)
show=$(ws keys wkd-show dave@example.com || true)
st=$(ws keys status dave@example.com)
if [[ $(http_code "$out") == 200 && $(json_state "$out") == revoked && $valid_before != r \
    && $(awk '{print $1, $2}' <<<"$show") == "$f_dave r" && $(json_state "$st") == revoked ]]; then
    pass "IT2.5 certificat de révocation (RNP) appliqué immédiatement : le WKD sert la clé marquée révoquée (GnuPG : « r »)"
else
    fail "IT2.5 révocation non appliquée (dépôt : $(http_code "$out"), WKD : ${show}, état : $(json_state "$st"))" "$out"
fi
out=$(deposit alice@example.com keys revcert dave@example.com)
if [[ $(http_code "$out") == 422 && $(wkd_fpr alice@example.com) == "$fpr_alice2" ]]; then
    pass "IT2.5 certificat de révocation d'une autre clé : refusé, clé d'alice intacte"
else
    fail "IT2.5 certificat étranger accepté (HTTP $(http_code "$out"))" "$out"
fi

# --- IT2.6 : HTTP en clair et TLS < 1.2 refusés ------------------------------------
out=$(ws curl -sS --max-time 10 http://keydir:8443/healthz 2>&1) && rc=0 || rc=$?
if (( rc != 0 )) && [[ $out != ok* ]]; then
    pass "IT2.6a HTTP en clair : aucune réponse (curl rc=$rc)"
else
    fail "IT2.6a l'annuaire répond en clair" "$out"
fi
tls_refused() { logs keydir | grep -qE 'tls refused src=10\.0\.2\.50'; }
wait_for 5 tls_refused && pass "IT2.6b tentative en clair journalisée (tls refused)" \
                       || fail "IT2.6b tentative en clair non journalisée"
out=$(ws curl -sS --max-time 10 --cacert /pki/ca.crt --tlsv1.1 --tls-max 1.1 --ciphers 'DEFAULT@SECLEVEL=0' \
    https://keydir:8443/healthz 2>&1) && rc=0 || rc=$?
if (( rc != 0 )) && [[ $out == *"alert protocol version"* || $out == *"unsupported protocol"* || $out == *"no protocols available"* ]]; then
    pass "IT2.6c client limité à TLS 1.1 : refusé"
    note "curl: ${out:0:150}"
else
    fail "IT2.6c TLS 1.1 accepté ou erreur inattendue (rc=$rc)" "$out"
fi
ok=1
for v in 1.2 1.3; do
    [[ $(ws curl -sS --max-time 10 --cacert /pki/ca.crt --tlsv$v --tls-max $v https://keydir:8443/healthz 2>&1) == ok ]] || ok=0
done
[[ $(ws curl -sS --max-time 10 --cacert /pki/ca.crt https://openpgpkey.example.com:8443/healthz 2>&1) == ok ]] || ok=0
(( ok )) && pass "IT2.6d TLS 1.2 et 1.3 acceptés, certificat vérifié (keydir et openpgpkey.example.com)" \
         || fail "IT2.6d TLS 1.2/1.3 ou vérification du certificat en échec"

# --- IT2.7 : état conservé après redémarrage --------------------------------------
dc restart keydir >/dev/null 2>&1
if wait_healthy keydir 60 \
    && [[ $(wkd_fpr alice@example.com) == "$fpr_alice2" && $(wkd_fpr bob@example.com) != "" ]] \
    && [[ $(json_state "$(ws keys status erin@example.com)") == pending ]] \
    && [[ $(json_state "$(ws keys status dave@example.com)") == revoked ]]; then
    pass "IT2.7 après redémarrage : clés validées servies, clé en attente toujours en attente, révocation conservée"
else
    fail "IT2.7 état perdu après redémarrage" "$(admin list 2>&1 | tail -8)"
fi
audit=$(admin audit --limit 200)
if grep -qE 'approve +alice@example.com' <<<"$audit" && grep -qE 'revoke +dave@example.com .*revoked:certificate' <<<"$audit" \
    && grep -qE 'deposit +alice@example.com .*refused:' <<<"$audit" && ! grep -q 'BEGIN PGP' <<<"$audit"; then
    pass "IT2.7 journal d'audit : dépôts, refus, validations et révocations (métadonnées seulement)"
else
    fail "IT2.7 journal d'audit incomplet" "$(head -5 <<<"$audit")"
fi
