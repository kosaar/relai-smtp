# shellcheck shell=bash
# Fonctions communes à entrypoint.sh et relay-reload-allowlist.
# Fichier destiné à être "sourcé", pas exécuté.

log()  { printf '%s relay-entrypoint[%s]: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$*"; }
warn() { log "WARNING: $*" >&2; }
die()  { log "FATAL: $*" >&2; log "FATAL: refus de démarrer (configuration invalide)." >&2; exit 1; }

# --- Validation d'adresses IP ------------------------------------------------

is_ipv4() {
    local ip=$1 o
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do
        # Pas de zéros non significatifs (ambigus : octal pour certaines libs).
        [[ $o =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( o <= 255 )) || return 1
    done
}

is_ipv6() {
    local ip=${1,,} head tail part g n=0
    local -a groups
    [[ $ip =~ ^[0-9a-f:]+$ ]] || return 1
    [[ $ip != *:::* ]] || return 1
    if [[ $ip == *::* ]]; then
        # Un seul "::" autorisé.
        [[ ${ip#*::} != *::* ]] || return 1
        head=${ip%%::*}; tail=${ip#*::}
    else
        head=$ip; tail=""
    fi
    for part in "$head" "$tail"; do
        [[ -z $part ]] && continue
        [[ $part != :* && $part != *: ]] || return 1
        IFS=: read -r -a groups <<<"$part"
        for g in "${groups[@]}"; do
            [[ $g =~ ^[0-9a-f]{1,4}$ ]] || return 1
            n=$((n + 1))
        done
    done
    if [[ $ip == *::* ]]; then (( n <= 7 )); else (( n == 8 )); fi
}

# --- Liste blanche ------------------------------------------------------------
# Sources (union) : variable ALLOWED_CLIENT_IPS (séparateurs : virgule,
# point-virgule, espaces) et fichier ALLOWED_CLIENT_IPS_FILE (une IP par ligne,
# commentaires "#" autorisés). Chaque entrée DOIT être une adresse d'hôte
# unique : les notations CIDR/plages sont refusées pour éviter d'ouvrir par
# erreur un sous-réseau entier.
#
# Résultat : variables globales MYNETWORKS (format Postfix), ALLOWED_LIST
# (lisible) et HAS_IPV6 (0/1). Termine le processus en cas d'erreur.
build_allowlist() {
    local raw="" entry ip
    local -a entries=() seen=() networks=()
    HAS_IPV6=0

    if [[ -n ${ALLOWED_CLIENT_IPS:-} ]]; then
        raw+="${ALLOWED_CLIENT_IPS}"$'\n'
    fi
    if [[ -n ${ALLOWED_CLIENT_IPS_FILE:-} ]]; then
        [[ -r $ALLOWED_CLIENT_IPS_FILE ]] \
            || die "ALLOWED_CLIENT_IPS_FILE=${ALLOWED_CLIENT_IPS_FILE} introuvable ou illisible."
        raw+="$(sed -e 's/#.*$//' "$ALLOWED_CLIENT_IPS_FILE")"$'\n'
    fi

    read -r -d '' -a entries < <(printf '%s' "$raw" | tr ',;\t\r' '    ' ; printf '\0') || true
    (( ${#entries[@]} > 0 )) \
        || die "ALLOWED_CLIENT_IPS (ou ALLOWED_CLIENT_IPS_FILE) est vide : au moins une IP d'application doit être déclarée (ex. ALLOWED_CLIENT_IPS=\"10.0.1.10,10.0.1.20\")."

    for entry in "${entries[@]}"; do
        ip=${entry#[}; ip=${ip%]}
        if [[ $ip == */* ]]; then
            die "Entrée '${entry}' refusée : seules des adresses d'hôte uniques sont acceptées (pas de CIDR/sous-réseau). Le préfixe /32 ou /128 est ajouté automatiquement."
        elif is_ipv4 "$ip"; then
            [[ $ip != 0.0.0.0 && $ip != 255.255.255.255 ]] \
                || die "Entrée '${entry}' refusée : adresse non spécifique/diffusion."
            ip="${ip}/32"
        elif is_ipv6 "$ip"; then
            [[ ${ip,,} != "::" ]] || die "Entrée '${entry}' refusée : adresse non spécifique."
            ip="[${ip,,}]/128"
            HAS_IPV6=1
        else
            die "Entrée '${entry}' de la liste blanche invalide : ce n'est pas une adresse IPv4 ou IPv6."
        fi
        if [[ " ${seen[*]-} " != *" ${ip} "* ]]; then
            seen+=("$ip")
            networks+=("$ip")
        fi
    done

    ALLOWED_LIST="${networks[*]}"
    # Boucle locale : nécessaire aux opérations internes au conteneur
    # (healthcheck, tests manuels via "docker exec"). Ce n'est pas un réseau.
    MYNETWORKS="127.0.0.1/32 ${networks[*]}"
    if (( HAS_IPV6 )); then
        MYNETWORKS="127.0.0.1/32 [::1]/128 ${networks[*]}"
    fi
}
