#!/usr/bin/env bash
# =============================================================================
#  Entrypoint du relai SMTP.
#  1. lit et valide la configuration (variables d'environnement + secrets) ;
#  2. génère /etc/postfix (main.cf, master.cf, réécriture, identifiants) ;
#  3. lance Postfix au premier plan ("postfix start-fg", logs sur stdout).
#  Toute valeur absente ou invalide => arrêt immédiat (code 1), jamais de
#  fonctionnement dégradé ou "ouvert".
# =============================================================================
set -Eeuo pipefail
umask 022

# shellcheck source=scripts/relay-lib.sh
source /usr/local/lib/relay-lib.sh

TEMPLATES=/usr/local/share/relay/templates
PF=/etc/postfix

# --- Lecture d'un secret ---------------------------------------------------------
# Ordre de priorité : <NOM>_FILE (chemin explicite) > /run/secrets/<nom> (Docker
# secret) > variable <NOM> (repli .env, déconseillé).
read_secret() {
    local var=$1 default_file=$2 file_var="${1}_FILE" file value
    file=${!file_var:-}
    if [[ -n $file ]]; then
        [[ -r $file ]] || die "${file_var}=${file} : fichier introuvable ou illisible."
        value=$(<"$file")
    elif [[ -r $default_file ]]; then
        value=$(<"$default_file")
    elif [[ -n ${!var:-} ]]; then
        warn "${var} lu depuis une variable d'environnement : préférer un Docker secret (${default_file})."
        value=${!var}
    else
        die "${var} manquant : fournir le secret ${default_file} (ou ${file_var})."
    fi
    # Retire un éventuel saut de ligne final (echo > fichier).
    value=${value%$'\n'}; value=${value%$'\r'}
    [[ -n $value ]] || die "${var} est vide."
    [[ $value != *$'\n'* ]] || die "${var} ne doit tenir que sur une ligne."
    printf -v "$var" '%s' "$value"
}

render() {  # render <template> <destination> : remplace les @@VAR@@
    local line var
    while IFS= read -r line || [[ -n $line ]]; do
        while [[ $line =~ @@([A-Z0-9_]+)@@ ]]; do
            var=${BASH_REMATCH[1]}
            line=${line//"@@${var}@@"/"${!var}"}
        done
        printf '%s\n' "$line"
    done <"$1" >"$2"
}

re_domain='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
re_host='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
re_local='^[A-Za-z0-9!#$%&*+/=?^_`{|}~.-]+$'

is_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

configure() {
    # ---- Liste blanche (validée en premier : c'est l'exigence de sécurité n°1)
    build_allowlist

    # ---- Domaine / adresse d'expédition
    SENDER_DOMAIN=${SENDER_DOMAIN:-}
    SENDER_DOMAIN=${SENDER_DOMAIN,,}
    [[ -n $SENDER_DOMAIN ]] || die "SENDER_DOMAIN est obligatoire (ex. example.com)."
    [[ $SENDER_DOMAIN =~ $re_domain ]] || die "SENDER_DOMAIN='${SENDER_DOMAIN}' n'est pas un nom de domaine valide."

    SENDER_ADDRESS=${SENDER_ADDRESS:-noreply@${SENDER_DOMAIN}}
    local s_local=${SENDER_ADDRESS%@*} s_domain=${SENDER_ADDRESS##*@}
    s_domain=${s_domain,,}
    [[ $SENDER_ADDRESS == *@* && $s_local =~ $re_local && $s_local != .* && $s_local != *. ]] \
        || die "SENDER_ADDRESS='${SENDER_ADDRESS}' n'est pas une adresse email valide."
    [[ $s_domain == "$SENDER_DOMAIN" || $s_domain == *".${SENDER_DOMAIN}" ]] \
        || die "SENDER_ADDRESS='${SENDER_ADDRESS}' n'appartient pas à SENDER_DOMAIN='${SENDER_DOMAIN}'."
    SENDER_ADDRESS="${s_local}@${s_domain}"

    SENDER_REWRITE_MODE=${SENDER_REWRITE_MODE:-always}
    [[ $SENDER_REWRITE_MODE =~ ^(always|foreign)$ ]] \
        || die "SENDER_REWRITE_MODE='${SENDER_REWRITE_MODE}' invalide (always | foreign)."

    RELAY_HOSTNAME=${RELAY_HOSTNAME:-relay.${SENDER_DOMAIN}}
    RELAY_HOSTNAME=${RELAY_HOSTNAME,,}
    [[ $RELAY_HOSTNAME =~ $re_domain ]] || die "RELAY_HOSTNAME='${RELAY_HOSTNAME}' invalide (FQDN attendu)."

    # ---- Fournisseur cloud
    RELAY_HOST=${RELAY_HOST:-}
    [[ -n $RELAY_HOST ]] || die "RELAY_HOST est obligatoire (MTA du fournisseur, ex. email-smtp.eu-west-1.amazonaws.com)."
    [[ $RELAY_HOST =~ $re_host ]] || is_ipv4 "$RELAY_HOST" \
        || die "RELAY_HOST='${RELAY_HOST}' n'est pas un nom d'hôte valide."
    RELAY_PORT=${RELAY_PORT:-587}
    is_port "$RELAY_PORT" || die "RELAY_PORT='${RELAY_PORT}' invalide."

    RELAY_TLS_WRAPPERMODE=${RELAY_TLS_WRAPPERMODE:-auto}
    case $RELAY_TLS_WRAPPERMODE in
        auto) if [[ $RELAY_PORT == 465 ]]; then RELAY_TLS_WRAPPERMODE=yes; else RELAY_TLS_WRAPPERMODE=no; fi ;;
        yes|no) ;;
        *) die "RELAY_TLS_WRAPPERMODE='${RELAY_TLS_WRAPPERMODE}' invalide (auto | yes | no)." ;;
    esac

    RELAY_TLS_SECURITY_LEVEL=${RELAY_TLS_SECURITY_LEVEL:-secure}
    [[ $RELAY_TLS_SECURITY_LEVEL =~ ^(encrypt|secure)$ ]] \
        || die "RELAY_TLS_SECURITY_LEVEL='${RELAY_TLS_SECURITY_LEVEL}' refusé : TLS obligatoire (encrypt | secure)."
    RELAY_TLS_CA_FILE=${RELAY_TLS_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}
    [[ -r $RELAY_TLS_CA_FILE ]] || die "RELAY_TLS_CA_FILE='${RELAY_TLS_CA_FILE}' introuvable ou illisible."

    RELAY_SASL_MECHANISMS=${RELAY_SASL_MECHANISMS:-plain, login}
    [[ $RELAY_SASL_MECHANISMS =~ ^[A-Za-z0-9,\ _-]+$ ]] \
        || die "RELAY_SASL_MECHANISMS='${RELAY_SASL_MECHANISMS}' invalide."

    read_secret RELAY_SMTP_USERNAME /run/secrets/relay_smtp_username
    read_secret RELAY_SMTP_PASSWORD /run/secrets/relay_smtp_password
    [[ $RELAY_SMTP_USERNAME != *[[:space:]]* ]] || die "RELAY_SMTP_USERNAME ne doit pas contenir d'espace."
    [[ $RELAY_SMTP_USERNAME != *:* ]] || die "RELAY_SMTP_USERNAME ne doit pas contenir ':'."

    # ---- Côté applications
    RELAY_LISTEN_PORT=${RELAY_LISTEN_PORT:-25}
    is_port "$RELAY_LISTEN_PORT" || die "RELAY_LISTEN_PORT='${RELAY_LISTEN_PORT}' invalide."

    MESSAGE_SIZE_LIMIT=${MESSAGE_SIZE_LIMIT:-10240000}
    [[ $MESSAGE_SIZE_LIMIT =~ ^[0-9]+$ ]] && (( MESSAGE_SIZE_LIMIT >= 102400 )) \
        || die "MESSAGE_SIZE_LIMIT='${MESSAGE_SIZE_LIMIT}' invalide (octets, >= 102400)."

    QUEUE_LIFETIME=${QUEUE_LIFETIME:-5d}
    [[ $QUEUE_LIFETIME =~ ^[0-9]+[smhdw]$ ]] || die "QUEUE_LIFETIME='${QUEUE_LIFETIME}' invalide (ex. 5d, 12h)."

    if (( HAS_IPV6 )); then INET_PROTOCOLS=all; else INET_PROTOCOLS=ipv4; fi
    INET_PROTOCOLS=${RELAY_INET_PROTOCOLS:-$INET_PROTOCOLS}
    [[ $INET_PROTOCOLS =~ ^(ipv4|ipv6|all)$ ]] || die "RELAY_INET_PROTOCOLS='${INET_PROTOCOLS}' invalide."
}

generate() {
    # /etc/postfix peut être un tmpfs vide (rootfs en lecture seule) :
    # on restaure les fichiers du paquet puis on génère la configuration.
    cp -a /usr/local/share/postfix-dist/. "$PF/"
    render "$TEMPLATES/main.cf.tmpl" "$PF/main.cf"
    render "$TEMPLATES/master.cf.tmpl" "$PF/master.cf"

    # Réécriture de l'expéditeur (table regexp, insensible à la casse).
    local dom_re=${SENDER_DOMAIN//./\\.}
    {
        echo "# Généré par entrypoint.sh — mode ${SENDER_REWRITE_MODE}"
        if [[ $SENDER_REWRITE_MODE == always ]]; then
            echo "/^.+\$/ ${SENDER_ADDRESS}"
        else
            # Seuls les expéditeurs hors domaine (et hors sous-domaines) sont réécrits.
            echo "!/@([a-z0-9-]+\\.)*${dom_re}\$/ ${SENDER_ADDRESS}"
        fi
    } >"$PF/sender_canonical.regexp"

    # Identifiants SASL : fichier root:root 0600, jamais dans l'image.
    (
        umask 077
        printf '[%s]:%s %s:%s\n' "$RELAY_HOST" "$RELAY_PORT" \
            "$RELAY_SMTP_USERNAME" "$RELAY_SMTP_PASSWORD" >"$PF/sasl_passwd"
    )
    chown root:root "$PF/sasl_passwd"
    chmod 0600 "$PF/sasl_passwd"
    unset RELAY_SMTP_PASSWORD

    # Répertoire de données (tmpfs possible). Les répertoires de la file
    # (volume) sont créés/contrôlés par "postfix check" puis au démarrage.
    install -d -o postfix -g postfix -m 0700 /var/lib/postfix
    postfix check || die "La configuration Postfix générée est invalide (postfix check)."
}

summary() {
    log "Relai SMTP ${RELAY_HOSTNAME} (écoute :${RELAY_LISTEN_PORT}, sans TLS/auth côté réseau privé)"
    log "Clients autorisés : ${ALLOWED_LIST} — tout autre client est rejeté."
    log "Relayhost : [${RELAY_HOST}]:${RELAY_PORT} TLS=${RELAY_TLS_SECURITY_LEVEL} wrappermode=${RELAY_TLS_WRAPPERMODE} >=TLSv1.2, SASL user=${RELAY_SMTP_USERNAME}"
    log "Expéditeur : ${SENDER_ADDRESS} (réécriture : ${SENDER_REWRITE_MODE}), taille max ${MESSAGE_SIZE_LIMIT} o"
}

configure
generate
summary

if [[ ${1:-} == postfix && ${2:-} == start-fg ]]; then
    log "Démarrage de Postfix au premier plan."
fi
exec "$@"
