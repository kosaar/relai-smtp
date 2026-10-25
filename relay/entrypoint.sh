#!/usr/bin/env bash
# =============================================================================
#  Entrypoint du relai SMTP.
#  1. valide l'inventaire des applications et leurs secrets (relay-config) ;
#  2. lit et valide le reste de la configuration (environnement + secrets) ;
#  3. génère /etc/postfix (main.cf, master.cf, base SASL des applications,
#     sender_login_maps, mynetworks, certificat, identifiants du fournisseur) ;
#  4. lance Postfix au premier plan ("postfix start-fg", logs sur stdout).
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

# Chemin d'un fichier secret : <NOM>_FILE > /run/secrets/<nom>.
secret_path() {
    local file_var="${1}_FILE"
    local file=${!file_var:-$2}
    [[ -r $file ]] || die "${1} manquant : fournir le secret ${2} (ou ${file_var})."
    printf '%s' "$file"
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

is_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

configure() {
    # ---- Inventaire des applications (exigence de sécurité n°1 : validé en premier)
    RELAY_INVENTORY_FILE=${RELAY_INVENTORY_FILE:-/etc/relay/applications.toml}
    RELAY_APP_SECRETS_DIR=${RELAY_APP_SECRETS_DIR:-/run/secrets/apps}
    export RELAY_INVENTORY_FILE RELAY_APP_SECRETS_DIR
    local out
    out=$(relay-config check 2>&1) || { printf '%s\n' "$out" >&2; die "inventaire ${RELAY_INVENTORY_FILE} ou secrets ${RELAY_APP_SECRETS_DIR} invalides."; }
    INVENTORY_SUMMARY=$out
    SENDER_DOMAIN=$(relay-config domain)

    RELAY_HOSTNAME=${RELAY_HOSTNAME:-relay.${SENDER_DOMAIN}}
    RELAY_HOSTNAME=${RELAY_HOSTNAME,,}
    [[ $RELAY_HOSTNAME =~ $re_domain ]] || die "RELAY_HOSTNAME='${RELAY_HOSTNAME}' invalide (FQDN attendu)."

    # ---- Certificat de soumission (587)
    RELAY_TLS_CERT=$(secret_path RELAY_TLS_CERT /run/secrets/relay_tls_cert)
    RELAY_TLS_KEY=$(secret_path RELAY_TLS_KEY /run/secrets/relay_tls_key)
    out=$(relay-config tls-check --cert "$RELAY_TLS_CERT" --key "$RELAY_TLS_KEY" 2>&1) \
        || { printf '%s\n' "$out" >&2; die "certificat de soumission invalide."; }

    # ---- Passerelle (milter) : obligatoire, aucun message ne passe sans elle
    RELAY_MILTER=${RELAY_MILTER:-inet:gateway:9900}
    [[ $RELAY_MILTER =~ ^inet:[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] \
        || die "RELAY_MILTER='${RELAY_MILTER}' invalide (ex. inet:gateway:9900)."

    # ---- Limitation des tentatives d'authentification (par IP et par minute)
    RELAY_AUTH_RATE_LIMIT=${RELAY_AUTH_RATE_LIMIT:-30}
    [[ $RELAY_AUTH_RATE_LIMIT =~ ^[0-9]+$ ]] && (( RELAY_AUTH_RATE_LIMIT >= 1 )) \
        || die "RELAY_AUTH_RATE_LIMIT='${RELAY_AUTH_RATE_LIMIT}' invalide (entier >= 1)."

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

    # ---- Divers
    MESSAGE_SIZE_LIMIT=${MESSAGE_SIZE_LIMIT:-10240000}
    [[ $MESSAGE_SIZE_LIMIT =~ ^[0-9]+$ ]] && (( MESSAGE_SIZE_LIMIT >= 102400 )) \
        || die "MESSAGE_SIZE_LIMIT='${MESSAGE_SIZE_LIMIT}' invalide (octets, >= 102400)."
    # Taille en file (après chiffrement) : marge de 50 % pour l'armure OpenPGP.
    # shellcheck disable=SC2034  # utilisée par render (master.cf.tmpl)
    QUEUE_SIZE_LIMIT=$(( MESSAGE_SIZE_LIMIT * 3 / 2 ))

    QUEUE_LIFETIME=${QUEUE_LIFETIME:-5d}
    [[ $QUEUE_LIFETIME =~ ^[0-9]+[smhdw]$ ]] || die "QUEUE_LIFETIME='${QUEUE_LIFETIME}' invalide (ex. 5d, 12h)."

    INET_PROTOCOLS=${RELAY_INET_PROTOCOLS:-ipv4}
    [[ $INET_PROTOCOLS =~ ^(ipv4|ipv6|all)$ ]] || die "RELAY_INET_PROTOCOLS='${INET_PROTOCOLS}' invalide."
}

generate() {
    # /etc/postfix peut être un tmpfs vide (rootfs en lecture seule) :
    # on restaure les fichiers du paquet puis on génère la configuration.
    cp -a /usr/local/share/postfix-dist/. "$PF/"
    render "$TEMPLATES/main.cf.tmpl" "$PF/main.cf"
    render "$TEMPLATES/master.cf.tmpl" "$PF/master.cf"

    # Applications : sender_login_maps, mynetworks (liste blanche IP) et base
    # SASL (realm = myhostname, car smtpd_sasl_local_domain est vide).
    install -d -o root -g postfix -m 0750 "$PF/sasl"
    render "$TEMPLATES/smtpd-sasl.conf.tmpl" "$PF/sasl/smtpd.conf"
    relay-config postfix --out "$PF" --sasldb "$PF/sasl/sasldb2" --realm "$RELAY_HOSTNAME" >/dev/null
    chown root:postfix "$PF"/sasl/sasldb2*
    chmod 0640 "$PF"/sasl/sasldb2*

    # Certificat de soumission : clé + chaîne dans un seul fichier root 0600
    # (lu par Postfix avant l'abandon des privilèges).
    (
        umask 077
        install -d -m 0700 "$PF/tls"
        cat "$RELAY_TLS_KEY" "$RELAY_TLS_CERT" >"$PF/tls/submission.pem"
    )

    # Identifiants du fournisseur : fichier root:root 0600, jamais dans l'image.
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
    log "Relai SMTP ${RELAY_HOSTNAME} : soumission :587 (STARTTLS >= TLSv1.2 obligatoire + SASL par application)"
    log "${INVENTORY_SUMMARY%%$'\n'*}"
    log "Seules les IP de l'inventaire peuvent se connecter ; chaque login n'envoie qu'avec son adresse."
    log "Passerelle (milter) : ${RELAY_MILTER} (injoignable => 451, rien n'est accepté)"
    log "Relayhost : [${RELAY_HOST}]:${RELAY_PORT} TLS=${RELAY_TLS_SECURITY_LEVEL} wrappermode=${RELAY_TLS_WRAPPERMODE} >=TLSv1.2, SASL user=${RELAY_SMTP_USERNAME}"
}

configure
generate
summary

if [[ ${1:-} == postfix && ${2:-} == start-fg ]]; then
    log "Démarrage de Postfix au premier plan."
fi
exec "$@"
