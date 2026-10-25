# shellcheck shell=bash
# Fonctions communes aux scripts du relai. Fichier destiné à être "sourcé".

log()  { printf '%s relay-entrypoint[%s]: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$*"; }
warn() { log "WARNING: $*" >&2; }
die()  { log "FATAL: $*" >&2; log "FATAL: refus de démarrer (configuration invalide)." >&2; exit 1; }

is_ipv4() {
    local ip=$1 o
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do
        # Pas de zéros non significatifs (ambigus : octal pour certaines libs).
        [[ $o =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( o <= 255 )) || return 1
    done
}
