#!/usr/bin/env bash
# Healthcheck Docker : le processus maître Postfix tourne, le service SMTP
# répond par une bannière 220 sur le port d'écoute, et l'IP de la passerelle
# n'a pas changé depuis le démarrage (sinon la réinjection serait refusée :
# redémarrer le relai).
set -euo pipefail
port=587

# Processus maître vivant (sans "postfix status", qui journalise à chaque appel).
pidfile=$(postconf -h queue_directory)/pid/master.pid
read -r pid 2>/dev/null <"$pidfile" && kill -0 "$pid" 2>/dev/null \
    || { echo "postfix master not running"; exit 1; }

exec 3<>"/dev/tcp/127.0.0.1/${port}" || { echo "port ${port} closed"; exit 1; }
IFS= read -r -t 5 banner <&3 || { echo "no SMTP banner"; exit 1; }
printf 'QUIT\r\n' >&3
exec 3>&-
[[ $banner == 220* ]] || { echo "unexpected banner: ${banner}"; exit 1; }

gw_file=$(postconf -h config_directory)/gateway_ip
if [[ -r $gw_file ]]; then
    read -r expected <"$gw_file"
    host=$(postconf -P submission/inet/smtpd_proxy_filter 2>/dev/null | sed 's/.*= *//; s/:[0-9]*$//')
    current=$(getent ahostsv4 "${host:-gateway}" | awk 'NR == 1 { print $1 }') || true
    [[ -z $current || $current == "$expected" ]] \
        || { echo "gateway IP changed (${expected} -> ${current}): restart the relay"; exit 1; }
fi
echo "ok: ${banner%$'\r'}"
