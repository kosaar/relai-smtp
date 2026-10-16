#!/usr/bin/env bash
# Healthcheck Docker : le processus maître Postfix tourne ET le service SMTP
# répond par une bannière 220 sur le port d'écoute.
set -euo pipefail
port=${RELAY_LISTEN_PORT:-25}

# Processus maître vivant (sans "postfix status", qui journalise à chaque appel).
pidfile=$(postconf -h queue_directory)/pid/master.pid
read -r pid 2>/dev/null <"$pidfile" && kill -0 "$pid" 2>/dev/null \
    || { echo "postfix master not running"; exit 1; }

exec 3<>"/dev/tcp/127.0.0.1/${port}" || { echo "port ${port} closed"; exit 1; }
IFS= read -r -t 5 banner <&3 || { echo "no SMTP banner"; exit 1; }
printf 'QUIT\r\n' >&3
exec 3>&-
[[ $banner == 220* ]] || { echo "unexpected banner: ${banner}"; exit 1; }
echo "ok: ${banner%$'\r'}"
