#!/usr/bin/env bash
# Sain si Postfix répond (bannière 220 sur 587) et si le maître Dovecot tourne.
exec 3<>/dev/tcp/127.0.0.1/587 && IFS= read -r -t 3 l <&3 && [[ $l == 220* ]] || exit 1
kill -0 "$(cat /run/dovecot/master.pid 2>/dev/null)" 2>/dev/null
