#!/bin/sh
# Appelé par le transport pipe "capture" : écrit le message reçu sur disque.
set -eu
dir=/var/mail/captured
tmp="$dir/.tmp.$1.$$"
{
    printf 'X-Envelope-To: %s\n' "$2"
    cat
} >"$tmp"
mv "$tmp" "$dir/$(date +%s%N)-$1.eml"
