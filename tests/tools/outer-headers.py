#!/usr/bin/env python3
"""En-têtes extérieurs d'un message brut (stdin), dépliés, un par ligne « Nom: valeur ».

Usage : outer-headers.py relay|provider|all

  provider  en-têtes ajoutés par le fournisseur simulé, en tête du message
            (Return-Path, Delivered-To, X-Original-To, Received « by provider » ou
            « by smtp.provider.test ») ;
  relay     tous les suivants : ceux que le relai a transmis au fournisseur ;
  all       l'ensemble.
"""
import re
import sys

PROVIDER = re.compile(r"^(return-path|delivered-to|x-original-to)$", re.I)


def headers(raw: bytes) -> list[tuple[str, str]]:
    head = raw.replace(b"\r\n", b"\n").split(b"\n\n", 1)[0].decode("utf-8", "replace")
    out: list[tuple[str, str]] = []
    for line in head.split("\n"):
        if line[:1] in (" ", "\t") and out:
            out[-1] = (out[-1][0], out[-1][1] + " " + line.strip())
        elif ":" in line:
            name, value = line.split(":", 1)
            out.append((name.strip(), value.strip()))
    return out


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    hs = headers(sys.stdin.buffer.read())
    n = 0
    while n < len(hs) and (PROVIDER.match(hs[n][0])
                           or (hs[n][0].lower() == "received" and re.search(r"\bby (provider|smtp\.provider\.test) ", hs[n][1]))):
        n += 1
    selected = {"provider": hs[:n], "relay": hs[n:], "all": hs}[which]
    for name, value in selected:
        print(f"{name}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
