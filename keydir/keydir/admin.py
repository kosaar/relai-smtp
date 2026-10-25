"""keydir-admin : administration de l'annuaire (dans le conteneur keydir).

  keydir-admin list [--state pending|approved|rejected|superseded|revoked]
  keydir-admin show <adresse>
  keydir-admin approve <adresse> <empreinte>   après comparaison HORS BANDE de l'empreinte
  keydir-admin reject <adresse> <empreinte>
  keydir-admin revoke <adresse>                révocation administrative (clé dépubliée)
  keydir-admin remove <adresse>                suppression de toutes les clés de l'adresse
  keydir-admin audit [--limit N]               dernières entrées du journal d'audit
"""
from __future__ import annotations

import argparse
import os
import pwd
import sys
import time

from keydir import policy
from keydir.store import Store, StoreError


def fmt_ts(ts: int | None) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else "-"


def norm_fpr(fpr: str) -> str:
    return "".join(fpr.split()).upper()


def actor() -> str:
    user = os.environ.get("KEYDIR_ADMIN") or os.environ.get("SUDO_USER")
    if not user:
        try:
            user = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            user = str(os.getuid())
    return f"admin:{user}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="keydir-admin", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=os.environ.get("KEYDIR_DB", "/var/lib/keydir/keydir.db"))
    sub = p.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--state", choices=["pending", "approved", "rejected", "superseded", "revoked"])
    for name in ("show", "revoke", "remove"):
        sub.add_parser(name).add_argument("email")
    for name in ("approve", "reject"):
        sp = sub.add_parser(name)
        sp.add_argument("email")
        sp.add_argument("fingerprint", nargs="+", help="empreinte (espaces autorisés)")
    au = sub.add_parser("audit")
    au.add_argument("--limit", type=int, default=50)
    a = p.parse_args(argv)

    store = Store(a.db)
    email = None
    if hasattr(a, "email"):
        email = policy.normalize_email(a.email)
        if not email:
            print(f"adresse invalide : {a.email}", file=sys.stderr)
            return 2
    try:
        if a.cmd == "list":
            rows = store.keys(state=a.state)
            print(f"{'ADRESSE':32} {'ÉTAT':10} {'EMPREINTE':40} {'ALGORITHME':16} {'DÉPÔT':10} EXPIRATION")
            for r in rows:
                print(f"{r.email:32} {r.state:10} {r.fingerprint:40} {r.algo:16} {fmt_ts(r.submitted_at):10} {fmt_ts(r.expires)}")
            return 0
        if a.cmd == "show":
            st = store.status(email)
            print(f"{email} : état {st['state']}" + (f", empreinte {st['fingerprint']}" if st["fingerprint"] else ""))
            for r in store.keys(email):
                print(f"  {r.fingerprint} {r.state:10} {r.algo} déposée {fmt_ts(r.submitted_at)} "
                      f"expire {fmt_ts(r.expires)}" + (" [publiée WKD]" if r.published else "")
                      + (f" (révoquée par {r.revoked_by})" if r.revoked_by else ""))
            return 0
        if a.cmd == "approve":
            fpr = norm_fpr(" ".join(a.fingerprint))
            old = store.approve(email, fpr, actor())
            print(f"clé {fpr} validée et publiée pour {email}" + (f" (remplace {', '.join(old)})" if old else ""))
            return 0
        if a.cmd == "reject":
            fpr = norm_fpr(" ".join(a.fingerprint))
            store.reject(email, fpr, actor())
            print(f"clé {fpr} refusée pour {email}")
            return 0
        if a.cmd == "revoke":
            fprs = store.revoke_admin(email, actor())
            print(f"clé(s) {', '.join(fprs)} révoquée(s) et dépubliée(s) pour {email}")
            return 0
        if a.cmd == "remove":
            n = store.remove(email, actor())
            print(f"{n} clé(s) supprimée(s) pour {email}")
            return 0
        if a.cmd == "audit":
            for ts, action, em, fpr, who, result in store.audit_entries(a.limit):
                print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))} {action:8} {em or '-':32} {fpr or '-':40} {who} {result}")
            return 0
    except StoreError as e:
        print(f"erreur : {e}", file=sys.stderr)
        return 1
    return 2
