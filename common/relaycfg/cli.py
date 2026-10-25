"""relay-config : contrôle et rendu de l'inventaire des applications.

  relay-config check     [--inventory F] [--secrets-dir D]
      Valide l'inventaire (et les secrets si --secrets-dir ou RELAY_APP_SECRETS_DIR).
  relay-config postfix   --out DIR --sasldb FICHIER --realm REALM [--inventory F] [--secrets-dir D]
      Génère sender_login_maps, mynetworks et la base SASL des applications.
  relay-config domain    [--inventory F]
      Affiche le domaine d'envoi (sender_domain).
  relay-config tls-check --cert F --key F
      Vérifie qu'un certificat et sa clé privée sont lisibles et correspondent.

Code de sortie : 0 si tout est valide, 1 sinon (messages « FATAL: » sur stderr).
Variables : RELAY_INVENTORY_FILE (/etc/relay/applications.toml),
RELAY_APP_SECRETS_DIR (/run/secrets/apps).
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import ssl
import subprocess
import sys
from pathlib import Path

from relaycfg import inventory as inv_mod

DEFAULT_INVENTORY = "/etc/relay/applications.toml"
DEFAULT_SECRETS = "/run/secrets/apps"


def fatal(errors: list[str]) -> int:
    for e in errors:
        print(f"FATAL: {e}", file=sys.stderr)
    return 1


def load_checked(path: str, secrets_dir: str | None) -> inv_mod.Inventory:
    inv = inv_mod.load(path)
    if secrets_dir:
        errors = inv_mod.check_secrets(inv, secrets_dir)
        if errors:
            raise inv_mod.InventoryError(errors)
    return inv


def describe(inv: inv_mod.Inventory) -> str:
    apps = ", ".join(
        f"{a.name} <{a.address}> [{' '.join(a.client_ips)}] {a.quota_per_hour}/h"
        for a in inv.applications.values()
    )
    return f"inventaire valide : domaine {inv.sender_domain}, {len(inv.applications)} application(s) : {apps}"


def cmd_check(a) -> int:
    inv = load_checked(a.inventory, a.secrets_dir)
    print(describe(inv))
    if not a.secrets_dir:
        print("(secrets non vérifiés : --secrets-dir absent)")
    return 0


def cmd_postfix(a) -> int:
    if not a.secrets_dir:
        return fatal(["--secrets-dir (ou RELAY_APP_SECRETS_DIR) est obligatoire pour générer la base SASL."])
    inv = load_checked(a.inventory, a.secrets_dir)
    out = Path(a.out)

    with (out / "sender_login_maps").open("w") as f:
        f.write("# Généré par relay-config : adresse expéditrice -> login SASL autorisé\n")
        for app in inv.applications.values():
            f.write(f"{app.address} {app.name}\n")

    with (out / "mynetworks").open("w") as f:
        f.write("127.0.0.1/32\n")
        for ip in inv.client_ips():
            f.write(f"{ip}/32\n" if ipaddress.ip_address(ip).version == 4 else f"[{ip}]/128\n")

    # Base reconstruite entièrement à chaque démarrage : une application retirée
    # de l'inventaire perd immédiatement son accès.
    sasldb = Path(a.sasldb)
    for old in sasldb.parent.glob(sasldb.name + "*"):
        old.unlink()
    for name in inv.applications:
        password = inv_mod.read_password(a.secrets_dir, name)
        subprocess.run(
            ["saslpasswd2", "-p", "-c", "-f", str(sasldb), "-u", a.realm, name],
            input=password.encode(), check=True,
        )
    print(describe(inv))
    return 0


def cmd_domain(a) -> int:
    print(inv_mod.load(a.inventory).sender_domain)
    return 0


def cmd_tls_check(a) -> int:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(a.cert, a.key)
    except (OSError, ssl.SSLError) as e:
        return fatal([f"certificat {a.cert} / clé {a.key} inutilisables ({e})."])
    print(f"certificat {a.cert} et clé {a.key} valides")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="relay-config", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--inventory", default=os.environ.get("RELAY_INVENTORY_FILE", DEFAULT_INVENTORY))
    common.add_argument("--secrets-dir", default=os.environ.get("RELAY_APP_SECRETS_DIR"))
    sub.add_parser("check", parents=[common]).set_defaults(func=cmd_check)
    pf = sub.add_parser("postfix", parents=[common])
    pf.add_argument("--out", required=True)
    pf.add_argument("--sasldb", required=True)
    pf.add_argument("--realm", required=True)
    pf.set_defaults(func=cmd_postfix)
    sub.add_parser("domain", parents=[common]).set_defaults(func=cmd_domain)
    tc = sub.add_parser("tls-check")
    tc.add_argument("--cert", required=True)
    tc.add_argument("--key", required=True)
    tc.set_defaults(func=cmd_tls_check)
    a = p.parse_args(argv)
    try:
        return a.func(a)
    except inv_mod.InventoryError as e:
        return fatal(e.errors)
    except (OSError, subprocess.CalledProcessError) as e:
        return fatal([str(e)])


if __name__ == "__main__":
    sys.exit(main())
