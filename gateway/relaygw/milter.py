"""Milter de la passerelle : identité de l'application (lot 1).

Contrôles : login SASL connu, IP cliente déclarée pour ce login, enveloppe et
en-tête From: égaux à l'adresse de l'application.

Postfix (smtpd_milters) appelle ce service pour chaque message soumis, AVANT la
mise en file. Le login SASL est lu dans la macro {auth_authen}.
Journaux : métadonnées seulement (identifiant de connexion, file, login, motif).
"""
from __future__ import annotations

import logging
import os
import sys
import time

import Milter

from relaycfg import inventory as inv_mod
from relaygw import policy

log = logging.getLogger("gateway")
INVENTORY: inv_mod.Inventory | None = None


class GatewayMilter(Milter.Base):
    def __init__(self):
        self.cid = Milter.uniqueID()
        self.app = None
        self.client_ip = None
        self.login = None
        self.from_values: list[str] = []

    # -- utilitaires ----------------------------------------------------------
    def _refuse(self, refusal: policy.Refusal, stage: str):
        qid = self.getsymval("{i}") or "NOQUEUE"
        log.info("reject cid=%s qid=%s stage=%s client=%s login=%s reason=%s code=%s",
                 self.cid, qid, stage, self.client_ip or "-", self.login or "-", refusal.reason, refusal.code)
        self.setreply(refusal.code, refusal.dsn, refusal.text)
        return Milter.REJECT if refusal.permanent else Milter.TEMPFAIL

    # -- callbacks ------------------------------------------------------------
    def connect(self, hostname, family, hostaddr):
        # hostaddr = (ip, port) en IPv4, (ip, port, flowinfo, scope) en IPv6.
        self.client_ip = hostaddr[0] if isinstance(hostaddr, tuple) and hostaddr else None
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *params):
        # Nouvelle transaction (plusieurs messages possibles par connexion).
        self.app, self.from_values = None, []
        self.login = self.getsymval("{auth_authen}")
        app, refusal = policy.resolve_login(INVENTORY, self.login)
        if refusal is None:
            refusal = policy.check_client_ip(app, self.client_ip)
        if refusal is None:
            refusal = policy.check_envelope_sender(app, mailfrom)
        if refusal:
            return self._refuse(refusal, "mail")
        self.app = app
        return Milter.CONTINUE

    def header(self, name, value):
        if name.lower() == "from":
            self.from_values.append(value)
        return Milter.CONTINUE

    def eom(self):
        if self.app is None:   # ne doit pas arriver : MAIL FROM non contrôlé
            return self._refuse(policy.Refusal("451", "4.7.1", "Gateway state error", "no-transaction"), "data")
        refusal = policy.check_from_headers(self.app, self.from_values)
        if refusal:
            return self._refuse(refusal, "data")
        log.info("accept cid=%s qid=%s login=%s", self.cid, self.getsymval("{i}") or "-", self.login)
        return Milter.ACCEPT

    def abort(self):
        return Milter.CONTINUE


def main() -> int:
    global INVENTORY
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s relay-gateway: %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
    path = os.environ.get("GATEWAY_INVENTORY_FILE", "/etc/relay/applications.toml")
    socket = os.environ.get("GATEWAY_LISTEN", "inet:9900@0.0.0.0")
    try:
        INVENTORY = inv_mod.load(path)
    except inv_mod.InventoryError as e:
        for err in e.errors:
            log.error("FATAL: %s", err)
        log.error("FATAL: refus de démarrer (inventaire invalide).")
        return 1
    log.info("inventaire %s : %d application(s) (%s), domaine %s", path, len(INVENTORY.applications),
             ", ".join(INVENTORY.applications), INVENTORY.sender_domain)
    Milter.factory = GatewayMilter
    Milter.set_flags(0)
    log.info("milter à l'écoute sur %s", socket)
    sys.stdout.flush()
    Milter.runmilter("relay-gateway", socket, timeout=300)
    log.info("arrêt du milter")
    return 0
