"""Milter de la passerelle : contrôles d'enveloppe, appelés par Postfix (smtpd :587).

  MAIL FROM : login SASL connu, IP cliente déclarée pour ce login, enveloppe =
              adresse de l'application ;
  RCPT TO   : clé OpenPGP valide du destinataire (WKD de l'annuaire, cache) ;
              sinon 550 5.7.1 pour ce destinataire, 451 4.7.1 si l'annuaire
              est injoignable.
Le contenu ne passe pas par le milter : Postfix le relaie au filtre avant file
(relaygw.proxy), qui le chiffre avant toute écriture dans la file.
Toute erreur interne => 451 (échec fermé). Journaux : métadonnées seulement.
"""
from __future__ import annotations

import logging
import os
import sys
import time

import Milter

from relaycfg import inventory as inv_mod
from relaygw import config as config_mod
from relaygw import policy, proxy
from relaygw.keys import KeyResolver

log = logging.getLogger("gateway")
INVENTORY: inv_mod.Inventory | None = None
RESOLVER: KeyResolver | None = None


class GatewayMilter(Milter.Base):
    def __init__(self):
        self.cid = Milter.uniqueID()
        self.client_ip = None
        self.login = None

    def _qid(self):
        return self.getsymval("{i}") or "NOQUEUE"

    def _refuse(self, refusal: policy.Refusal, stage: str, extra: str = ""):
        log.info("reject cid=%s qid=%s stage=%s client=%s login=%s reason=%s code=%s%s",
                 self.cid, self._qid(), stage, self.client_ip or "-", self.login or "-",
                 refusal.reason, refusal.code, extra)
        self.setreply(refusal.code, refusal.dsn, refusal.text)
        return Milter.REJECT if refusal.permanent else Milter.TEMPFAIL

    def connect(self, hostname, family, hostaddr):
        # hostaddr = (ip, port) en IPv4, (ip, port, flowinfo, scope) en IPv6.
        self.client_ip = hostaddr[0] if isinstance(hostaddr, tuple) and hostaddr else None
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *params):
        self.login = self.getsymval("{auth_authen}")
        app, refusal = policy.resolve_login(INVENTORY, self.login)
        if refusal is None:
            refusal = policy.check_client_ip(app, self.client_ip)
        if refusal is None:
            refusal = policy.check_envelope_sender(app, mailfrom)
        if refusal:
            return self._refuse(refusal, "mail")
        return Milter.CONTINUE

    def envrcpt(self, to, *params):
        rcpt = policy.strip_brackets(to).lower()
        found = RESOLVER.lookup(rcpt)
        if found.status == "ok":
            return Milter.CONTINUE
        if found.status == "nokey":
            refusal = policy.Refusal("550", "5.7.1", f"No valid OpenPGP key for <{rcpt}>: message not sent", found.reason)
        else:
            refusal = policy.Refusal("451", "4.7.1", "Key directory unavailable, try again later", found.reason)
        return self._refuse(refusal, "rcpt", f" rcpt={rcpt}")


def main() -> int:
    global INVENTORY, RESOLVER
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s relay-gateway: %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
    errors: list[str] = []
    config = None
    try:
        config = config_mod.load()
    except config_mod.ConfigError as e:
        errors += e.errors
    path = os.environ.get("GATEWAY_INVENTORY_FILE", "/etc/relay/applications.toml")
    try:
        INVENTORY = inv_mod.load(path)
    except inv_mod.InventoryError as e:
        errors += e.errors
    if errors:
        for err in errors:
            log.error("FATAL: %s", err)
        log.error("FATAL: refus de démarrer (configuration invalide).")
        return 1
    RESOLVER = KeyResolver(config.keydir_url, config.keydir_ca_file, config.key_cache_ttl)
    log.info("inventaire %s : %d application(s) (%s), domaine %s", path, len(INVENTORY.applications),
             ", ".join(INVENTORY.applications), INVENTORY.sender_domain)
    log.info("annuaire %s (cache %d s), objet extérieur « %s »", config.keydir_url, config.key_cache_ttl,
             config.neutral_subject)
    proxy.CTX = proxy.Context(INVENTORY, config, RESOLVER)
    try:
        proxy.serve(config.proxy_listen)
    except OSError as e:
        log.error("FATAL: filtre avant file : écoute impossible sur %s (%s)", config.proxy_listen, e)
        return 1
    log.info("filtre avant file à l'écoute sur %s, réinjection vers le relai appelant (port %d)",
             config.proxy_listen, config.reinject_port)
    Milter.factory = GatewayMilter
    Milter.set_flags(0)   # le milter ne modifie jamais le message
    log.info("milter à l'écoute sur %s", config.listen)
    sys.stdout.flush()
    Milter.runmilter("relay-gateway", config.listen, timeout=300)
    log.info("arrêt du milter")
    return 0
