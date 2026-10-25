"""Milter de la passerelle, appelé par Postfix AVANT la mise en file.

  MAIL FROM : login SASL connu, IP cliente déclarée pour ce login, enveloppe =
              adresse de l'application ;
  RCPT TO   : clé OpenPGP valide du destinataire (WKD de l'annuaire, cache) ;
              sinon 550 5.7.1 pour ce destinataire, 451 4.7.1 si l'annuaire
              est injoignable ;
  fin       : en-tête From: = adresse de l'application ; le message est chiffré
              (PGP/MIME, en-têtes protégés) pour tous les destinataires
              acceptés, l'objet extérieur devient neutre. Le message n'est
              donc jamais écrit en clair dans la file de Postfix.
Toute erreur interne => 451 (échec fermé). Journaux : métadonnées seulement.
"""
from __future__ import annotations

import io
import logging
import os
import sys
import time

import Milter

from pgpkeys import openpgp
from relaycfg import inventory as inv_mod
from relaygw import config as config_mod
from relaygw import crypto, pgpmime, policy
from relaygw.keys import KeyResolver

log = logging.getLogger("gateway")
INVENTORY: inv_mod.Inventory | None = None
CONFIG: config_mod.Config | None = None
RESOLVER: KeyResolver | None = None
CHUNK = 65535


@Milter.header_leading_space
class GatewayMilter(Milter.Base):
    def __init__(self):
        self.cid = Milter.uniqueID()
        self.client_ip = None
        self.login = None
        self._reset()

    def _reset(self):
        self.app = None
        self.recipients: list[tuple[str, str, bytes]] = []   # (adresse, empreinte, clé)
        self.headers: list[tuple[str, bytes]] = []
        self.buf = io.BytesIO()

    # -- utilitaires ----------------------------------------------------------
    def _qid(self):
        return self.getsymval("{i}") or "NOQUEUE"

    def _refuse(self, refusal: policy.Refusal, stage: str, extra: str = ""):
        log.info("reject cid=%s qid=%s stage=%s client=%s login=%s reason=%s code=%s%s",
                 self.cid, self._qid(), stage, self.client_ip or "-", self.login or "-",
                 refusal.reason, refusal.code, extra)
        self.setreply(refusal.code, refusal.dsn, refusal.text)
        return Milter.REJECT if refusal.permanent else Milter.TEMPFAIL

    # -- callbacks ------------------------------------------------------------
    def connect(self, hostname, family, hostaddr):
        # hostaddr = (ip, port) en IPv4, (ip, port, flowinfo, scope) en IPv6.
        self.client_ip = hostaddr[0] if isinstance(hostaddr, tuple) and hostaddr else None
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *params):
        self._reset()   # nouvelle transaction (plusieurs messages possibles par connexion)
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

    def envrcpt(self, to, *params):
        rcpt = policy.strip_brackets(to).lower()
        found = RESOLVER.lookup(rcpt)
        if found.status == "ok":
            self.recipients.append((rcpt, found.fingerprint, found.key))
            return Milter.CONTINUE
        if found.status == "nokey":
            refusal = policy.Refusal("550", "5.7.1", f"No valid OpenPGP key for <{rcpt}>: message not sent", found.reason)
        else:
            refusal = policy.Refusal("451", "4.7.1", "Key directory unavailable, try again later", found.reason)
        return self._refuse(refusal, "rcpt", f" rcpt={rcpt}")

    @Milter.decode("bytes")
    def header(self, name, value):
        self.headers.append((name, value))
        return Milter.CONTINUE

    def body(self, chunk):
        self.buf.write(chunk)
        return Milter.CONTINUE

    def eom(self):
        if self.app is None or not self.recipients:   # ne doit pas arriver
            return self._refuse(policy.Refusal("451", "4.7.1", "Gateway state error", "no-transaction"), "data")
        from_values = [v.decode("utf-8", "replace") for n, v in self.headers if n.lower() == "from"]
        refusal = policy.check_from_headers(self.app, from_values)
        if refusal:
            return self._refuse(refusal, "data")
        try:
            return self._encrypt()
        except (openpgp.GpgError, OSError, ValueError) as e:
            log.error("encrypt failed cid=%s qid=%s login=%s error=%s", self.cid, self._qid(), self.login, type(e).__name__)
            return self._refuse(policy.Refusal("451", "4.7.1", "Encryption failed, try again later", "encrypt-error"), "data")

    def _encrypt(self):
        started = time.monotonic()
        body = self.buf.getvalue()
        inner = pgpmime.build_inner(self.headers, body)
        armored = crypto.encrypt(inner, [(fpr, key) for _, fpr, key in self.recipients])
        boundary = pgpmime.new_boundary()
        for op, name, idx, value in pgpmime.outer_header_changes(self.headers, CONFIG.neutral_subject, boundary):
            if op == "add":
                self.addheader(name, value)
            else:
                self.chgheader(name, idx, value if value is not None else "")
        new_body = pgpmime.build_encrypted_body(armored, boundary)
        for i in range(0, len(new_body), CHUNK):
            self.replacebody(new_body[i:i + CHUNK])
        log.info("encrypt cid=%s qid=%s login=%s rcpts=%d size_in=%d size_out=%d ms=%d",
                 self.cid, self._qid(), self.login, len(self.recipients), len(body), len(new_body),
                 (time.monotonic() - started) * 1000)
        return Milter.ACCEPT

    def abort(self):
        self._reset()
        return Milter.CONTINUE

    def close(self):
        self._reset()
        return Milter.CONTINUE


def main() -> int:
    global INVENTORY, CONFIG, RESOLVER
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s relay-gateway: %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
    errors: list[str] = []
    try:
        CONFIG = config_mod.load()
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
    RESOLVER = KeyResolver(CONFIG.keydir_url, CONFIG.keydir_ca_file, CONFIG.key_cache_ttl)
    log.info("inventaire %s : %d application(s) (%s), domaine %s", path, len(INVENTORY.applications),
             ", ".join(INVENTORY.applications), INVENTORY.sender_domain)
    log.info("annuaire %s (cache %d s), objet extérieur « %s »", CONFIG.keydir_url, CONFIG.key_cache_ttl,
             CONFIG.neutral_subject)
    Milter.factory = GatewayMilter
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGHDRS | Milter.CHGBODY)
    log.info("milter à l'écoute sur %s", CONFIG.listen)
    sys.stdout.flush()
    Milter.runmilter("relay-gateway", CONFIG.listen, timeout=300)
    log.info("arrêt du milter")
    return 0
