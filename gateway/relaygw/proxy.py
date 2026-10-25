"""Filtre avant mise en file (smtpd_proxy_filter de Postfix) : chiffrement.

Postfix (smtpd :587) relaie en temps réel chaque transaction, après ses
contrôles et ceux du milter (identité au MAIL FROM, clé au RCPT TO), à ce
serveur SMTP. Le message n'est donc JAMAIS écrit en clair dans la file : seul
le message chiffré est réinjecté dans le relai qui l'a transmis (smtpd de
réinjection, même adresse IP, port GATEWAY_REINJECT_PORT, sans filtre ni
milter), et la réponse de la réinjection (« 250 … queued as … ») est rendue à
l'application.

En fin de DATA :
  - From: = adresse de l'application (enveloppe), IP cliente (XFORWARD) déclarée ;
  - contrôle du contenu décodé (relaygw.content) : 550 5.7.1 + identifiant de règle ;
  - chiffrement PGP/MIME pour tous les destinataires (en-têtes protégés) ;
  - en-têtes extérieurs en liste blanche (D9) : objet neutre, identifiants de
    message pseudonymisés (HMAC), le reste n'existe plus que chiffré.
Toute erreur interne => 451 (échec fermé). Journaux : métadonnées seulement.
"""
from __future__ import annotations

import logging
import smtplib
import socket
import socketserver
import threading
import time
from dataclasses import dataclass

from pgpkeys import openpgp
from relaygw import content, crypto, pgpmime, policy

log = logging.getLogger("gateway")
MAX_LINE = 4096
MAX_DATA = 64 * 1024 * 1024   # garde-fou mémoire ; Postfix impose déjà message_size_limit
TIMEOUT = 300


@dataclass
class Context:
    inventory: object
    config: object
    resolver: object
    rules: object = None   # relaygw.content.Rules ; None = aucun contrôle (tests unitaires)


CTX: Context | None = None
_ids = iter(range(1, 1 << 62))
_ids_lock = threading.Lock()


def _next_id() -> str:
    with _ids_lock:
        return f"P{next(_ids):06d}"


class Reply(Exception):
    """Réponse SMTP finale d'une transaction."""
    def __init__(self, line: str):
        super().__init__(line)
        self.line = line


class Session(socketserver.StreamRequestHandler):
    timeout = TIMEOUT

    def setup(self):
        super().setup()
        self.cid = _next_id()
        self.client_ip = None
        self._reset()

    def _reset(self):
        self.sender = None
        self.rcpts: list[str] = []

    def send(self, line: str):
        self.wfile.write(line.encode("utf-8", "replace") + b"\r\n")
        self.wfile.flush()

    def handle(self):
        try:
            self.send("220 gateway ESMTP")
            while True:
                raw = self.rfile.readline(MAX_LINE + 1)
                if not raw:
                    return
                if len(raw) > MAX_LINE:
                    self.send("500 5.5.2 Line too long")
                    return
                line = raw.rstrip(b"\r\n").decode("utf-8", "replace")
                verb, _, arg = line.partition(" ")
                verb = verb.upper()
                if verb in ("EHLO", "HELO"):
                    self._reset()
                    self.send("250-gateway\r\n250-8BITMIME\r\n250 XFORWARD NAME ADDR PROTO HELO"
                              if verb == "EHLO" else "250 gateway")
                elif verb == "XFORWARD":
                    for item in arg.split():
                        k, _, v = item.partition("=")
                        if k.upper() == "ADDR" and v not in ("[UNAVAILABLE]", "[TEMPUNAVAIL]"):
                            self.client_ip = v.removeprefix("IPV6:")
                    self.send("250 2.0.0 Ok")
                elif verb == "MAIL" and arg.upper().startswith("FROM:"):
                    self._reset()
                    self.sender = policy.strip_brackets(arg[5:].strip().split(" ")[0]).lower()
                    self.send("250 2.1.0 Ok")
                elif verb == "RCPT" and arg.upper().startswith("TO:"):
                    if self.sender is None:
                        self.send("503 5.5.1 Error: need MAIL command")
                        continue
                    self.rcpts.append(policy.strip_brackets(arg[3:].strip().split(" ")[0]).lower())
                    self.send("250 2.1.5 Ok")
                elif verb == "DATA":
                    if not self.rcpts:
                        self.send("503 5.5.1 Error: need RCPT command")
                        continue
                    self.send("354 End data with <CR><LF>.<CR><LF>")
                    data = self._read_data()
                    if data is None:
                        return
                    self.send(self._transaction(data))
                    self._reset()
                elif verb == "RSET":
                    self._reset()
                    self.send("250 2.0.0 Ok")
                elif verb == "NOOP":
                    self.send("250 2.0.0 Ok")
                elif verb == "QUIT":
                    self.send("221 2.0.0 Bye")
                    return
                else:
                    self.send("502 5.5.2 Error: command not recognized")
        except (OSError, socket.timeout):
            return

    def _read_data(self) -> bytes | None:
        """Corps du DATA (point de transparence retiré), None si la connexion tombe."""
        chunks, size, too_big = [], 0, False
        while True:
            line = self.rfile.readline(1 << 20)
            if not line:
                return None
            if line in (b".\r\n", b".\n"):
                break
            if line.startswith(b"."):
                line = line[1:]
            size += len(line)
            if size > MAX_DATA:
                too_big = True
            elif not too_big:
                chunks.append(line)
        return b"" if too_big else b"".join(chunks)

    # -- transaction ----------------------------------------------------------
    def _refuse(self, refusal: policy.Refusal, app=None) -> str:
        log.info("reject cid=%s qid=NOQUEUE stage=data client=%s login=%s reason=%s code=%s",
                 self.cid, self.client_ip or "-", app.name if app else "-", refusal.reason, refusal.code)
        return f"{refusal.code} {refusal.dsn} {refusal.text}"

    def _transaction(self, data: bytes) -> str:
        if not data:
            return self._refuse(policy.Refusal("552", "5.3.4", "Message too big", "too-big"))
        app, refusal = policy.resolve_sender(CTX.inventory, self.sender)
        if refusal:
            return self._refuse(refusal)
        refusal = policy.check_client_ip(app, self.client_ip)
        if refusal:
            return self._refuse(refusal, app)
        headers, body = pgpmime.parse_message(data)
        from_values = [v.decode("utf-8", "replace") for n, v in headers if n.lower() == "from"]
        refusal = policy.check_from_headers(app, from_values)
        if refusal:
            return self._refuse(refusal, app)
        if CTX.rules is not None:
            rule = content.scan(CTX.rules, data)
            if rule:
                return self._refuse(policy.Refusal("550", "5.7.1", f"Message blocked by content policy (rule {rule})",
                                                   f"content:{rule}"), app)
        try:
            return self._encrypt_and_reinject(app, headers, body)
        except Reply as r:
            return r.line
        except (openpgp.GpgError, OSError, ValueError) as e:
            log.error("encrypt failed cid=%s login=%s error=%s", self.cid, app.name, type(e).__name__)
            return self._refuse(policy.Refusal("451", "4.7.1", "Encryption failed, try again later",
                                               "encrypt-error"), app)

    def _encrypt_and_reinject(self, app, headers, body) -> str:
        started = time.monotonic()
        keys = []
        for rcpt in self.rcpts:
            found = CTX.resolver.lookup(rcpt)
            if found.status != "ok":   # clé disparue depuis le RCPT TO (cache expiré)
                raise Reply(self._refuse(policy.Refusal("451", "4.7.1", f"No usable OpenPGP key for <{rcpt}>, "
                                                        "try again later", found.reason), app))
            keys.append((found.fingerprint, found.key))
        inner = pgpmime.build_inner(headers, body)
        armored = crypto.encrypt(inner, keys)
        boundary = pgpmime.new_boundary()
        outer = pgpmime.build_outer_headers(headers, CTX.config.neutral_subject, boundary,
                                            CTX.config.hmac_key, CTX.inventory.sender_domain)
        message = outer + b"\r\n" + pgpmime.build_encrypted_body(armored, boundary)
        code, text = self._reinject(message)
        qid = text.rsplit(" ", 1)[-1] if "queued as" in text else "-"
        if code != 250:
            log.error("reinject failed cid=%s login=%s code=%s", self.cid, app.name, code)
            return self._refuse(policy.Refusal("451", "4.3.0", "Reinjection failed, try again later",
                                               "reinject-error"), app)
        log.info("encrypt cid=%s qid=%s login=%s rcpts=%d size_in=%d size_out=%d ms=%d",
                 self.cid, qid, app.name, len(self.rcpts), len(body), len(message),
                 (time.monotonic() - started) * 1000)
        return f"250 {text}"

    def _reinject(self, message: bytes) -> tuple[int, str]:
        relay = self.client_address[0]   # le relai qui a transmis la transaction
        try:
            with smtplib.SMTP(relay, CTX.config.reinject_port, local_hostname="gateway", timeout=120) as s:
                s.ehlo()
                code, resp = s.mail(self.sender)
                if code != 250:
                    return code, resp.decode("utf-8", "replace")
                for rcpt in self.rcpts:
                    code, resp = s.rcpt(rcpt)
                    if code not in (250, 251):
                        return code, resp.decode("utf-8", "replace")
                code, resp = s.data(message)
                return code, resp.decode("utf-8", "replace")
        except (OSError, smtplib.SMTPException) as e:
            log.error("reinject unreachable cid=%s error=%s", self.cid, type(e).__name__)
            return 0, ""


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


def serve(listen: str) -> Server:
    """Démarre le filtre dans un thread ; renvoie le serveur."""
    host, _, port = listen.rpartition(":")
    server = Server((host or "0.0.0.0", int(port)), Session)
    threading.Thread(target=server.serve_forever, name="proxy", daemon=True).start()
    return server
