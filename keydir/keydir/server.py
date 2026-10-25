"""Serveur HTTPS de l'annuaire (TLS >= 1.2 uniquement, aucun port en clair).

  POST /api/v1/keys?email=<adresse>    dépôt d'une clé publique (=> pending)
                                       ou d'un certificat de révocation (appliqué immédiatement)
  GET  /api/v1/keys/<adresse>          état de la clé d'une adresse
  GET  /.well-known/openpgpkey/<domaine>/hu/<hachage>[?l=<local>]   WKD (méthode avancée)
  GET  /.well-known/openpgpkey/<domaine>/policy                      WKD : fichier de politique
  GET  /healthz                        sonde de santé
"""
from __future__ import annotations

import json
import logging
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from keydir import config as config_mod
from pgpkeys import openpgp, policy
from keydir.store import Store, StoreError

log = logging.getLogger("keydir")
WKD_RE = re.compile(r"^/\.well-known/openpgpkey/([a-z0-9.-]+)/hu/([a-z0-9]{32})$")
POLICY_RE = re.compile(r"^/\.well-known/openpgpkey/([a-z0-9.-]+)/policy$")
STATUS_RE = re.compile(r"^/api/v1/keys/([^/]+)$")


class Handler(BaseHTTPRequestHandler):
    server_version = "keydir"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- utilitaires ----------------------------------------------------------
    @property
    def app(self):
        return self.server.app

    def log_message(self, fmt, *args):   # journal d'accès : méthode, chemin sans paramètres, code
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store" if ctype.startswith("application/json") else "max-age=300")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        log.info("http src=%s %s %s -> %d", self.client_address[0], self.command, urlsplit(self.path).path, code)

    def _json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode() + b"\n", "application/json; charset=utf-8")

    def _error(self, code: int, message: str, details: list[str] | None = None):
        body = {"error": message}
        if details:
            body["details"] = details
        self._json(code, body)

    # -- routes ---------------------------------------------------------------
    def do_GET(self):
        url = urlsplit(self.path)
        path = url.path
        if path == "/healthz":
            return self._send(200, b"ok\n", "text/plain")
        if m := WKD_RE.match(path):
            domain, h = m.groups()
            data = self.app.store.wkd_lookup(domain, h) if domain in self.app.config.domains else None
            if data is None:
                return self._send(404, b"not found\n", "text/plain")
            return self._send(200, data, "application/octet-stream")
        if m := POLICY_RE.match(path):
            if m.group(1) in self.app.config.domains:
                return self._send(200, b"", "text/plain")
            return self._send(404, b"not found\n", "text/plain")
        if m := STATUS_RE.match(path):
            email = policy.normalize_email(unquote(m.group(1)))
            if not email:
                return self._error(400, "adresse invalide")
            return self._json(200, self.app.store.status(email))
        return self._send(404, b"not found\n", "text/plain")

    do_HEAD = do_GET

    def do_POST(self):
        url = urlsplit(self.path)
        if url.path != "/api/v1/keys":
            return self._send(404, b"not found\n", "text/plain")
        email = policy.normalize_email((parse_qs(url.query).get("email") or [""])[0])
        if not email:
            return self._error(400, "paramètre email absent ou invalide")
        length = self.headers.get("Content-Length")
        if not length or not length.isdigit():
            return self._error(411, "Content-Length requis")
        if int(length) > self.app.config.max_key_size:
            self.close_connection = True
            return self._error(413, f"clé trop volumineuse (maximum {self.app.config.max_key_size} octets)")
        data = self.rfile.read(int(length))
        self.app.deposit(self, email, data)


class TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, app):
        self.app = app
        cfg = app.config
        self.tls = config_mod.tls_context(cfg.cert, cfg.key)
        super().__init__((cfg.host, cfg.port), Handler)

    def finish_request(self, request, client_address):
        # Poignée de main TLS dans le fil de la requête : un client lent ou en
        # clair ne bloque pas les autres. Aucune réponse en clair n'est possible.
        request.settimeout(15)
        try:
            tls = self.tls.wrap_socket(request, server_side=True)
        except (OSError, ValueError) as e:
            log.info("tls refused src=%s reason=%s", client_address[0], type(e).__name__ + ":" + str(e)[:80])
            return
        try:
            Handler(tls, client_address, self)
        finally:
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tls.close()


class App:
    def __init__(self, cfg: config_mod.Config):
        self.config = cfg
        self.store = Store(cfg.db)

    def deposit(self, handler: Handler, email: str, data: bytes):
        src = handler.client_address[0]
        actor = f"api:{src}"
        now = int(time.time())
        try:
            keys = openpgp.inspect(data)
        except (openpgp.GpgError, OSError) as e:
            log.warning("gpg error src=%s: %s", src, e)
            return handler._error(500, "erreur interne")
        if not keys:
            # Pas de clé : certificat de révocation ?
            try:
                fpr = self.store.revoke_certificate(email, data, actor)
            except StoreError:
                log.info("deposit refused email=%s src=%s reason=unreadable-or-unmatched-revocation", email, src)
                return handler._error(422, "dépôt refusé", [
                    f"contenu illisible : ni clé publique OpenPGP, ni certificat de révocation d'une clé de {email}"])
            log.info("revoked email=%s fpr=%s src=%s by=certificate", email, fpr, src)
            return handler._json(200, {"email": email, "fingerprint": fpr, "state": "revoked"})
        errors = policy.check_key(keys, email, set(self.config.domains), now)
        if errors:
            self.store.audit("deposit", email, keys[0].fingerprint if len(keys) == 1 else None, actor,
                             "refused:" + "; ".join(errors)[:200])
            log.info("deposit refused email=%s src=%s reasons=%d", email, src, len(errors))
            return handler._error(422, "clé refusée", errors)
        info = keys[0]
        try:
            state = self.store.deposit(email, info, policy.algo_name(info.algo, info.bits, info.curve), data, actor)
        except StoreError as e:
            return handler._error(422, "clé refusée", [str(e)])
        log.info("deposit email=%s fpr=%s state=%s src=%s", email, info.fingerprint, state, src)
        handler._json(202 if state == "pending" else 200,
                      {"email": email, "fingerprint": info.fingerprint, "state": state})


def purge_loop(app: App):
    while True:
        try:
            n = app.store.purge_audit(app.config.audit_retention_days)
            if n:
                log.info("audit purge: %d entrée(s) de plus de %d jours supprimée(s)", n, app.config.audit_retention_days)
        except Exception as e:   # ne doit pas arrêter le service
            log.warning("audit purge failed: %s", e)
        time.sleep(3600)


def main() -> int:
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s keydir: %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
    try:
        cfg = config_mod.load()
    except config_mod.ConfigError as e:
        for err in e.errors:
            log.error("FATAL: %s", err)
        log.error("FATAL: refus de démarrer (configuration invalide).")
        return 1
    app = App(cfg)
    threading.Thread(target=purge_loop, args=(app,), daemon=True).start()
    srv = TLSServer(app)
    log.info("annuaire HTTPS (TLS >= 1.2) sur %s:%d, domaines : %s, rétention de l'audit : %d jours",
             cfg.host, cfg.port, " ".join(sorted(cfg.domains)), cfg.audit_retention_days)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
