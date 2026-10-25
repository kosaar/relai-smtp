"""Clés des destinataires : WKD de l'annuaire (HTTPS vérifié) + cache.

Résultat d'une recherche :
  ok          clé valide (non expirée, non révoquée, sous-clé de chiffrement) ;
  nokey       aucune clé utilisable : le destinataire est refusé (550) ;
  unavailable annuaire injoignable ou réponse inattendue : refus temporaire
              (451). Échec fermé : jamais de repli sur un envoi en clair, ni
              sur une entrée de cache expirée.
Les résultats ok et nokey sont gardés en cache `ttl` secondes.
"""
from __future__ import annotations

import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import quote

from pgpkeys import openpgp, policy, wkd


@dataclass(frozen=True)
class Lookup:
    status: str                 # ok | nokey | unavailable
    reason: str = ""            # motif court (journaux, métriques)
    fingerprint: str | None = None
    key: bytes | None = None


def classify(errors: list[str]) -> str:
    text = " ".join(errors)
    if "révoquée" in text:
        return "key-revoked"
    if "expirée" in text:
        return "key-expired"
    if "sous-clé de chiffrement" in text:
        return "key-unusable"
    return "key-invalid"


class KeyResolver:
    def __init__(self, base_url: str, cafile: str | None, ttl: int, timeout: float = 10,
                 clock=time.monotonic, fetch=None):
        self.base_url = base_url.rstrip("/")
        self.ttl = ttl
        self.timeout = timeout
        self.clock = clock
        self._fetch = fetch or self._https_get
        self._cache: dict[str, tuple[float, Lookup]] = {}
        self._lock = threading.Lock()
        self._ctx = ssl.create_default_context(cafile=cafile)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    def url_for(self, email: str) -> str:
        local = email.partition("@")[0]
        return f"{self.base_url}{wkd.advanced_path(email)}?l={quote(local)}"

    def _https_get(self, url: str) -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(url, context=self._ctx, timeout=self.timeout) as r:
                return r.status, r.read(1024 * 1024)
        except urllib.error.HTTPError as e:
            return e.code, b""

    def lookup(self, email: str) -> Lookup:
        now = self.clock()
        with self._lock:
            hit = self._cache.get(email)
            if hit and hit[0] > now:
                return hit[1]
        result = self.resolve(email)
        with self._lock:
            if result.status == "unavailable":
                self._cache.pop(email, None)
            else:
                self._cache[email] = (now + self.ttl, result)
        return result

    def resolve(self, email: str) -> Lookup:
        try:
            code, data = self._fetch(self.url_for(email))
        except (OSError, ValueError):
            return Lookup("unavailable", "keydir-unreachable")
        if code == 404:
            return Lookup("nokey", "no-key")
        if code != 200 or not data:
            return Lookup("unavailable", f"keydir-http-{code}")
        try:
            keys = openpgp.inspect(data)
        except (openpgp.GpgError, OSError):
            return Lookup("unavailable", "gpg-error")
        errors = policy.check_key(keys, email, set(), int(time.time()))
        if errors:
            return Lookup("nokey", classify(errors))
        return Lookup("ok", "", keys[0].fingerprint, data)
