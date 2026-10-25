"""Configuration de l'annuaire (variables d'environnement), validée au démarrage."""
from __future__ import annotations

import os
import re
import ssl
from dataclasses import dataclass

DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    cert: str
    key: str
    db: str
    domains: frozenset[str]
    audit_retention_days: int
    max_key_size: int
    metrics_listen: tuple[str, int] | None = None
    expiry_warning_days: int = 30


def _int(env, name, default, lo, hi, errors):
    raw = env.get(name, str(default))
    if not raw.isdigit() or not lo <= int(raw) <= hi:
        errors.append(f"{name}='{raw}' invalide (entier de {lo} à {hi}).")
        return default
    return int(raw)


def load(env=os.environ) -> Config:
    errors: list[str] = []
    listen = env.get("KEYDIR_LISTEN", "0.0.0.0:8443")
    host, _, port = listen.rpartition(":")
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        errors.append(f"KEYDIR_LISTEN='{listen}' invalide (ex. 0.0.0.0:8443).")
        port = "8443"
    domains = frozenset(d.strip().lower() for d in re.split(r"[\s,]+", env.get("KEYDIR_DOMAINS", "")) if d.strip())
    if not domains:
        errors.append("KEYDIR_DOMAINS est obligatoire (domaines dont l'annuaire publie les clés, ex. \"example.com\").")
    for d in sorted(domains):
        if not DOMAIN_RE.match(d):
            errors.append(f"KEYDIR_DOMAINS : '{d}' n'est pas un nom de domaine valide.")
    retention = _int(env, "KEYDIR_AUDIT_RETENTION_DAYS", 365, 1, 3650, errors)
    warning_days = _int(env, "KEYDIR_EXPIRY_WARNING_DAYS", 30, 1, 365, errors)
    # Métriques (HTTP, port interne non publié) ; vide = désactivées.
    metrics_raw = env.get("KEYDIR_METRICS_LISTEN", "0.0.0.0:9155")
    metrics_listen = None
    if metrics_raw:
        mhost, _, mport = metrics_raw.rpartition(":")
        if not mhost or not mport.isdigit() or not 1 <= int(mport) <= 65535 or mport == port:
            errors.append(f"KEYDIR_METRICS_LISTEN='{metrics_raw}' invalide (ex. 0.0.0.0:9155, vide = désactivé).")
        else:
            metrics_listen = (mhost, int(mport))
    max_size = _int(env, "KEYDIR_MAX_KEY_SIZE", 65536, 1024, 1048576, errors)
    cert = env.get("KEYDIR_TLS_CERT", "/run/keydir/tls/cert.pem")
    key = env.get("KEYDIR_TLS_KEY", "/run/keydir/tls/key.pem")
    try:
        tls_context(cert, key)
    except (OSError, ssl.SSLError) as e:
        errors.append(f"certificat {cert} / clé {key} inutilisables ({e}).")
    if errors:
        raise ConfigError(errors)
    return Config(host, int(port), cert, key, env.get("KEYDIR_DB", "/var/lib/keydir/keydir.db"),
                  domains, retention, max_size, metrics_listen, warning_days)


def tls_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL")
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.load_cert_chain(cert, key)
    return ctx
