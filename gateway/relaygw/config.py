"""Configuration de la passerelle (variables d'environnement), validée au démarrage."""
from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class Config:
    listen: str
    keydir_url: str
    keydir_ca_file: str | None
    key_cache_ttl: int
    neutral_subject: str
    hmac_key: bytes
    proxy_listen: str
    reinject_port: int


def load(env=os.environ) -> Config:
    errors: list[str] = []
    listen = env.get("GATEWAY_LISTEN", "inet:9900@0.0.0.0")
    url = env.get("GATEWAY_KEYDIR_URL", "https://keydir:8443").rstrip("/")
    if not url.startswith("https://") or len(url) <= len("https://"):
        errors.append(f"GATEWAY_KEYDIR_URL='{url}' invalide : HTTPS obligatoire (ex. https://keydir:8443).")
    ca = env.get("GATEWAY_KEYDIR_CA_FILE") or None
    if ca and not os.access(ca, os.R_OK):
        errors.append(f"GATEWAY_KEYDIR_CA_FILE='{ca}' introuvable ou illisible.")
    raw_ttl = env.get("GATEWAY_KEY_CACHE_TTL", "300")
    ttl = int(raw_ttl) if raw_ttl.isdigit() else -1
    if not 1 <= ttl <= 86400:
        errors.append(f"GATEWAY_KEY_CACHE_TTL='{raw_ttl}' invalide (secondes, de 1 à 86400).")
    subject = env.get("GATEWAY_NEUTRAL_SUBJECT", "Message chiffré").strip()
    if not subject or len(subject) > 200 or any(c in subject for c in "\r\n"):
        errors.append("GATEWAY_NEUTRAL_SUBJECT doit être un texte non vide d'une ligne (200 caractères max.).")
    proxy_listen = env.get("GATEWAY_PROXY_LISTEN", "0.0.0.0:10025")
    host, _, port = proxy_listen.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        errors.append(f"GATEWAY_PROXY_LISTEN='{proxy_listen}' invalide (adresse:port).")
    raw_port = env.get("GATEWAY_REINJECT_PORT", "10026")
    reinject_port = int(raw_port) if raw_port.isdigit() else 0
    if not 0 < reinject_port < 65536:
        errors.append(f"GATEWAY_REINJECT_PORT='{raw_port}' invalide.")
    key = b""
    key_file = env.get("GATEWAY_HMAC_KEY_FILE", "/run/secrets/gateway_hmac_key")
    try:
        with open(key_file, "rb") as f:
            key = f.read().strip()
    except OSError:
        errors.append(f"GATEWAY_HMAC_KEY_FILE='{key_file}' introuvable ou illisible (secret gateway_hmac_key).")
    else:
        if len(key) < 32:
            errors.append("Le secret gateway_hmac_key doit faire au moins 32 caractères (ex. openssl rand -base64 48).")
    if errors:
        raise ConfigError(errors)
    return Config(listen, url, ca, ttl, subject, key, proxy_listen, reinject_port)
