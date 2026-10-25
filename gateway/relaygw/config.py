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
    if errors:
        raise ConfigError(errors)
    return Config(listen, url, ca, ttl, subject)
