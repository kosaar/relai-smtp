"""Web Key Directory (draft-koch-openpgp-webkey-service) : calcul des chemins."""
from __future__ import annotations

import hashlib

ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"


def zbase32(data: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    bits += "0" * (-len(bits) % 5)
    return "".join(ZBASE32[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def wkd_hash(local_part: str) -> str:
    """Hachage WKD de la partie locale (convertie en minuscules), 32 caractères."""
    return zbase32(hashlib.sha1(local_part.lower().encode("utf-8")).digest())


def advanced_path(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"/.well-known/openpgpkey/{domain.lower()}/hu/{wkd_hash(local)}"
