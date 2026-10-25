"""Lecture de messages PGP/MIME côté poste (rôle de Thunderbird) — TEST UNIQUEMENT.

Le déchiffrement passe par RNP (bibliothèque OpenPGP de Thunderbird), avec les
trousseaux du poste (~/.rnp/<adresse>, plus les trousseaux archivés après une
rotation). Les identifiants de clés des paquets sont lus par GnuPG.
"""
from __future__ import annotations

import email
import email.policy
import glob
import hashlib
import os
import re
import subprocess
import tempfile
from email.header import decode_header, make_header

RNP_BASE = os.environ.get("RNP_HOME_BASE", os.path.expanduser("~/.rnp"))
ARMOR_RE = re.compile(rb"-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----", re.S)


def homes_for(mailbox: str) -> list[str]:
    """Trousseaux RNP d'une adresse : courant d'abord, puis archives (plus récente d'abord)."""
    base = os.path.join(RNP_BASE, mailbox)
    archived = sorted(glob.glob(base + ".*"), reverse=True)
    return [h for h in [base, *archived] if os.path.isdir(h)]


def armored_part(raw: bytes) -> bytes | None:
    m = ARMOR_RE.search(raw)
    return m.group(0) if m else None


def rnp_decrypt(armored: bytes, home: str) -> bytes | None:
    # --allow-hidden : destinataires masqués (--throw-keyids), comme dans Thunderbird.
    proc = subprocess.run(["rnp", "--homedir", home, "--decrypt", "--allow-hidden", "--password", "", "--output", "-"],
                          input=armored, capture_output=True, timeout=60)
    return proc.stdout if proc.returncode == 0 and proc.stdout else None


def decrypt(raw: bytes, homes: list[str]) -> tuple[bytes | None, str | None]:
    """(partie déchiffrée, trousseau utilisé) ou (None, None)."""
    armored = armored_part(raw)
    if armored is None:
        return None, None
    for home in homes:
        plain = rnp_decrypt(armored, home)
        if plain is not None:
            return plain, home
    return None, None


def keyids(raw: bytes) -> list[str]:
    """Identifiants de clés des paquets de session chiffrés (GnuPG --list-packets)."""
    armored = armored_part(raw)
    if armored is None:
        return []
    with tempfile.TemporaryDirectory() as home:
        proc = subprocess.run(["gpg", "--homedir", home, "--batch", "--no-tty", "--list-packets"],
                              input=armored, capture_output=True, timeout=60)
        subprocess.run(["gpgconf", "--homedir", home, "--kill", "all"], capture_output=True)
    return re.findall(r":pubkey enc packet: .*keyid ([0-9A-F]{16})", proc.stdout.decode("utf-8", "replace"))


def decoded(value: str | None) -> str | None:
    if value is None:
        return None
    return str(make_header(decode_header(value)))


def summarize(raw: bytes, homes: list[str]) -> dict:
    outer = email.message_from_bytes(raw, policy=email.policy.compat32)
    out = {
        "outer": {
            "content_type": outer.get_content_type(),
            "protocol": outer.get_param("protocol"),
            "subject": decoded(outer.get("Subject")),
            "headers": [k for k in outer.keys()],
            "parts": [p.get_content_type() for p in outer.walk()][1:] if outer.is_multipart() else [],
        },
        "keyids": keyids(raw),
        "decrypted": False,
    }
    plain, home = decrypt(raw, homes)
    if plain is None:
        return out
    inner = email.message_from_bytes(plain, policy=email.policy.compat32)
    texts, attachments = [], []
    for part in inner.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        if part.get_filename():
            attachments.append({"name": decoded(part.get_filename()), "sha256": hashlib.sha256(payload).hexdigest(),
                                "size": len(payload), "content_type": part.get_content_type()})
        elif part.get_content_type() == "text/plain":
            texts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    out.update({
        "decrypted": True,
        "home": os.path.basename(home),
        "inner": {
            "content_type": inner.get_content_type(),
            "protected_headers": inner.get_param("protected-headers"),
            "subject": decoded(inner.get("Subject")),
            "from": inner.get("From"),
            "to": inner.get("To"),
            "message_id": inner.get("Message-ID"),
            "headers": [k for k in inner.keys()],
            "text": "\n".join(texts),
            "attachments": attachments,
        },
    })
    return out
