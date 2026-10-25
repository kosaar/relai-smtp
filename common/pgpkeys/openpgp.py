"""Lecture et manipulation de clés OpenPGP avec GnuPG (trousseaux temporaires).

Aucun trousseau persistant : chaque opération utilise un répertoire GnuPG
jetable, supprimé ensuite. Seules des clés PUBLIQUES sont manipulées.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from email.utils import parseaddr

GPG = os.environ.get("PGP_GPG", "gpg")
BASE_ARGS = ["--batch", "--no-tty", "--quiet", "--no-greeting", "--no-autostart",
             "--no-permission-warning", "--with-colons", "--fixed-list-mode"]


class GpgError(Exception):
    pass


@dataclass
class SubKey:
    fingerprint: str
    algo: int
    bits: int
    curve: str
    caps: str
    created: int
    expires: int | None
    revoked: bool


@dataclass
class KeyInfo:
    fingerprint: str
    algo: int
    bits: int
    curve: str
    caps: str
    created: int
    expires: int | None
    revoked: bool
    uids: list[tuple[str, str, bool]] = field(default_factory=list)   # (texte, email, révoqué)
    subkeys: list[SubKey] = field(default_factory=list)

    def emails(self) -> set[str]:
        return {email for _, email, revoked in self.uids if email and not revoked}


@contextmanager
def temp_home():
    tmp = os.environ.get("PGP_TMPDIR") or None
    home = tempfile.mkdtemp(prefix="gnupg-", dir=tmp)
    os.chmod(home, 0o700)
    try:
        yield home
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _gpg(home: str, args: list[str], data: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run([GPG, "--homedir", home, *BASE_ARGS, *args], input=data,
                          capture_output=True, timeout=30)
    if check and proc.returncode != 0:
        raise GpgError(proc.stderr.decode("utf-8", "replace").strip()[:300] or f"gpg exit {proc.returncode}")
    return proc


def _int(value: str) -> int | None:
    return int(value) if value.isdigit() and int(value) > 0 else None


def parse_colons(text: str) -> list[KeyInfo]:
    keys: list[KeyInfo] = []
    current = None   # dernier pub/sub, pour rattacher la ligne fpr
    for line in text.splitlines():
        f = line.split(":")
        if len(f) < 12:
            f += [""] * (12 - len(f))
        rtype = f[0]
        curve = f[16] if len(f) > 16 else ""
        if rtype == "pub":
            current = KeyInfo("", int(f[3] or 0), int(f[2] or 0), curve, f[11], int(f[5] or 0),
                              _int(f[6]), f[1] == "r")
            keys.append(current)
        elif rtype == "sub" and keys:
            current = SubKey("", int(f[3] or 0), int(f[2] or 0), curve, f[11], int(f[5] or 0),
                             _int(f[6]), f[1] == "r")
            keys[-1].subkeys.append(current)
        elif rtype == "fpr" and current is not None and not current.fingerprint:
            current.fingerprint = f[9].upper()
        elif rtype == "uid" and keys:
            text_uid = f[9].replace("\\x3a", ":")
            email = parseaddr(text_uid)[1].lower()
            if "@" not in email:
                email = ""
            keys[-1].uids.append((text_uid, email, f[1] == "r"))
    return keys


def inspect(data: bytes) -> list[KeyInfo]:
    """Clés contenues dans `data` (armure ASCII ou binaire), sans les importer."""
    with temp_home() as home:
        proc = _gpg(home, ["--show-keys", "-"], data, check=False)
    return parse_colons(proc.stdout.decode("utf-8", "replace"))


def export_for_wkd(key_data: bytes, fingerprint: str, email: str) -> bytes:
    """Clé publique binaire minimale, réduite à l'identité `email` (format WKD)."""
    with temp_home() as home:
        _gpg(home, ["--import"], key_data)
        out = _gpg(home, ["--export", "--export-options", "export-minimal",
                          "--export-filter", f"keep-uid=mbox = {email}", fingerprint]).stdout
    if not out:
        raise GpgError("export vide")
    return out


def apply_revocation(key_data: bytes, fingerprint: str, revocation: bytes) -> bytes | None:
    """Applique un certificat de révocation : clé révoquée (binaire) ou None s'il ne s'applique pas."""
    with temp_home() as home:
        _gpg(home, ["--import"], key_data)
        _gpg(home, ["--import"], revocation, check=False)
        keys = parse_colons(_gpg(home, ["--list-keys", fingerprint]).stdout.decode("utf-8", "replace"))
        if not keys or not keys[0].revoked:
            return None
        return _gpg(home, ["--export", fingerprint]).stdout
