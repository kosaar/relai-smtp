"""Contrôle du contenu sortant (D8), avant chiffrement.

Règles versionnées (config/content-rules.toml), appliquées au texte DÉCODÉ :
en-têtes (RFC 2047 décodé), chaque partie MIME (quoted-printable et base64
décodés, jeu de caractères appliqué), pièces jointes comprises, messages
attachés (message/rfc822) compris. Les archives (zip…) ne sont pas ouvertes.

Un refus ne porte que l'identifiant de la règle : jamais le contenu trouvé.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from email import message_from_bytes, policy
from email.header import decode_header, make_header

TOP_KEYS = {"version", "patterns", "attachments"}
PATTERN_KEYS = {"id", "description", "regex"}
ATTACHMENT_KEYS = {"forbidden_extensions", "max_size"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
EXT_RE = re.compile(r"^[a-z0-9]{1,16}$")


class RulesError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class Pattern:
    id: str
    regex: re.Pattern


@dataclass(frozen=True)
class Rules:
    version: int
    patterns: tuple[Pattern, ...]
    forbidden_extensions: frozenset[str]
    max_size: int   # taille maximale d'une pièce jointe décodée, 0 = aucune


def parse(data: dict, source: str = "règles") -> Rules:
    errors: list[str] = []
    for key in sorted(set(data) - TOP_KEYS):
        errors.append(f"{source} : clé inconnue '{key}'.")
    version = data.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        errors.append(f"{source} : version={version!r} absente ou invalide (entier >= 1).")
    patterns: list[Pattern] = []
    seen: set[str] = set()
    raw_patterns = data.get("patterns", [])
    if not isinstance(raw_patterns, list):
        errors.append(f"{source} : 'patterns' doit être une liste ([[patterns]]).")
        raw_patterns = []
    for n, entry in enumerate(raw_patterns, 1):
        where = f"{source} : motif n°{n}"
        if not isinstance(entry, dict):
            errors.append(f"{where} invalide.")
            continue
        for key in sorted(set(entry) - PATTERN_KEYS):
            errors.append(f"{where} : clé inconnue '{key}'.")
        rid = entry.get("id")
        if not isinstance(rid, str) or not ID_RE.match(rid):
            errors.append(f"{where} : id={rid!r} invalide (minuscules, chiffres, tirets).")
            rid = None
        elif rid in seen:
            errors.append(f"{where} : id '{rid}' en double.")
        else:
            seen.add(rid)
        regex = entry.get("regex")
        compiled = None
        if not isinstance(regex, str) or not regex:
            errors.append(f"{where} : regex absente.")
        else:
            try:
                compiled = re.compile(regex)
            except re.error as e:
                errors.append(f"{where} ('{rid}') : regex invalide ({e}).")
        if rid and compiled is not None:
            patterns.append(Pattern(rid, compiled))
    att = data.get("attachments", {})
    if not isinstance(att, dict):
        errors.append(f"{source} : [attachments] invalide.")
        att = {}
    for key in sorted(set(att) - ATTACHMENT_KEYS):
        errors.append(f"{source} : [attachments] : clé inconnue '{key}'.")
    exts = att.get("forbidden_extensions", [])
    if not isinstance(exts, list) or not all(isinstance(e, str) for e in exts):
        errors.append(f"{source} : forbidden_extensions doit être une liste de chaînes.")
        exts = []
    clean = set()
    for e in exts:
        e = e.lower().lstrip(".")
        if not EXT_RE.match(e):
            errors.append(f"{source} : extension '{e}' invalide.")
        clean.add(e)
    max_size = att.get("max_size", 0)
    if not isinstance(max_size, int) or isinstance(max_size, bool) or max_size < 0:
        errors.append(f"{source} : max_size={max_size!r} invalide (octets, 0 = aucune limite).")
        max_size = 0
    if errors:
        raise RulesError(errors)
    return Rules(version, tuple(patterns), frozenset(clean), max_size)


def load(path: str) -> Rules:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except OSError as e:
        raise RulesError([f"règles de contenu {path} illisibles ({e.strerror})."]) from e
    except tomllib.TOMLDecodeError as e:
        raise RulesError([f"règles de contenu {path} : TOML invalide ({e})."]) from e
    return parse(data, path)


def _decoded_header(value) -> str:
    try:
        return str(make_header(decode_header(str(value))))
    except (ValueError, LookupError, UnicodeError):
        return str(value)


def _text(payload: bytes, charset: str | None) -> str:
    try:
        return payload.decode(charset or "utf-8", "replace")
    except LookupError:
        return payload.decode("utf-8", "replace")


def _extension(filename: str | None) -> str | None:
    if not filename or "." not in filename:
        return None
    return filename.rsplit(".", 1)[1].strip().lower()


def scan(rules: Rules, data: bytes) -> str | None:
    """Identifiant de la première règle enfreinte, None si le message est sain."""
    msg = message_from_bytes(data, policy=policy.compat32)
    for part in msg.walk():
        texts = [f"{k}: {_decoded_header(v)}" for k, v in part.items()]
        filename = part.get_filename()
        if filename is not None:
            filename = _decoded_header(filename)
            ext = _extension(filename)
            if ext in rules.forbidden_extensions:
                return "forbidden-extension"
        if not part.is_multipart():
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                if rules.max_size and filename is not None and len(payload) > rules.max_size:
                    return "attachment-too-big"
                texts.append(_text(payload, part.get_content_charset()))
        for text in texts:
            for pattern in rules.patterns:
                if pattern.regex.search(text):
                    return pattern.id
    return None
