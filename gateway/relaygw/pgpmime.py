"""Construction d'un message PGP/MIME (RFC 3156) avec en-têtes protégés.

Fonctions pures (aucune E/S), testées unitairement. Les en-têtes sont
manipulés sous forme brute : (nom, valeur en octets telle que reçue, avec son
pliage), pour que la partie chiffrée restitue exactement l'original.

Partie chiffrée (lue par Thunderbird, « protected-headers v1 ») :

    Content-Type: multipart/mixed; boundary="…"; protected-headers="v1"
    Subject: <objet réel>            <- en-têtes protégés : TOUS les en-têtes
    From: … / Message-ID: <réel> …      d'origine (X-GitLab-*, Received…)
    X-GitLab-Project: …

    --…
    Content-Type: <type d'origine>   <- entité MIME d'origine, inchangée
    Content-Transfer-Encoding: …

    <corps d'origine>
    --…--
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from email.header import Header

# En-têtes extérieurs autorisés (D9) : tous les autres n'existent plus que dans
# la partie chiffrée. Message-ID, In-Reply-To et References sont pseudonymisés.
OUTER_ALLOWED = ("from", "to", "cc", "date", "subject", "mime-version", "content-type",
                 "message-id", "in-reply-to", "references", "reply-to", "auto-submitted")
MSGID_HEADERS = ("message-id", "in-reply-to", "references")
MSGID_RE = re.compile(rb"<([^<>]+)>")
MAX_REFERENCES = 10   # premier identifiant (racine du fil) + 9 derniers (RFC 5322 § 3.6.4)
# En-têtes qui décrivent l'entité MIME d'origine : ils passent dans la partie chiffrée.
CONTENT = ("content-type", "content-transfer-encoding", "content-disposition",
           "content-description", "content-id", "content-language", "content-location",
           "content-md5", "content-base", "content-features", "content-duration")
DEFAULT_CONTENT_TYPE = b" text/plain; charset=us-ascii"
PREAMBLE = b"This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n"


def crlf(data: bytes) -> bytes:
    """Fins de ligne normalisées en CRLF."""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")


def header_line(name: str, value: bytes) -> bytes:
    value = crlf(value)
    if not value.startswith((b" ", b"\t")):
        value = b" " + value
    return name.encode("ascii") + b":" + value + b"\r\n"


def new_boundary() -> str:
    return "------------" + secrets.token_hex(12)


def encode_subject(text: str) -> str:
    try:
        text.encode("ascii")
        return text
    except UnicodeEncodeError:
        return Header(text, "utf-8").encode()


def build_inner(headers: list[tuple[str, bytes]], body: bytes, boundary: str | None = None) -> bytes:
    """Partie MIME à chiffrer : tous les en-têtes d'origine (protégés) + entité MIME d'origine."""
    boundary = boundary or new_boundary()
    protected = [header_line(n, v) for n, v in headers if n.lower() not in CONTENT]
    content = [header_line(n, v) for n, v in headers if n.lower() in CONTENT]
    if not any(n.lower() == "content-type" for n, _ in headers):
        content.insert(0, header_line("Content-Type", DEFAULT_CONTENT_TYPE))
    out = [header_line("Content-Type", f' multipart/mixed; boundary="{boundary}"; protected-headers="v1"'.encode()),
           *protected, b"\r\n",
           f"--{boundary}\r\n".encode(), *content, b"\r\n",
           crlf(body), f"\r\n--{boundary}--\r\n".encode()]
    return b"".join(out)


def outer_content_type(boundary: str) -> str:
    return f'multipart/encrypted; protocol="application/pgp-encrypted"; boundary="{boundary}"'


def build_encrypted_body(armored: bytes, boundary: str) -> bytes:
    b = boundary.encode()
    return b"".join([
        PREAMBLE,
        b"--" + b + b"\r\n",
        b"Content-Type: application/pgp-encrypted\r\n",
        b"Content-Description: PGP/MIME version identification\r\n\r\n",
        b"Version: 1\r\n\r\n",
        b"--" + b + b"\r\n",
        b'Content-Type: application/octet-stream; name="encrypted.asc"\r\n',
        b"Content-Description: OpenPGP encrypted message\r\n",
        b'Content-Disposition: inline; filename="encrypted.asc"\r\n\r\n',
        crlf(armored).rstrip(b"\r\n"), b"\r\n",
        b"--" + b + b"--\r\n",
    ])


def pseudonymize_ids(value: bytes, key: bytes, domain: str, limit: int = MAX_REFERENCES) -> str:
    """Identifiants de message pseudonymisés : <hmac@domaine>, séparés par une espace.

    Même identifiant d'origine => même pseudonyme (le fil est conservé dans
    Thunderbird), sans le nom d'hôte interne ni rien de devinable sans la clé.
    Au-delà de `limit` identifiants, on garde le premier et les derniers.
    Chaîne vide si la valeur ne contient aucun identifiant.
    """
    ids = [re.sub(rb"\s+", b"", m) for m in MSGID_RE.findall(value)]
    if len(ids) > limit:
        ids = ids[:1] + ids[-(limit - 1):]
    return " ".join(f"<{hmac.new(key, i, hashlib.sha256).hexdigest()[:32]}@{domain}>" for i in ids)


def random_message_id(domain: str) -> str:
    return f"<{secrets.token_hex(16)}@{domain}>"


def build_outer_headers(headers: list[tuple[str, bytes]], neutral_subject: str, boundary: str,
                        key: bytes, domain: str) -> bytes:
    """En-têtes extérieurs (bloc terminé par CRLF, sans la ligne vide).

    Seuls les en-têtes de OUTER_ALLOWED subsistent, dans l'ordre d'origine ;
    l'objet devient neutre, le type multipart/encrypted, les identifiants de
    message sont pseudonymisés (un Message-ID aléatoire est ajouté s'il manque).
    """
    replaced = {
        "subject": " " + encode_subject(neutral_subject),
        "content-type": " " + outer_content_type(boundary),
        "mime-version": " 1.0",
    }
    canonical = {"subject": "Subject", "content-type": "Content-Type", "mime-version": "MIME-Version",
                 "message-id": "Message-ID", "in-reply-to": "In-Reply-To", "references": "References"}
    out: list[bytes] = []
    done: set[str] = set()
    for name, value in headers:
        low = name.lower()
        if low not in OUTER_ALLOWED or low in done:
            continue
        if low in replaced:
            out.append(header_line(canonical[low], replaced[low].encode()))
            done.add(low)
        elif low in MSGID_HEADERS:
            done.add(low)   # un seul exemplaire, pseudonymisé ; supprimé s'il est invalide
            pseudo = pseudonymize_ids(value, key, domain)
            if pseudo:
                out.append(header_line(canonical[low], (" " + pseudo).encode()))
                done.add(low + ":ok")
        else:
            out.append(header_line(name, value))
    for low in ("mime-version", "subject", "content-type"):
        if low not in done:
            out.append(header_line(canonical[low], replaced[low].encode()))
    if "message-id:ok" not in done:
        out.append(header_line("Message-ID", (" " + random_message_id(domain)).encode()))
    return b"".join(out)


HEADER_NAME = re.compile(rb"^[!-9;-~]+$")   # RFC 5322 : caractères imprimables sauf « : »


def parse_message(data: bytes) -> tuple[list[tuple[str, bytes]], bytes]:
    """(en-têtes, corps) d'un message brut. Valeurs brutes : espace initiale et
    pliage conservés. Une ligne qui n'est ni un en-tête ni une continuation
    termine les en-têtes (comme Postfix)."""
    data = crlf(data)
    headers: list[tuple[str, bytes]] = []
    pos = 0
    while pos < len(data):
        end = data.find(b"\r\n", pos)
        end = len(data) if end < 0 else end
        line = data[pos:end]
        if line == b"":
            return headers, data[end + 2:]
        if line[:1] in (b" ", b"\t") and headers:
            name, value = headers[-1]
            headers[-1] = (name, value + b"\r\n" + line)
        else:
            name, sep, value = line.partition(b":")
            if not sep or not HEADER_NAME.match(name):
                return headers, data[pos:]
            headers.append((name.decode("ascii"), value))
        pos = end + 2
    return headers, b""
