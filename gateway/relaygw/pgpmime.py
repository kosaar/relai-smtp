"""Construction d'un message PGP/MIME (RFC 3156) avec en-têtes protégés.

Fonctions pures (aucune E/S), testées unitairement. Les en-têtes sont
manipulés sous forme brute : (nom, valeur en octets telle que reçue, avec son
pliage), pour que la partie chiffrée restitue exactement l'original.

Partie chiffrée (lue par Thunderbird, « protected-headers v1 ») :

    Content-Type: multipart/mixed; boundary="…"; protected-headers="v1"
    Subject: <objet réel>            <- en-têtes protégés
    From: … / To: … / Date: … / Message-ID: …

    --…
    Content-Type: <type d'origine>   <- entité MIME d'origine, inchangée
    Content-Transfer-Encoding: …

    <corps d'origine>
    --…--
"""
from __future__ import annotations

import secrets
from email.header import Header

# En-têtes recopiés dans la partie chiffrée (l'objet réel n'existe plus qu'ici).
PROTECTED = ("from", "sender", "reply-to", "to", "cc", "date", "subject", "message-id",
             "in-reply-to", "references", "followup-to", "mail-followup-to")
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
    """Partie MIME à chiffrer : en-têtes protégés + entité MIME d'origine."""
    boundary = boundary or new_boundary()
    protected = [header_line(n, v) for n, v in headers if n.lower() in PROTECTED]
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


def outer_header_changes(headers: list[tuple[str, bytes]], neutral_subject: str, boundary: str):
    """Modifications des en-têtes extérieurs : liste de (opération, nom, index, valeur).

    opération : "change" (index = n-ième occurrence, 1-based ; valeur None =
    suppression) ou "add". L'objet devient neutre, le type devient
    multipart/encrypted, les autres en-têtes Content-* disparaissent.
    """
    ops = []
    counts: dict[str, int] = {}
    seen_subject = seen_ctype = seen_mime = False
    for name, _ in headers:
        low = name.lower()
        counts[low] = counts.get(low, 0) + 1
    # Les suppressions se font de la dernière occurrence vers la première, pour
    # que les index restent valides.
    for low, n in counts.items():
        name = next(h for h, _ in headers if h.lower() == low)
        if low == "subject":
            seen_subject = True
            ops.append(("change", name, 1, " " + encode_subject(neutral_subject)))
            ops += [("change", name, i, None) for i in range(n, 1, -1)]
        elif low == "content-type":
            seen_ctype = True
            ops.append(("change", name, 1, " " + outer_content_type(boundary)))
            ops += [("change", name, i, None) for i in range(n, 1, -1)]
        elif low in CONTENT:
            ops += [("change", name, i, None) for i in range(n, 0, -1)]
        elif low == "mime-version":
            seen_mime = True
            ops.append(("change", name, 1, " 1.0"))
            ops += [("change", name, i, None) for i in range(n, 1, -1)]
    if not seen_mime:
        ops.append(("add", "MIME-Version", 0, " 1.0"))
    if not seen_subject:
        ops.append(("add", "Subject", 0, " " + encode_subject(neutral_subject)))
    if not seen_ctype:
        ops.append(("add", "Content-Type", 0, " " + outer_content_type(boundary)))
    return ops
