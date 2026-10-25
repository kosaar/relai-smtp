"""Règles d'identité de la passerelle (fonctions pures, sans E/S).

Un login SASL (application de l'inventaire) n'envoie que depuis SES IP
(client_ips) et qu'avec SON adresse :
  - enveloppe (MAIL FROM) : déjà imposé par Postfix (reject_sender_login_mismatch),
    revérifié ici en défense en profondeur ;
  - en-tête From: : un seul en-tête, une seule adresse, égale à celle du login ;
    un nom affiché ne peut pas contenir une autre adresse e-mail.
Chaque refus porte un identifiant de motif court, seul élément journalisé
(jamais le contenu ni les en-têtes du message).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email.header import decode_header, make_header
from email.utils import getaddresses

ADDR_IN_TEXT = re.compile(r"[^\s<>\"'@]+@[^\s<>\"'@]+\.[^\s<>\"'@]+")


@dataclass(frozen=True)
class Refusal:
    code: str      # code SMTP (550, 451…)
    dsn: str       # code étendu (5.7.1…)
    text: str      # message renvoyé à l'application
    reason: str    # identifiant de motif, journalisé

    @property
    def permanent(self) -> bool:
        return self.code.startswith("5")


def strip_brackets(addr: str | None) -> str:
    addr = (addr or "").strip()
    if addr.startswith("<") and addr.endswith(">"):
        addr = addr[1:-1]
    return addr.strip()


def resolve_login(inventory, login: str | None):
    """Application associée au login SASL, ou Refusal."""
    if not login:
        return None, Refusal("550", "5.7.1", "Authentication required", "no-login")
    app = inventory.by_login(login)
    if app is None:
        return None, Refusal("550", "5.7.1", "Unknown application login", "unknown-login")
    return app, None


def check_client_ip(app, client_ip: str | None) -> Refusal | None:
    """Le login n'est utilisable que depuis les IP déclarées pour l'application."""
    try:
        ip = ipaddress.ip_address((client_ip or "").strip("[]"))
    except ValueError:
        ip = None
    if ip is None or ip.compressed not in app.client_ips:
        return Refusal("550", "5.7.1", "This login is not allowed from this host", "client-ip-mismatch")
    return None


def check_envelope_sender(app, mailfrom: str | None) -> Refusal | None:
    sender = strip_brackets(mailfrom).lower()
    if not sender:
        return Refusal("550", "5.7.1", "Null sender is not allowed for applications", "null-sender")
    if sender != app.address:
        return Refusal("553", "5.7.1", f"Sender address must be {app.address}", "envelope-mismatch")
    return None


def _decoded(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except (ValueError, LookupError, UnicodeError):
        return value


def check_from_headers(app, values: list[str]) -> Refusal | None:
    """Contrôle des en-têtes From: (valeurs brutes, dans l'ordre du message)."""
    if not values:
        return Refusal("550", "5.7.1", "Missing From: header", "from-missing")
    if len(values) > 1:
        return Refusal("550", "5.7.1", "Exactly one From: header is required", "from-multiple")
    pairs = getaddresses([" ".join(values[0].split())])
    pairs = [(name, addr) for name, addr in pairs if name or addr]
    if len(pairs) != 1 or not pairs[0][1] or "@" not in pairs[0][1]:
        return Refusal("550", "5.7.1", "From: must contain exactly one address", "from-invalid")
    name, addr = pairs[0]
    if addr.strip().lower() != app.address:
        return Refusal("550", "5.7.1", f"From: header must be {app.address}", "from-mismatch")
    for found in ADDR_IN_TEXT.findall(_decoded(name)):
        if found.lower() != app.address:
            return Refusal("550", "5.7.1", "From: display name must not contain another address", "from-display-spoof")
    return None
