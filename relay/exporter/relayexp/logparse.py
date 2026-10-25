"""Analyse des journaux Postfix du relai pour l'exporteur (fonctions pures).

Seules des métadonnées sont lues (adresses d'enveloppe, codes de réponse,
identifiant de règle de contenu) : les journaux ne contiennent ni objet ni corps.

Événements comptés :
  - échecs d'authentification SASL (par application, d'après l'IP du client) ;
  - refus (smtpd, milter, filtre avant file) par application (login SASL,
    sinon adresse d'enveloppe, sinon IP du client) et par motif ;
  - refus faute de clé, par destinataire ;
  - blocages de contenu, par application et par règle ;
  - livraisons vers le smarthost (sent, deferred, bounced, expired) et
    différés par motif, par application (expéditeur d'enveloppe).

Le dernier résultat de livraison des derniers messages (identifiant de file →
statut et motif, sans adresse) est conservé pour relay-smoke-test.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field

from relayexp.metrics import Registry

LINE_RE = re.compile(r"\bpostfix(?P<svc>(?:/[\w.-]+)+)\[\d+\]: (?P<msg>.*)$")
SASL_FAIL_RE = re.compile(r"^warning: [^\s\[]*\[(?P<ip>[0-9A-Fa-f.:]+)\](?::\d+)?: SASL \S+ authentication failed")
REJECT_RE = re.compile(
    r"^(?:(?P<qid>\w+): )?(?P<kind>reject|milter-reject|proxy-reject): (?P<stage>[A-Z][A-Z-]*)"
    r"(?: from (?P<client>[^:]*?))?: (?P<code>[245]\d\d)[ -](?P<text>.*)$")
ENVELOPE_RE = re.compile(r"; from=<(?P<sender>[^>]*)>(?: to=<(?P<rcpt>[^>]*)>)?")
SASL_USER_RE = re.compile(r" sasl_username=<(?P<login>[^>]*)>")
CLIENT_IP_RE = re.compile(r"\[(?P<ip>[0-9A-Fa-f.:]+)\]")
NOKEY_RE = re.compile(r"No valid OpenPGP key for <(?P<rcpt>[^>]+)>")
CONTENT_RE = re.compile(r"content policy \(rule (?P<rule>[a-z0-9][a-z0-9-]{0,62})\)")
QMGR_FROM_RE = re.compile(r"^(?P<qid>[0-9A-Za-z]+): from=<(?P<sender>[^>]*)>, (?:size=|status=expired)")
DELIVERY_RE = re.compile(
    r"^(?P<qid>[0-9A-Za-z]+): to=<[^>]*>,.*\bstatus=(?P<status>sent|deferred|bounced)(?: \((?P<detail>.*)\))?$")
EXPIRED_RE = re.compile(r"^(?P<qid>[0-9A-Za-z]+): from=<[^>]*>, status=expired")
REMOVED_RE = re.compile(r"^(?P<qid>[0-9A-Za-z]+): removed$")

# Motif de refus d'après le texte de la réponse (ordre significatif).
REJECT_REASONS: list[tuple[str, str]] = [
    ("No valid OpenPGP key", "no_key"),
    ("No usable OpenPGP key", "key_unusable"),
    ("Key directory unavailable", "keydir_unavailable"),
    ("content policy (rule", "content"),
    ("Client host rejected", "client_host"),
    ("not allowed from this host", "client_ip_mismatch"),
    ("not owned by user", "envelope_sender"),
    ("Sender address must be", "envelope_sender"),
    ("Null sender", "envelope_sender"),
    ("From:", "header_from"),
    ("Authentication required", "auth_required"),
    ("Relay access denied", "auth_required"),
    ("Unknown application login", "unknown_login"),
    ("Message too big", "size"),
    ("Message size exceeds", "size"),
    ("Encryption failed", "encryption_error"),
    ("Reinjection failed", "reinjection_error"),
    ("Service unavailable", "gateway_unavailable"),
    ("queue file write error", "gateway_unavailable"),
    ("too many", "rate_limit"),
]
DEFER_REASONS: list[tuple[str, str]] = [
    ("SASL authentication failed", "auth"),
    ("certificate", "tls"),
    ("TLS", "tls"),
    ("Host or domain name not found", "dns"),
    ("Name service error", "dns"),
    ("Connection refused", "connection"),
    ("Connection timed out", "connection"),
    ("No route to host", "connection"),
    ("Network is unreachable", "connection"),
    ("lost connection", "connection"),
    ("conversation with", "connection"),
    ("connect to", "connection"),
    (" said: 4", "remote_temporary"),
]
MAX_RECIPIENT_SERIES = 1000
MAX_TRACKED_QIDS = 20000
MAX_OUTCOMES = 5000
UNKNOWN = "unknown"
NO_SENDER = "none"


def _classify(text: str, table: list[tuple[str, str]]) -> str:
    for needle, reason in table:
        if needle in text:
            return reason
    return "other"


def reject_reason(code: str, text: str) -> str:
    reason = _classify(text, REJECT_REASONS)
    if reason == "other" and code == "552":
        return "size"
    return reason


def defer_reason(detail: str) -> str:
    return _classify(detail or "", DEFER_REASONS)


@dataclass
class AppMap:
    """Application d'après le login SASL, l'adresse expéditrice ou l'IP du client (inventaire)."""
    addresses: dict[str, str] = field(default_factory=dict)
    ips: dict[str, str] = field(default_factory=dict)

    @property
    def names(self) -> set[str]:
        return set(self.addresses.values())

    @classmethod
    def from_inventory(cls, inventory) -> "AppMap":
        addresses = {app.address.lower(): name for name, app in inventory.applications.items()}
        by_ip: dict[str, list[str]] = {}
        for name, app in inventory.applications.items():
            for ip in app.client_ips:
                by_ip.setdefault(ip, []).append(name)
        return cls(addresses, {ip: "+".join(sorted(names)) for ip, names in by_ip.items()})

    def by_sender(self, sender: str | None) -> str | None:
        if sender is None:
            return None
        if sender == "":
            return NO_SENDER
        return self.addresses.get(sender.lower(), UNKNOWN)

    def by_ip(self, ip: str | None) -> str:
        return self.ips.get(ip or "", UNKNOWN)

    def by_login(self, login: str | None) -> str | None:
        if not login:
            return None
        return login if login in self.names else UNKNOWN


class LogParser:
    def __init__(self, registry: Registry, apps: AppMap):
        self.apps = apps
        self.lines = registry.counter("relay_log_lines_total", "Lignes de journal Postfix analysées")
        self.auth_failures = registry.counter(
            "relay_auth_failures_total", "Échecs d'authentification SASL sur la soumission, par application "
            "(d'après l'IP du client)", ("app",))
        self.rejects = registry.counter(
            "relay_rejects_total", "Commandes SMTP refusées (relai, milter, filtre avant file), par application, "
            "motif et classe (permanent, temporary)", ("app", "reason", "class"))
        self.nokey = registry.counter(
            "relay_nokey_rejects_total", "Destinataires refusés faute de clé OpenPGP valide", ("recipient",))
        self.content = registry.counter(
            "relay_content_blocks_total", "Messages bloqués par le contrôle du contenu, par application et règle",
            ("app", "rule"))
        self.deliveries = registry.counter(
            "relay_deliveries_total", "Tentatives de livraison vers le smarthost, par application et résultat "
            "(sent, deferred, bounced, expired)", ("app", "status"))
        self.deferrals = registry.counter(
            "relay_deferrals_total", "Livraisons différées, par application et motif", ("app", "reason"))
        self._senders: OrderedDict[str, str] = OrderedDict()
        self._outcomes: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._recipients: set[str] = set()

    # -- utilitaires ------------------------------------------------------------
    def _remember(self, qid: str, sender: str) -> None:
        self._senders[qid] = sender
        self._senders.move_to_end(qid)
        while len(self._senders) > MAX_TRACKED_QIDS:
            self._senders.popitem(last=False)

    def _record(self, qid: str, status: str, reason: str = "") -> None:
        self._outcomes[qid] = (status, reason)
        self._outcomes.move_to_end(qid)
        while len(self._outcomes) > MAX_OUTCOMES:
            self._outcomes.popitem(last=False)

    def outcome(self, qid: str) -> tuple[str, str] | None:
        """Dernier résultat de livraison du message (statut, motif de différé), None si inconnu."""
        return self._outcomes.get(qid)

    def _app_of_qid(self, qid: str) -> str:
        sender = self._senders.get(qid)
        return self.apps.by_sender(sender) if sender is not None else UNKNOWN

    def _recipient_label(self, rcpt: str) -> str:
        rcpt = rcpt.lower()
        if rcpt in self._recipients or len(self._recipients) < MAX_RECIPIENT_SERIES:
            self._recipients.add(rcpt)
            return rcpt
        return "other"

    # -- analyse ------------------------------------------------------------------
    def feed(self, line: str) -> None:
        m = LINE_RE.search(line.rstrip("\r\n"))
        if not m:
            return
        self.lines.inc()
        svc, msg = m["svc"], m["msg"]
        if svc.endswith("/smtpd"):
            self._smtpd(msg)
        elif svc.endswith("/qmgr"):
            self._qmgr(msg)
        else:
            self._delivery(msg)

    def _smtpd(self, msg: str) -> None:
        m = SASL_FAIL_RE.match(msg)
        if m:
            self.auth_failures.inc(app=self.apps.by_ip(m["ip"]))
            return
        m = REJECT_RE.match(msg)
        if not m:
            return
        text, env, login = m["text"], None, None
        cut = text.rfind("; from=<")
        if cut >= 0:
            env = ENVELOPE_RE.match(text[cut:])
            lm = SASL_USER_RE.search(text[cut:])
            login = lm["login"] if lm else None
            text = text[:cut]
        elif "; proto=" in text:
            text = text[:text.rfind("; proto=")]
        app = self.apps.by_login(login)
        if app in (None, UNKNOWN) and env:
            app = self.apps.by_sender(env["sender"])
        if app in (None, UNKNOWN) and m["client"]:
            ipm = CLIENT_IP_RE.search(m["client"])
            if ipm:
                app = self.apps.by_ip(ipm["ip"])
        app = app or UNKNOWN
        code = m["code"]
        reason = reject_reason(code, text)
        self.rejects.inc(app=app, reason=reason, **{"class": "permanent" if code[0] == "5" else "temporary"})
        if reason == "no_key":
            k = NOKEY_RE.search(text)
            rcpt = k["rcpt"] if k else (env["rcpt"] if env and env["rcpt"] else UNKNOWN)
            self.nokey.inc(recipient=self._recipient_label(rcpt))
        elif reason == "content":
            c = CONTENT_RE.search(text)
            self.content.inc(app=app, rule=c["rule"] if c else UNKNOWN)

    def _qmgr(self, msg: str) -> None:
        m = EXPIRED_RE.match(msg)
        if m:
            self.deliveries.inc(app=self._app_of_qid(m["qid"]), status="expired")
            self._record(m["qid"], "expired")
            return
        m = QMGR_FROM_RE.match(msg)
        if m:
            self._remember(m["qid"], m["sender"])
            return
        m = REMOVED_RE.match(msg)
        if m:
            self._senders.pop(m["qid"], None)

    def _delivery(self, msg: str) -> None:
        m = DELIVERY_RE.match(msg)
        if not m:
            return
        app = self._app_of_qid(m["qid"])
        status = m["status"]
        self.deliveries.inc(app=app, status=status)
        reason = defer_reason(m["detail"]) if status == "deferred" else ""
        if reason:
            self.deferrals.inc(app=app, reason=reason)
        self._record(m["qid"], status, reason)
