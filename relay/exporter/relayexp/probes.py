"""Sondes de l'exporteur : file Postfix, smarthost (TLS), métriques de l'annuaire."""
from __future__ import annotations

import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

QUEUES = ("maildrop", "incoming", "active", "deferred", "hold")
RELAYHOST_RE = re.compile(r"^\[?(?P<host>[^\]\[:]+)\]?(?::(?P<port>\d{1,5}))?$")


# -- File d'attente -------------------------------------------------------------------
@dataclass
class QueueStats:
    ok: bool
    counts: dict[str, int]
    oldest_age: float
    error: str = ""


def parse_postqueue_json(output: str, now: float) -> QueueStats:
    """Sortie de « postqueue -j » (un objet JSON par message) -> compteurs et âge."""
    counts = {q: 0 for q in QUEUES}
    oldest = None
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        q = msg.get("queue_name", "unknown")
        counts[q] = counts.get(q, 0) + 1
        arrival = msg.get("arrival_time")
        if isinstance(arrival, (int, float)):
            oldest = arrival if oldest is None else min(oldest, arrival)
    age = max(0.0, now - oldest) if oldest is not None else 0.0
    return QueueStats(True, counts, age)


def postqueue_json(timeout: float = 10) -> str | None:
    """Sortie de « postqueue -j » (un objet JSON par message), None si illisible."""
    try:
        return subprocess.run(["postqueue", "-j"], capture_output=True, text=True, timeout=timeout,
                              check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None


def queue_stats(timeout: float = 10) -> QueueStats:
    out = postqueue_json(timeout)
    if out is None:
        return QueueStats(False, {}, 0.0, "postqueue")
    try:
        return parse_postqueue_json(out, time.time())
    except ValueError as e:
        return QueueStats(False, {}, 0.0, type(e).__name__)


# -- Smarthost ------------------------------------------------------------------------
@dataclass
class SmarthostConfig:
    host: str
    port: int
    wrapper: bool
    cafile: str
    timeout: float = 15


@dataclass
class SmarthostStatus:
    up: bool = False
    verified: bool = False
    cert_not_after: float | None = None
    last_probe: float = 0.0
    error: str = ""


def parse_relayhost(value: str) -> tuple[str, int]:
    m = RELAYHOST_RE.match(value.strip())
    if not m:
        raise ValueError(f"relayhost illisible : {value!r}")
    return m["host"], int(m["port"] or 25)


def postconf(*names: str) -> dict[str, str]:
    out = subprocess.run(["postconf", *names], capture_output=True, text=True, timeout=10, check=True).stdout
    values = {}
    for line in out.splitlines():
        k, _, v = line.partition("=")
        values[k.strip()] = v.strip()
    return values


def smarthost_config_from_postfix() -> SmarthostConfig:
    v = postconf("relayhost", "smtp_tls_wrappermode", "smtp_tls_CAfile")
    host, port = parse_relayhost(v["relayhost"])
    return SmarthostConfig(host, port, v["smtp_tls_wrappermode"] == "yes", v["smtp_tls_CAfile"])


def _not_after_of_der(der: bytes) -> float | None:
    """Date d'expiration d'un certificat non vérifié (DER), pour la signaler quand même."""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            f.flush()
            decoded = ssl._ssl._test_decode_cert(f.name)   # API interne stable de CPython
        return float(ssl.cert_time_to_seconds(decoded["notAfter"]))
    except Exception:   # noqa: BLE001 — information facultative
        return None


def probe_smarthost(cfg: SmarthostConfig) -> SmarthostStatus:
    """Connexion TLS au smarthost (STARTTLS ou TLS implicite), certificat vérifié par l'AC
    configurée et le nom d'hôte, comme le fait Postfix (smtp_tls_security_level=secure).
    Aucune authentification ni message : EHLO, STARTTLS, QUIT."""
    st = SmarthostStatus(last_probe=time.time())
    try:
        verify = ssl.create_default_context(cafile=cfg.cafile)
        verify.minimum_version = ssl.TLSVersion.TLSv1_2
        st.cert_not_after, st.verified = _tls_cert(cfg, verify)
        st.up = True
        return st
    except ssl.SSLCertVerificationError:
        st.error = "certificate"
        st.up = True   # joignable, mais certificat refusé
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        try:
            st.cert_not_after, _ = _tls_cert(cfg, insecure, der=True)
        except Exception:   # noqa: BLE001
            pass
    except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
        st.error = type(e).__name__
    return st


def _tls_cert(cfg: SmarthostConfig, ctx: ssl.SSLContext, der: bool = False) -> tuple[float | None, bool]:
    if cfg.wrapper:
        client = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=cfg.timeout, context=ctx)
    else:
        client = smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout)
    try:
        client.ehlo()
        if not cfg.wrapper:
            client.starttls(context=ctx)
        sock = client.sock
        if der:
            return _not_after_of_der(sock.getpeercert(binary_form=True)), False
        cert = sock.getpeercert()
        return float(ssl.cert_time_to_seconds(cert["notAfter"])), True
    finally:
        try:
            client.quit()
        except (OSError, smtplib.SMTPException):
            client.close()


class SmarthostProber:
    """Sonde périodique (fil dédié) ; la dernière mesure est servie à chaque requête."""

    def __init__(self, cfg: SmarthostConfig | None, interval: float):
        self.cfg, self.interval = cfg, interval
        self.status = SmarthostStatus(error="not-probed")
        self._lock = threading.Lock()

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True, name="smarthost-probe").start()

    def _loop(self) -> None:
        while True:
            try:
                st = probe_smarthost(self.cfg) if self.cfg else SmarthostStatus(error="no-config")
            except Exception as e:   # noqa: BLE001 — la sonde ne doit jamais s'arrêter
                st = SmarthostStatus(last_probe=time.time(), error=type(e).__name__)
            with self._lock:
                self.status = st
            time.sleep(self.interval)

    def current(self) -> SmarthostStatus:
        with self._lock:
            return self.status


# -- Annuaire de clés -------------------------------------------------------------------
def fetch_text(url: str, timeout: float = 5) -> str | None:
    """Métriques texte de l'annuaire (réseau interne) ; None si injoignable."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:   # noqa: S310 — URL de configuration
            if resp.status != 200:
                return None
            return resp.read(1 << 20).decode("utf-8", "replace")
    except (OSError, urllib.error.URLError, ValueError, socket.timeout):
        return None


def env_int(name: str, default: int) -> int:
    """Entier d'environnement (déjà validé par l'entrypoint du relai)."""
    raw = os.environ.get(name, "")
    return int(raw) if raw.isdigit() else default
