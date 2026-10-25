"""relay-smoke-test : test de bon fonctionnement du relai après un déploiement.

Lancé dans le conteneur du relai (docker compose exec relay relay-smoke-test),
il emprunte le chemin réel d'un message d'application :

  1. soumission sur 127.0.0.1:587 en STARTTLS (certificat présenté comparé à
     celui du relai), AUTH de l'application locale de supervision (inventaire :
     client_ips = ["127.0.0.1"], mot de passe dans les secrets des
     applications) ;
  2. contrôles de la passerelle (enveloppe, clé OpenPGP du destinataire sur
     l'annuaire, From:, contenu), chiffrement, mise en file ;
  3. livraison au smarthost : le résultat (sent, deferred, bounced, expired)
     est lu auprès de l'exporteur (GET /delivery?qid=…), qui le tire des
     journaux de Postfix.

Le message de contrôle (objet « Contrôle du relai SMTP <jeton> ») arrive
chiffré dans la BAL de supervision, dont la clé doit être publiée sur
l'annuaire comme celle de tout destinataire.

Codes de sortie :
  0  message accepté par le smarthost (status=sent) ;
  1  échec : refus à la soumission, livraison différée, rejetée ou expirée ;
  2  usage ou configuration invalide (application, secret, destinataire) ;
  3  résultat non confirmé dans le délai (exporteur injoignable, file lente).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import smtplib
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from relayexp import probes

OK, FAILED, CONFIG, UNCONFIRMED = 0, 1, 2, 3
QUEUED_RE = re.compile(r"queued as ([0-9A-Za-z]+)")
PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


class SmokeError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def leaf_certificate(chain_file: str) -> bytes:
    """Certificat (DER) du relai : premier certificat du fichier de chaîne de smtpd."""
    try:
        with open(chain_file, "rb") as f:
            m = PEM_CERT_RE.search(f.read())
    except OSError as e:
        raise SmokeError(CONFIG, f"certificat du relai {chain_file} illisible ({e.strerror})") from None
    if not m:
        raise SmokeError(CONFIG, f"aucun certificat dans {chain_file}")
    return ssl.PEM_cert_to_DER_cert(m.group(0).decode())


def pinned_context() -> ssl.SSLContext:
    # Connexion au relai lui-même : la confiance vient de la comparaison avec le
    # certificat qu'il est configuré pour présenter (voir submit), pas d'une AC.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def control_message(sender: str, rcpt: str, domain: str, token: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = rcpt
    msg["Subject"] = f"Contrôle du relai SMTP {token}"
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid("smoke", domain=domain)
    msg.set_content(
        f"Message de contrôle émis par relay-smoke-test (relai {socket.gethostname()}) "
        f"le {time.strftime('%Y-%m-%d à %H:%M:%S UTC', time.gmtime())}.\n"
        f"Jeton : {token}\n\nAucune action n'est requise.\n", cte="quoted-printable")
    return msg


def submit(server: str, port: int, login: str, password: str, msg: EmailMessage,
           expected_cert: bytes, timeout: float = 30) -> str:
    """Soumet le message ; renvoie la réponse finale (« 250 … queued as … »)."""
    sender, rcpt = msg["From"], msg["To"]
    try:
        with smtplib.SMTP(server, port, timeout=timeout) as s:
            s.ehlo("relay-smoke-test")
            if not s.has_extn("starttls"):
                raise SmokeError(FAILED, "le relai n'annonce pas STARTTLS")
            s.starttls(context=pinned_context())
            if s.sock.getpeercert(binary_form=True) != expected_cert:
                raise SmokeError(FAILED, "le certificat présenté sur le port de soumission n'est pas celui du relai")
            s.ehlo("relay-smoke-test")
            try:
                s.login(login, password)
            except smtplib.SMTPAuthenticationError as e:
                raise SmokeError(FAILED, f"authentification refusée : {e.smtp_code} {e.smtp_error.decode(errors='replace')}") from None
            for step, command in (("MAIL FROM", lambda: s.mail(sender)),
                                  ("RCPT TO", lambda: s.rcpt(rcpt)),
                                  ("DATA", lambda: s.data(msg.as_bytes()))):
                code, resp = command()
                if code not in (250, 251):
                    raise SmokeError(FAILED, f"{step} refusé : {code} {resp.decode(errors='replace')}")
            return f"{code} {resp.decode(errors='replace')}"
    except SmokeError:
        raise
    except smtplib.SMTPResponseException as e:
        raise SmokeError(FAILED, f"soumission refusée : {e.smtp_code} {e.smtp_error.decode(errors='replace')}") from None
    except (smtplib.SMTPException, OSError) as e:
        raise SmokeError(FAILED, f"soumission impossible sur {server}:{port} ({e})") from None


def delivery_status(metrics_url: str, qid: str, timeout: float = 5) -> dict | None:
    """Résultat de livraison connu de l'exporteur ; None s'il n'en a pas encore."""
    try:
        with urllib.request.urlopen(f"{metrics_url}/delivery?qid={qid}", timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def queue_state(qid: str) -> str:
    """État du message dans la file Postfix (postqueue -j), pour le diagnostic."""
    out = probes.postqueue_json()
    if out is None:
        return "file illisible"
    for line in out.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("queue_id") == qid:
            reasons = {r.get("delay_reason", "") for r in entry.get("recipients", [])} - {""}
            return f"en file « {entry.get('queue_name')} »" + (f" ({'; '.join(sorted(reasons))})" if reasons else "")
    return "hors de la file"


def wait_delivery(metrics_url: str, qid: str, timeout: float, interval: float = 1.0) -> tuple[int, str]:
    deadline = time.monotonic() + timeout
    exporter_error = ""
    while True:
        try:
            st = delivery_status(metrics_url, qid)
            exporter_error = ""
        except (urllib.error.URLError, OSError, ValueError) as e:
            st, exporter_error = None, str(getattr(e, "reason", e))
        if st and st.get("status"):
            status, reason = st["status"], st.get("reason") or ""
            if status == "sent":
                return OK, "accepté par le smarthost (status=sent)"
            detail = f" (motif : {reason})" if reason else ""
            if status == "deferred":
                return FAILED, (f"livraison différée{detail} ; le message reste en file et sera "
                                "réessayé par Postfix")
            return FAILED, f"livraison {'rejetée' if status == 'bounced' else 'expirée'} (status={status})"
        if time.monotonic() >= deadline:
            why = f"exporteur injoignable sur {metrics_url} ({exporter_error})" if exporter_error \
                else "aucun résultat de livraison"
            return UNCONFIRMED, f"{why} après {timeout:g} s ; message {queue_state(qid)}"
        time.sleep(interval)


def default_metrics_url() -> str:
    port = os.environ.get("RELAY_METRICS_LISTEN", "0.0.0.0:9154").rpartition(":")[2] or "9154"
    return f"http://127.0.0.1:{port}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="relay-smoke-test", description=__doc__.split("\n\n")[0],
                                epilog="Codes de sortie : 0 accepté par le smarthost, 1 échec, "
                                       "2 configuration invalide, 3 non confirmé.")
    p.add_argument("--app", default=os.environ.get("RELAY_SMOKE_APP", "supervision"),
                   help="application locale émettrice (défaut : RELAY_SMOKE_APP ou « supervision »)")
    p.add_argument("--to", default=os.environ.get("RELAY_SMOKE_TO", ""),
                   help="BAL de supervision destinataire, dont la clé est publiée sur l'annuaire "
                        "(défaut : RELAY_SMOKE_TO)")
    p.add_argument("--timeout", type=float, default=60, help="attente du résultat de livraison, en s (60)")
    p.add_argument("--server", default="127.0.0.1", help="adresse de soumission (127.0.0.1)")
    p.add_argument("--port", type=int, default=587, help="port de soumission (587)")
    p.add_argument("--inventory", default=os.environ.get("RELAY_INVENTORY_FILE", "/etc/relay/applications.toml"),
                   help="inventaire des applications (RELAY_INVENTORY_FILE)")
    p.add_argument("--secrets-dir", default=os.environ.get("RELAY_APP_SECRETS_DIR", "/run/secrets/apps"),
                   help="mots de passe des applications (RELAY_APP_SECRETS_DIR)")
    p.add_argument("--tls-chain", default="/etc/postfix/tls/submission.pem",
                   help="chaîne TLS de smtpd (certificat attendu sur le port de soumission)")
    p.add_argument("--metrics-url", default=default_metrics_url(), help="exporteur du relai")
    a = p.parse_args(argv)

    try:
        code, text = run(a)
    except SmokeError as e:
        code, text = e.code, str(e)
    stream = sys.stdout if code == OK else sys.stderr
    print(f"{'OK' if code == OK else 'ÉCHEC' if code != UNCONFIRMED else 'NON CONFIRMÉ'} : {text}", file=stream)
    return code


def run(a) -> tuple[int, str]:
    from relaycfg import inventory as inv_mod

    if not a.to or a.to.count("@") != 1:
        raise SmokeError(CONFIG, "destinataire absent ou invalide (--to ou RELAY_SMOKE_TO)")
    try:
        inv = inv_mod.load(a.inventory)
    except inv_mod.InventoryError as e:
        raise SmokeError(CONFIG, f"inventaire invalide : {e}") from None
    app = inv.by_login(a.app)
    if app is None:
        raise SmokeError(CONFIG, f"application « {a.app} » absente de l'inventaire {a.inventory}")
    if a.server not in app.client_ips:
        raise SmokeError(CONFIG, f"l'application « {a.app} » doit être locale : client_ips = [\"{a.server}\"]")
    try:
        password = inv_mod.read_password(a.secrets_dir, a.app)
    except OSError as e:
        raise SmokeError(CONFIG, f"secret de l'application « {a.app} » illisible ({e.strerror})") from None
    expected = leaf_certificate(a.tls_chain)

    token = secrets.token_hex(6)
    msg = control_message(app.address, a.to, inv.sender_domain, token)
    print(f"relay-smoke-test : {app.address} -> {a.to} (application {a.app}, {a.server}:{a.port}), "
          f"objet « {msg['Subject']} »", flush=True)
    reply = submit(a.server, a.port, a.app, password, msg, expected)
    m = QUEUED_RE.search(reply)
    if not m:
        raise SmokeError(UNCONFIRMED, f"identifiant de file absent de la réponse : {reply}")
    qid = m.group(1)
    print(f"  soumis et chiffré : {reply.strip()}", flush=True)
    code, text = wait_delivery(a.metrics_url, qid, a.timeout)
    return code, f"message de contrôle {qid} : {text}"
