"""Exporteur Prometheus du relai (F4), lancé par relay-run sous un utilisateur
non privilégié (nobody, groupe supplémentaire postdrop pour « postqueue -j »).

Entrée standard : copie des journaux Postfix (relay-run). Sortie HTTP :
  GET /metrics          métriques texte Prometheus
  GET /healthz          « ok »
  GET /delivery?qid=Q   dernier résultat de livraison du message Q (JSON :
                        statut sent, deferred, bounced, expired et motif du
                        différé ; 404 si inconnu) — utilisé par relay-smoke-test

Métriques servies :
  - compteurs tirés des journaux (relayexp.logparse) ;
  - file d'attente : messages par file, âge du plus ancien (postqueue -j) ;
  - smarthost : joignabilité, certificat vérifié, date d'expiration du
    certificat (sonde TLS périodique, sans authentification ni message) ;
  - annuaire de clés : métriques de keydir (clés proches de l'expiration,
    expirées, révoquées), recopiées telles quelles depuis le réseau interne.

Variables : RELAY_METRICS_LISTEN (0.0.0.0:9154), RELAY_METRICS_PROBE_INTERVAL
(300 s), RELAY_KEYDIR_METRICS_URL (http://keydir:9155/metrics, vide =
désactivé), RELAY_INVENTORY_FILE (/etc/relay/applications.toml).
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from relayexp import probes
from relayexp.logparse import AppMap, LogParser
from relayexp.metrics import Registry

log = logging.getLogger("relay-exporter")
QID_RE = re.compile(r"^[0-9A-Za-z]{5,32}$")


class Exporter:
    def __init__(self, apps: AppMap, prober: probes.SmarthostProber, keydir_url: str):
        self.registry = Registry()
        self.parser = LogParser(self.registry, apps)
        self.prober = prober
        self.keydir_url = keydir_url
        self.started = time.time()

    def feed_stream(self, stream) -> None:
        for raw in stream:
            try:
                self.parser.feed(raw.decode("utf-8", "replace"))
            except Exception as e:   # noqa: BLE001 — une ligne illisible n'arrête pas l'exporteur
                log.warning("ligne de journal ignorée (%s)", type(e).__name__)

    def render(self) -> str:
        dyn = Registry()
        q = probes.queue_stats()
        dyn.gauge("relay_queue_scrape_ok", "1 si la file Postfix a pu être lue (postqueue -j)").set(int(q.ok))
        msgs = dyn.gauge("relay_queue_messages", "Messages en file, par file Postfix", ("queue",))
        for name, n in sorted(q.counts.items()):
            msgs.set(n, queue=name)
        dyn.gauge("relay_queue_oldest_message_age_seconds",
                  "Âge du plus ancien message en file (0 si la file est vide)").set(round(q.oldest_age, 3))

        st = self.prober.current()
        dyn.gauge("relay_smarthost_up", "1 si le smarthost répond en TLS (dernière sonde)").set(int(st.up))
        dyn.gauge("relay_smarthost_tls_verified",
                  "1 si le certificat du smarthost est valide pour l'AC et le nom configurés").set(int(st.verified))
        if st.cert_not_after is not None:
            dyn.gauge("relay_smarthost_certificate_expiry_timestamp_seconds",
                      "Date d'expiration du certificat du smarthost (epoch)").set(int(st.cert_not_after))
        dyn.gauge("relay_smarthost_last_probe_timestamp_seconds", "Date de la dernière sonde (epoch)").set(
            int(st.last_probe))

        dyn.gauge("relay_exporter_start_time_seconds", "Démarrage de l'exporteur (epoch)").set(int(self.started))
        keydir_text = probes.fetch_text(self.keydir_url) if self.keydir_url else None
        if self.keydir_url:
            dyn.gauge("relay_keydir_metrics_up", "1 si les métriques de l'annuaire de clés ont été lues").set(
                int(keydir_text is not None))
        out = self.registry.render() + dyn.render()
        if keydir_text:
            out += keydir_text if keydir_text.endswith("\n") else keydir_text + "\n"
        return out


class Handler(BaseHTTPRequestHandler):
    server_version = "relay-exporter"
    sys_version = ""

    def log_message(self, fmt, *args):   # pas de journal d'accès (scrapes fréquents)
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _delivery(self, query: str) -> None:
        qid = parse_qs(query).get("qid", [""])[0]
        if not QID_RE.match(qid):
            self._send(400, b'{"error": "qid"}\n', "application/json")
            return
        found = self.server.exporter.parser.outcome(qid)
        status, reason = found if found else (None, "")
        body = json.dumps({"qid": qid, "status": status, "reason": reason}).encode() + b"\n"
        self._send(200 if found else 404, body, "application/json")

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/delivery":
            self._delivery(query)
        elif path == "/metrics":
            body = self.server.exporter.render().encode()
            self._send(200, body, "text/plain; version=0.0.4; charset=utf-8")
        elif path == "/healthz":
            self._send(200, b"ok\n", "text/plain; charset=utf-8")
        else:
            self._send(404, b"not found\n", "text/plain; charset=utf-8")


def load_apps(path: str) -> AppMap:
    try:
        from relaycfg import inventory
        return AppMap.from_inventory(inventory.load(path))
    except Exception as e:   # noqa: BLE001 — sans inventaire, l'application vaut « unknown »
        log.warning("inventaire %s illisible (%s) : applications non identifiées", path, e)
        return AppMap()


def main() -> int:
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format="%(asctime)s relay-exporter: %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
    listen = os.environ.get("RELAY_METRICS_LISTEN", "0.0.0.0:9154")
    host, _, port = listen.rpartition(":")
    interval = probes.env_int("RELAY_METRICS_PROBE_INTERVAL", 300)
    keydir_url = os.environ.get("RELAY_KEYDIR_METRICS_URL", "http://keydir:9155/metrics")
    apps = load_apps(os.environ.get("RELAY_INVENTORY_FILE", "/etc/relay/applications.toml"))
    try:
        sh_cfg = probes.smarthost_config_from_postfix()
    except Exception as e:   # noqa: BLE001
        log.warning("configuration du smarthost illisible (%s) : sonde désactivée", e)
        sh_cfg = None
    prober = probes.SmarthostProber(sh_cfg, interval)
    exporter = Exporter(apps, prober, keydir_url)
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    srv.daemon_threads = True
    srv.exporter = exporter
    prober.start()
    threading.Thread(target=srv.serve_forever, daemon=True, name="http").start()
    log.info("métriques sur http://%s/metrics (%d application(s) connues, smarthost %s, sonde toutes les %d s%s)",
             listen, len(set(apps.addresses.values())),
             f"{sh_cfg.host}:{sh_cfg.port}" if sh_cfg else "inconnu", interval,
             f", annuaire {keydir_url}" if keydir_url else "")
    exporter.feed_stream(sys.stdin.buffer)   # jusqu'à la fin des journaux (arrêt de Postfix)
    srv.shutdown()
    return 0
