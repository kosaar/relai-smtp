"""Tests unitaires de l'exporteur du relai : registre, analyse des journaux Postfix
(lignes réelles relevées sur la stack de test), file d'attente, smarthost."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.unit import ROOT
from relayexp import logparse, probes
from relayexp.logparse import AppMap, LogParser
from relayexp.metrics import Registry, sample

H = "Oct 25 20:55:35 relay "
APPS = AppMap({"gitlab@example.com": "gitlab", "jenkins@example.com": "jenkins"},
              {"10.0.1.10": "gitlab", "10.0.1.20": "jenkins"})
GITLAB = "smtp-relay-test-client-gitlab-1.smtp-relay-test_private[10.0.1.10]"


def parser():
    reg = Registry()
    return reg, LogParser(reg, APPS)


class RegistryTest(unittest.TestCase):
    def test_render_and_escape(self):
        reg = Registry()
        c = reg.counter("x_total", "Aide", ("a",))
        c.inc(a='v"1')
        c.inc(2, a='v"1')
        reg.gauge("g", "Jauge").set(1.5)
        text = reg.render()
        self.assertIn('# TYPE x_total counter', text)
        self.assertIn('x_total{a="v\\"1"} 3', text)
        self.assertIn("g 1.5", text)

    def test_label_mismatch(self):
        c = Registry().counter("y_total", "Aide", ("a",))
        with self.assertRaises(ValueError):
            c.inc(b="1")

    def test_sample_no_labels(self):
        self.assertEqual(sample("m", None, 2), "m 2")


class LogParserTest(unittest.TestCase):
    def test_sasl_failure_by_ip(self):
        reg, p = parser()
        p.feed(H + "postfix/smtpd[320]: warning: SASL authentication failure: Password verification failed")
        p.feed(H + f"postfix/smtpd[320]: warning: {GITLAB}: SASL PLAIN authentication failed: "
                   "authentication failure, sasl_username=gitlab")
        self.assertEqual(p.auth_failures.get(app="gitlab"), 1)
        self.assertEqual(p.lines.get(), 2)

    def test_nokey_reject(self):
        reg, p = parser()
        p.feed(H + f"postfix/smtpd[320]: NOQUEUE: milter-reject: RCPT from {GITLAB}: 550 5.7.1 No valid OpenPGP "
                   "key for <Carol@example.com>: message not sent; from=<gitlab@example.com> to=<carol@example.com> "
                   "proto=ESMTP helo=<gitlab> sasl_username=<gitlab>")
        self.assertEqual(p.rejects.get(app="gitlab", reason="no_key", **{"class": "permanent"}), 1)
        self.assertEqual(p.nokey.get(recipient="carol@example.com"), 1)

    def test_content_proxy_reject_without_queue_id(self):
        reg, p = parser()
        p.feed(H + "postfix/smtpd[320]: proxy-reject: END-OF-MESSAGE: 550 5.7.1 Message blocked by content "
                   "policy (rule private-key); from=<gitlab@example.com> to=<alice@example.com> proto=ESMTP "
                   "helo=<gitlab> sasl_username=<gitlab>")
        self.assertEqual(p.content.get(app="gitlab", rule="private-key"), 1)
        self.assertEqual(p.rejects.get(app="gitlab", reason="content", **{"class": "permanent"}), 1)

    def test_client_host_reject_unknown_ip(self):
        reg, p = parser()
        p.feed(H + "postfix/smtpd[320]: NOQUEUE: reject: CONNECT from x[10.0.1.30]: 554 5.7.1 <x[10.0.1.30]>: "
                   "Client host rejected: Access denied; proto=SMTP")
        self.assertEqual(p.rejects.get(app="unknown", reason="client_host", **{"class": "permanent"}), 1)

    def test_sender_mismatch_attributed_by_login(self):
        reg, p = parser()
        p.feed(H + f"postfix/smtpd[320]: NOQUEUE: reject: MAIL from {GITLAB}: 553 5.7.1 <jenkins@example.com>: "
                   "Sender address rejected: not owned by user gitlab; from=<jenkins@example.com> proto=ESMTP "
                   "helo=<gitlab> sasl_username=<gitlab>")
        self.assertEqual(p.rejects.get(app="gitlab", reason="envelope_sender", **{"class": "permanent"}), 1)

    def test_temporary_class(self):
        reg, p = parser()
        p.feed(H + f"postfix/smtpd[320]: NOQUEUE: milter-reject: RCPT from {GITLAB}: 451 4.7.1 Key directory "
                   "unavailable, try again later; from=<gitlab@example.com> to=<a@example.com> proto=ESMTP helo=<g>")
        self.assertEqual(p.rejects.get(app="gitlab", reason="keydir_unavailable", **{"class": "temporary"}), 1)

    def test_deliveries_and_deferrals(self):
        reg, p = parser()
        lines = [
            "postfix/qmgr[311]: CFE41A409C: from=<gitlab@example.com>, size=1861, nrcpt=1 (queue active)",
            "postfix/smtp[333]: CFE41A409C: to=<alice@example.com>, relay=provider[10.0.2.10]:587, delay=0.05, "
            "delays=0.01/0.01/0.01/0.02, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as DA62AAA2CA)",
            "postfix/qmgr[311]: CFE41A409C: removed",
            "postfix/qmgr[305]: E7E50A40BF: from=<jenkins@example.com>, size=1865, nrcpt=1 (queue active)",
            "postfix/smtp[355]: E7E50A40BF: to=<alice@example.com>, relay=provider[10.0.2.10]:587, delay=0.03, "
            "delays=0.01/0.02/0.01/0, dsn=4.7.8, status=deferred (SASL authentication failed; server "
            "provider[10.0.2.10] said: 535 5.7.8 Error: authentication failed: authentication failure)",
            "postfix/smtp[356]: 1234ABCD: to=<bob@example.com>, relay=none, delay=30, delays=0/0/30/0, dsn=4.4.1, "
            "status=deferred (connect to provider[10.0.2.10]:587: Connection refused)",
        ]
        for line in lines:
            p.feed(H + line)
        self.assertEqual(p.deliveries.get(app="gitlab", status="sent"), 1)
        self.assertEqual(p.deliveries.get(app="jenkins", status="deferred"), 1)
        self.assertEqual(p.deferrals.get(app="jenkins", reason="auth"), 1)
        self.assertEqual(p.deferrals.get(app="unknown", reason="connection"), 1)
        self.assertNotIn("CFE41A409C", p._senders)

    def test_expired_and_null_sender(self):
        reg, p = parser()
        p.feed(H + "postfix/qmgr[1]: ABC123: from=<>, size=10, nrcpt=1 (queue active)")
        p.feed(H + "postfix/qmgr[1]: ABC123: from=<>, status=expired, returned to sender")
        self.assertEqual(p.deliveries.get(app="none", status="expired"), 1)

    def test_recipient_series_capped(self):
        reg, p = parser()
        for i in range(logparse.MAX_RECIPIENT_SERIES + 5):
            p.feed(H + f"postfix/smtpd[1]: NOQUEUE: milter-reject: RCPT from {GITLAB}: 550 5.7.1 No valid OpenPGP "
                       f"key for <u{i}@example.com>: message not sent; from=<gitlab@example.com> "
                       f"to=<u{i}@example.com> proto=ESMTP helo=<g>")
        self.assertEqual(p.nokey.get(recipient="other"), 5)

    def test_non_postfix_lines_ignored(self):
        reg, p = parser()
        p.feed("2026-10-25T20:55:00Z relay-entrypoint[1]: Relai SMTP ...")
        p.feed("")
        self.assertEqual(p.lines.get(), 0)

    def test_reason_tables(self):
        self.assertEqual(logparse.reject_reason("552", "Something"), "size")
        self.assertEqual(logparse.reject_reason("550", "From: header must be x"), "header_from")
        self.assertEqual(logparse.reject_reason("550", "whatever"), "other")
        self.assertEqual(logparse.defer_reason("Server certificate not verified"), "tls")
        self.assertEqual(logparse.defer_reason(None), "other")


class QueueTest(unittest.TestCase):
    def test_parse_postqueue_json(self):
        out = "\n".join(json.dumps(m) for m in [
            {"queue_name": "deferred", "queue_id": "A", "arrival_time": 1000, "message_size": 1},
            {"queue_name": "deferred", "queue_id": "B", "arrival_time": 1500, "message_size": 1},
            {"queue_name": "active", "queue_id": "C", "arrival_time": 1900, "message_size": 1},
        ])
        st = probes.parse_postqueue_json(out, 2000)
        self.assertEqual(st.counts["deferred"], 2)
        self.assertEqual(st.counts["active"], 1)
        self.assertEqual(st.counts["hold"], 0)
        self.assertEqual(st.oldest_age, 1000)

    def test_empty_queue(self):
        st = probes.parse_postqueue_json("", 2000)
        self.assertEqual(sum(st.counts.values()), 0)
        self.assertEqual(st.oldest_age, 0)


class SmarthostTest(unittest.TestCase):
    def test_parse_relayhost(self):
        self.assertEqual(probes.parse_relayhost("[provider]:587"), ("provider", 587))
        self.assertEqual(probes.parse_relayhost("[smtp.example.com]:465"), ("smtp.example.com", 465))
        self.assertEqual(probes.parse_relayhost("mx.example.com"), ("mx.example.com", 25))
        with self.assertRaises(ValueError):
            probes.parse_relayhost("")

    def test_unreachable(self):
        st = probes.probe_smarthost(probes.SmarthostConfig("127.0.0.1", 9, False, "/nonexistent", timeout=2))
        self.assertFalse(st.up)
        self.assertTrue(st.error)


class SupervisorTest(unittest.TestCase):
    """relay-run dans un processus séparé (gestionnaires de signaux, récupération des fils)."""

    def run_supervisor(self, main_cmd, exporter_cmd):
        code = ("import sys; from relayexp.supervisor import Supervisor; "
                f"sys.exit(Supervisor({main_cmd!r}, {exporter_cmd!r}, drop_privileges=False).run())")
        env = dict(os.environ, PYTHONPATH=str(ROOT / "relay" / "exporter"))
        return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env)

    def test_tee_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            copy = os.path.join(d, "copie")
            res = self.run_supervisor(["sh", "-c", "sleep 0.5; echo ligne1; echo ligne2; exit 3"],
                                      ["sh", "-c", f"cat > {copy}"])
            self.assertEqual(res.returncode, 3)
            self.assertEqual(res.stdout, "ligne1\nligne2\n")
            with open(copy) as f:
                self.assertEqual(f.read(), "ligne1\nligne2\n")
            self.assertIn("Postfix terminé (code 3)", res.stderr)

    def test_dead_exporter_never_blocks_logs(self):
        res = self.run_supervisor(["sh", "-c", "sleep 0.5; for i in $(seq 1 2000); do echo ligne-$i; done"],
                                  ["sh", "-c", "exit 0"])
        self.assertEqual(res.returncode, 0)
        self.assertEqual(len(res.stdout.splitlines()), 2000)

    def test_long_lines_truncated_for_exporter_only(self):
        with tempfile.TemporaryDirectory() as d:
            copy = os.path.join(d, "copie")
            res = self.run_supervisor(["sh", "-c", "sleep 0.5; head -c 9000 /dev/zero | tr '\\0' x; echo"],
                                      ["sh", "-c", f"cat > {copy}"])
            self.assertEqual(len(res.stdout), 9001)
            with open(copy) as f:
                self.assertEqual(len(f.read()), 4000)


if __name__ == "__main__":
    unittest.main()
