"""Tests unitaires du filtre avant file (relaygw.proxy) : dialogue SMTP avec
Postfix, refus (From:, IP, clé), réinjection du message chiffré dans un
serveur SMTP local qui capture ce qu'il reçoit. Le chiffrement GnuPG est
remplacé par une fonction factice (testé à part dans test_gateway_crypto)."""
import logging
import smtplib
import socketserver
import threading
import unittest
from types import SimpleNamespace

from tests.unit import ROOT  # noqa: F401  (chemins d'import)
from relaycfg import inventory as inv_mod
from relaygw import crypto, proxy
from relaygw.keys import Lookup

INVENTORY = inv_mod.parse({
    "sender_domain": "example.com",
    "applications": {"gitlab": {"address": "gitlab@example.com", "client_ips": ["10.0.1.10"], "quota_per_hour": 10}},
})


class FakeResolver:
    def __init__(self):
        self.status = {}

    def lookup(self, rcpt):
        st = self.status.get(rcpt, "ok")
        return Lookup(st, "no-key" if st != "ok" else "", "F" * 40 if st == "ok" else None, b"key")


class Capture(socketserver.StreamRequestHandler):
    """Serveur de réinjection minimal : enregistre l'enveloppe et le message."""
    received: list = []

    def handle(self):
        w = self.wfile.write
        w(b"220 reinject\r\n")
        env, data = {"rcpts": []}, None
        while line := self.rfile.readline():
            cmd = line.strip().upper()
            if cmd.startswith(b"EHLO"):
                w(b"250 reinject\r\n")
            elif cmd.startswith(b"MAIL FROM:"):
                env["from"] = line.strip()[10:]
                w(b"250 ok\r\n")
            elif cmd.startswith(b"RCPT TO:"):
                env["rcpts"].append(line.strip()[8:])
                w(b"250 ok\r\n")
            elif cmd == b"DATA":
                w(b"354 go\r\n")
                lines = []
                while (d := self.rfile.readline()) != b".\r\n":
                    lines.append(d[1:] if d.startswith(b".") else d)
                data = b"".join(lines)
                Capture.received.append((env, data))
                w(b"250 2.0.0 Ok: queued as ABC123\r\n")
            elif cmd == b"QUIT":
                w(b"221 bye\r\n")
                return


class ProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.getLogger("gateway").disabled = True
        cls.reinject = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Capture)
        threading.Thread(target=cls.reinject.serve_forever, daemon=True).start()
        cls.resolver = FakeResolver()
        config = SimpleNamespace(neutral_subject="Message chiffré", hmac_key=b"k" * 32,
                                 reinject_port=cls.reinject.server_address[1])
        proxy.CTX = proxy.Context(INVENTORY, config, cls.resolver)
        cls.server = proxy.serve("127.0.0.1:0")
        cls.port = cls.server.server_address[1]
        cls._encrypt = crypto.encrypt
        crypto.encrypt = lambda data, keys: b"-----BEGIN PGP MESSAGE-----\n\nFAKE\n-----END PGP MESSAGE-----\n"

    @classmethod
    def tearDownClass(cls):
        crypto.encrypt = cls._encrypt
        cls.server.shutdown()
        cls.reinject.shutdown()

    def setUp(self):
        Capture.received.clear()
        self.resolver.status.clear()

    def send(self, msg, sender="gitlab@example.com", rcpts=("alice@example.com",), addr="10.0.1.10"):
        with smtplib.SMTP("127.0.0.1", self.port, timeout=10) as s:
            code, resp = s.ehlo("relay")
            self.assertIn(b"XFORWARD", resp)
            self.assertEqual(s.docmd("XFORWARD", f"NAME=client ADDR={addr} PROTO=ESMTP")[0], 250)
            self.assertEqual(s.mail(sender)[0], 250)
            for r in rcpts:
                self.assertEqual(s.rcpt(r)[0], 250)
            return s.data(msg)

    def test_encrypt_and_reinject(self):
        msg = (b"From: GitLab <gitlab@example.com>\r\nTo: alice@example.com\r\nSubject: secret\r\n"
               b"Message-ID: <1@gitlab.internal>\r\nX-GitLab-Project: infra\r\n\r\n.ligne\r\ncorps\r\n")
        code, resp = self.send(msg, rcpts=("alice@example.com", "bob@example.com"))
        self.assertEqual((code, resp), (250, b"2.0.0 Ok: queued as ABC123"))
        ((env, data),) = Capture.received
        self.assertEqual(env, {"from": b"<gitlab@example.com>", "rcpts": [b"<alice@example.com>", b"<bob@example.com>"]})
        head = data.split(b"\r\n\r\n", 1)[0]
        for leak in (b"secret", b"gitlab.internal", b"X-GitLab", b"corps", b"ligne"):
            self.assertNotIn(leak, data)
        self.assertIn(b"Subject: =?utf-8?q?Message_chiffr=C3=A9?=", head)
        self.assertIn(b"multipart/encrypted", head)
        self.assertIn(b"FAKE", data)

    def test_refusals(self):
        ok = b"From: gitlab@example.com\r\nSubject: x\r\n\r\nx\r\n"
        self.assertEqual(self.send(b"From: other@example.com\r\n\r\nx\r\n")[0], 550)
        self.assertEqual(self.send(ok, addr="10.9.9.9")[0], 550)
        self.assertEqual(self.send(ok, sender="jenkins@example.com")[0], 451)
        self.resolver.status["bob@example.com"] = "nokey"
        code, resp = self.send(ok, rcpts=("alice@example.com", "bob@example.com"))
        self.assertEqual(code, 451)
        self.assertIn(b"bob@example.com", resp)
        self.assertEqual(Capture.received, [])

    def test_reinjection_down(self):
        port = proxy.CTX.config.reinject_port
        proxy.CTX.config.reinject_port = 1
        try:
            code, resp = self.send(b"From: gitlab@example.com\r\n\r\nx\r\n")
        finally:
            proxy.CTX.config.reinject_port = port
        self.assertEqual((code, resp[:5]), (451, b"4.3.0"))


if __name__ == "__main__":
    unittest.main()
