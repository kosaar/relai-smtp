"""Tests unitaires du contrôle du contenu (relaygw.content)."""
import base64
import os
import tempfile
import unittest
from email.message import EmailMessage

from tests.unit import ROOT
from relaygw import content

RULES = content.load(str(ROOT / "config" / "content-rules.toml"))   # règles de production


def message(text="Bonjour", attachments=(), subject="Pipeline"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "gitlab@example.com", "alice@example.com", subject
    m.set_content(text)
    for name, data in attachments:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return m.as_bytes()


class ScanTest(unittest.TestCase):
    def test_clean(self):
        self.assertIsNone(content.scan(RULES, message(
            "La clé publique est jointe. PRIVATE KEY n'est pas un bloc.", [("rapport.pdf", b"%PDF-1.7 ...")])))

    def test_private_key(self):
        for block in ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
                      "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----"):
            self.assertEqual(content.scan(RULES, message(f"voici\n{block}\nMIIE...")), "private-key", block)

    def test_token_in_base64_attachment(self):
        token = "glpat-" + "a1B2c3D4e5F6g7H8i9J0"
        raw = message("rien", [("config.txt", f"url=https://x\ntoken={token}\n".encode())])
        self.assertNotIn(token.encode(), raw)                     # encodé en base64 dans le message
        self.assertIn(base64.b64encode(b"url=")[:4], raw)
        self.assertEqual(content.scan(RULES, raw), "gitlab-token")

    def test_quoted_printable_and_headers(self):
        raw = (b"From: a@b\r\nSubject: =?utf-8?b?" + base64.b64encode(b"cle AKIAABCDEFGHIJKLMNOP") + b"?=\r\n\r\nx\r\n")
        self.assertEqual(content.scan(RULES, raw), "aws-access-key")
        raw = (b"From: a@b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
               b"-----BEGIN PRIVATE=\r\n KEY-----\r\n")
        self.assertEqual(content.scan(RULES, raw), "private-key")

    def test_extensions_and_nested(self):
        self.assertEqual(content.scan(RULES, message(attachments=[("setup.EXE", b"MZ")])), "forbidden-extension")
        self.assertEqual(content.scan(RULES, message(attachments=[("facture.pdf.js", b"x")])), "forbidden-extension")
        self.assertIsNone(content.scan(RULES, message(attachments=[("exe-notes.txt", b"x")])))
        inner = EmailMessage()
        inner["Subject"] = "transféré"
        inner.set_content("-----BEGIN EC PRIVATE KEY-----")
        outer = EmailMessage()
        outer["From"] = "gitlab@example.com"
        outer.set_content("voir pièce jointe")
        outer.add_attachment(inner)
        self.assertEqual(content.scan(RULES, outer.as_bytes()), "private-key")

    def test_max_size(self):
        rules = content.parse({"version": 1, "attachments": {"max_size": 10}})
        self.assertEqual(content.scan(rules, message(attachments=[("a.bin", b"x" * 11)])), "attachment-too-big")
        self.assertIsNone(content.scan(rules, message("corps plus long que dix octets")))


class ParseTest(unittest.TestCase):
    def test_invalid(self):
        with self.assertRaises(content.RulesError) as cm:
            content.parse({"version": 0, "inconnu": 1,
                           "patterns": [{"id": "A B", "regex": "x"}, {"id": "ok", "regex": "("},
                                        {"id": "ok", "regex": "y"}, {"id": "z", "foo": 1}],
                           "attachments": {"forbidden_extensions": ["e xe"], "max_size": -1, "x": 2}})
        msg = " ".join(cm.exception.errors)
        for needle in ("version=0", "'inconnu'", "id='A B'", "regex invalide", "en double", "regex absente",
                       "'foo'", "extension 'e xe'", "max_size=-1", "clé inconnue 'x'"):
            self.assertIn(needle, msg)

    def test_load_errors(self):
        with self.assertRaises(content.RulesError):
            content.load("/nonexistent/rules.toml")
        fd, bad = tempfile.mkstemp(suffix=".toml")
        try:
            os.write(fd, b"version = [")
            os.close(fd)
            with self.assertRaises(content.RulesError) as cm:
                content.load(bad)
            self.assertIn("TOML invalide", cm.exception.errors[0])
        finally:
            os.unlink(bad)


if __name__ == "__main__":
    unittest.main()
