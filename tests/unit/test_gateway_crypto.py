"""Tests unitaires de la passerelle : PGP/MIME (pgpmime), résolution des clés
(keys, avec un faux transport HTTP) et chiffrement GnuPG (crypto)."""
import email
import email.policy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.unit import ROOT  # noqa: F401  (chemins d'import)
from relaygw import pgpmime
from relaygw.keys import KeyResolver, classify

HEADERS = [
    ("Received", b" from gitlab by relay"),
    ("From", b" GitLab <gitlab@example.com>"),
    ("To", b" alice@example.com"),
    ("Subject", b" =?utf-8?q?R=C3=A9sultat?=\r\n\t du pipeline"),
    ("Message-ID", b" <1@gitlab>"),
    ("MIME-Version", b" 1.0"),
    ("Content-Type", b' multipart/mixed; boundary="XYZ"'),
    ("Content-Transfer-Encoding", b" 7bit"),
    ("X-GitLab-Project", b" infra"),
]
BODY = b"--XYZ\r\nContent-Type: text/plain\r\n\r\nbonjour\r\n--XYZ--\r\n"


class PgpMimeTest(unittest.TestCase):
    def test_inner_roundtrip(self):
        inner = pgpmime.build_inner(HEADERS, BODY, boundary="B0")
        msg = email.message_from_bytes(inner, policy=email.policy.compat32)
        self.assertEqual(msg.get_content_type(), "multipart/mixed")
        self.assertEqual(msg.get_param("protected-headers"), "v1")
        self.assertEqual(msg["Subject"], "=?utf-8?q?R=C3=A9sultat?=\r\n\t du pipeline")
        self.assertIsNone(msg["X-GitLab-Project"])          # lot 3 : en-têtes protégés seulement
        (part,) = msg.get_payload()
        self.assertEqual(part.get_content_type(), "multipart/mixed")
        self.assertEqual(part.get_boundary(), "XYZ")
        # Entité d'origine restituée octet pour octet.
        start = inner.index(b"--B0\r\n") + len(b"--B0\r\n")
        entity = inner[start:inner.rindex(b"\r\n--B0--")]
        self.assertTrue(entity.endswith(b"\r\n\r\n" + BODY.rstrip(b"\r\n") + b"\r\n"))
        self.assertIn(b'Content-Type: multipart/mixed; boundary="XYZ"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n', entity)

    def test_inner_default_content_type_and_crlf(self):
        inner = pgpmime.build_inner([("Subject", b"x")], b"ligne1\nligne2\n", boundary="B1")
        self.assertIn(b"--B1\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nligne1\r\nligne2\r\n\r\n--B1--\r\n", inner)
        self.assertIn(b"Subject: x\r\n", inner)

    def test_outer_changes(self):
        ops = pgpmime.outer_header_changes(HEADERS + [("Subject", b" doublon")], "Message chiffré", "OB")
        self.assertIn(("change", "Subject", 1, " =?utf-8?q?Message_chiffr=C3=A9?="), ops)
        self.assertIn(("change", "Subject", 2, None), ops)
        self.assertIn(("change", "Content-Type", 1,
                       ' multipart/encrypted; protocol="application/pgp-encrypted"; boundary="OB"'), ops)
        self.assertIn(("change", "Content-Transfer-Encoding", 1, None), ops)
        self.assertIn(("change", "MIME-Version", 1, " 1.0"), ops)
        self.assertFalse([o for o in ops if o[1] in ("From", "To", "Received")])
        ops = pgpmime.outer_header_changes([("From", b" a@b.c")], "Chiffré", "OB")
        self.assertEqual({o[1] for o in ops if o[0] == "add"}, {"MIME-Version", "Subject", "Content-Type"})

    def test_encrypted_body(self):
        body = pgpmime.build_encrypted_body(b"-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n", "OB")
        msg = email.message_from_bytes(
            b'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="OB"\r\n\r\n' + body)
        parts = msg.get_payload()
        self.assertEqual([p.get_content_type() for p in parts], ["application/pgp-encrypted", "application/octet-stream"])
        self.assertEqual(parts[0].get_payload().strip(), "Version: 1")
        self.assertIn("-----END PGP MESSAGE-----", parts[1].get_payload())
        self.assertNotIn(b"\n", body.replace(b"\r\n", b""))


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class KeyResolverTest(unittest.TestCase):
    def resolver(self, responses, clock=None):
        calls = []

        def fetch(url):
            calls.append(url)
            r = responses.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        return KeyResolver("https://keydir:8443/", None, ttl=5, clock=clock or FakeClock(), fetch=fetch), calls

    def test_url(self):
        r, _ = self.resolver([])
        self.assertEqual(r.url_for("Joe.Doe@example.org".lower()),
                         "https://keydir:8443/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe")

    def test_nokey_cached_unavailable_not_cached(self):
        clock = FakeClock()
        r, calls = self.resolver([(404, b""), ConnectionRefusedError(), (503, b"x")], clock)
        self.assertEqual(r.lookup("carol@example.com").status, "nokey")
        self.assertEqual(r.lookup("carol@example.com").reason, "no-key")
        self.assertEqual(len(calls), 1)                      # servi par le cache
        clock.t += 6                                         # cache expiré
        self.assertEqual(r.lookup("carol@example.com").status, "unavailable")
        self.assertEqual(r.lookup("carol@example.com").reason, "keydir-http-503")   # pas de cache
        self.assertEqual(len(calls), 3)

    def test_classify(self):
        self.assertEqual(classify(["clé révoquée", "x"]), "key-revoked")
        self.assertEqual(classify(["clé expirée"]), "key-expired")
        self.assertEqual(classify(["aucune sous-clé de chiffrement"]), "key-unusable")
        self.assertEqual(classify(["aucune identité"]), "key-invalid")


@unittest.skipUnless(shutil.which("gpg") and shutil.which("gpg-agent"), "GnuPG complet absent (gpg + gpg-agent)")
class CryptoTest(unittest.TestCase):
    def test_encrypt_keyids(self):
        from relaygw import crypto
        from pgpkeys import openpgp
        homes = {}
        try:
            for who in ("alice", "bob"):
                h = Path(tempfile.mkdtemp())
                homes[who] = h
                g = ["gpg", "--homedir", str(h), "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", ""]
                subprocess.run(g + ["--quick-gen-key", f"{who}@example.com", "default", "default", "1y"], check=True,
                               capture_output=True)
            keys = []
            for who, h in homes.items():
                pub = subprocess.run(["gpg", "--homedir", str(h), "--batch", "--export", f"{who}@example.com"],
                                     check=True, capture_output=True).stdout
                (info,) = openpgp.inspect(pub)
                keys.append((info.fingerprint, pub))
            inner = pgpmime.build_inner(HEADERS, BODY)
            armored = crypto.encrypt(inner, keys)
            for h in homes.values():
                # Code de sortie non nul possible : GnuPG essaie sa clé sur chaque
                # destinataire anonyme et signale les essais infructueux.
                plain = subprocess.run(["gpg", "--homedir", str(h), "--batch", "--quiet",
                                        "--pinentry-mode", "loopback", "--passphrase", "", "--decrypt"],
                                       input=armored, capture_output=True).stdout
                self.assertEqual(plain, inner)
            packets = subprocess.run(["gpg", "--homedir", str(homes["alice"]), "--batch", "--list-packets",
                                      "--pinentry-mode", "loopback", "--passphrase", ""],
                                     input=armored, capture_output=True).stdout.decode()
            # Plusieurs destinataires : identifiants visibles (compatibilité RNP/Thunderbird).
            self.assertEqual(packets.count("keyid 0000000000000000"), 0)
            self.assertEqual(packets.count(":pubkey enc packet:"), 2)
            single = crypto.encrypt(inner, keys[:1])
            packets = subprocess.run(["gpg", "--homedir", str(homes["bob"]), "--batch", "--list-packets"],
                                     input=single, capture_output=True).stdout.decode()
            self.assertEqual(packets.count("keyid 0000000000000000"), 1)   # un seul : masqué
        finally:
            for h in homes.values():
                subprocess.run(["gpgconf", "--homedir", str(h), "--kill", "all"], capture_output=True)
                shutil.rmtree(h, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
