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
KEY = b"cle-hmac-de-test-0123456789abcdef"
BODY = b"--XYZ\r\nContent-Type: text/plain\r\n\r\nbonjour\r\n--XYZ--\r\n"


class PgpMimeTest(unittest.TestCase):
    def test_inner_roundtrip(self):
        inner = pgpmime.build_inner(HEADERS, BODY, boundary="B0")
        msg = email.message_from_bytes(inner, policy=email.policy.compat32)
        self.assertEqual(msg.get_content_type(), "multipart/mixed")
        self.assertEqual(msg.get_param("protected-headers"), "v1")
        self.assertEqual(msg["Subject"], "=?utf-8?q?R=C3=A9sultat?=\r\n\t du pipeline")
        # Tous les en-têtes d'origine sont dans la partie chiffrée (D9).
        self.assertEqual(msg["X-GitLab-Project"], "infra")
        self.assertEqual(msg["Received"], "from gitlab by relay")
        self.assertEqual(msg["Message-ID"], "<1@gitlab>")
        self.assertIsNone(msg["Content-Transfer-Encoding"])   # décrit l'entité d'origine
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

    def outer(self, headers):
        raw = pgpmime.build_outer_headers(headers, "Message chiffré", "OB", KEY, "example.com")
        self.assertTrue(raw.endswith(b"\r\n"))
        return email.message_from_bytes(raw + b"\r\n", policy=email.policy.compat32), raw

    def test_outer_allowlist(self):
        msg, raw = self.outer(HEADERS + [("Subject", b" doublon"), ("X-Mailer", b" a"), ("Cc", b" b@example.com"),
                                         ("Auto-Submitted", b" auto-generated"), ("References", b" <0@gitlab> <1@gitlab>")])
        self.assertEqual([k.lower() for k in msg.keys()],
                         ["from", "to", "subject", "message-id", "mime-version", "content-type", "cc",
                          "auto-submitted", "references"])
        self.assertEqual(msg["Subject"], "=?utf-8?q?Message_chiffr=C3=A9?=")
        self.assertEqual(msg["Content-Type"], 'multipart/encrypted; protocol="application/pgp-encrypted"; boundary="OB"')
        self.assertEqual(msg["From"], "GitLab <gitlab@example.com>")
        mid = pgpmime.pseudonymize_ids(b"<1@gitlab>", KEY, "example.com")
        self.assertEqual(msg["Message-ID"], mid)
        self.assertEqual(msg["References"].split()[1], mid)
        for leak in (b"gitlab>", b"Received", b"X-GitLab", b"X-Mailer", b"Content-Transfer-Encoding", b"doublon"):
            self.assertNotIn(leak, raw)

    def test_outer_missing_and_invalid(self):
        msg, _ = self.outer([("From", b" a@example.com")])
        self.assertEqual(msg["MIME-Version"], "1.0")
        self.assertRegex(msg["Message-ID"], r"^<[0-9a-f]{32}@example\.com>$")
        msg, raw = self.outer([("Message-ID", b" sans-chevrons"), ("References", b" rien")])
        self.assertNotIn(b"References", raw)
        self.assertNotIn(b"sans-chevrons", raw)
        self.assertRegex(msg["Message-ID"], r"^<[0-9a-f]{32}@example\.com>$")

    def test_parse_message(self):
        h, b = pgpmime.parse_message(b"From: a@b\nSubject: x\n\ty\nX-A:1\n\nligne\n.point\n")
        self.assertEqual(h, [("From", b" a@b"), ("Subject", b" x\r\n\ty"), ("X-A", b"1")])
        self.assertEqual(b, b"ligne\r\n.point\r\n")
        h, b = pgpmime.parse_message(b"From: a@b\r\npas un en-tete\r\nsuite\r\n")
        self.assertEqual(h, [("From", b" a@b")])
        self.assertEqual(b, b"pas un en-tete\r\nsuite\r\n")
        self.assertEqual(pgpmime.parse_message(b"From: a@b\r\n"), ([("From", b" a@b")], b""))

    def test_pseudonymize_ids(self):
        p = pgpmime.pseudonymize_ids
        a = p(b" <issue_42@gitlab.internal.lan>", KEY, "example.com")
        self.assertRegex(a, r"^<[0-9a-f]{32}@example\.com>$")
        self.assertNotIn("gitlab", a)
        # Déterministe (fil conservé), plié ou non ; dépend de la clé.
        self.assertEqual(a, p(b"\r\n\t<issue_42@gitlab.internal.lan>", KEY, "example.com"))
        self.assertEqual(a, p(b" <issue_42@gitlab.\r\n internal.lan>", KEY, "example.com"))
        self.assertNotEqual(a, p(b" <issue_42@gitlab.internal.lan>", b"k" * 32, "example.com"))
        refs = p(b" <r1@h>\r\n <r2@h> <issue_42@gitlab.internal.lan>", KEY, "example.com").split(" ")
        self.assertEqual(refs[2], a)
        self.assertEqual(len(refs), 3)
        many = p(b" ".join(b"<id%d@h>" % i for i in range(30)), KEY, "example.com").split(" ")
        self.assertEqual(len(many), pgpmime.MAX_REFERENCES)
        self.assertEqual(many[0], p(b"<id0@h>", KEY, "example.com"))
        self.assertEqual(many[-1], p(b"<id29@h>", KEY, "example.com"))
        self.assertEqual(p(b" pas d'identifiant", KEY, "example.com"), "")

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
