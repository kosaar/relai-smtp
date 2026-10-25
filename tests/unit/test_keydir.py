"""Tests unitaires de l'annuaire : WKD, analyse de la sortie GnuPG, règles d'acceptation."""
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from tests.unit import ROOT  # noqa: F401  (chemins d'import)
from pgpkeys import openpgp, policy, wkd
from pgpkeys.openpgp import KeyInfo, SubKey

NOW = int(time.time())
YEAR = 365 * 86400


def key(algo=22, bits=255, curve="ed25519", uids=(("alice@example.com", "alice@example.com", False),),
        subs=None, expires=None, revoked=False):
    if subs is None:
        subs = [SubKey("S" * 40, 18, 255, "cv25519", "e", NOW, NOW + YEAR, False)]
    return KeyInfo("F" * 40, algo, bits, curve, "scSC", NOW, expires, revoked, list(uids), list(subs))


class WkdTest(unittest.TestCase):
    def test_spec_vector(self):
        # Exemple de draft-koch-openpgp-webkey-service.
        self.assertEqual(wkd.wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q")
        self.assertEqual(wkd.advanced_path("Joe.Doe@Example.ORG"),
                         "/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q")

    def test_zbase32_length(self):
        self.assertEqual(len(wkd.zbase32(bytes(20))), 32)


class ParseColonsTest(unittest.TestCase):
    SAMPLE = "\n".join([
        "pub:-:255:22:31990C5128F10CCD:1792955268:1856027268::-:::scSC:::::ed25519:::0:",
        "fpr:::::::::D241BB7DFEBF23563E1948FE31990C5128F10CCD:",
        "uid:-::::1792955268::HASH::Alice <Alice@Example.com>::::::::::0:",
        "uid:r::::1792955268::HASH::old\\x3a name <old@example.com>::::::::::0:",
        "sub:e:255:18:F6B95D70B97E15ED:1792955268:1792955269:::::e:::::cv25519::",
        "fpr:::::::::886BE112291C0D5303E58DF3F6B95D70B97E15ED:",
    ])

    def test_parse(self):
        (k,) = openpgp.parse_colons(self.SAMPLE)
        self.assertEqual((k.fingerprint, k.algo, k.curve, k.expires), ("D241BB7DFEBF23563E1948FE31990C5128F10CCD", 22, "ed25519", 1856027268))
        self.assertEqual(k.emails(), {"alice@example.com"})          # UID révoqué ignoré
        self.assertEqual(k.uids[1][0], "old: name <old@example.com>")
        self.assertEqual(k.subkeys[0].fingerprint, "886BE112291C0D5303E58DF3F6B95D70B97E15ED")
        self.assertEqual(k.subkeys[0].caps, "e")


class PolicyTest(unittest.TestCase):
    DOMAINS = {"example.com", "partner.test"}

    def check(self, info, email="alice@example.com"):
        return " | ".join(policy.check_key([info] if info else [], email, self.DOMAINS, NOW))

    def test_accepted(self):
        self.assertEqual(self.check(key()), "")
        rsa = key(1, 3072, "", subs=[SubKey("S" * 40, 1, 3072, "", "e", NOW, None, False)])
        self.assertEqual(self.check(rsa), "")
        v6 = key(27, 255, "", subs=[SubKey("S" * 40, 25, 255, "", "e", NOW, None, False)])
        self.assertEqual(self.check(v6), "")

    def test_refused(self):
        self.assertIn("aucune clé publique", self.check(None))
        self.assertIn("un seul certificat", " ".join(policy.check_key([key(), key()], "alice@example.com", self.DOMAINS, NOW)))
        self.assertIn("aucune sous-clé de chiffrement", self.check(key(subs=[])))
        self.assertIn("clé expirée", self.check(key(expires=NOW - 1)))
        self.assertIn("clé révoquée", self.check(key(revoked=True)))
        self.assertIn("RSA 2048", self.check(key(1, 2048, "", subs=[SubKey("S" * 40, 1, 2048, "", "e", NOW, None, False)])))
        self.assertIn("ECDSA nistp256", self.check(key(19, 256, "nistp256")))
        self.assertIn("aucune identité", self.check(key(), "bob@example.com"))
        self.assertIn("domaine 'other.test'", self.check(key(), "alice@other.test"))
        for sub in (SubKey("S" * 40, 18, 255, "cv25519", "e", NOW, NOW - 1, False),
                    SubKey("S" * 40, 18, 255, "cv25519", "e", NOW, None, True),
                    SubKey("S" * 40, 18, 256, "nistp256", "e", NOW, None, False)):
            with self.subTest(sub=sub):
                self.assertIn("aucune sous-clé de chiffrement valide", self.check(key(subs=[sub])))

    def test_normalize_email(self):
        self.assertEqual(policy.normalize_email(" Alice@Example.COM "), "alice@example.com")
        for bad in ("", None, "alice", "a@b", "alice@@example.com", "a b@example.com"):
            self.assertIsNone(policy.normalize_email(bad))


@unittest.skipUnless(shutil.which("gpg") and shutil.which("gpg-agent"), "GnuPG complet absent (gpg + gpg-agent)")
class GpgTest(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.addCleanup(subprocess.run, ["gpgconf", "--homedir", str(self.home), "--kill", "all"], capture_output=True)

    def gpg(self, *args):
        return subprocess.run(["gpg", "--homedir", str(self.home), "--batch", "--quiet", "--pinentry-mode", "loopback",
                               "--passphrase", "", *args], capture_output=True, check=True).stdout

    def test_inspect_export_and_revoke(self):
        self.gpg("--quick-gen-key", "Alice <alice@example.com>", "default", "default", "1y")
        self.gpg("--quick-add-uid", "alice@example.com", "bob@example.com")
        pub = self.gpg("--armor", "--export", "alice@example.com")
        (info,) = openpgp.inspect(pub)
        self.assertEqual(info.emails(), {"alice@example.com", "bob@example.com"})
        self.assertEqual(policy.check_key([info], "alice@example.com", {"example.com"}, NOW), [])
        blob = openpgp.export_for_wkd(pub, info.fingerprint, "alice@example.com")
        (served,) = openpgp.inspect(blob)
        self.assertEqual(served.emails(), {"alice@example.com"})      # UID de bob retiré
        self.assertIsNone(openpgp.apply_revocation(pub, info.fingerprint, b"garbage"))
        rev_file = next((self.home / "openpgp-revocs.d").glob("*.rev"))
        rev = rev_file.read_bytes().replace(b":-----BEGIN", b"-----BEGIN")
        revoked = openpgp.apply_revocation(pub, info.fingerprint, rev)
        self.assertTrue(openpgp.inspect(revoked)[0].revoked)
        self.assertEqual(openpgp.inspect(b"not a key"), [])


if __name__ == "__main__":
    unittest.main()
