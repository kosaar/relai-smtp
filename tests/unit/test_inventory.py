"""Tests unitaires de relaycfg.inventory et de la CLI relay-config."""
import contextlib
import io
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from tests.unit import ROOT
from relaycfg import cli
from relaycfg import inventory as inv

BASE = """
sender_domain = "example.com"
[defaults]
quota_per_hour = 100
[applications.gitlab]
address = "GitLab@Example.com"
client_ips = ["10.0.1.10", "10.0.1.10", "fd00::10"]
quota_per_hour = 500
[applications.jenkins]
address = "jenkins@example.com"
client_ips = ["10.0.1.20"]
"""


def parse(text):
    return inv.parse(tomllib.loads(text), "test")


def errors_of(text, count=None):
    """Erreurs (jointes) levées par l'inventaire ; échoue s'il est accepté."""
    try:
        parse(text)
    except inv.InventoryError as e:
        if count is not None and len(e.errors) != count:
            raise AssertionError(f"{count} erreur(s) attendue(s) : {e.errors}") from None
        return " | ".join(e.errors)
    raise AssertionError("InventoryError attendue")


class ParseTest(unittest.TestCase):
    def test_valid(self):
        i = parse(BASE)
        self.assertEqual(i.sender_domain, "example.com")
        gl = i.by_login("gitlab")
        self.assertEqual(gl.address, "gitlab@example.com")        # normalisée
        self.assertEqual(gl.client_ips, ("10.0.1.10", "fd00::10"))  # sans doublon
        self.assertEqual(gl.quota_per_hour, 500)
        self.assertEqual(i.by_login("jenkins").quota_per_hour, 100)  # [defaults]
        self.assertIsNone(i.by_login("inconnu"))
        self.assertIsNone(i.by_login(None))
        self.assertEqual(i.client_ips(), ["10.0.1.10", "10.0.1.20", "fd00::10"])

    def test_default_quota_without_defaults(self):
        i = parse('sender_domain = "example.com"\n[applications.a]\naddress = "a@example.com"\nclient_ips = ["10.0.0.1"]\n')
        self.assertEqual(i.by_login("a").quota_per_hour, inv.DEFAULT_QUOTA)

    def test_duplicate_address(self):
        e = errors_of(BASE.replace('"jenkins@example.com"', '"gitlab@example.com"'))
        self.assertIn("déjà attribuée à l'application 'gitlab'", e)

    def test_address_outside_domain(self):
        self.assertIn("n'appartient pas à sender_domain", errors_of(BASE.replace("jenkins@example.com", "jenkins@other.test")))

    def test_invalid_quota(self):
        for bad in ("0", "-1", "100001", '"10"', "true", "1.5"):
            with self.subTest(bad=bad):
                self.assertIn("quota_per_hour", errors_of(BASE.replace("quota_per_hour = 500", f"quota_per_hour = {bad}")))

    def test_invalid_ips(self):
        for bad, msg in (('"10.0.1.0/24"', "pas de CIDR"), ('"999.1.1.1"', "n'est pas une adresse"),
                         ('"127.0.0.2"', "bouclage"), ('"0.0.0.0"', "non spécifiée"), ("10", "chaîne attendue"),
                         ('"10.0.1.20", "127.0.0.1"', "seule IP")):
            with self.subTest(bad=bad):
                self.assertIn(msg, errors_of(BASE.replace('["10.0.1.20"]', f"[{bad}]")))
        self.assertIn("liste non vide", errors_of(BASE.replace('["10.0.1.20"]', "[]")))

    def test_local_application(self):
        for local in ("127.0.0.1", "::1"):
            with self.subTest(local=local):
                app = parse(BASE.replace('["10.0.1.20"]', f'["{local}"]')).applications["jenkins"]
                self.assertEqual(app.client_ips, (local,))

    def test_invalid_names_and_keys(self):
        self.assertIn("nom invalide", errors_of(BASE.replace("[applications.jenkins]", "[applications.Jenkins]")))
        self.assertIn("clé inconnue 'adress'", errors_of(BASE.replace('address = "jenkins', 'adress = "jenkins')))
        self.assertIn("clé inconnue 'extra'", errors_of("extra = 1\n" + BASE))

    def test_missing_domain_and_apps(self):
        e = errors_of('[defaults]\nquota_per_hour = 10\n')
        self.assertIn("sender_domain", e)
        self.assertIn("aucune application", e)

    def test_all_errors_reported_together(self):
        text = BASE.replace("jenkins@example.com", "jenkins@other.test").replace("quota_per_hour = 500", "quota_per_hour = 0")
        errors_of(text, count=2)


class SecretsTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.inv = parse(BASE)

    def test_secrets(self):
        (self.dir / "gitlab").write_text("x" * 16 + "\n")
        (self.dir / "jenkins").write_text("court")
        errs = inv.check_secrets(self.inv, self.dir)
        self.assertEqual(len(errs), 1)
        self.assertIn("au moins 16", errs[0])
        self.assertEqual(inv.read_password(self.dir, "gitlab"), "x" * 16)
        (self.dir / "jenkins").unlink()
        self.assertIn("absent", inv.check_secrets(self.inv, self.dir)[0])
        (self.dir / "jenkins").write_text("a" * 16 + "\nb")
        self.assertIn("une ligne", inv.check_secrets(self.inv, self.dir)[0])


class CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "apps.toml").write_text(BASE)
        (self.dir / "secrets").mkdir()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def test_check_ok_and_fatal(self):
        rc, out, _ = self.run_cli("check", "--inventory", str(self.dir / "apps.toml"))
        self.assertEqual(rc, 0)
        self.assertIn("2 application(s)", out)
        rc, _, err = self.run_cli("check", "--inventory", str(self.dir / "apps.toml"),
                                  "--secrets-dir", str(self.dir / "secrets"))
        self.assertEqual(rc, 1)
        self.assertEqual(err.count("FATAL:"), 2)
        rc, _, err = self.run_cli("check", "--inventory", str(self.dir / "absent.toml"))
        self.assertEqual(rc, 1)
        self.assertIn("introuvable", err)

    def test_domain(self):
        rc, out, _ = self.run_cli("domain", "--inventory", str(self.dir / "apps.toml"))
        self.assertEqual((rc, out.strip()), (0, "example.com"))

    @unittest.skipUnless(shutil.which("saslpasswd2"), "saslpasswd2 absent (testé dans l'image du relai)")
    def test_postfix(self):
        for app in ("gitlab", "jenkins"):
            (self.dir / "secrets" / app).write_text(app * 4)
        rc, _, err = self.run_cli("postfix", "--inventory", str(self.dir / "apps.toml"), "--secrets-dir",
                                  str(self.dir / "secrets"), "--out", str(self.dir), "--sasldb",
                                  str(self.dir / "sasldb2"), "--realm", "relay.example.com")
        self.assertEqual(rc, 0, err)
        self.assertIn("gitlab@example.com gitlab", (self.dir / "sender_login_maps").read_text())
        self.assertEqual((self.dir / "mynetworks").read_text().split(),
                         ["127.0.0.1/32", "10.0.1.10/32", "10.0.1.20/32", "[fd00::10]/128"])
        users = subprocess.run(["sasldblistusers2", "-f", str(self.dir / "sasldb2")],
                               capture_output=True, text=True, check=True).stdout
        self.assertIn("gitlab@relay.example.com", users)

    def test_production_inventory_is_valid(self):
        rc, _, err = self.run_cli("check", "--inventory", str(ROOT / "config" / "applications.toml"))
        self.assertEqual(rc, 0, err)

    def test_tls_check(self):
        rc, _, err = self.run_cli("tls-check", "--cert", str(self.dir / "apps.toml"), "--key", str(self.dir / "apps.toml"))
        self.assertEqual(rc, 1)
        self.assertIn("inutilisables", err)


if __name__ == "__main__":
    unittest.main()
