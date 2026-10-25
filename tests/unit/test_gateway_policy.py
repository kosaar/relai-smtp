"""Tests unitaires des règles d'identité de la passerelle (relaygw.policy)."""
import unittest

from tests.unit import ROOT  # noqa: F401  (chemins d'import)
from relaycfg.inventory import Application, Inventory
from relaygw import policy

GITLAB = Application("gitlab", "gitlab@example.com", ("10.0.1.10", "fd00::10"), 200)
INV = Inventory("example.com", {"gitlab": GITLAB})


class PolicyTest(unittest.TestCase):
    def reason(self, refusal):
        return refusal.reason if refusal else None

    def test_login(self):
        self.assertEqual(policy.resolve_login(INV, "gitlab"), (GITLAB, None))
        self.assertEqual(self.reason(policy.resolve_login(INV, None)[1]), "no-login")
        self.assertEqual(self.reason(policy.resolve_login(INV, "jenkins")[1]), "unknown-login")

    def test_client_ip(self):
        self.assertIsNone(policy.check_client_ip(GITLAB, "10.0.1.10"))
        self.assertIsNone(policy.check_client_ip(GITLAB, "FD00:0::10"))
        for bad in ("10.0.1.20", None, "", "garbage"):
            self.assertEqual(self.reason(policy.check_client_ip(GITLAB, bad)), "client-ip-mismatch")

    def test_envelope(self):
        self.assertIsNone(policy.check_envelope_sender(GITLAB, "<GitLab@Example.com>"))
        self.assertEqual(self.reason(policy.check_envelope_sender(GITLAB, "<>")), "null-sender")
        r = policy.check_envelope_sender(GITLAB, "<jenkins@example.com>")
        self.assertEqual((r.code, r.dsn, r.reason), ("553", "5.7.1", "envelope-mismatch"))

    def test_from_ok(self):
        for value in ("gitlab@example.com", "GitLab <gitlab@example.com>", '"GitLab CI" <GITLAB@example.com>',
                      "=?utf-8?q?GitLab_=C3=A9t=C3=A9?= <gitlab@example.com>",
                      '"gitlab@example.com" <gitlab@example.com>', "GitLab\r\n <gitlab@example.com>"):
            with self.subTest(value=value):
                self.assertIsNone(policy.check_from_headers(GITLAB, [value]))

    def test_from_refused(self):
        cases = {
            "from-missing": [],
            "from-multiple": ["gitlab@example.com", "gitlab@example.com"],
            "from-invalid": ["gitlab@example.com, jenkins@example.com"],
            "from-mismatch": ["Jenkins <jenkins@example.com>"],
            "from-display-spoof": ['"jenkins@example.com" <gitlab@example.com>'],
        }
        for reason, values in cases.items():
            with self.subTest(reason=reason):
                r = policy.check_from_headers(GITLAB, values)
                self.assertEqual((r.code, r.dsn, r.reason), ("550", "5.7.1", reason))
                self.assertTrue(r.permanent)
        self.assertEqual(self.reason(policy.check_from_headers(GITLAB, ["undisclosed-recipients:;"])), "from-invalid")
        self.assertEqual(self.reason(policy.check_from_headers(
            GITLAB, ["=?utf-8?q?jenkins=40example=2Ecom?= <gitlab@example.com>"])), "from-display-spoof")


if __name__ == "__main__":
    unittest.main()
