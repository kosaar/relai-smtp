"""Tests unitaires des métriques de l'annuaire (clés proches de l'expiration, expirées, révoquées)."""
import unittest
from types import SimpleNamespace

from tests.unit import ROOT  # noqa: F401  (chemins d'import)
from keydir import metrics

NOW = 1_800_000_000
DAY = 86400


def row(email, state, expires=None):
    return SimpleNamespace(email=email, state=state, expires=expires)


class KeydirMetricsTest(unittest.TestCase):
    def render(self, rows, warning=30):
        return metrics.render(rows, NOW, warning)

    def test_states_and_flags(self):
        text = self.render([
            row("ok@example.com", "approved", NOW + 400 * DAY),
            row("soon@example.com", "approved", NOW + 10 * DAY),
            row("old@example.com", "approved", NOW - DAY),
            row("never@example.com", "approved", None),
            row("rev@example.com", "revoked"),
            row("rev@example.com", "pending"),
            row("rotated@example.com", "revoked"),
            row("rotated@example.com", "approved", NOW + 400 * DAY),
            row("new@example.com", "pending"),
        ])
        self.assertIn('keydir_keys{state="approved"} 5', text)
        self.assertIn('keydir_keys{state="pending"} 2', text)
        self.assertIn('keydir_keys{state="revoked"} 2', text)
        self.assertIn("keydir_keys_expiring_soon 1", text)
        self.assertIn('keydir_key_expiring_soon{email="soon@example.com"} 1', text)
        self.assertIn("keydir_keys_expired 1", text)
        self.assertIn('keydir_key_expired{email="old@example.com"} 1', text)
        self.assertIn("keydir_keys_revoked 1", text)
        self.assertIn('keydir_key_revoked{email="rev@example.com"} 1', text)
        self.assertNotIn('keydir_key_revoked{email="rotated@example.com"}', text)
        self.assertIn(f'keydir_key_expiry_timestamp_seconds{{email="soon@example.com"}} {NOW + 10 * DAY}', text)
        self.assertNotIn('expiry_timestamp_seconds{email="never@example.com"}', text)

    def test_warning_threshold(self):
        rows = [row("soon@example.com", "approved", NOW + 10 * DAY)]
        self.assertIn("keydir_keys_expiring_soon 0", self.render(rows, warning=7))
        self.assertIn("keydir_keys_expiring_soon 1", self.render(rows, warning=10))
        self.assertIn("keydir_expiry_warning_days 10", self.render(rows, warning=10))

    def test_empty(self):
        text = self.render([])
        self.assertIn('keydir_keys{state="approved"} 0', text)
        self.assertTrue(text.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
