"""Tests unitaires de la configuration de la passerelle (relaygw.config)."""
import os
import tempfile
import unittest

from tests.unit import ROOT  # noqa: F401  (chemins d'import)
from relaygw import config


class GatewayConfigTest(unittest.TestCase):
    def setUp(self):
        fd, self.key = tempfile.mkstemp()
        os.write(fd, b"k" * 48 + b"\n")
        os.close(fd)
        self.addCleanup(os.unlink, self.key)

    def env(self, **kw):
        return {"GATEWAY_HMAC_KEY_FILE": self.key, **kw}

    def test_defaults(self):
        c = config.load(self.env())
        self.assertEqual(c.keydir_url, "https://keydir:8443")
        self.assertEqual(c.key_cache_ttl, 300)
        self.assertEqual(c.neutral_subject, "Message chiffré")
        self.assertEqual(c.hmac_key, b"k" * 48)

    def test_invalid(self):
        with open(self.key, "wb") as f:
            f.write(b"trop-courte")
        with self.assertRaises(config.ConfigError) as cm:
            config.load(self.env(GATEWAY_KEYDIR_URL="http://keydir", GATEWAY_KEY_CACHE_TTL="0",
                                 GATEWAY_NEUTRAL_SUBJECT=" "))
        msg = " ".join(cm.exception.errors)
        for needle in ("HTTPS obligatoire", "GATEWAY_KEY_CACHE_TTL", "GATEWAY_NEUTRAL_SUBJECT", "32 caractères"):
            self.assertIn(needle, msg)

    def test_missing_key(self):
        with self.assertRaises(config.ConfigError) as cm:
            config.load({"GATEWAY_HMAC_KEY_FILE": "/nonexistent/key"})
        self.assertIn("gateway_hmac_key", cm.exception.errors[0])


if __name__ == "__main__":
    unittest.main()
