"""Verify the encrypted Comms vault boundary with known fixture credentials."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BRIDGE = Path(__file__).resolve().parents[1] / "scripts/comms_vault.py"


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.env = dict(os.environ, COMMS_VAULT_DIR=self.directory.name,
                        COMMS_VAULT_KEY=base64.urlsafe_b64encode(os.urandom(32)).decode())
        self.identity = {"service": "comms.slack.agent", "account": "fixture:builder:agent", "kind": "agent"}

    def call(self, operation, **fields):
        return subprocess.run([sys.executable, str(BRIDGE)],
                              input=json.dumps(dict(self.identity, op=operation, **fields)),
                              env=self.env, capture_output=True, text=True)

    def save(self):
        result = self.call("save", secret="fixture-credential")
        self.assertEqual(result.returncode, 0, result.stderr)
        return next(Path(self.directory.name).glob("*.sealed"))

    def test_roundtrip_is_encrypted_and_private(self):
        path = self.save()
        self.assertNotIn(b"fixture-credential", path.read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        result = self.call("load")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"secret": "fixture-credential"})

    def test_wrong_key_cannot_read(self):
        self.save()
        self.env["COMMS_VAULT_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
        result = self.call("load")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("fixture-credential", result.stderr)

    def test_tampering_is_rejected(self):
        path = self.save()
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        result = self.call("load")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")

    def test_profiles_are_separate_and_delete_persists(self):
        path = self.save()
        self.identity["account"] = "fixture:another:agent"
        self.assertEqual(json.loads(self.call("load").stdout), None)
        self.identity["account"] = "fixture:builder:agent"
        self.assertEqual(self.call("delete").returncode, 0)
        self.assertFalse(path.exists())
        self.assertEqual(json.loads(self.call("load").stdout), None)


if __name__ == "__main__":
    unittest.main()
