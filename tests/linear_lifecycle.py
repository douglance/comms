"""Exercise the real Linear schema and owner-transfer SQL with foreign keys enabled."""
import json
import pathlib
import re
import sqlite3
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class LinearTransferTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute(
            "CREATE TABLE agents(id TEXT PRIMARY KEY, profile_name TEXT, "
            "revoked_at INTEGER, expires_at INTEGER)"
        )
        self.db.executemany("INSERT INTO agents VALUES (?,?,NULL,1000)", [
            ("original", "engineer"), ("replacement", "engineer"), ("other", "sales")
        ])
        self.db.executescript((ROOT / "migrations/control/0006_linear.sql").read_text())
        self.db.execute("INSERT INTO linear_apps VALUES (?,?,?,?,?,?,?,?,?)", (
            "original", "engineer", "Engineer", "fixture", "organization",
            "app-user", "client", "original-ciphertext", 100
        ))
        self.db.execute("INSERT INTO linear_events VALUES (41,?,?,?,?)", (
            "original", "event", '{"real":"event"}', 100
        ))
        self.db.execute("INSERT INTO linear_oauth_states VALUES (?,?,?,?)", (
            "pending-state", "original", "client", 1000
        ))
        self.db.executescript((ROOT / "migrations/control/0007_linear_transfer.sql").read_text())
        source = (ROOT / "crates/comms-linear/src/lib.rs").read_text()
        self.sql = json.loads(re.search(
            r'pub const TRANSFER_APP_SQL: &str\s*=\s*(".*?");', source, re.DOTALL
        ).group(1))
        self.db.commit()

    def transfer(self, target="replacement", now=200):
        with self.db:
            changed = self.db.execute(self.sql, (
                target, "replacement-ciphertext", now, "original", "engineer"
            )).fetchall()
            self.db.execute(
                "DELETE FROM linear_oauth_states WHERE agent_id=? AND client_id=?",
                (target, "client"),
            )
        return changed

    def test_owner_transfer_preserves_identity_events_and_cursor(self):
        self.assertEqual(self.transfer(), [("replacement",)])
        self.assertIsNone(self.db.execute(
            "SELECT agent_id FROM linear_apps WHERE agent_id='original'"
        ).fetchone())
        self.assertEqual(self.db.execute(
            "SELECT profile_name,app_user_id,client_id,sealed_json FROM linear_apps "
            "WHERE agent_id='replacement'"
        ).fetchone(), ("engineer", "app-user", "client", "replacement-ciphertext"))
        self.assertEqual(self.db.execute(
            "SELECT sequence,event_hash,payload_json FROM linear_events "
            "WHERE agent_id='replacement'"
        ).fetchall(), [(41, "event", '{"real":"event"}')])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM linear_oauth_states").fetchone()[0], 0)
        self.db.execute(
            "INSERT INTO linear_events(agent_id,event_hash,payload_json,received_at) VALUES (?,?,?,?)",
            ("replacement", "next-event", "{}", 201),
        )
        self.assertEqual(self.db.execute(
            "SELECT sequence FROM linear_events WHERE event_hash='next-event'"
        ).fetchone(), (42,))
        self.assertEqual(self.transfer(), [])

    def test_foreign_profile_inactive_and_missing_targets_are_rejected(self):
        for target, now in [("other", 200), ("replacement", 1000), ("missing", 200)]:
            self.assertEqual(self.transfer(target, now), [])
        self.db.execute("UPDATE agents SET revoked_at=1 WHERE id='replacement'")
        self.assertEqual(self.transfer(), [])
        self.assertEqual(self.db.execute(
            "SELECT agent_id,sealed_json FROM linear_apps"
        ).fetchone(), ("original", "original-ciphertext"))
        self.assertEqual(self.db.execute(
            "SELECT agent_id,sequence FROM linear_events"
        ).fetchone(), ("original", 41))

    def test_existing_target_binding_fails_atomically(self):
        self.db.execute("INSERT INTO linear_apps VALUES (?,?,?,?,?,?,?,?,?)", (
            "replacement", "second-profile", "Second", "fixture", "organization",
            "second-app", "second-client", "second-ciphertext", 100
        ))
        self.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.transfer()
        self.assertEqual(self.db.execute(
            "SELECT agent_id FROM linear_events WHERE sequence=41"
        ).fetchone(), ("original",))
        self.assertEqual(self.db.execute(
            "SELECT agent_id FROM linear_oauth_states WHERE state_hash='pending-state'"
        ).fetchone(), ("original",))


if __name__ == "__main__":
    unittest.main()
