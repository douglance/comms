#!/usr/bin/env python3
"""Offline Slack catalog generation checks."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SlackCatalogGenerationTest(unittest.TestCase):
    def run_script(self, *args: str) -> dict:
        result = subprocess.run(
            [sys.executable, "scripts/slack_sources.py", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(result.stdout)

    def test_pinned_raw_inventory_matches_embedded_catalog(self) -> None:
        report = self.run_script("--catalog-check")
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["inventory"]["method_count"], 350)
        self.assertEqual(report["embedded"]["method_count"], 350)
        self.assertEqual(report["embedded"]["schema_methods"], 292)
        self.assertEqual(report["embedded"]["docs_only_methods"], 58)
        self.assertEqual(report["missing_from_embedded"], [])
        self.assertEqual(report["extra_in_embedded"], [])
        self.assertEqual(report["markdown_suffix_methods"], [])
        self.assertTrue(report["stronger_schema_kept"], report)

    def test_caller_schemas_do_not_require_vault_authority(self) -> None:
        catalog = json.loads((ROOT / "crates/comms-slack-api/data/catalog.json").read_text())
        for method in catalog["methods"]:
            self.assertNotIn("token", method["input_schema"].get("required", []), method["name"])
            self.assertNotIn("token", method["input_schema"].get("properties", {}), method["name"])

    def test_catalog_ops_are_griz_create_operations(self) -> None:
        ops = self.run_script("--catalog-ops")
        self.assertEqual({op["path"] for op in ops}, {
            "crates/comms-slack-api/data/catalog.json",
            "crates/comms-slack-api/data/docs_index.json",
            "docs/slack/README.md",
        })
        self.assertTrue(all(op["op"] == "create" and op.get("overwrite") is True for op in ops), ops)


    def test_official_bot_scopes_and_get_encoding_are_preserved(self) -> None:
        catalog = json.loads((ROOT / "crates/comms-slack-api/data/catalog.json").read_text())
        member = next(method for method in catalog["methods"] if method["name"] == "conversations.members")
        self.assertEqual(member["token_types"], ["bot", "user"])
        self.assertEqual(member["scopes"], ["channels:read", "groups:read", "im:read", "mpim:read"])
        self.assertEqual(member["http_method"], "GET")
        self.assertIn("application/x-www-form-urlencoded", member["content_types"])
        self.assertEqual(member["rate_limit"], "Tier 4: 100+ per minute")
        generated = json.loads(next(op["text"] for op in self.run_script("--catalog-ops") if op["path"].endswith("catalog.json")))
        self.assertEqual(generated, catalog)
        self.assertEqual(self.run_script("--catalog-check")["metadata_mismatches"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
