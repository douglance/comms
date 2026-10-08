#!/usr/bin/env python3
"""Checks for SDK-derived Slack request schemas."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def schema_for(method: str) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "scripts/slack_sdk_schema.py", "--method", method],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def find_property(schema: dict[str, Any], name: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict) and name in props:
            found.append(props[name])
        for key in ("allOf", "anyOf", "oneOf"):
            for item in schema.get(key, []) if isinstance(schema.get(key), list) else []:
                found.extend(find_property(item, name))
        if isinstance(schema.get("items"), dict):
            found.extend(find_property(schema["items"], name))
    return found




def allows_object_schema(schema: dict[str, Any]) -> bool:
    if schema.get("type") == "object":
        return True
    for key in ("allOf", "anyOf", "oneOf"):
        if any(allows_object_schema(item) for item in schema.get(key, []) if isinstance(item, dict)):
            return True
    return False
def contains_property(schema: dict[str, Any], name: str) -> bool:
    return bool(find_property(schema, name))


def validate(schema: dict[str, Any], value: Any) -> bool:
    if not schema:
        return True
    if "not" in schema:
        return not validate(schema["not"], value)
    if "$ref" in schema:
        raise AssertionError("test validator does not expect refs")
    if "const" in schema:
        return value == schema["const"]
    if "enum" in schema:
        return value in schema["enum"]
    if "allOf" in schema:
        return all(validate(item, value) for item in schema["allOf"])
    if "anyOf" in schema:
        return any(validate(item, value) for item in schema["anyOf"])
    typ = schema.get("type")
    if typ == "object":
        if not isinstance(value, dict):
            return False
        for required in schema.get("required", []):
            if required not in value:
                return False
        props = schema.get("properties", {})
        for key, item in value.items():
            if key in props and not validate(props[key], item):
                return False
            if key not in props and schema.get("additionalProperties") is False:
                return False
        return True
    if typ == "array":
        return isinstance(value, list) and all(validate(schema.get("items", {}), item) for item in value)
    if typ == "string":
        return isinstance(value, str)
    if typ == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if typ == "boolean":
        return isinstance(value, bool)
    return True


class SlackSdkSchemaGenerationTest(unittest.TestCase):

    def test_file_completion_preserves_nonempty_sdk_tuple(self) -> None:
        report = schema_for("files.completeUploadExternal")
        files = find_property(report["schema"], "files")
        self.assertTrue(files)
        for schema in files:
            self.assertEqual(schema["type"], "array")
            self.assertEqual(schema["minItems"], 1)
            self.assertEqual(schema["prefixItems"][0]["required"], ["id"])
            self.assertEqual(schema["items"]["properties"]["id"], {"type": "string"})
        self.assertFalse(any(name.startswith("[FileUploadComplete") for name in report["unresolved"]))


    def test_chat_post_message_uses_sdk_blocks_and_metadata_types(self) -> None:
        report = schema_for("chat.postMessage")
        schema = report["schema"]
        block_schemas = find_property(schema, "blocks")
        metadata_schemas = find_property(schema, "metadata")
        self.assertTrue(block_schemas, report)
        self.assertTrue(metadata_schemas, report)
        self.assertTrue(any(item.get("type") == "array" for item in block_schemas), block_schemas)
        self.assertTrue(any(allows_object_schema(item) for item in metadata_schemas), metadata_schemas)
        self.assertFalse(contains_property(schema, "token"), schema)

    def test_chat_post_message_accepts_block_only_message_and_rejects_string_blocks(self) -> None:
        schema = schema_for("chat.postMessage")["schema"]
        block_only = {"channel": "C123", "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "hi"}}]}
        bad_blocks = {"channel": "C123", "blocks": "not an array"}
        metadata = {"channel": "C123", "text": "hi", "metadata": {"event_type": "thing", "event_payload": {"id": 1}}}
        self.assertTrue(validate(schema, block_only), schema)
        self.assertTrue(validate(schema, metadata), schema)
        self.assertFalse(validate(schema, bad_blocks), schema)

    def test_receipt_records_pinned_supplemental_sdk_sources(self) -> None:
        receipt = json.loads((ROOT / "docs/slack/raw/sdk/sdk-request-supplement.json").read_text())
        self.assertEqual(receipt["revision"], "9b53a7c9e98ef8f06f1956ba88321e217eb642be")
        self.assertGreaterEqual(receipt["file_count"], 51)
        self.assertIn("packages/web-api/src/types/request/chat.ts", receipt["files"])
        self.assertIn("packages/web-api/src/types/helpers.ts", receipt["files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
