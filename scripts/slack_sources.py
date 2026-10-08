#!/usr/bin/env python3
"""Refresh and validate pinned Slack source snapshots.

The default mode fetches official Slack docs/spec sources and emits griz create
operations. Offline modes never fetch or write source files; they derive an
independent method inventory from docs/slack/raw and compare it with the embedded
catalog artifacts.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "docs" / "slack" / "raw"
CATALOG_PATH = ROOT / "crates" / "comms-slack-api" / "data" / "catalog.json"
DOCS_INDEX_PATH = ROOT / "crates" / "comms-slack-api" / "data" / "docs_index.json"
README_PATH = ROOT / "docs" / "slack" / "README.md"

URLS = [
    ("https://docs.slack.dev/llms.txt", "docs/slack/raw/llms.txt", "docs-index"),
    ("https://docs.slack.dev/llms-full.txt", "docs/slack/raw/llms-full.txt", "docs-full"),
    ("https://docs.slack.dev/llms-sitemap.md", "docs/slack/raw/llms-sitemap.md", "docs-sitemap"),
]

METHOD_URL = re.compile(r"https://docs\.slack\.dev/reference/methods/([^/#?)\s`]+)")
SDK_METHOD_URL = re.compile(r"https://docs\.slack\.dev/reference/methods/([A-Za-z0-9_.]+)")


def fetch(url: str) -> tuple[bytes, str, dict[str, str]]:
    request = urllib.request.Request(url, headers={"User-Agent": "comms-slack-api-corpus/0.1"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read(), response.geturl(), dict(response.headers)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def strip_terminal_markdown(name: str) -> str:
    return name[:-3] if name.endswith(".md") else name


def canonical_key(name: str) -> str:
    return strip_terminal_markdown(name).lower()


def docs_methods(raw: Path) -> dict[str, str]:
    text = read_text(raw / "llms-sitemap.md")
    methods: dict[str, str] = {}
    for match in METHOD_URL.finditer(text):
        name = strip_terminal_markdown(match.group(1))
        methods.setdefault(canonical_key(name), name)
    return methods


def sdk_methods(raw: Path) -> dict[str, str]:
    text = read_text(raw / "sdk" / "packages__web-api__src__methods.ts")
    methods: dict[str, str] = {}
    for match in SDK_METHOD_URL.finditer(text):
        name = strip_terminal_markdown(match.group(1))
        methods.setdefault(canonical_key(name), name)
    return methods


def openapi_methods(raw: Path) -> dict[str, str]:
    path = raw / "specs" / "slack_web_openapi_v2_without_examples.json"
    spec = json.loads(read_text(path))
    methods: dict[str, str] = {}
    for path_name in spec.get("paths", {}):
        if not path_name.startswith("/"):
            continue
        name = path_name.strip("/")
        if "." not in name:
            continue
        methods.setdefault(canonical_key(name), name)
    return methods


def source_receipts(raw: Path) -> list[dict[str, Any]]:
    manifest_path = raw.parent / "source-manifest.json"
    if not manifest_path.exists():
        return []
    manifest = json.loads(read_text(manifest_path))
    sources = manifest.get("sources", [])
    return sources if isinstance(sources, list) else []


def build_inventory(raw: Path = RAW) -> dict[str, Any]:
    docs = docs_methods(raw)
    sdk = sdk_methods(raw)
    openapi = openapi_methods(raw)
    merged: dict[str, str] = {}
    for source in (docs, openapi, sdk):
        for key, name in sorted(source.items()):
            merged[key] = name
    docs_only = sorted(set(merged) - set(sdk) - set(openapi))
    schema = sorted(set(merged) & (set(sdk) | set(openapi)))
    return {
        "method_count": len(merged),
        "docs_method_count": len(docs),
        "sdk_method_count": len(sdk),
        "openapi_method_count": len(openapi),
        "schema_method_count": len(schema),
        "docs_only_method_count": len(docs_only),
        "canonical_keys": sorted(merged),
        "docs_only": docs_only,
        "sources": source_receipts(raw),
    }


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    return json.loads(read_text(path))


def pinned_method_facts(raw: Path = RAW) -> dict[str, dict[str, Any]]:
    text = read_text(raw / "llms-full.txt")
    facts: dict[str, dict[str, Any]] = {}
    for heading in re.finditer(r"(?m)^# ([A-Za-z0-9_.]+) method$", text):
        end = text.find("\n# ", heading.end())
        body = text[heading.end():end if end >= 0 else len(text)]
        start = body.find("## Facts")
        end = body.find("## Arguments")
        if start < 0 or end <= start:
            continue
        body = body[start:end]
        scopes_start = body.find("**Scopes**")
        scopes_end = body.find("**Content types**")
        scopes_body = body[scopes_start:scopes_end] if scopes_start >= 0 and scopes_end > scopes_start else ""
        endpoint = re.search(r"(GET|POST|PUT|PATCH|DELETE) https://slack\.com/api/([A-Za-z0-9_.]+)", body)
        rate = re.search(r"\*\*Rate Limits\*\*\[([^\]]+)\]", body)
        item = {
            "token_types": sorted({value.lower() for value in re.findall(r"(?m)^(Bot|User|App-level|Configuration) token:", scopes_body)}),
            "scopes": sorted(set(re.findall(r"\[`([A-Za-z0-9_.:-]+)`\]\(https://docs\.slack\.dev/reference/scopes/", scopes_body))),
            "content_types": sorted(set(re.findall(r"`(application/[^`]+)`", body[scopes_end:] if scopes_end >= 0 else ""))),
            "rate_limit": rate.group(1) if rate else "",
        }
        if endpoint:
            item["http_method"] = endpoint.group(1)
        facts[canonical_key(heading.group(1))] = item
    return facts


def indexed_sdk_schema(schema: dict[str, Any]) -> dict[str, Any]:
    def index(node: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
        properties = dict(node.get("properties", {}))
        required = set(node.get("required", []))
        for kind in ("allOf", "anyOf", "oneOf"):
            branches = [index(branch) for branch in node.get(kind, [])]
            if branches:
                required.update(set.union(*(branch[1] for branch in branches)) if kind == "allOf" else set.intersection(*(branch[1] for branch in branches)))
            for child, _ in branches:
                for name, value in child.items():
                    if name in properties and properties[name] != value:
                        properties[name] = {"anyOf": [properties[name], value]}
                    else:
                        properties[name] = value
        return properties, required
    properties, required = index(schema)
    schema["type"] = "object"
    schema["properties"] = properties
    if required:
        schema["required"] = sorted(required)
    return schema


def enriched_catalog(raw: Path = RAW, catalog_path: Path = CATALOG_PATH) -> dict[str, Any]:
    catalog = load_catalog(catalog_path)
    facts = pinned_method_facts(raw)
    from slack_sdk_schema import TypeEnvironment
    sdk = TypeEnvironment(raw / "sdk")
    for method in catalog.get("methods", []):
        metadata = facts.get(canonical_key(method["name"]))
        if metadata is not None:
            method.update(metadata)
        if method["name"] in sdk.method_arguments:
            report = sdk.schema_for_method(method["name"])
            method["input_schema"] = indexed_sdk_schema(report["schema"])
            method["input_schema"]["x-comms-unresolved-sdk-types"] = report["unresolved"]
            method["sdk_argument_type"] = report["argument_type"]
            method["coverage"] = "sdk-schema"
    # Authentication comes from the installation vault, never caller parameters.
    for method in catalog["methods"]:
        schema = method.get("input_schema", {})
        schema.get("properties", {}).pop("token", None)
        if "required" in schema:
            schema["required"] = [name for name in schema["required"] if name != "token"]
    coverage = catalog["coverage"]
    coverage["sdk_schema_methods"] = sum(method["coverage"] == "sdk-schema" for method in catalog["methods"])
    coverage["openapi_schema_methods"] = sum(method["coverage"] in {"schema", "openapi-schema"} for method in catalog["methods"])
    coverage["sdk_source_files"] = len(list((raw / "sdk").rglob("*.ts")))
    coverage["schema_methods"] = coverage["sdk_schema_methods"] + coverage["openapi_schema_methods"]
    coverage["docs_only_methods"] = sum(method["coverage"] == "docs-only" for method in catalog["methods"])
    coverage["unresolved"] = [method["name"] for method in catalog["methods"] if method["coverage"] == "docs-only"]
    return catalog


def catalog_keys(catalog: dict[str, Any]) -> set[str]:
    keys = set()
    for method in catalog.get("methods", []):
        if not isinstance(method, dict):
            continue
        key = method.get("canonical_key") or method.get("name")
        if isinstance(key, str):
            keys.add(canonical_key(key))
    return keys


def validate_catalog(raw: Path = RAW, catalog_path: Path = CATALOG_PATH) -> dict[str, Any]:
    inventory = build_inventory(raw)
    catalog = load_catalog(catalog_path)
    embedded_keys = catalog_keys(catalog)
    raw_keys = set(inventory["canonical_keys"])
    methods = catalog.get("methods", [])
    coverage = catalog.get("coverage", {}) if isinstance(catalog.get("coverage"), dict) else {}
    bad_markdown = sorted(
        method.get("name")
        for method in methods
        if isinstance(method, dict) and isinstance(method.get("name"), str) and method["name"].endswith(".md")
    )
    by_name = {method.get("name"): method for method in methods if isinstance(method, dict)}
    chat = by_name.get("chat.postMessage", {})
    report = {
        "ok": not (raw_keys - embedded_keys or embedded_keys - raw_keys or bad_markdown),
        "inventory": {k: inventory[k] for k in ("method_count", "docs_method_count", "sdk_method_count", "openapi_method_count", "schema_method_count", "docs_only_method_count")},
        "embedded": {
            "method_count": len(methods),
            "schema_methods": coverage.get("schema_methods"),
            "sdk_schema_methods": coverage.get("sdk_schema_methods"),
            "openapi_schema_methods": coverage.get("openapi_schema_methods"),
            "docs_only_methods": coverage.get("docs_only_methods"),
            "docs_index_entries": coverage.get("docs_index_entries"),
        },
        "missing_from_embedded": sorted(raw_keys - embedded_keys),
        "extra_in_embedded": sorted(embedded_keys - raw_keys),
        "markdown_suffix_methods": bad_markdown,
        "stronger_schema_kept": chat.get("coverage") == "sdk-schema" and "channel" in chat.get("input_schema", {}).get("properties", {}),
    }
    facts = pinned_method_facts(raw)
    mismatches = []
    for method in methods:
        metadata = facts.get(canonical_key(method["name"]))
        if metadata is not None and any(method.get(key) != value for key, value in metadata.items()):
            mismatches.append(method["name"])
    report["metadata_mismatches"] = sorted(mismatches)
    report["ok"] = bool(report["ok"] and report["stronger_schema_kept"] and not mismatches)
    return report


def fetch_source_ops() -> list[dict[str, Any]]:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    ops: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    for url, path, kind in URLS:
        body, final_url, headers = fetch(url)
        ops.append({"op": "create", "path": path, "text": body.decode("utf-8", "replace"), "overwrite": True})
        sources.append(
            {
                "name": path.rsplit("/", 1)[1],
                "kind": kind,
                "url": url,
                "final_url": final_url,
                "fetched_at": now,
                "bytes": len(body),
                "sha256": sha256_bytes(body),
                "etag": headers.get("ETag"),
                "last_modified": headers.get("Last-Modified"),
            }
        )
    ops.append({"op": "create", "path": "docs/slack/source-manifest.json", "text": json.dumps({"generated_at": now, "sources": sources}, indent=2) + "\n", "overwrite": True})
    return ops


def catalog_ops() -> list[dict[str, Any]]:
    check = validate_catalog()
    if not check["ok"]:
        raise SystemExit(json.dumps(check, indent=2))
    return [
        {"op": "create", "path": "crates/comms-slack-api/data/catalog.json", "text": json.dumps(enriched_catalog(), indent=2, ensure_ascii=False) + "\n", "overwrite": True},
        {"op": "create", "path": "crates/comms-slack-api/data/docs_index.json", "text": read_text(DOCS_INDEX_PATH), "overwrite": True},
        {"op": "create", "path": "docs/slack/README.md", "text": read_text(README_PATH), "overwrite": True},
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ops", action="store_true", help="fetch live Slack docs snapshots and emit griz create ops")
    parser.add_argument("--inventory", action="store_true", help="print offline method inventory derived from docs/slack/raw")
    parser.add_argument("--catalog-check", action="store_true", help="validate embedded catalog against pinned raw docs/schema sources")
    parser.add_argument("--catalog-ops", action="store_true", help="validate then emit griz create ops for embedded catalog artifacts")
    args = parser.parse_args()

    if args.ops:
        print(json.dumps(fetch_source_ops(), indent=2))
        return 0
    if args.inventory:
        print(json.dumps(build_inventory(), indent=2, sort_keys=True))
        return 0
    if args.catalog_check:
        report = validate_catalog()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["ok"] else 1
    if args.catalog_ops:
        print(json.dumps(catalog_ops(), indent=2))
        return 0
    report = validate_catalog()
    print(json.dumps(report if report["ok"] else {"generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(), "sources": source_receipts(RAW)}, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
