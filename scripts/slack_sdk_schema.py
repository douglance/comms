#!/usr/bin/env python3
"""Derive Slack Web API input schemas from pinned node-slack-sdk request types.

This generator is deliberately offline. It reads docs/slack/raw/sdk snapshots and
prints structured JSON schemas; it does not mutate the embedded catalog.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SDK_RAW = ROOT / "docs/slack/raw/sdk"
METHODS_SNAPSHOT = SDK_RAW / "packages__web-api__src__methods.ts"
REQUEST_PREFIX = "packages__web-api__src__types__request__"
EXTERNAL_OBJECT_TYPES = {
    "AnyChunk",
    "Block",
    "EntityMetadata",
    "KnownBlock",
    "LinkUnfurls",
    "MessageAttachment",
    "MessageMetadata",
    "View",
}


@dataclass
class InterfaceDecl:
    name: str
    extends: list[str]
    body: str


@dataclass
class TypeDecl:
    name: str
    expr: str


class TypeEnvironment:
    def __init__(self, root: Path = SDK_RAW):
        self.root = root
        self.interfaces: dict[str, InterfaceDecl] = {}
        self.aliases: dict[str, TypeDecl] = {}
        self.method_arguments: dict[str, str] = {}
        self.unresolved: set[str] = set()
        self.source_files: list[str] = []
        self._load()

    def _load(self) -> None:
        if not METHODS_SNAPSHOT.exists():
            raise SystemExit(f"missing SDK methods snapshot: {METHODS_SNAPSHOT}")
        for path in sorted(self.root.glob("*.ts")):
            text = path.read_text()
            self.source_files.append(path.name)
            self._parse_declarations(text)
        self.method_arguments = parse_method_arguments(METHODS_SNAPSHOT.read_text())

    def _parse_declarations(self, text: str) -> None:
        clean = strip_comments(text)
        for match in re.finditer(r"(?:export\s+)?interface\s+(\w+)\s*([^\{]*)\{", clean):
            name = match.group(1)
            prefix = match.group(2) or ""
            body, _ = balanced(clean, match.end() - 1, "{", "}")
            extends: list[str] = []
            ext = re.search(r"extends\s+(.+)$", prefix.strip())
            if ext:
                extends = [part.strip() for part in split_top_level(ext.group(1), ",") if part.strip()]
            self.interfaces[name] = InterfaceDecl(name=name, extends=extends, body=body[1:-1])
        pos = 0
        while True:
            match = re.search(r"(?:export\s+)?type\s+(\w+)\s*=", clean[pos:])
            if not match:
                break
            name = match.group(1)
            start = pos + match.end()
            end = find_top_level_semicolon(clean, start)
            if end == -1:
                break
            self.aliases[name] = TypeDecl(name=name, expr=clean[start:end].strip())
            pos = end + 1

    def schema_for_method(self, method: str) -> dict[str, Any]:
        if method not in self.method_arguments:
            raise SystemExit(f"method {method!r} not found in SDK methods snapshot")
        self.unresolved.clear()
        argument_type = self.method_arguments[method]
        schema = self.resolve(argument_type, ())
        schema = prune_empty_allof(schema)
        return {
            "method": method,
            "argument_type": argument_type,
            "schema": schema,
            "unresolved": sorted(self.unresolved),
            "source_files": self.source_files,
        }

    def resolve(self, expr: str, seen: tuple[str, ...]) -> dict[str, Any]:
        expr = normalize_type(expr)
        if not expr:
            return true_schema()
        expr = strip_wrapping_parens(expr)
        if expr.startswith("typeof "):
            return true_schema()
        union = split_top_level(expr, "|")
        if len(union) > 1:
            literal_values = []
            schemas = []
            for part in union:
                part = part.strip()
                literal = literal_value(part)
                if literal is not None:
                    literal_values.append(literal)
                else:
                    schemas.append(self.resolve(part, seen))
            if literal_values and not schemas:
                return {"enum": literal_values}
            any_of = [{"const": value} for value in literal_values] + schemas
            return {"anyOf": [schema for schema in any_of if not is_never(schema)]}
        intersection = split_top_level(expr, "&")
        if len(intersection) > 1:
            parts = [self.resolve(part, seen) for part in intersection]
            parts = [part for part in parts if not is_empty_object_schema(part)]
            if not parts:
                return object_schema()
            if len(parts) == 1:
                return parts[0]
            return {"allOf": parts}
        if expr.startswith("[") and expr.endswith("]"):
            prefix = []
            minimum = 0
            rest = None
            for part in split_top_level(expr[1:-1], ","):
                part = part.strip()
                if not part:
                    continue
                if part.startswith("..."):
                    array = self.resolve(part[3:], seen)
                    rest = array.get("items", {})
                    break
                optional = part.endswith("?")
                prefix.append(self.resolve(part[:-1] if optional else part, seen))
                if not optional:
                    minimum += 1
            schema = {"type": "array", "prefixItems": prefix, "minItems": minimum}
            if rest is None:
                schema["maxItems"] = len(prefix)
                schema["items"] = False
            else:
                schema["items"] = rest
            return schema
        if expr.endswith("[]"):
            return {"type": "array", "items": self.resolve(expr[:-2], seen)}
        array_match = re.match(r"(?:ReadonlyArray|Array)<(.+)>", expr)
        if array_match:
            return {"type": "array", "items": self.resolve(array_match.group(1), seen)}
        partial = generic_arg(expr, "Partial")
        if partial is not None:
            return make_partial(self.resolve(partial, seen))
        pick = generic_args(expr, "Pick")
        if pick:
            base = self.resolve(pick[0], seen)
            keys = [v for v in literal_union_values(pick[1]) if isinstance(v, str)]
            return pick_properties(base, keys)
        omit = generic_args(expr, "Omit")
        if omit:
            base = self.resolve(omit[0], seen)
            keys = [v for v in literal_union_values(omit[1]) if isinstance(v, str)]
            return omit_properties(base, keys)
        if expr in {"string", "String"}:
            return {"type": "string"}
        if expr in {"number", "Number"}:
            return {"type": "number"}
        if expr in {"boolean", "Boolean"}:
            return {"type": "boolean"}
        if expr in {"object", "Record<string, unknown>", "Record<string, any>", "JsonObject"}:
            return object_schema(additional=True)
        if expr in {"unknown", "any", "undefined", "null"}:
            return true_schema()
        if expr == "never":
            return {"not": {}}
        literal = literal_value(expr)
        if literal is not None:
            return {"const": literal}
        if expr.startswith("{") and expr.endswith("}"):
            return self.object_from_body(expr[1:-1], seen)
        name = re.sub(r"<.*>$", "", expr).strip()
        if name in seen:
            return object_schema(additional=True, note=f"recursive:{name}")
        if name in {"KnownBlock", "View"}:
            self.unresolved.add(name)
            return object_schema(additional=True, note=f"shared:{name}")
        if name in self.interfaces:
            return self.interface_schema(self.interfaces[name], seen + (name,))
        if name in self.aliases:
            return self.resolve(self.aliases[name].expr, seen + (name,))
        if name in EXTERNAL_OBJECT_TYPES:
            return object_schema(additional=True, note=name)
        self.unresolved.add(name)
        return object_schema(additional=True, note=f"unresolved:{name}")

    def interface_schema(self, decl: InterfaceDecl, seen: tuple[str, ...]) -> dict[str, Any]:
        parts = [self.resolve(base, seen) for base in decl.extends]
        own = self.object_from_body(decl.body, seen)
        if not is_empty_object_schema(own):
            parts.append(own)
        parts = [part for part in parts if not is_empty_object_schema(part)]
        if not parts:
            return object_schema()
        if len(parts) == 1:
            return parts[0]
        return {"allOf": parts}

    def object_from_body(self, body: str, seen: tuple[str, ...]) -> dict[str, Any]:
        properties: dict[str, Any] = {}
        required: list[str] = []
        additional: bool | dict[str, Any] = True
        for member in split_members(body):
            member = member.strip()
            if not member:
                continue
            if member.startswith("["):
                idx = re.match(r"\[[^\]]+\]\s*:\s*(.+)$", member, flags=re.S)
                if idx:
                    additional = self.resolve(idx.group(1), seen)
                continue
            prop = re.match(r"(?:readonly\s+)?(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z_$][\w$-]*))(\?)?\s*:\s*(.+)$", member, flags=re.S)
            if not prop:
                continue
            name = prop.group(1) or prop.group(2) or prop.group(3)
            if name == "token":
                continue
            optional = bool(prop.group(4))
            properties[name] = self.resolve(prop.group(5).strip(), seen)
            if not optional:
                required.append(name)
        schema = object_schema(additional=additional)
        if properties:
            schema["properties"] = properties
        if required:
            schema["required"] = sorted(set(required))
        return schema


def parse_method_arguments(text: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    pattern = re.compile(r"bindApiCall\s*<\s*(\w+)\s*,\s*\w+\s*>\s*\((.*?)\)", re.S)
    for match in pattern.finditer(text):
        args = match.group(2)
        method = re.search(r"['\"]([a-zA-Z0-9_.]+)['\"]", args)
        if method:
            mapping[method.group(1)] = match.group(1)
    return mapping


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text


def balanced(text: str, start: int, open_ch: str, close_ch: str) -> tuple[str, int]:
    depth = 0
    quote: str | None = None
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if char == quote and text[index - 1] != "\\":
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == open_ch:
            depth += 1
        elif char == close_ch:
            depth -= 1
            if depth == 0:
                return text[start : index + 1], index + 1
    raise ValueError(f"unbalanced {open_ch}{close_ch}")


def find_top_level_semicolon(text: str, start: int) -> int:
    depth = {"<": 0, "(": 0, "{": 0, "[": 0}
    quote: str | None = None
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            if ch == quote and text[i - 1] != "\\":
                quote = None
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            continue
        if ch in "<({[":
            depth[ch] += 1
        elif ch == ">" and depth["<"]:
            depth["<"] -= 1
        elif ch == ")" and depth["("]:
            depth["("] -= 1
        elif ch == "}" and depth["{"]:
            depth["{"] -= 1
        elif ch == "]" and depth["["]:
            depth["["] -= 1
        elif ch == ";" and not any(depth.values()):
            return i
    return -1


def split_top_level(text: str, sep: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = {"<": 0, "(": 0, "{": 0, "[": 0}
    quote: str | None = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote and text[i - 1] != "\\":
                quote = None
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            continue
        if ch in "<({[":
            depth[ch] += 1
        elif ch == ">" and depth["<"]:
            depth["<"] -= 1
        elif ch == ")" and depth["("]:
            depth["("] -= 1
        elif ch == "}" and depth["{"]:
            depth["{"] -= 1
        elif ch == "]" and depth["["]:
            depth["["] -= 1
        elif ch == sep and not any(depth.values()):
            parts.append(text[start:i].strip())
            start = i + 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def split_members(body: str) -> list[str]:
    members: list[str] = []
    start = 0
    depth = {"<": 0, "(": 0, "{": 0, "[": 0}
    quote: str | None = None
    for i, ch in enumerate(body):
        if quote:
            if ch == quote and body[i - 1] != "\\":
                quote = None
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            continue
        if ch in "<({[":
            depth[ch] += 1
        elif ch == ">" and depth["<"]:
            depth["<"] -= 1
        elif ch == ")" and depth["("]:
            depth["("] -= 1
        elif ch == "}" and depth["{"]:
            depth["{"] -= 1
        elif ch == "]" and depth["["]:
            depth["["] -= 1
        elif ch in ";\n" and not any(depth.values()):
            item = body[start:i].strip().rstrip(",")
            if item:
                members.append(item)
            start = i + 1
    tail = body[start:].strip().rstrip(",")
    if tail:
        members.append(tail)
    return members


def normalize_type(expr: str) -> str:
    expr = re.sub(r"\s+", " ", expr.strip())
    expr = expr.replace("readonly ", "")
    return expr.strip()


def strip_wrapping_parens(expr: str) -> str:
    while expr.startswith("(") and expr.endswith(")"):
        try:
            body, end = balanced(expr, 0, "(", ")")
        except ValueError:
            return expr
        if end == len(expr):
            expr = body[1:-1].strip()
        else:
            return expr
    return expr


def generic_arg(expr: str, name: str) -> str | None:
    args = generic_args(expr, name)
    return args[0] if args and len(args) == 1 else None


def generic_args(expr: str, name: str) -> list[str] | None:
    prefix = f"{name}<"
    if not expr.startswith(prefix) or not expr.endswith(">"):
        return None
    return split_top_level(expr[len(prefix) : -1], ",")


def literal_value(expr: str) -> Any | None:
    expr = expr.strip()
    if len(expr) >= 2 and expr[0] == expr[-1] and expr[0] in {"'", '"'}:
        return expr[1:-1]
    if expr == "true":
        return True
    if expr == "false":
        return False
    return None


def literal_union_values(expr: str) -> list[Any]:
    return [literal_value(part) for part in split_top_level(expr, "|") if literal_value(part) is not None]


def object_schema(*, additional: bool | dict[str, Any] = True, note: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "additionalProperties": additional}
    if note:
        schema["x-slack-sdk-type"] = note
    return schema


def true_schema() -> dict[str, Any]:
    return {}


def is_never(schema: dict[str, Any]) -> bool:
    return schema == {"not": {}}


def is_empty_object_schema(schema: dict[str, Any]) -> bool:
    return schema == {} or (
        schema.get("type") == "object"
        and schema.get("additionalProperties") in (False, True, None)
        and not schema.get("properties")
        and not schema.get("required")
        and "x-slack-sdk-type" not in schema
    )


def make_partial(schema: dict[str, Any]) -> dict[str, Any]:
    schema = json.loads(json.dumps(schema))
    if schema.get("type") == "object":
        schema.pop("required", None)
    for key in ("allOf", "anyOf", "oneOf"):
        if key in schema:
            schema[key] = [make_partial(item) for item in schema[key]]
    return schema


def pick_properties(schema: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    schema = flatten_simple_allof(schema)
    props = schema.get("properties", {}) if isinstance(schema.get("properties"), dict) else {}
    out = object_schema()
    out["properties"] = {key: props[key] for key in keys if key in props}
    required = [key for key in schema.get("required", []) if key in out["properties"]]
    if required:
        out["required"] = required
    return out


def omit_properties(schema: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    schema = flatten_simple_allof(schema)
    props = dict(schema.get("properties", {})) if isinstance(schema.get("properties"), dict) else {}
    for key in keys:
        props.pop(key, None)
    schema["properties"] = props
    if "required" in schema:
        schema["required"] = [key for key in schema["required"] if key not in keys]
    return schema


def flatten_simple_allof(schema: dict[str, Any]) -> dict[str, Any]:
    if "allOf" not in schema:
        return schema
    merged = object_schema()
    for part in schema["allOf"]:
        if part.get("type") != "object":
            return schema
        merged.setdefault("properties", {}).update(part.get("properties", {}))
        if part.get("required"):
            merged.setdefault("required", []).extend(part["required"])
    if "required" in merged:
        merged["required"] = sorted(set(merged["required"]))
    return merged


def prune_empty_allof(schema: dict[str, Any]) -> dict[str, Any]:
    if isinstance(schema, dict):
        for key in list(schema):
            if isinstance(schema[key], dict):
                schema[key] = prune_empty_allof(schema[key])
            elif isinstance(schema[key], list):
                schema[key] = [prune_empty_allof(item) if isinstance(item, dict) else item for item in schema[key]]
        if "allOf" in schema:
            schema["allOf"] = [item for item in schema["allOf"] if not is_empty_object_schema(item)]
            if len(schema["allOf"]) == 1:
                return schema["allOf"][0]
    return schema


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--method")
    group.add_argument("--all", action="store_true")
    group.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)
    env = TypeEnvironment()
    if args.summary:
        print(json.dumps({"source_files": env.source_files, "method_count": len(env.method_arguments)}, indent=2, sort_keys=True))
    elif args.all:
        print(json.dumps({method: env.schema_for_method(method) for method in sorted(env.method_arguments)}, indent=2, sort_keys=True))
    else:
        print(json.dumps(env.schema_for_method(args.method), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
