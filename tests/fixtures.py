#!/usr/bin/env python3
"""Local Cloudflare Access fixture for comms integration tests.

The server keeps its RSA private key only in process memory. It emits a JWKS at
/certs and mints local-only Access-style JWTs at /token. It also offers a tiny
owner-login reverse proxy that adds the signed Access header so browser-based
checks can exercise the Worker's real owner confirmation HTML without a live
Cloudflare Access prompt.
"""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import json
import secrets
import threading
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_EMAIL = "owner@example.com"
DEFAULT_AUD = "comms-local-tests"
ISSUER = "https://fixture.cloudflareaccess.com"
KID = "comms-local-test-key"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

SLACK_FIXTURE_TEAM_ID = "TEXAMPLE"
SLACK_FIXTURE_OWNER_ID = "UEXAMPLE"
SLACK_FIXTURE_BOT_USER_ID = "B_FIXTURE"
SLACK_FIXTURE_BOT_TOKEN = "xoxb-fixture-bot"
SLACK_FIXTURE_USER_TOKEN = "xoxp-fixture-owner"
SLACK_FIXTURE_SIGNING_SECRET = "com-slack-fixture-secret"
_SLACK_LOCK = threading.Lock()
_SLACK_COUNTERS: collections.Counter[str] = collections.Counter()
_SLACK_MESSAGES: list[dict[str, Any]] = []
_SLACK_REST_REQUESTS: list[dict[str, Any]] = []
_SLACK_UPLOADS: dict[str, dict[str, Any]] = {}
_SLACK_CHANNELS: dict[str, dict[str, Any]] = {
    "D_OWNER": {"id": "D_OWNER", "name": "owner-dm", "is_im": True},
    "C_GENERAL": {"id": "C_GENERAL", "name": "general", "is_channel": True},
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(length, "big"))


def jwks() -> dict[str, Any]:
    numbers = _KEY.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": KID,
                "alg": "RS256",
                "use": "sig",
                "n": _int_b64(numbers.n),
                "e": _int_b64(numbers.e),
            }
        ]
    }


def mint_token(email: str = DEFAULT_EMAIL, aud: str = DEFAULT_AUD, exp: int | None = None, nbf: int | None = None) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    payload = {
        "iss": ISSUER,
        "aud": aud,
        "email": email,
        "iat": now,
        "nbf": now if nbf is None else nbf,
        "exp": now + 600 if exp is None else exp,
    }
    signing_input = ".".join(
        [
            _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ]
    )
    signature = _KEY.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "comms-access-fixture/1"

    def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover - keeps secrets out of logs.
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/certs":
            self._json(HTTPStatus.OK, jwks())
            return
        if parsed.path == "/token":
            query = urllib.parse.parse_qs(parsed.query)
            email = _one(query, "email", DEFAULT_EMAIL)
            aud = _one(query, "aud", DEFAULT_AUD)
            exp_text = _one(query, "exp", "")
            nbf_text = _one(query, "nbf", "")
            exp = int(exp_text) if exp_text else None
            nbf = int(nbf_text) if nbf_text else None
            self._json(HTTPStatus.OK, {"token": mint_token(email=email, aud=aud, exp=exp, nbf=nbf)})
            return
        if parsed.path == "/owner/login":
            self._proxy_owner(parsed, method="GET", body=b"")
            return
        if parsed.path in {"/api/_fixture/metadata", "/_fixture/slack"}:
            self._json(HTTPStatus.OK, _slack_metadata())
            return
        if parsed.path.startswith("/api/"):
            self._slack_api(parsed)
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/_fixture/reset":
            self._slack_reset()
            return
        if parsed.path.startswith("/api/"):
            self._slack_api(parsed)
            return
        if parsed.path == "/owner/approve":
            length = int(self.headers.get("content-length", "0") or "0")
            body = self.rfile.read(length)
            self._proxy_owner(parsed, method="POST", body=body)
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    do_PATCH = do_POST
    do_PUT = do_POST
    do_DELETE = do_POST

    def _slack_reset(self) -> None:
        with _SLACK_LOCK:
            _SLACK_COUNTERS.clear()
            _SLACK_MESSAGES.clear()
            _SLACK_REST_REQUESTS.clear()
            _SLACK_UPLOADS.clear()
            _SLACK_CHANNELS.clear()
            _SLACK_CHANNELS.update(
                {
                    "D_OWNER": {"id": "D_OWNER", "name": "owner-dm", "is_im": True},
                    "C_GENERAL": {"id": "C_GENERAL", "name": "general", "is_channel": True},
                }
            )
        self._json(HTTPStatus.OK, {"ok": True})

    def _slack_api(self, parsed: urllib.parse.ParseResult) -> None:
        length = int(self.headers.get("content-length", "0") or "0")
        raw = self.rfile.read(length)
        method = parsed.path.removeprefix("/api/")
        if method.startswith("files/upload/"):
            file_id = method.removeprefix("files/upload/")
            with _SLACK_LOCK:
                _SLACK_COUNTERS["files.upload.transfer"] += 1
                record = _SLACK_UPLOADS.get(file_id)
                if record is not None:
                    record["transferred_bytes"] = len(raw)
                    record["sha256"] = hashlib.sha256(raw).hexdigest()
                    record["transfer_authorization"] = self.headers.get("authorization")
                    record["transferred"] = len(raw) == record["length"]
            status = 503 if record and record["filename"] == "fixture-transfer-failure" else (200 if record and record["transferred"] else 400)
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            return
        payload = _slack_payload(raw, self.headers.get("content-type", ""))
        if parsed.query:
            query_payload = {
                key: values[-1] if values else ""
                for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()
            }
            query_payload.update(payload)
            payload = query_payload
        if method == "files.getUploadURLExternal":
            file_id = "F_FIXTURE_" + secrets.token_hex(6)
            with _SLACK_LOCK:
                _SLACK_COUNTERS[method] += 1
                _SLACK_UPLOADS[file_id] = {"id": file_id, "filename": payload["filename"], "length": int(payload["length"]), "get_params": payload, "transferred": False, "completed": False}
            host, port = self.server.server_address
            url = f"http://{host}:{port}/api/files/upload/{file_id}"
            if payload["filename"] == "fixture-untrusted-url":
                url = "https://attacker.invalid/upload/" + file_id
            self._json(HTTPStatus.OK, {"ok": True, "file_id": file_id, "upload_url": url})
            return
        if method == "files.completeUploadExternal":
            files = payload.get("files", [])
            with _SLACK_LOCK:
                _SLACK_COUNTERS[method] += 1
                valid = bool(files) and all(item.get("id") in _SLACK_UPLOADS and _SLACK_UPLOADS[item["id"]]["transferred"] and not _SLACK_UPLOADS[item["id"]]["completed"] for item in files)
                if valid:
                    for item in files:
                        _SLACK_UPLOADS[item["id"]]["completed"] = True
                        _SLACK_UPLOADS[item["id"]]["complete_params"] = payload
            self._json(HTTPStatus.OK, {"ok": valid, "files": files} if valid else {"ok": False, "error": "invalid_upload_state"})
            return
        if method == "admin.analytics.getFile" or (method == "search.messages" and payload.get("query") == "fixture-binary-search"):
            with _SLACK_LOCK:
                _SLACK_COUNTERS[method] += 1
            if payload.get("date") == "1900-01-01":
                self._json(HTTPStatus.OK, {"ok": False, "error": "invalid_date"})
                return
            import gzip
            body = gzip.compress(b'{"date":"2026-10-06","user_id":"U_TEST","messages_posted_count":7}\n', mtime=0)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Disposition", 'attachment; filename="fixture-analytics.json.gz"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method.startswith(("scim/", "audit/", "status/", "admin.legalHold.")):
            with _SLACK_LOCK:
                _SLACK_COUNTERS[method] += 1
                _SLACK_REST_REQUESTS.append({
                    "path": method, "verb": self.command, "params": payload,
                    "authorization": self.headers.get("authorization"),
                    "content_type": self.headers.get("content-type"),
                })
            if method.startswith("status/"):
                if self.command != "GET" or self.headers.get("authorization"):
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "status_must_be_public_get"})
                elif method.endswith("/history"):
                    self._json(HTTPStatus.OK, [{"id": "incident-1", "status": "resolved"}])
                else:
                    self._json(HTTPStatus.OK, {"status": "ok", "active_incidents": []})
            elif method.startswith("admin.legalHold."):
                if self.command != "POST" or self.headers.get("content-type") != "application/x-www-form-urlencoded":
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "legal_hold_requires_form_post"})
                else:
                    self._json(HTTPStatus.OK, {"ok": True, "received": payload})
            elif method.startswith("audit/"):
                if self.command != "GET":
                    self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "wrong_verb"})
                else:
                    self._json(HTTPStatus.OK, {"entries": [], "response_metadata": {"next_cursor": ""}})
            elif self.command == "DELETE":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._json(HTTPStatus.OK, {"id": "U_REST", "received": payload})
            return
        status, body = _slack_response(method, payload)
        self._json(status, body)

    def _proxy_owner(self, parsed: urllib.parse.ParseResult, method: str, body: bytes) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        worker = _one(query, "worker", "http://127.0.0.1:9411").rstrip("/")
        if not _is_loopback(worker):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "worker_must_be_loopback"})
            return
        token = mint_token()
        target_path = parsed.path
        forward_query = [(key, value) for key, values in query.items() if key != "worker" for value in values]
        target = f"{worker}{target_path}"
        if forward_query:
            target = f"{target}?{urllib.parse.urlencode(forward_query)}"
        headers = {"Cf-Access-Jwt-Assertion": token, "Origin": worker}
        content_type = self.headers.get("content-type")
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(target, data=body if method == "POST" else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                self._copy_response(response.status, response.headers, response.read())
        except urllib.error.HTTPError as error:
            self._copy_response(error.code, error.headers, error.read())
        except urllib.error.URLError:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": "worker_unreachable"})

    def _copy_response(self, status: int, headers: Any, body: bytes) -> None:
        self.send_response(status)
        for name, value in headers.items():
            lower = name.lower()
            if lower in {"connection", "content-length", "transfer-encoding"}:
                continue
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _slack_payload(raw: bytes, content_type: str) -> dict[str, Any]:
    if not raw:
        return {}
    if "application/json" in content_type:
        try:
            parsed = json.loads(raw.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
    form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    payload: dict[str, Any] = {key: values[-1] if values else "" for key, values in form.items()}
    if isinstance(payload.get("payload"), str):
        try:
            nested = json.loads(str(payload["payload"]))
            if isinstance(nested, dict):
                payload["payload_json"] = nested
        except json.JSONDecodeError:
            pass
    return payload

def _slack_metadata() -> dict[str, Any]:
    with _SLACK_LOCK:
        return {
            "ok": True,
            "team_id": SLACK_FIXTURE_TEAM_ID,
            "owner_user_id": SLACK_FIXTURE_OWNER_ID,
            "bot_user_id": SLACK_FIXTURE_BOT_USER_ID,
            "signing_secret": SLACK_FIXTURE_SIGNING_SECRET,
            "counters": dict(_SLACK_COUNTERS),
            "channels": list(_SLACK_CHANNELS.values()),
            "messages": list(_SLACK_MESSAGES),
            "rest_requests": list(_SLACK_REST_REQUESTS),
            "uploads": list(_SLACK_UPLOADS.values()),
        }

def _slack_response(method: str, payload: dict[str, Any]) -> tuple[HTTPStatus, dict[str, Any]]:
    with _SLACK_LOCK:
        _SLACK_COUNTERS[method] += 1
        if method == "oauth.v2.access":
            return HTTPStatus.OK, {
                "ok": True,
                "access_token": SLACK_FIXTURE_BOT_TOKEN,
                "token_type": "bot",
                "bot_user_id": SLACK_FIXTURE_BOT_USER_ID,
                "scope": "app_mentions:read,channels:history,channels:manage,channels:read,chat:write,commands,emoji:read,groups:history,im:history,im:write,mpim:history,reactions:write,search:read,users:read",
                "team": {"id": "T_WRONG" if payload.get("code") == "fixture-wrong-team" else SLACK_FIXTURE_TEAM_ID, "name": "fixture-team"},
                "authed_user": {"id": "U_WRONG" if payload.get("code") == "fixture-wrong-user" else SLACK_FIXTURE_OWNER_ID, "access_token": SLACK_FIXTURE_USER_TOKEN, "scope": "channels:history,groups:history,im:history,mpim:history,search:read.public,search:read.private,search:read.im"},
            }
        if method == "conversations.open":
            return HTTPStatus.OK, {"ok": True, "channel": {"id": "D_OWNER", "is_im": True}}
        if method == "chat.postMessage":
            channel = str(payload.get("channel") or "D_OWNER")
            ts = f"{time.time_ns() // 1000000000}.{time.time_ns() % 1000000000 // 1000:06d}"
            message = {
                "type": "message",
                "channel": channel,
                "ts": ts,
                "thread_ts": str(payload.get("thread_ts") or ts),
                "text": str(payload.get("text") or ""),
                "blocks": payload.get("blocks"),
                "metadata": payload.get("metadata"),
                "username": payload.get("username"),
                "icon_emoji": payload.get("icon_emoji"),
                "icon_url": payload.get("icon_url"),
            }
            _SLACK_MESSAGES.append(message)
            return HTTPStatus.OK, {"ok": True, "channel": channel, "ts": ts, "message": message}
        if method == "agents.sessions.setStatus":
            _SLACK_REST_REQUESTS.append({"method": method, "params": payload})
            return HTTPStatus.OK, {"ok": True, "status": payload.get("status"), "agent_status": payload.get("status")}
        if method == "chat.update":
            channel = str(payload.get("channel") or "")
            ts = str(payload.get("ts") or "")
            for message in _SLACK_MESSAGES:
                if message.get("channel") == channel and message.get("ts") == ts:
                    if "text" in payload:
                        message["text"] = str(payload.get("text") or "")
                    if "blocks" in payload:
                        message["blocks"] = payload.get("blocks")
                    return HTTPStatus.OK, {"ok": True, "channel": channel, "ts": ts, "message": message}
            return HTTPStatus.OK, {"ok": False, "error": "message_not_found"}
        if method == "conversations.create":
            name = str(payload.get("name") or f"fixture-{secrets.token_hex(3)}")
            channel_id = "C" + secrets.token_hex(5).upper()
            channel = {"id": channel_id, "name": name, "is_channel": True, "is_private": str(payload.get("is_private")).lower() == "true", "members": []}
            _SLACK_CHANNELS[channel_id] = channel
            return HTTPStatus.OK, {"ok": True, "channel": channel}
        if method == "conversations.invite":
            channel = str(payload.get("channel") or "")
            record = _SLACK_CHANNELS.get(channel, {"id": channel})
            record.setdefault("members", []).extend(str(payload.get("users", "")).split(","))
            return HTTPStatus.OK, {"ok": True, "channel": record}
        if method == "conversations.history":
            channel = str(payload.get("channel") or "")
            messages = [message for message in reversed(_SLACK_MESSAGES) if not channel or message.get("channel") == channel]
            return HTTPStatus.OK, {"ok": True, "messages": messages, "has_more": False}
        if method in {"search.messages", "search.query"}:
            query = str(payload.get("query") or "").lower()
            matches = [message for message in _SLACK_MESSAGES if query in str(message.get("text", "")).lower()]
            return HTTPStatus.OK, {"ok": True, "query": query, "messages": {"matches": matches, "pagination": {"total_count": len(matches)}}}
        if method == "assistant.search.context":
            query = str(payload.get("query") or "")
            return HTTPStatus.OK, {"ok": True, "query": query, "results": [{"source": "fixture", "text": message.get("text", ""), "channel": message.get("channel")} for message in _SLACK_MESSAGES if query.casefold() in str(message.get("text", "")).casefold()][-5:]}
        return HTTPStatus.OK, {"ok": False, "error": "unsupported_fixture_method", "method": method}

def _one(query: dict[str, list[str]], name: str, default: str) -> str:
    values = query.get(name)
    return values[0] if values else default


def _is_loopback(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.hostname in {"127.0.0.1", "localhost", "::1"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9412)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("fixture only binds loopback hosts")
    server = ThreadingHTTPServer((args.host, args.port), FixtureHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
