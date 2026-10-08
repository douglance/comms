#!/usr/bin/env python3
"""Adversarial black-box integration tests for the local comms Worker.

Run after the parent has started the Access fixture on 127.0.0.1:9412 and the
Wrangler Worker on 127.0.0.1:9411, for example:

    python3 tests/integration.py --url http://127.0.0.1:9411

The tests intentionally avoid printing bearer tokens, owner invitations, or raw
media. Failure messages name the request surface and safe status/error metadata.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import select
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

DEFAULT_URL = "http://127.0.0.1:9411"
DEFAULT_FIXTURE_URL = "http://127.0.0.1:9412"
OWNER_EMAIL = "owner@example.com"
ACCESS_AUD = "comms-local-tests"


@dataclass
class HttpResult:
    method: str
    path: str
    status: int
    headers: dict[str, str]
    body: bytes
    json: Any | None

    @property
    def error_code(self) -> str:
        value = self.json
        if isinstance(value, dict):
            error = value.get("error")
            if isinstance(error, dict) and isinstance(error.get("code"), str):
                return error["code"]
            if isinstance(value.get("code"), str):
                return value["code"]
        return ""

    @property
    def safe_meta(self) -> str:
        keys = sorted(self.json.keys()) if isinstance(self.json, dict) else []
        code = self.error_code or "none"
        return f"{self.method} {self.path} status={self.status} code={code} keys={keys}"


class CommsClient:
    def __init__(self, base_url: str, fixture_url: str):
        self.base_url = base_url.rstrip("/")
        self.fixture_url = fixture_url.rstrip("/")

    def access_token(self, *, email: str = OWNER_EMAIL, aud: str = ACCESS_AUD, exp: int | None = None, nbf: int | None = None) -> str:
        query = {"email": email, "aud": aud}
        if exp is not None:
            query["exp"] = str(exp)
        if nbf is not None:
            query["nbf"] = str(nbf)
        result = self.request_url(f"{self.fixture_url}/token?{urllib.parse.urlencode(query)}", method="GET")
        self.assert_status(result, 200)
        assert isinstance(result.json, dict), result.safe_meta
        return result.json["token"]

    def request(self, method: str, path: str, body: Any | bytes | None = None, *, bearer: str | None = None,
                access_jwt: str | None = None, headers: dict[str, str] | None = None) -> HttpResult:
        return self.request_url(f"{self.base_url}{path}", method=method, body=body, bearer=bearer, access_jwt=access_jwt, headers=headers, path=path)

    def request_url(self, url: str, method: str, body: Any | bytes | None = None, *, bearer: str | None = None,
                    access_jwt: str | None = None, headers: dict[str, str] | None = None, path: str | None = None) -> HttpResult:
        request_headers = dict(headers or {})
        data: bytes | None
        if isinstance(body, bytes):
            data = body
        elif body is None:
            data = None
        else:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        if bearer is not None:
            request_headers["Authorization"] = f"Bearer {bearer}"
        if access_jwt is not None:
            request_headers["Cf-Access-Jwt-Assertion"] = access_jwt
        req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                raw = response.read()
                return self._result(method, path or urllib.parse.urlparse(url).path, response.status, response.headers, raw)
        except urllib.error.HTTPError as error:
            try:
                raw = error.read()
                return self._result(method, path or urllib.parse.urlparse(url).path, error.code, error.headers, raw)
            finally:
                error.close()

    def _result(self, method: str, path: str, status: int, headers: Any, raw: bytes) -> HttpResult:
        parsed = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                try:
                    text = raw.decode("utf-8")
                    for line in text.splitlines():
                        if line.startswith("data: "):
                            parsed = json.loads(line[6:])
                            break
                except (UnicodeDecodeError, json.JSONDecodeError):
                    parsed = None
        return HttpResult(method, path, status, {k.lower(): v for k, v in headers.items()}, raw, parsed)

    @staticmethod
    def assert_status(result: HttpResult, expected: int | set[int]) -> None:
        allowed = {expected} if isinstance(expected, int) else expected
        assert result.status in allowed, f"unexpected status: {result.safe_meta}; expected={sorted(allowed)}"


def coerce_data(result: HttpResult) -> Any:
    if isinstance(result.json, dict) and result.json.get("ok") is True and "data" in result.json:
        return result.json["data"]
    return result.json


def assert_success_envelope(test: unittest.TestCase, result: HttpResult) -> Any:
    test.assertEqual(result.status, 200, result.safe_meta)
    test.assertIsInstance(result.json, dict, result.safe_meta)
    test.assertTrue(result.json.get("ok"), result.safe_meta)
    test.assertIn("data", result.json, result.safe_meta)
    return result.json["data"]


def is_success(result: HttpResult) -> bool:
    if isinstance(result.json, dict) and "ok" in result.json:
        return result.status < 400 and result.json.get("ok") is True
    return 200 <= result.status < 300


def rows_of(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        return data["rows"]
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        results = data["results"]
        if not results:
            return []
        first = results[0]
        if isinstance(first, dict) and isinstance(first.get("rows"), list):
            return first["rows"]
        if all(isinstance(row, dict) for row in results):
            return results
    if isinstance(data, list) and all(isinstance(row, dict) for row in data):
        return data
    return []


def unique_name(prefix: str) -> str:
    return f"it_{prefix}_{int(time.time() * 1000)}_{secrets.token_hex(4)}"


class CommsIntegrationTest(unittest.TestCase):
    client: CommsClient
    cli: str | None

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = CommsClient(ARGS.url, ARGS.fixture_url)
        cls.cli = ARGS.cli if ARGS.cli and os.path.exists(ARGS.cli) else None
        health = cls.client.request("GET", "/health")
        if health.status != 200:
            raise unittest.SkipTest(f"Worker is not ready at {ARGS.url}: {health.safe_meta}")
        certs = cls.client.request_url(f"{ARGS.fixture_url}/certs", method="GET")
        if certs.status != 200:
            raise unittest.SkipTest(f"Access fixture is not ready at {ARGS.fixture_url}: {certs.safe_meta}")

    def start_device(self) -> dict[str, Any]:
        result = self.client.request("POST", "/auth/start", {})
        self.client.assert_status(result, 200)
        data = coerce_data(result)
        self.assertIsInstance(data, dict, result.safe_meta)
        for key in ["device_code", "user_code", "verification_uri", "expires_at"]:
            self.assertIn(key, data, result.safe_meta)
        return data

    def approve_device(self, user_code: str, *, allow_legacy_code_field: bool = True) -> HttpResult:
        token = self.client.access_token()
        result = self.client.request(
            "POST",
            "/owner/approve",
            {"user_code": user_code},
            access_jwt=token,
            headers={"Origin": self.client.base_url},
        )
        if result.status != 200 and allow_legacy_code_field:
            result = self.client.request(
                "POST",
                "/owner/approve",
                {"code": user_code},
                access_jwt=token,
                headers={"Origin": self.client.base_url},
            )
        return result

    def owner_token(self) -> str:
        started = self.start_device()
        approve = self.approve_device(started["user_code"])
        self.client.assert_status(approve, 200)
        poll = self.client.request("POST", "/auth/poll", {"device_code": started["device_code"]})
        self.client.assert_status(poll, 200)
        data = coerce_data(poll)
        self.assertIsInstance(data, dict, poll.safe_meta)
        self.assertIn("owner_token", data, poll.safe_meta)
        return data["owner_token"]

    def invite(self, owner_token: str, *, label: str = "agent", ttl_seconds: int = 60) -> str:
        result = self.client.request("POST", "/owner/invite", {"label": label, "ttl_seconds": ttl_seconds}, bearer=owner_token)
        self.client.assert_status(result, 200)
        data = coerce_data(result)
        self.assertIsInstance(data, dict, result.safe_meta)
        self.assertIn("invitation", data, result.safe_meta)
        return data["invitation"]

    def join(self, invitation: str, *, label: str | None = None) -> tuple[str, str]:
        body: dict[str, Any] = {"invitation": invitation}
        if label is not None:
            body["label"] = label
        result = self.client.request("POST", "/agent/join", body)
        self.client.assert_status(result, 200)
        data = coerce_data(result)
        self.assertIsInstance(data, dict, result.safe_meta)
        self.assertIn("agent_id", data, result.safe_meta)
        self.assertIn("token", data, result.safe_meta)
        return data["agent_id"], data["token"]

    def enroll_agent(self, owner_token: str | None = None, *, label: str = "agent", ttl_seconds: int = 60) -> tuple[str, str, str]:
        owner = owner_token or self.owner_token()
        invitation = self.invite(owner, label=label, ttl_seconds=ttl_seconds)
        agent_id, token = self.join(invitation, label=label)
        return owner, agent_id, token

    def sql(self, token: str, sql: str, params: list[Any] | None = None, *, status: int | set[int] = 200) -> HttpResult:
        result = self.client.request("POST", "/api/sql", {"sql": sql, "params": [] if params is None else params}, bearer=token)
        self.client.assert_status(result, status)
        return result

    def test_auth_start_uses_success_envelope(self) -> None:
        result = self.client.request("POST", "/auth/start", {})
        data = assert_success_envelope(self, result)
        self.assertIn("device_code", data)
        self.assertIn("user_code", data)

    def test_owner_approve_accepts_user_code_field(self) -> None:
        started = self.start_device()
        result = self.approve_device(started["user_code"], allow_legacy_code_field=False)
        self.client.assert_status(result, 200)
        poll = self.client.request("POST", "/auth/poll", {"device_code": started["device_code"]})
        self.client.assert_status(poll, 200)
        self.assertIn("owner_token", coerce_data(poll), poll.safe_meta)

    def test_owner_html_form_approval_completes_device_login(self) -> None:
        started = self.start_device()
        login_url = f"{self.client.fixture_url}/owner/login?{urllib.parse.urlencode({'worker': self.client.base_url, 'code': started['user_code']})}"
        login = self.client.request_url(login_url, method="GET")
        self.client.assert_status(login, 200)
        login_html = login.body.decode("utf-8", "replace")
        self.assertIn("<title>Approve device · comms</title>", login_html, login.safe_meta)
        self.assertIn(f"value=\"{started['user_code']}\"", login_html, login.safe_meta)
        form_body = urllib.parse.urlencode({"code": started["user_code"]}).encode("utf-8")
        approve_url = f"{self.client.fixture_url}/owner/approve?{urllib.parse.urlencode({'worker': self.client.base_url})}"
        approved = self.client.request_url(
            approve_url,
            method="POST",
            body=form_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.client.assert_status(approved, 200)
        approved_html = approved.body.decode("utf-8", "replace")
        self.assertIn("text/html", approved.headers.get("content-type", ""), approved.safe_meta)
        self.assertIn("<title>Device approved · comms</title>", approved_html, approved.safe_meta)
        poll = self.client.request("POST", "/auth/poll", {"device_code": started["device_code"]})
        self.client.assert_status(poll, 200)
        self.assertIn("owner_token", coerce_data(poll), poll.safe_meta)

    def test_access_jwt_negative_cases_are_denied(self) -> None:
        started = self.start_device()
        now = int(time.time())
        cases = [
            self.client.access_token(exp=now - 5),
            self.client.access_token(email="mallory@example.com"),
            self.client.access_token(aud="wrong-audience"),
        ]
        good = self.client.access_token()
        cases.append(good.rsplit(".", 1)[0] + ".AAAA")
        for token in cases:
            result = self.client.request(
                "POST",
                "/owner/approve",
                {"user_code": started["user_code"]},
                access_jwt=token,
                headers={"Origin": self.client.base_url},
            )
            self.assertIn(result.status, {401, 403}, result.safe_meta)
        pending = self.client.request("POST", "/auth/poll", {"device_code": started["device_code"]})
        self.assertEqual(pending.status, 202, pending.safe_meta)

    def test_device_poll_is_pending_then_one_time_under_race(self) -> None:
        started = self.start_device()
        pending = self.client.request("POST", "/auth/poll", {"device_code": started["device_code"]})
        self.assertEqual(pending.status, 202, pending.safe_meta)
        self.client.assert_status(self.approve_device(started["user_code"]), 200)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.client.request("POST", "/auth/poll", {"device_code": started["device_code"]}), range(6)))
        successes = [r for r in results if r.status == 200 and isinstance(coerce_data(r), dict) and "owner_token" in coerce_data(r)]
        self.assertEqual(len(successes), 1, [r.safe_meta for r in results])

    def test_owner_and_anonymous_tokens_cannot_write_shared_sql(self) -> None:
        owner, _agent_id, agent_token = self.enroll_agent(label="owner-sql-guard")
        table = unique_name("owner_guard")
        anonymous = self.client.request("POST", "/api/sql", {"sql": f"CREATE TABLE {table}(id TEXT)", "params": []})
        self.assertEqual(anonymous.status, 401, anonymous.safe_meta)
        owner_write = self.client.request("POST", "/api/sql", {"sql": f"CREATE TABLE {table}(id TEXT)", "params": []}, bearer=owner)
        self.assertEqual(owner_write.status, 401, owner_write.safe_meta)
        schema = self.sql(agent_token, "SELECT name FROM sqlite_schema WHERE name = ?", [table])
        self.assertEqual(rows_of(coerce_data(schema)), [], schema.safe_meta)

    def test_invitation_join_race_only_one_wins_and_agent_ids_are_unique(self) -> None:
        owner = self.owner_token()
        invitation = self.invite(owner, label="same-label", ttl_seconds=60)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.client.request("POST", "/agent/join", {"invitation": invitation, "label": "same-label"}), range(8)))
        winners = [coerce_data(r) for r in results if is_success(r) and isinstance(coerce_data(r), dict) and "agent_id" in coerce_data(r)]
        self.assertEqual(len(winners), 1, [r.safe_meta for r in results])
        self.assertTrue(str(winners[0]["agent_id"]).startswith("agent_"))
        first_invitation = self.invite(owner, label="same-label", ttl_seconds=60)
        second_invitation = self.invite(owner, label="same-label", ttl_seconds=60)
        first_id, _ = self.join(first_invitation, label="same-label")
        second_id, _ = self.join(second_invitation, label="same-label")
        self.assertNotEqual(first_id, second_id)

    def test_agent_identity_comes_from_bearer_not_x_agent_header(self) -> None:
        owner = self.owner_token()
        _owner, first_id, first_token = self.enroll_agent(owner, label="identity-a")
        _owner, second_id, _second_token = self.enroll_agent(owner, label="identity-b")
        result = self.client.request("GET", "/agent/me", bearer=first_token, headers={"x-comms-agent": second_id})
        self.client.assert_status(result, 200)
        data = coerce_data(result)
        self.assertEqual(data["agent_id"], first_id, result.safe_meta)

    def test_sql_primitives_preserve_values_and_allow_schema_evolution(self) -> None:
        _owner, agent_id, token = self.enroll_agent(label="sql")
        table = unique_name("values")
        fts = unique_name("fts")
        self.sql(token, f"CREATE TABLE {table}(id TEXT PRIMARY KEY, n REAL, s TEXT, nil TEXT, js TEXT)")
        self.sql(token, f"ALTER TABLE {table} ADD COLUMN extra TEXT")
        self.sql(token, f"INSERT INTO {table}(id,n,s,nil,js,extra) VALUES(?,?,?,?,?,?)", ["row", 42.25, "hello", None, json.dumps({"k": [1, 2, 3]}), "added"])
        selected = self.sql(token, f"SELECT id, n, s, nil, json_extract(js, '$.k[1]') AS j, extra FROM {table} WHERE id = ?", ["row"])
        rows = rows_of(coerce_data(selected))
        self.assertEqual(rows, [{"id": "row", "n": 42.25, "s": "hello", "nil": None, "j": 2, "extra": "added"}], selected.safe_meta)
        self.assertIn(agent_id, selected.headers.get("x-comms-agent", ""))
        bound = self.sql(token, "SELECT ? AS yes, ? AS no, hex(?) AS binary", [True, False, {"encoding": "base64", "data": "AP8="}])
        self.assertEqual(rows_of(coerce_data(bound)), [{"yes": 1, "no": 0, "binary": "00FF"}], bound.safe_meta)
        self.sql(token, f"CREATE VIRTUAL TABLE {fts} USING fts5(body)")
        self.sql(token, f"INSERT INTO {fts}(body) VALUES(?)", ["multimodal agents coordinate through shared text"])
        match = self.sql(token, f"SELECT rowid FROM {fts} WHERE {fts} MATCH ?", ["coordinate"])
        self.assertEqual(len(rows_of(coerce_data(match))), 1, match.safe_meta)
        schema = self.client.request("POST", "/api/schema", {}, bearer=token)
        self.client.assert_status(schema, 200)
        schema_text = json.dumps(coerce_data(schema), sort_keys=True)
        self.assertIn(table, schema_text)
        self.sql(token, f"DROP TABLE {fts}")
        self.sql(token, f"DROP TABLE {table}")
        gone = self.sql(token, "SELECT name FROM sqlite_schema WHERE name IN (?, ?)", [table, fts])
        self.assertEqual(rows_of(coerce_data(gone)), [], gone.safe_meta)

    def test_batch_rolls_back_all_statements_on_failure(self) -> None:
        _owner, _agent_id, token = self.enroll_agent(label="batch")
        positive = unique_name("batch_ok")
        ok = self.client.request(
            "POST",
            "/api/batch",
            {
                "statements": [
                    {"sql": f"CREATE TABLE {positive}(id TEXT PRIMARY KEY)", "params": []},
                    {"sql": f"INSERT INTO {positive}(id) VALUES(?)", "params": ["ok"]},
                ]
            },
            bearer=token,
        )
        self.client.assert_status(ok, 200)
        positive_rows = self.sql(token, f"SELECT id FROM {positive} WHERE id = ?", ["ok"])
        self.assertEqual(rows_of(coerce_data(positive_rows)), [{"id": "ok"}], positive_rows.safe_meta)
        table = unique_name("rollback")
        result = self.client.request(
            "POST",
            "/api/batch",
            {
                "statements": [
                    {"sql": f"CREATE TABLE {table}(id TEXT PRIMARY KEY)", "params": []},
                    {"sql": f"INSERT INTO {table}(id) VALUES(?)", "params": ["same"]},
                    {"sql": f"INSERT INTO {table}(id) VALUES(?)", "params": ["same"]},
                ]
            },
            bearer=token,
        )
        self.assertFalse(is_success(result), result.safe_meta)
        check = self.sql(token, "SELECT name FROM sqlite_schema WHERE name = ?", [table])
        self.assertEqual(rows_of(coerce_data(check)), [], check.safe_meta)

    def test_control_tables_are_not_reachable_from_shared_sql(self) -> None:
        _owner, _agent_id, token = self.enroll_agent(label="control")
        public = unique_name("control_positive")
        self.sql(token, f"CREATE TABLE {public}(id TEXT PRIMARY KEY)")
        self.sql(token, f"INSERT INTO {public}(id) VALUES(?)", ["visible"])
        public_rows = self.sql(token, f"SELECT id FROM {public} WHERE id = ?", ["visible"])
        self.assertEqual(rows_of(coerce_data(public_rows)), [{"id": "visible"}], public_rows.safe_meta)
        visible = self.sql(token, "SELECT name FROM sqlite_schema WHERE name IN ('owners','agents','invitations','devices','downloads')")
        self.assertEqual(rows_of(coerce_data(visible)), [], visible.safe_meta)
        for name in ["owners", "agents", "devices", "invitations", "downloads"]:
            result = self.client.request("POST", "/api/sql", {"sql": f"SELECT * FROM {name} LIMIT 1", "params": []}, bearer=token)
            self.assertFalse(is_success(result), result.safe_meta)

    def test_inline_and_raw_media_round_trip_with_independent_sha(self) -> None:
        _owner, agent_id, token = self.enroll_agent(label="media")
        payloads = [
            (b"hello text", "text/plain", "note.txt", "data"),
            (b"\x89PNG\r\n\x1a\n" + secrets.token_bytes(24), "image/png", "pixel.png", "image_data"),
            (b"RIFF" + secrets.token_bytes(32), "audio/wav", "sound.wav", "audio_data"),
            (secrets.token_bytes(64), "application/octet-stream", "blob.bin", "data"),
        ]
        for raw, mime, name, rich_key in payloads:
            encoded = base64.b64encode(raw).decode("ascii")
            put = self.client.request("POST", "/api/blob/put", {"data": encoded, "mime_type": mime, "name": name}, bearer=token)
            self.client.assert_status(put, 200)
            descriptor = coerce_data(put)
            self.assertEqual(descriptor["bytes"], len(raw), put.safe_meta)
            self.assertEqual(descriptor["sha256"], hashlib.sha256(raw).hexdigest(), put.safe_meta)
            self.assertEqual(descriptor["created_by"], agent_id, put.safe_meta)
            inline = self.client.request("POST", "/api/blob/get", {"id": descriptor["id"], "inline": True}, bearer=token)
            self.client.assert_status(inline, 200)
            inline_data = coerce_data(inline)
            self.assertEqual(base64.b64decode(inline_data["data"]), raw, inline.safe_meta)
            self.assertEqual(base64.b64decode(inline_data[rich_key]), raw, inline.safe_meta)
        raw = b"raw media body " + secrets.token_bytes(16)
        raw_put = self.client.request("POST", "/media", raw, bearer=token, headers={"Content-Type": "application/x-test", "x-comms-name": "raw.bin"})
        self.client.assert_status(raw_put, {200, 201})
        raw_descriptor = coerce_data(raw_put)
        get = self.client.request("GET", f"/media/{urllib.parse.quote(raw_descriptor['id'])}", bearer=token)
        self.client.assert_status(get, 200)
        self.assertEqual(get.body, raw, get.safe_meta)
        self.assertEqual(hashlib.sha256(get.body).hexdigest(), raw_descriptor["sha256"], get.safe_meta)

    def test_multipart_upload_is_creator_bound_and_byte_exact(self) -> None:
        owner = self.owner_token()
        _owner, agent_id, token = self.enroll_agent(owner, label="multipart-a")
        _owner, _other_id, other_token = self.enroll_agent(owner, label="multipart-b")
        part1 = (b"A1234567" * (5 * 1024 * 1024 // 8))
        part2 = (b"B7654321" * ((3 * 1024 * 1024 + 64) // 8))
        raw = part1 + part2
        expected_sha = hashlib.sha256(raw).hexdigest()
        created = self.client.request(
            "POST",
            "/uploads",
            {"mime_type": "application/octet-stream", "name": "large.bin"},
            bearer=token,
            headers={"Content-Type": "application/json"},
        )
        self.client.assert_status(created, 201)
        upload = coerce_data(created)
        self.assertEqual(upload["mime_type"], "application/octet-stream", created.safe_meta)
        self.assertEqual(upload["name"], "large.bin", created.safe_meta)
        blob_id = upload["id"]
        upload_id = upload["upload_id"]
        denied = self.client.request("PUT", f"/uploads/{blob_id}/{upload_id}/1", part1, bearer=other_token)
        self.assertFalse(is_success(denied), denied.safe_meta)
        part_zero = self.client.request("PUT", f"/uploads/{blob_id}/{upload_id}/0", b"zero", bearer=token)
        self.assertEqual(part_zero.status, 400, part_zero.safe_meta)
        bad_percent = self.client.request("PUT", f"/uploads/{blob_id}/{upload_id}/%ZZ", b"bad", bearer=token)
        self.assertEqual(bad_percent.status, 400, bad_percent.safe_meta)
        part_one = self.client.request("PUT", f"/uploads/{blob_id}/{upload_id}/1", part1, bearer=token)
        self.client.assert_status(part_one, 200)
        part_two = self.client.request("PUT", f"/uploads/{blob_id}/{upload_id}/2", part2, bearer=token)
        self.client.assert_status(part_two, 200)
        parts = [coerce_data(part_one), coerce_data(part_two)]
        completed = self.client.request(
            "POST",
            f"/uploads/{blob_id}/{upload_id}/complete",
            {"parts": parts},
            bearer=token,
        )
        self.client.assert_status(completed, 200)
        descriptor = coerce_data(completed)
        self.assertEqual(descriptor["id"], blob_id, completed.safe_meta)
        self.assertEqual(descriptor["bytes"], len(raw), completed.safe_meta)
        self.assertEqual(descriptor["created_by"], agent_id, completed.safe_meta)
        inline = self.client.request("POST", "/api/blob/get", {"id": blob_id, "inline": True}, bearer=token)
        self.client.assert_status(inline, 200)
        inline_data = coerce_data(inline)
        self.assertEqual(inline_data["bytes"], len(raw), inline.safe_meta)
        self.assertEqual(inline_data["sha256"], expected_sha, inline.safe_meta)
        self.assertEqual(base64.b64decode(inline_data["data"]), raw, inline.safe_meta)
        media = self.client.request("GET", f"/media/{urllib.parse.quote(blob_id)}", bearer=token)
        self.client.assert_status(media, 200)
        self.assertEqual(media.body, raw, media.safe_meta)
        self.assertEqual(hashlib.sha256(media.body).hexdigest(), expected_sha, media.safe_meta)

    def test_download_ticket_is_get_only_and_revocation_invalidates_it(self) -> None:
        owner, agent_id, token = self.enroll_agent(label="ticket")
        raw = b"ticket bytes " + secrets.token_bytes(8)
        put = self.client.request("POST", "/api/blob/put", {"data": base64.b64encode(raw).decode("ascii"), "mime_type": "application/octet-stream", "name": "ticket.bin"}, bearer=token)
        self.client.assert_status(put, 200)
        blob_id = coerce_data(put)["id"]
        link_response = self.client.request("POST", "/api/blob/get", {"id": blob_id, "inline": False}, bearer=token)
        self.client.assert_status(link_response, 200)
        link_data = coerce_data(link_response)
        ticket_url = link_data.get("url") or link_data.get("download_url") or link_data.get("href")
        self.assertIsInstance(ticket_url, str, link_response.safe_meta)
        ticket_get = self.client.request_url(ticket_url, method="GET")
        self.client.assert_status(ticket_get, 200)
        self.assertEqual(ticket_get.body, raw, ticket_get.safe_meta)
        for method in ["POST", "DELETE", "PUT"]:
            denied = self.client.request_url(ticket_url, method=method, body=b"overwrite")
            self.assertFalse(is_success(denied), denied.safe_meta)
        revoke = self.client.request("POST", "/owner/revoke", {"id": agent_id}, bearer=owner)
        self.client.assert_status(revoke, 200)
        denied_bearer = self.client.request("GET", "/agent/me", bearer=token)
        self.assertEqual(denied_bearer.status, 401, denied_bearer.safe_meta)
        denied_ticket = self.client.request_url(ticket_url, method="GET")
        self.assertIn(denied_ticket.status, {401, 403}, denied_ticket.safe_meta)

    def test_short_ttl_agent_expires(self) -> None:
        owner = self.owner_token()
        invitation = self.invite(owner, label="expires", ttl_seconds=1)
        _agent_id, token = self.join(invitation, label="expires")
        time.sleep(2)
        result = self.client.request("GET", "/agent/me", bearer=token)
        self.assertEqual(result.status, 401, result.safe_meta)

    def mcp_rpc(self, token: str, rpc_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        result = self.client.request(
            "POST",
            "/api/mcp",
            {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params},
            bearer=token,
            headers={"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"},
        )
        self.client.assert_status(result, 200)
        self.assertIsInstance(result.json, dict, result.safe_meta)
        self.assertNotIn("error", result.json, result.json)
        return result.json.get("result", {})

    def mcp_tool_call(self, token: str, rpc_id: int, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.mcp_rpc(token, rpc_id, "tools/call", {"name": name, "arguments": arguments})
        self.assertFalse(result.get("isError"), result)
        return result

    @staticmethod
    def mcp_structured_content(result: dict[str, Any]) -> dict[str, Any]:
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                    try:
                        parsed = json.loads(item["text"])
                    except json.JSONDecodeError:
                        continue
                    if isinstance(parsed, dict):
                        return parsed
        return result

    def mcp_pending_seq(self, execution: dict[str, Any]) -> int:
        pending = [entry for entry in execution.get("log", []) if isinstance(entry, dict) and entry.get("state") == "pending"]
        self.assertTrue(pending, execution)
        seq = pending[0].get("seq")
        self.assertIsInstance(seq, int, execution)
        return seq

    def mcp_codemode_execute(self, token: str, rpc_id: int, code: str) -> dict[str, Any]:
        execution = self.mcp_structured_content(self.mcp_tool_call(token, rpc_id, "codemode_execute", {"code": code}))
        self.assertIsInstance(execution.get("id"), str, execution)
        execution_id = execution["id"]
        rpc_id += 1
        for _ in range(20):
            status = execution.get("status")
            if status != "paused":
                self.assertEqual(status, "completed", execution)
                return execution
            seq = self.mcp_pending_seq(execution)
            execution = self.mcp_structured_content(
                self.mcp_tool_call(token, rpc_id, "codemode_decide", {"id": execution_id, "seq": seq, "decision": "approve"})
            )
            rpc_id += 1
        self.fail(f"CodeMode execution did not complete after approvals: {execution}")

    @staticmethod
    def mcp_tool_names(result: dict[str, Any]) -> set[str]:
        structured = result.get("structuredContent")
        if isinstance(structured, dict) and isinstance(structured.get("tools"), list):
            return {tool.get("name") for tool in structured["tools"] if isinstance(tool, dict) and isinstance(tool.get("name"), str)}
        return set()

    def test_http_mcp_endpoint_projects_tools_and_rich_blob_content(self) -> None:
        _owner, _agent_id, token = self.enroll_agent(label="http-mcp")
        initialized = self.mcp_rpc(token, 1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "comms-integration", "version": "test"}})
        self.assertEqual(initialized.get("protocolVersion"), "2025-06-18")
        listed = self.mcp_rpc(token, 2, "tools/list", {})
        listed_names = {tool.get("name") for tool in listed.get("tools", []) if isinstance(tool, dict)}
        self.assertEqual(
            {"codemode_search", "codemode_execute", "codemode_execution", "codemode_decide", "codemode_cancel"},
            listed_names,
            sorted(listed_names),
        )
        table = unique_name("mcp")
        sql_code = (
            f"await comms.sql({json.dumps({'sql': f'CREATE TABLE {table}(id TEXT PRIMARY KEY, msg TEXT)', 'params': []})});"
            f"await comms.sql({json.dumps({'sql': f'INSERT INTO {table}(id,msg) VALUES(?,?)', 'params': ['one', 'from http mcp']})});"
            f"return await comms.sql({json.dumps({'sql': f'SELECT msg FROM {table} WHERE id = ?', 'params': ['one']})});"
        )
        selected = self.mcp_codemode_execute(token, 3, sql_code)
        self.assertEqual(rows_of(selected.get("result")), [{"msg": "from http mcp"}], selected)
        png = b"\x89PNG\r\n\x1a\n" + secrets.token_bytes(16)
        png_b64 = base64.b64encode(png).decode("ascii")
        blob_code = (
            f"const put = await comms.blob_put({json.dumps({'data': png_b64, 'mime_type': 'image/png', 'name': 'mcp.png'})});"
            "return await comms.blob_get({id: put.id, inline: true});"
        )
        got = self.mcp_codemode_execute(token, 20, blob_code)
        blob = got.get("result")
        self.assertIsInstance(blob, dict, got)
        self.assertEqual(blob.get("data"), png_b64, got)
        self.assertEqual(blob.get("image_data"), png_b64, got)
        self.assertEqual(blob.get("mime_type"), "image/png", got)
        self.assertIsInstance(blob.get("id"), str, got)

    def test_cli_two_processes_and_stdio_mcp_round_trip(self) -> None:
        if not self.cli:
            self.skipTest("--cli was not supplied or does not exist")
        _owner, _first_id, first_token = self.enroll_agent(label="cli-a")
        _owner, _second_id, second_token = self.enroll_agent(label="cli-b")
        table = unique_name("cli")
        self.run_cli(first_token, ["sql", "--sql", f"CREATE TABLE {table}(id TEXT PRIMARY KEY, msg TEXT)", "--params", "[]", "--format", "json"])
        self.run_cli(first_token, ["sql", "--sql", f"INSERT INTO {table}(id,msg) VALUES(?,?)", "--params", json.dumps(["cli", "hello from cli"]), "--format", "json"])
        output = self.run_cli(second_token, ["sql", "--sql", f"SELECT msg FROM {table} WHERE id = ?", "--params", json.dumps(["cli"]), "--format", "json"])
        self.assertEqual(rows_of(output), [{"msg": "hello from cli"}])
        mcp_output = self.run_mcp_call(second_token, "sql", {"sql": f"SELECT msg FROM {table} WHERE id = ?", "params": ["cli"]})
        structured = mcp_output.get("structuredContent") if isinstance(mcp_output, dict) else None
        self.assertEqual(rows_of(structured or mcp_output), [{"msg": "hello from cli"}], mcp_output)

    def test_cli_large_blob_file_round_trip_is_byte_exact(self) -> None:
        if not self.cli:
            self.skipTest("--cli was not supplied or does not exist")
        owner = self.owner_token()
        _owner, _first_id, first_token = self.enroll_agent(owner, label="cli-blob-a")
        _owner, _second_id, second_token = self.enroll_agent(owner, label="cli-blob-b")
        size = 8 * 1024 * 1024 + 137
        pattern = bytes(range(256))
        raw = (pattern * ((size // len(pattern)) + 1))[:size]
        expected_sha = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory(prefix="comms-cli-blob-") as directory:
            input_path = os.path.join(directory, "input.bin")
            output_path = os.path.join(directory, "output.bin")
            with open(input_path, "wb") as handle:
                handle.write(raw)
            put = self.run_cli(first_token, ["blob", "put", "--file", input_path, "--mime-type", "application/octet-stream", "--name", "large-cli.bin", "--format", "json"])
            put_data = put.get("data") if isinstance(put, dict) and put.get("ok") is True else put
            self.assertIsInstance(put_data, dict, put)
            blob_id = put_data["id"]
            self.assertEqual(put_data.get("bytes"), size, put)
            got = self.run_cli(second_token, ["blob", "get", "--id", blob_id, "--output", output_path, "--format", "json"])
            got_data = got.get("data") if isinstance(got, dict) and got.get("ok") is True else got
            self.assertIsInstance(got_data, dict, got)
            self.assertEqual(got_data.get("bytes"), size, got)
            with open(output_path, "rb") as handle:
                downloaded = handle.read()
            self.assertEqual(hashlib.sha256(downloaded).hexdigest(), expected_sha)
            self.assertEqual(downloaded, raw)

    def run_cli(self, token: str, args: list[str]) -> Any:
        env = {"COMMS_URL": self.client.base_url, "COMMS_TOKEN": token, "PATH": os.environ.get("PATH", "")}
        proc = subprocess.run([self.cli, *args], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False)
        self.assertEqual(proc.returncode, 0, f"cli failed rc={proc.returncode} stderr={proc.stderr[:300]!r}")
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"cli stdout was not JSON: {error}: {proc.stdout[:200]!r}")

    def run_mcp_call(self, token: str, tool_name: str, arguments: dict[str, Any]) -> Any:
        env = {"COMMS_URL": self.client.base_url, "COMMS_TOKEN": token, "PATH": os.environ.get("PATH", "")}
        proc = subprocess.Popen([self.cli, "--mcp"], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.stdin and proc.stdout
        protocol_version = "2026-07-28"
        meta = {
            "io.modelcontextprotocol/protocolVersion": protocol_version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "comms-integration", "version": "0"},
        }
        try:
            self._send_mcp(proc, {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta}})
            discover = self._read_mcp(proc)
            self.assertNotIn("error", discover, discover)
            supported = discover.get("result", {}).get("supportedVersions", [])
            self.assertIn(protocol_version, supported, discover)
            if tool_name not in {"sql", "blob_put", "blob_get"}:
                self.fail(f"unsupported logical MCP tool for CodeMode bridge: {tool_name}")
            code = f"return await comms.{tool_name}({json.dumps(arguments, separators=(',', ':'))});"
            self._send_mcp(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"_meta": meta, "name": "codemode_execute", "arguments": {"code": code}}})
            result = self._read_mcp(proc)
            self.assertNotIn("error", result, result)
            execution = self.mcp_structured_content(result.get("result", {}))
            execution_id = execution.get("id")
            self.assertIsInstance(execution_id, str, execution)
            rpc_id = 3
            for _ in range(20):
                status = execution.get("status")
                if status != "paused":
                    self.assertEqual(status, "completed", execution)
                    return execution.get("result")
                seq = self.mcp_pending_seq(execution)
                self._send_mcp(
                    proc,
                    {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "method": "tools/call",
                        "params": {"_meta": meta, "name": "codemode_decide", "arguments": {"id": execution_id, "seq": seq, "decision": "approve"}},
                    },
                )
                result = self._read_mcp(proc)
                self.assertNotIn("error", result, result)
                execution = self.mcp_structured_content(result.get("result", {}))
                rpc_id += 1
            self.fail(f"CodeMode MCP process did not complete after approvals: {execution}")
        finally:
            proc.kill()
            proc.communicate(timeout=5)

    @staticmethod
    def _send_mcp(proc: subprocess.Popen[bytes], message: dict[str, Any]) -> None:
        data = json.dumps(message, separators=(",", ":")).encode("utf-8")
        assert proc.stdin
        proc.stdin.write(data + b"\n")
        proc.stdin.flush()

    @staticmethod
    def _read_mcp(proc: subprocess.Popen[bytes]) -> dict[str, Any]:
        assert proc.stdout
        ready, _, _ = select.select([proc.stdout], [], [], 5)
        if not ready:
            raise AssertionError("mcp process did not respond within 5 seconds")
        line = proc.stdout.readline()
        if not line:
            raise AssertionError("mcp process closed before response")
        return json.loads(line.decode("utf-8"))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--fixture-url", default=DEFAULT_FIXTURE_URL)
    parser.add_argument("--cli", default=None)
    parser.add_argument("unittest_args", nargs="*")
    return parser.parse_args(argv)


ARGS = parse_args(sys.argv[1:])
sys.argv = [sys.argv[0], *ARGS.unittest_args]


if __name__ == "__main__":
    unittest.main(verbosity=2)
