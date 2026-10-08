#!/usr/bin/env python3
"""Black-box Slack integration tests for the local comms Worker.

Run after the parent has started the Access/Slack fixture on 127.0.0.1:9412 and
Wrangler Worker on 127.0.0.1:9411:

    python3 tests/slack_integration.py --url http://127.0.0.1:9411 --fixture-url http://127.0.0.1:9412
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import sys
import time
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_ORIGINAL_ARGV = sys.argv[:]
sys.argv = [sys.argv[0]]
from integration import ACCESS_AUD, DEFAULT_FIXTURE_URL, DEFAULT_URL, OWNER_EMAIL, CommsClient, HttpResult, coerce_data, rows_of, unique_name
sys.argv = _ORIGINAL_ARGV

SLACK_TEAM_ID = "TEXAMPLE"
OWNER_SLACK_ID = "UEXAMPLE"
SIGNING_SECRET = b"com-slack-fixture-secret"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--fixture-url", default=DEFAULT_FIXTURE_URL)
    parser.add_argument("--state-dir", default=".wrangler/state")
    parser.add_argument("unittest_args", nargs="*")
    return parser.parse_args(argv)


ARGS = parse_args(sys.argv[1:])
sys.argv = [sys.argv[0], *ARGS.unittest_args]


def assert_success(test: unittest.TestCase, result: HttpResult) -> Any:
    test.assertEqual(result.status, 200, result.safe_meta)
    test.assertIsInstance(result.json, dict, result.safe_meta)
    if "ok" in result.json:
        test.assertTrue(result.json.get("ok"), result.safe_meta)
    return coerce_data(result)


def sign_slack(body: bytes, *, timestamp: int | None = None, secret: bytes = SIGNING_SECRET) -> dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    base = b"v0:" + ts.encode("ascii") + b":" + body
    digest = hmac.new(secret, base, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": f"v0={digest}",
    }


def signed_json(value: dict[str, Any], *, timestamp: int | None = None) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return body, sign_slack(body, timestamp=timestamp)


def extract_button_value(message: dict[str, Any]) -> dict[str, Any]:
    blocks = message.get("blocks")
    assert isinstance(blocks, list), message
    for block in blocks:
        elements = block.get("elements") if isinstance(block, dict) else None
        if not isinstance(elements, list):
            continue
        for element in elements:
            if not isinstance(element, dict):
                continue
            for action in element.get("elements", []) if isinstance(element.get("elements"), list) else [element]:
                value = action.get("value") if isinstance(action, dict) else None
                if isinstance(value, str):
                    try:
                        decoded = json.loads(value)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(decoded, dict):
                        return decoded
    raise AssertionError(f"no Slack button value in fixture message: {message}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class SlackIntegrationTest(unittest.TestCase):
    client: CommsClient

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = CommsClient(ARGS.url, ARGS.fixture_url)
        metadata = cls.client.request_url(f"{cls.client.fixture_url}/api/_fixture/metadata", method="GET")
        if metadata.status != 200:
            raise RuntimeError(f"Slack fixture is not reachable: {metadata.safe_meta}")
        health = cls.client.request("GET", "/health")
        if health.status != 200:
            raise RuntimeError(f"Worker is not reachable: {health.safe_meta}")

    def setUp(self) -> None:
        self.fixture_reset()

    def fixture_reset(self) -> None:
        result = self.client.request_url(f"{self.client.fixture_url}/api/_fixture/reset", method="POST", body={})
        self.assertEqual(result.status, 200, result.safe_meta)

    def fixture_metadata(self) -> dict[str, Any]:
        result = self.client.request_url(f"{self.client.fixture_url}/api/_fixture/metadata", method="GET")
        self.assertEqual(result.status, 200, result.safe_meta)
        self.assertIsInstance(result.json, dict, result.safe_meta)
        return result.json

    def start_device(self) -> dict[str, Any]:
        result = self.client.request("POST", "/auth/start", {})
        return assert_success(self, result)

    def owner_token(self) -> str:
        started = self.start_device()
        token = self.client.access_token(email=OWNER_EMAIL, aud=ACCESS_AUD)
        approve = self.client.request(
            "POST",
            "/owner/approve",
            {"user_code": started["user_code"]},
            access_jwt=token,
            headers={"Origin": self.client.base_url},
        )
        self.assertEqual(approve.status, 200, approve.safe_meta)
        poll = self.client.request("POST", "/auth/poll", {"device_code": started["device_code"]})
        data = assert_success(self, poll)
        self.assertIsInstance(data, dict, poll.safe_meta)
        return data["owner_token"]

    def enroll_agent(self, *, label: str | None = None) -> tuple[str, str, str]:
        owner = self.owner_token()
        invite = self.client.request("POST", "/owner/invite", {"label": label or unique_name("slack"), "ttl_seconds": 120}, bearer=owner)
        data = assert_success(self, invite)
        invitation = data["invitation"]
        join = self.client.request("POST", "/agent/join", {"invitation": invitation, "label": label or unique_name("slack_agent")})
        joined = assert_success(self, join)
        return owner, joined["agent_id"], joined["token"]

    def create_question(self, token: str, **overrides: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "idempotency_key": f"itest-{secrets.token_hex(8)}",
            "text": "Should I continue?",
            "choices": [{"id": "yes", "text": "Yes", "value": "yes"}, {"id": "no", "text": "No", "value": "no"}],
            "deadline_seconds": 300,
        }
        body.update(overrides)
        result = self.client.request("POST", "/api/question/create", body, bearer=token)
        data = assert_success(self, result)
        self.assertIsInstance(data, dict, result.safe_meta)
        record = data.get("question", data)
        self.assertIsInstance(record, dict, result.safe_meta)
        self.assertIn("id", record, result.safe_meta)
        return record

    def status_question(self, token: str, question_id: str) -> dict[str, Any]:
        result = self.client.request("POST", "/api/question/status", {"id": question_id}, bearer=token)
        data = assert_success(self, result)
        self.assertIsInstance(data, dict, result.safe_meta)
        record = data.get("question", data)
        self.assertIsInstance(record, dict, result.safe_meta)
        return record

    def signed_post(self, path: str, payload: dict[str, Any], *, timestamp: int | None = None) -> HttpResult:
        body, headers = signed_json(payload, timestamp=timestamp)
        return self.client.request("POST", path, body, headers=headers)

    def interaction_payload(self, *, question_id: str, message: dict[str, Any], answer: str = "yes", team: str = SLACK_TEAM_ID, user: str = OWNER_SLACK_ID) -> dict[str, Any]:
        return {
            "type": "block_actions",
            "team": {"id": team},
            "user": {"id": user},
            "container": {"type": "message", "channel_id": message["channel"], "message_ts": message["ts"]},
            "actions": [{"action_id": "answer", "block_id": question_id, "value": json.dumps({"question_id": question_id, "answer": answer})}],
        }

    def test_named_sessions_are_agent_owned_and_used_by_questions(self) -> None:
        import os
        import subprocess
        _owner, agent, token = self.enroll_agent(label=unique_name("session-agent"))
        _owner2, _agent2, other = self.enroll_agent(label=unique_name("other-session-agent"))
        cli = Path(__file__).resolve().parents[1] / "target/debug/comms"
        env = {"PATH": os.environ.get("PATH", ""), "COMMS_URL": self.client.base_url, "COMMS_TOKEN": token}
        sessions = []
        for interface in ("http", "mcp", "cli"):
            params = {"session_id": unique_name("session").replace(".", "-"), "name": "Ada " + interface,
                "icon_emoji": ":microscope:", "title": "Independent research " + interface}
            for replay in (False, True):
                if interface == "http":
                    response = self.client.request("POST", "/api/slack/invoke", {"method": "comms.sessions.start", "params": params}, bearer=token)
                    result = assert_success(self, response)
                elif interface == "mcp":
                    response = self.client.request("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 70, "method": "tools/call",
                        "params": {"name": "codemode_execute", "arguments": {"code": "return await comms.slack_session_start(" + json.dumps(params) + ")"}}}, bearer=token)
                    self.assertEqual(response.status, 200, response.safe_meta)
                    state = response.json["result"]["structuredContent"]
                    self.assertEqual(state["status"], "completed", json.dumps(state))
                    result = state["result"]
                else:
                    completed = subprocess.run([str(cli), "slack", "session", "start", "--session-id", params["session_id"],
                        "--name", params["name"], "--icon-emoji", params["icon_emoji"], "--title", params["title"], "--json"],
                        env=env, text=True, capture_output=True, check=True)
                    result = json.loads(completed.stdout)
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["agent_id"], agent)
                session = result["session"]
                self.assertEqual(session["name"], params["name"])
                self.assertEqual(session["icon_emoji"], ":microscope:")
                if replay:
                    self.assertEqual(session, sessions[-1])
                else:
                    sessions.append(session)
        self.assertEqual(len({s["thread_ts"] for s in sessions}), 3)
        counters = self.fixture_metadata()["counters"]
        self.assertEqual(counters["chat.postMessage"], 3)
        self.assertEqual(counters["agents.sessions.setStatus"], 3)
        session = sessions[-1]
        for method, params in (
            ("comms.sessions.send", {"session_id": session["session_id"], "text": "Update", "idempotency_key": "update"}),
            ("comms.sessions.status", {"session_id": session["session_id"], "status": "active", "idempotency_key": "ready"}),
        ):
            before = self.fixture_metadata()["counters"]
            denied = self.client.request("POST", "/api/slack/invoke", {"method": method, "params": params}, bearer=other)
            self.assertEqual(denied.status, 400, denied.safe_meta)
            self.assertEqual(self.fixture_metadata()["counters"], before)
            first = assert_success(self, self.client.request("POST", "/api/slack/invoke", {"method": method, "params": params}, bearer=token))
            self.assertTrue(first["ok"], first)
            replay = assert_success(self, self.client.request("POST", "/api/slack/invoke", {"method": method, "params": params}, bearer=token))
            self.assertTrue(replay["replayed"], replay)
        message = self.fixture_metadata()["messages"][-1]
        self.assertEqual(message["thread_ts"], session["thread_ts"])
        self.assertEqual(message["username"], session["name"])
        self.assertEqual(message["icon_emoji"], session["icon_emoji"])
        start = {"session_id": session["session_id"], "name": "Different", "icon_emoji": ":robot_face:", "title": "Different"}
        conflict = self.client.request("POST", "/api/slack/invoke", {"method": "comms.sessions.start", "params": start}, bearer=token)
        self.assertEqual(conflict.status, 400, conflict.safe_meta)
        before = self.fixture_metadata()["counters"]
        for invalid in (
            {"session_id": "bad/id", "name": "Ada", "icon_emoji": ":robot_face:"},
            {"session_id": "bad", "name": "", "icon_emoji": ":robot_face:"},
            {"session_id": "bad", "name": "Ada", "icon_url": "http://example.com/a.png"},
            {"session_id": "bad", "name": "Ada", "icon_url": "https://example.com/a.png", "icon_emoji": ":robot_face:"},
        ):
            response = self.client.request("POST", "/api/slack/invoke", {"method": "comms.sessions.start", "params": invalid}, bearer=token)
            self.assertEqual(response.status, 400, response.safe_meta)
        self.assertEqual(self.fixture_metadata()["counters"], before)
        question = self.create_question(token, text="Continue in this session?")
        self.assertEqual(question["request"]["destination"], {"channel": session["channel_id"], "thread_ts": session["thread_ts"]})
        message = self.fixture_metadata()["messages"][-1]
        self.assertEqual(message["username"], session["name"])
        callback = self.signed_post("/slack/events", {"type": "event_callback", "team_id": SLACK_TEAM_ID,
            "event_id": unique_name("session-reply"), "event": {"type": "message", "user": OWNER_SLACK_ID,
            "channel": session["channel_id"], "thread_ts": session["thread_ts"], "text": "Proceed"}})
        self.assertEqual(callback.status, 200, callback.safe_meta)
        answered = self.status_question(token, question["id"])
        self.assertEqual(answered["state"], "answered")
        self.assertEqual(answered["answer"]["value"], "Proceed")

        rich = [{"type": "section", "text": {"type": "mrkdwn", "text": "*Session report*"}}]
        response = self.client.request("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 71, "method": "tools/call",
            "params": {"name": "codemode_execute", "arguments": {"code": "return await comms.slack_session_send(" +
                json.dumps({"session_id": session["session_id"], "blocks": rich, "idempotency_key": "rich-report"}) + ")"}}}, bearer=token)
        self.assertEqual(response.status, 200, response.safe_meta)
        state = response.json["result"]["structuredContent"]
        self.assertEqual(state["status"], "completed", json.dumps(state))
        message = self.fixture_metadata()["messages"][-1]
        self.assertEqual(message["blocks"], rich)
        self.assertEqual(message["username"], session["name"])
        self.assertEqual(message["thread_ts"], session["thread_ts"])
        url_session = assert_success(self, self.client.request("POST", "/api/slack/invoke",
            {"method": "comms.sessions.start", "params": {"session_id": unique_name("url-session"), "name": "Nova",
                "icon_url": "https://example.com/nova.png", "title": "New task"}}, bearer=token))
        self.assertEqual(url_session["session"]["icon_url"], "https://example.com/nova.png")
        self.assertEqual(self.fixture_metadata()["messages"][-1]["icon_url"], "https://example.com/nova.png")


    def test_swarm_agents_send_named_messages_to_shared_channels(self) -> None:
        import os
        import subprocess
        cli = Path(__file__).resolve().parents[1] / "target/debug/comms"
        agents = []
        for name, icon in (("Builder", ":hammer:"), ("Reviewer", ":mag:")):
            _owner, agent_id, token = self.enroll_agent(label=unique_name(name))
            sid = unique_name("swarm-session").replace(".", "-")
            result = assert_success(self, self.client.request("POST", "/api/slack/invoke",
                {"method": "comms.sessions.start", "params": {"session_id": sid,
                    "name": name, "icon_emoji": icon}}, bearer=token))
            agents.append((agent_id, token, sid, name, icon, result["session"]))
        self.assertNotEqual(agents[0][0], agents[1][0])
        created = assert_success(self, self.client.request("POST", "/api/slack/invoke",
            {"method": "conversations.create", "params": {"name": unique_name("swarm"),
                "is_private": False, "idempotency_key": unique_name("create")}}, bearer=agents[0][1]))
        channel = created["body"]["channel"]["id"]
        _, token, sid, name, icon, session = agents[0]
        env = {"PATH": os.environ.get("PATH", ""), "COMMS_URL": self.client.base_url, "COMMS_TOKEN": token}
        result = subprocess.run([str(cli), "slack", "session", "send", "--session-id", sid,
            "--channel", channel, "--text", "Ready for review", "--idempotency-key", "shared",
            "--json"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        posted = json.loads(result.stdout)
        self.assertTrue(posted["ok"], posted)
        ts = posted["body"]["ts"]
        message = self.fixture_metadata()["messages"][-1]
        self.assertEqual(message["channel"], channel)
        self.assertEqual(message["username"], name)
        self.assertEqual(message["icon_emoji"], icon)
        self.assertNotEqual(message["thread_ts"], session["thread_ts"])
        _, other, other_sid, other_name, other_icon, _ = agents[1]
        history = assert_success(self, self.client.request("POST", "/api/slack/invoke",
            {"method": "conversations.history", "params": {"channel": channel, "limit": 10}}, bearer=other))
        self.assertEqual(history["body"]["messages"][0]["text"], "Ready for review")
        params = {"session_id": other_sid, "channel": channel, "thread_ts": ts,
            "text": "Reviewed", "idempotency_key": "reply"}
        response = self.client.request("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 89,
            "method": "tools/call", "params": {"name": "codemode_execute", "arguments": {
                "code": "return await comms.slack_session_send(" + json.dumps(params) + ")"}}}, bearer=other)
        self.assertEqual(response.status, 200, response.safe_meta)
        self.assertEqual(response.json["result"]["structuredContent"]["status"], "completed", response.json)
        message = self.fixture_metadata()["messages"][-1]
        self.assertEqual((message["channel"], message["thread_ts"], message["username"], message["icon_emoji"]),
            (channel, ts, other_name, other_icon))
        before = self.fixture_metadata()["counters"]
        denied = self.client.request("POST", "/api/slack/invoke",
            {"method": "comms.sessions.send", "params": {**params, "session_id": sid}}, bearer=other)
        self.assertEqual(denied.status, 400, denied.safe_meta)
        self.assertEqual(self.fixture_metadata()["counters"], before)
        conflict = self.client.request("POST", "/api/slack/invoke",
            {"method": "comms.sessions.send", "params": {**params, "thread_ts": "123.000001"}}, bearer=other)
        self.assertEqual(conflict.status, 400, conflict.safe_meta)
        self.assertEqual(self.fixture_metadata()["counters"], before)
        for invalid in ({"channel": "wrong/channel"}, {"channel": channel, "thread_ts": "bad"}, {"thread_ts": ts}):
            rejected = self.client.request("POST", "/api/slack/invoke",
                {"method": "comms.sessions.send", "params": {"session_id": other_sid, "text": "Rejected",
                    "idempotency_key": unique_name("invalid-send"), **invalid}}, bearer=other)
            self.assertEqual(rejected.status, 400, rejected.safe_meta)
            self.assertEqual(self.fixture_metadata()["counters"], before)

    def test_sdk_block_arrays_are_preserved_and_string_blocks_are_rejected(self) -> None:
        _owner, _agent, token = self.enroll_agent(label=unique_name("blocks"))
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "*SDK block array*"}}]
        rejected = self.client.request("POST", "/api/slack/invoke", {
            "method": "chat.postMessage", "params": {"channel": "C_GENERAL", "blocks": json.dumps(blocks)}
        }, bearer=token)
        self.assertGreaterEqual(rejected.status, 400, rejected.safe_meta)
        self.assertEqual(self.fixture_metadata()["counters"].get("chat.postMessage", 0), 0)
        posted = self.client.request("POST", "/api/slack/invoke", {
            "method": "chat.postMessage", "params": {"channel": "C_GENERAL", "blocks": blocks}
        }, bearer=token)
        self.assertEqual(posted.status, 200, posted.safe_meta)
        self.assertEqual(self.fixture_metadata()["messages"][-1]["blocks"], blocks)
        self.assertEqual(self.fixture_metadata()["counters"].get("chat.postMessage"), 1)


    def test_all_rest_family_routes_preserve_verbs_and_payloads(self) -> None:
        _owner, _agent, token = self.enroll_agent(label=unique_name("rest"))
        expected = []
        for version in ("v1", "v2"):
            prefix = "scim/" + version
            expected.append(("scim." + version + ".config.info", "GET", prefix + ("/ServiceProviderConfigs" if version == "v1" else "/ServiceProviderConfig"), {}))
            if version == "v2":
                expected.extend([
                    ("scim.v2.resource_types.list", "GET", prefix + "/ResourceTypes", {}),
                    ("scim.v2.schemas.list", "GET", prefix + "/Schemas", {}),
                ])
            for kind, resource in (("users", "Users"), ("groups", "Groups")):
                name = "scim." + version + "." + kind
                path = prefix + "/" + resource
                expected.extend([
                    ("scim." + version + ".schemas." + kind, "GET", prefix + "/Schemas/" + resource, {}),
                    (name + ".list", "GET", path, {"count": 7, "startIndex": 2, "filter": 'displayName eq "Test & Agent"'}),
                    (name + ".get", "GET", path + "/U_OTHER", {"id": "U_OTHER"}),
                    (name + ".create", "POST", path, {"body": {"displayName": "fixture", "members": []}}),
                    (name + ".update", "PATCH", path + "/U_OTHER", {"id": "U_OTHER", "body": {"active": True}}),
                    (name + ".replace", "PUT", path + "/U_OTHER", {"id": "U_OTHER", "body": {"displayName": "replace"}}),
                    (name + ".delete", "DELETE", path + "/U_OTHER", {"id": "U_OTHER"}),
                ])
        expected.extend([
            ("audit.actions.list", "GET", "audit/v1/actions", {}),
            ("audit.schemas.list", "GET", "audit/v1/schemas", {}),
            ("audit.logs.list", "GET", "audit/v1/logs", {"limit": 10, "action": "user_login", "cursor": "a=b c"}),
        ])
        self.assertEqual(len(expected), 35)
        for method, verb, path, params in expected:
            with self.subTest(method=method):
                result = self.client.request("POST", "/api/slack/invoke", {"method": method, "params": params}, bearer=token)
                data = assert_success(self, result)
                self.assertTrue(data["ok"], result.safe_meta)
                received = self.fixture_metadata()["rest_requests"][-1]
                self.assertEqual(received["path"], path)
                self.assertEqual(received["verb"], verb)
                if verb in {"POST", "PUT", "PATCH"}:
                    self.assertEqual(received["params"], params["body"])
                    self.assertEqual(received["content_type"], "application/json")
                elif verb == "GET":
                    self.assertEqual(received["params"], {key: str(value) for key, value in params.items() if key != "id"})
                if method in {"audit.actions.list", "audit.schemas.list"}:
                    self.assertIsNone(received["authorization"])
                    self.assertEqual(data["token_class"], "public")
                else:
                    self.assertIn("Bearer fixture-slack-", received["authorization"])
                if verb == "DELETE":
                    self.assertEqual(data["status"], 204)
                    self.assertIsNone(data["body"])
        import os
        import subprocess
        cli = Path(__file__).resolve().parents[1] / "target/debug/comms"
        completed = subprocess.run([str(cli), "slack", "invoke", "--method", "audit.actions.list", "--params", "{}", "--json"],
            env={"PATH": os.environ.get("PATH", ""), "COMMS_URL": self.client.base_url, "COMMS_TOKEN": token},
            text=True, capture_output=True, check=True)
        self.assertTrue(json.loads(completed.stdout)["ok"], completed.stdout)
        self.assertEqual(self.fixture_metadata()["rest_requests"][-1]["path"], "audit/v1/actions")
        mcp = self.client.request("POST", "/api/mcp", {
            "jsonrpc": "2.0", "id": 25, "method": "tools/call",
            "params": {"name": "codemode_execute", "arguments": {"code": "return await comms.slack_invoke({method:'audit.actions.list',params:{}})"}}
        }, bearer=token)
        self.assertEqual(mcp.status, 200, mcp.safe_meta)
        self.assertNotIn("error", mcp.json, mcp.safe_meta)
        self.assertFalse(mcp.json["result"].get("isError", False), mcp.safe_meta)
        self.assertEqual(mcp.json["result"]["structuredContent"]["status"], "completed", json.dumps(mcp.json))
        self.assertEqual(len(self.fixture_metadata()["rest_requests"]), 37, json.dumps(mcp.json))
        self.assertEqual(self.fixture_metadata()["rest_requests"][-1]["path"], "audit/v1/actions")
        before = len(self.fixture_metadata()["rest_requests"])
        for method in ("scim.v1.users.delete", "scim.v2.users.update", "scim.v2.users.replace"):
            denied = self.client.request("POST", "/api/slack/invoke", {"method": method, "params": {"id": OWNER_SLACK_ID, "body": {"active": False}}}, bearer=token)
            self.assertGreaterEqual(denied.status, 400, denied.safe_meta)
        self.assertEqual(len(self.fixture_metadata()["rest_requests"]), before)
        denied_mcp = self.client.request("POST", "/api/mcp", {
            "jsonrpc": "2.0", "id": 26, "method": "tools/call",
            "params": {"name": "codemode_execute", "arguments": {"code":
                "return await comms.slack_invoke({method:'scim.v2.users.update',params:{id:" +
                json.dumps(OWNER_SLACK_ID) + ",body:{active:false}}})"}}
        }, bearer=token)
        self.assertEqual(denied_mcp.status, 200, denied_mcp.safe_meta)
        denied_state = denied_mcp.json["result"]["structuredContent"]
        self.assertEqual(denied_state["status"], "error", json.dumps(denied_state))
        self.assertIn("protected", denied_state["error"])
        self.assertEqual(len(self.fixture_metadata()["rest_requests"]), before)

    def test_external_upload_streams_blobs_and_replays_without_duplicate_provider_calls(self) -> None:
        import os
        import subprocess
        _owner, _agent, token = self.enroll_agent(label=unique_name("upload"))
        raw = b"\x00\xffAgent upload bytes\r\n"
        media = self.client.request("POST", "/media", raw, bearer=token, headers={"Content-Type": "application/octet-stream", "X-Comms-Name": "agent.bin"})
        self.assertEqual(media.status, 201, media.safe_meta)
        blob = coerce_data(media)
        cli = Path(__file__).resolve().parents[1] / "target/debug/comms"
        env = {"PATH": os.environ.get("PATH", ""), "COMMS_URL": self.client.base_url, "COMMS_TOKEN": token}
        file_ids = []
        for interface in ("http", "mcp", "cli"):
            params = {"blob_id": blob["id"], "filename": "agent.bin", "idempotency_key": unique_name("upload-key"),
                "get_params": {"alt_txt": "A report", "length": 999},
                "complete_params": {"channel_id": "C_GENERAL", "initial_comment": "Report", "thread_ts": "1.2", "title": "Agent report"}}
            for replay in (False, True):
                if interface == "http":
                    response = self.client.request("POST", "/api/slack/invoke", {"method": "files.uploadExternal", "params": params}, bearer=token)
                    result = assert_success(self, response)
                elif interface == "mcp":
                    response = self.client.request("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 60, "method": "tools/call",
                        "params": {"name": "codemode_execute", "arguments": {"code": "return await comms.slack_upload(" + json.dumps(params) + ")"}}}, bearer=token)
                    self.assertEqual(response.status, 200, response.safe_meta)
                    state = response.json["result"]["structuredContent"]
                    self.assertEqual(state["status"], "completed", json.dumps(state))
                    result = state["result"]
                else:
                    completed = subprocess.run([str(cli), "slack", "upload", "--blob-id", blob["id"], "--filename", "agent.bin",
                        "--idempotency-key", params["idempotency_key"], "--get-params", json.dumps(params["get_params"]),
                        "--complete-params", json.dumps(params["complete_params"]), "--json"], env=env, text=True, capture_output=True, check=True)
                    result = json.loads(completed.stdout)
                self.assertTrue(result["ok"], json.dumps(result))
                self.assertEqual(result["replayed"], replay)
                self.assertNotIn("upload_url", json.dumps(result))
                if not replay:
                    file_ids.append(result["file_id"])
                else:
                    self.assertEqual(result["file_id"], file_ids[-1])
        uploads = self.fixture_metadata()["uploads"]
        self.assertEqual(len(uploads), 3)
        for upload in uploads:
            self.assertTrue(upload["completed"])
            self.assertEqual(upload["length"], len(raw))
            self.assertEqual(upload["transferred_bytes"], len(raw))
            self.assertEqual(upload["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertIsNone(upload["transfer_authorization"])
            self.assertEqual(upload["get_params"]["alt_txt"], "A report")
            self.assertEqual(upload["complete_params"]["channel_id"], "C_GENERAL")
            self.assertEqual(upload["complete_params"]["thread_ts"], "1.2")
            self.assertEqual(upload["complete_params"]["files"], [{"id": upload["id"], "title": "Agent report"}])
        counters = self.fixture_metadata()["counters"]
        for method in ("files.getUploadURLExternal", "files.upload.transfer", "files.completeUploadExternal"):
            self.assertEqual(counters.get(method), 3)
        conflict = self.client.request("POST", "/api/slack/invoke", {"method": "files.uploadExternal", "params": {**params, "filename": "different.bin"}}, bearer=token)
        self.assertEqual(conflict.status, 400, conflict.safe_meta)
        params = {"blob_id": blob["id"], "filename": "concurrent.bin", "idempotency_key": unique_name("concurrent-upload")}
        def invoke(_):
            return self.client.request("POST", "/api/slack/invoke", {"method": "files.uploadExternal", "params": params}, bearer=token)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(invoke, range(2)))
        self.assertTrue(any(coerce_data(result).get("ok") for result in results), [r.safe_meta for r in results])
        replay = invoke(None)
        self.assertTrue(coerce_data(replay)["replayed"])
        self.assertEqual(self.fixture_metadata()["counters"]["files.completeUploadExternal"], 4)
        for filename in ("fixture-untrusted-url", "fixture-transfer-failure"):
            params = {"blob_id": blob["id"], "filename": filename, "idempotency_key": unique_name("bad-upload")}
            response = invoke(None)
            self.assertEqual(response.status, 200, response.safe_meta)
            result = coerce_data(response)
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], "ambiguous")
            if filename == "fixture-untrusted-url":
                self.assertEqual(result["error"], "Slack returned an untrusted upload endpoint")
            self.assertTrue(result["file_id"])
            before = self.fixture_metadata()["counters"]
            replay = invoke(None)
            self.assertEqual(coerce_data(replay)["error"], "delivery_requires_reconciliation")
            self.assertEqual(self.fixture_metadata()["counters"], before)
        self.assertEqual(self.fixture_metadata()["counters"]["files.completeUploadExternal"], 4)
        for db in Path(ARGS.state_dir).rglob("*.sqlite*"):
            if "observability" in db.parts:
                continue
            contents = db.read_bytes()
            for file_id in file_ids:
                self.assertTrue((self.client.fixture_url + "/api/files/upload/" + file_id).encode() not in contents, "provider upload URL retained in " + str(db))

    def test_binary_analytics_exports_are_downloadable_without_inline_bytes(self) -> None:
        import gzip
        import os
        import subprocess
        import tempfile
        _owner, agent, token = self.enroll_agent(label=unique_name("analytics"))
        params = {"type": "member", "date": "2026-10-06"}
        expected = b'{"date":"2026-10-06","user_id":"U_TEST","messages_posted_count":7}\n'
        cli = Path(__file__).resolve().parents[1] / "target/debug/comms"
        cli_env = {"PATH": os.environ.get("PATH", ""), "COMMS_URL": self.client.base_url, "COMMS_TOKEN": token}

        def artifact_in(value: Any) -> dict[str, Any] | None:
            if isinstance(value, dict):
                if isinstance(value.get("artifact"), dict):
                    return value["artifact"]
                for child in value.values():
                    found = artifact_in(child)
                    if found is not None:
                        return found
            elif isinstance(value, list):
                for child in value:
                    found = artifact_in(child)
                    if found is not None:
                        return found
            return None

        for interface in ("http", "mcp", "cli"):
            with self.subTest(interface=interface):
                if interface == "http":
                    response = self.client.request("POST", "/api/slack/invoke", {"method": "admin.analytics.getFile", "params": params}, bearer=token)
                    result = assert_success(self, response)
                    self.assertTrue(result["ok"], response.safe_meta)
                elif interface == "mcp":
                    response = self.client.request("POST", "/api/mcp", {
                        "jsonrpc": "2.0", "id": 50, "method": "tools/call",
                        "params": {"name": "codemode_execute", "arguments": {"code":
                            "return await comms.slack_invoke(" + json.dumps({"method": "admin.analytics.getFile", "params": params}) + ")"}}
                    }, bearer=token)
                    self.assertEqual(response.status, 200, response.safe_meta)
                    result = response.json["result"]["structuredContent"]
                    self.assertEqual(result["status"], "completed", json.dumps(result))
                else:
                    completed = subprocess.run([str(cli), "slack", "invoke", "--method", "admin.analytics.getFile", "--params", json.dumps(params), "--json"],
                        env=cli_env, text=True, capture_output=True, check=True)
                    result = json.loads(completed.stdout)
                    self.assertTrue(result["ok"], completed.stdout)
                encoded_result = json.dumps(result)
                self.assertNotIn("U_TEST", encoded_result)
                self.assertLess(len(encoded_result), 4096)
                artifact = artifact_in(result)
                self.assertIsNotNone(artifact, encoded_result)
                self.assertEqual(artifact["mime_type"], "application/gzip")
                self.assertEqual(artifact["created_by"], agent)
                self.assertEqual(artifact["name"], "fixture-analytics.json.gz")
                downloaded = self.client.request("GET", "/media/" + artifact["id"], bearer=token)
                self.assertEqual(downloaded.status, 200, downloaded.safe_meta)
                self.assertEqual(downloaded.headers["content-type"], "application/gzip")
                self.assertEqual(artifact["bytes"], len(downloaded.body))
                self.assertEqual(gzip.decompress(downloaded.body), expected)
                anonymous = self.client.request("GET", "/media/" + artifact["id"])
                self.assertEqual(anonymous.status, 401, anonymous.safe_meta)
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "analytics.json.gz"
                    subprocess.run([str(cli), "blob", "get", "--id", artifact["id"], "--output", str(output), "--json"],
                        env=cli_env, text=True, capture_output=True, check=True)
                    self.assertEqual(output.read_bytes(), downloaded.body)
        error = self.client.request("POST", "/api/slack/invoke", {"method": "admin.analytics.getFile", "params": {"type": "member", "date": "1900-01-01"}}, bearer=token)
        self.assertEqual(error.status, 200, error.safe_meta)
        data = coerce_data(error)
        self.assertFalse(data["ok"])
        self.assertEqual(data["body"], {"ok": False, "error": "invalid_date"})
        self.assertIsNone(artifact_in(data))
        search = self.client.request("POST", "/api/slack/invoke", {"method": "search.messages", "params": {"query": "fixture-binary-search"}}, bearer=token)
        self.assertEqual(search.status, 400, search.safe_meta)
        self.assertIn("zero-retention search requires a JSON response", json.dumps(search.json))
        self.assertIsNone(artifact_in(search.json))

    def test_legal_hold_and_status_routes_through_http_and_mcp(self) -> None:
        _owner, _agent, token = self.enroll_agent(label=unique_name("supplement"))
        cases = [
            ("status.current", {}, "status/v2.0.0/current", "public"),
            ("status.history", {}, "status/v2.0.0/history", "public"),
            ("admin.legalHold.policies.activate", {"policy_id": "H123"}, "admin.legalHold.policies.activate", "admin"),
            ("admin.legalHold.policies.create", {"name": "Case A"}, "admin.legalHold.policies.create", "admin"),
            ("admin.legalHold.policies.info", {"policy_id": "H123"}, "admin.legalHold.policies.info", "admin"),
            ("admin.legalHold.policies.list", {"limit": 10}, "admin.legalHold.policies.list", "admin"),
            ("admin.legalHold.policies.release", {"policy_id": "H123"}, "admin.legalHold.policies.release", "admin"),
            ("admin.legalHold.policies.set", {"policy_id": "H123", "description": "updated"}, "admin.legalHold.policies.set", "admin"),
            ("admin.legalHold.entities.add", {"policy_id": "H123", "entities": [{"entity_type": "USER", "entity_id": "U_OTHER"}]}, "admin.legalHold.entities.add", "admin"),
            ("admin.legalHold.entities.list", {"policy_id": "H123"}, "admin.legalHold.entities.list", "admin"),
            ("admin.legalHold.entities.remove", {"policy_id": "H123", "ids": ["He123"]}, "admin.legalHold.entities.remove", "admin"),
        ]
        for method, params, path, token_class in cases:
            for interface in ("http", "mcp"):
                with self.subTest(method=method, interface=interface):
                    if interface == "http":
                        response = self.client.request("POST", "/api/slack/invoke", {"method": method, "params": params}, bearer=token)
                        data = assert_success(self, response)
                        self.assertEqual(data["token_class"], token_class)
                        if method == "status.history":
                            self.assertIsInstance(data["body"], list)
                    else:
                        response = self.client.request("POST", "/api/mcp", {
                            "jsonrpc": "2.0", "id": 40, "method": "tools/call",
                            "params": {"name": "codemode_execute", "arguments": {"code":
                                "return await comms.slack_invoke(" + json.dumps({"method": method, "params": params}) + ")"}}
                        }, bearer=token)
                        self.assertEqual(response.status, 200, response.safe_meta)
                        self.assertEqual(response.json["result"]["structuredContent"]["status"], "completed", json.dumps(response.json))
                    received = self.fixture_metadata()["rest_requests"][-1]
                    self.assertEqual(received["path"], path)
                    self.assertEqual(received["verb"], "GET" if token_class == "public" else "POST")
                    if token_class == "public":
                        self.assertIsNone(received["authorization"])
                        self.assertIsNone(received["content_type"])
                    else:
                        self.assertEqual(received["content_type"], "application/x-www-form-urlencoded")
                        self.assertIn("Bearer fixture-slack-", received["authorization"])
                        wire = received["params"]
                        for key, value in params.items():
                            self.assertEqual(json.loads(wire[key]) if isinstance(value, list) else wire[key], value if isinstance(value, (list, str)) else str(value))
        self.assertEqual(len(self.fixture_metadata()["rest_requests"]), 22)
        import os
        import subprocess
        cli = Path(__file__).resolve().parents[1] / "target/debug/comms"
        for method, params, path in [
            ("status.current", {}, "status/v2.0.0/current"),
            ("status.history", {}, "status/v2.0.0/history"),
            ("admin.legalHold.entities.add", {"policy_id": "H123", "entities": [{"entity_type": "USER", "entity_id": "U_OTHER"}]}, "admin.legalHold.entities.add"),
        ]:
            completed = subprocess.run(
                [str(cli), "slack", "invoke", "--method", method, "--params", json.dumps(params), "--json"],
                env={"PATH": os.environ.get("PATH", ""), "COMMS_URL": self.client.base_url, "COMMS_TOKEN": token},
                text=True, capture_output=True, check=True,
            )
            self.assertTrue(json.loads(completed.stdout)["ok"], completed.stdout)
            self.assertEqual(self.fixture_metadata()["rest_requests"][-1]["path"], path)
        self.assertEqual(len(self.fixture_metadata()["rest_requests"]), 25)

    def test_fixture_exposes_bounded_slack_api_routes_and_counters(self) -> None:
        opened = self.client.request_url(f"{self.client.fixture_url}/api/conversations.open", method="POST", body={"users": OWNER_SLACK_ID})
        self.assertEqual(opened.status, 200, opened.safe_meta)
        posted = self.client.request_url(f"{self.client.fixture_url}/api/chat.postMessage", method="POST", body={"channel": "D_OWNER", "text": "fixture search needle"})
        self.assertEqual(posted.status, 200, posted.safe_meta)
        history = self.client.request_url(f"{self.client.fixture_url}/api/conversations.history", method="POST", body={"channel": "D_OWNER"})
        self.assertEqual(history.status, 200, history.safe_meta)
        search = self.client.request_url(f"{self.client.fixture_url}/api/search.messages", method="POST", body={"query": "needle"})
        self.assertEqual(search.status, 200, search.safe_meta)
        metadata = self.fixture_metadata()
        self.assertEqual(metadata["counters"].get("conversations.open"), 1)
        self.assertEqual(metadata["counters"].get("chat.postMessage"), 1)
        self.assertEqual(metadata["counters"].get("conversations.history"), 1)
        self.assertEqual(metadata["counters"].get("search.messages"), 1)
        self.assertEqual(metadata["team_id"], SLACK_TEAM_ID)
        self.assertEqual(metadata["owner_user_id"], OWNER_SLACK_ID)

    def test_runtime_delivery_claim_private_owner_invite_and_zero_retention_guard(self) -> None:
        _owner, _agent, token = self.enroll_agent(label=unique_name("outbox"))
        body = {"method": "chat.postMessage", "params": {"channel": "C_GENERAL", "text": "One delivery", "idempotency_key": secrets.token_hex(12)}}
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.client.request("POST", "/api/slack/invoke", body, bearer=token), range(2)))
        self.assertTrue(any(r.status == 200 for r in results), [r.safe_meta for r in results])
        replay = self.client.request("POST", "/api/slack/invoke", body, bearer=token)
        self.assertEqual(replay.status, 200, replay.safe_meta)
        self.assertEqual(self.fixture_metadata()["counters"].get("chat.postMessage"), 1)
        created = self.client.request("POST", "/api/slack/invoke", {"method": "conversations.create", "params": {"name": unique_name("private"), "is_private": True, "idempotency_key": secrets.token_hex(12)}}, bearer=token)
        self.assertEqual(created.status, 200, created.safe_meta)
        channels = self.fixture_metadata()["channels"]
        private = [c for c in channels if c.get("is_private")]
        self.assertEqual(len(private), 1, channels)
        self.assertIn(OWNER_SLACK_ID, private[0]["members"])
        before = self.fixture_metadata()["counters"].get("search.messages", 0)
        rejected = self.client.request("POST", "/api/slack/invoke", {"method": "search.messages", "params": {"query": "fixture", "idempotency_key": "must-not-persist"}}, bearer=token)
        self.assertIn(b"zero-retention", rejected.body.lower(), rejected.safe_meta)
        self.assertEqual(self.fixture_metadata()["counters"].get("search.messages", 0), before)


    def test_supplemental_admin_grant_survives_oauth_installation(self) -> None:
        access = self.client.access_token(email=OWNER_EMAIL, aud=ACCESS_AUD)
        install = self.no_redirect_request("GET", "/owner/slack/install", access_jwt=access, headers={"Origin": self.client.base_url})
        self.assertIn(install.status, {302, 303}, install.safe_meta)
        state = urllib.parse.parse_qs(urllib.parse.urlparse(install.headers["location"]).query)["state"][0]
        callback = self.client.request("GET", "/owner/slack/callback?" + urllib.parse.urlencode({"code":"fixture-code","state":state}), access_jwt=access)
        self.assertEqual(callback.status, 200, callback.safe_meta)
        _owner, _agent, token = self.enroll_agent(label=unique_name("supplemental"))
        invoked = self.client.request("POST", "/api/slack/invoke", {"method":"admin.apps.mcp.servers.list","params":{}}, bearer=token)
        self.assertEqual(invoked.status, 200, invoked.safe_meta)
        data = coerce_data(invoked)
        self.assertEqual(data["token_class"], "admin", data)
        self.assertEqual(data["body"]["error"], "unsupported_fixture_method", data)
        self.assertEqual(self.fixture_metadata()["counters"].get("admin.apps.mcp.servers.list"), 1)
        rejected = self.client.request("POST", "/api/slack/invoke", {"method":"admin.apps.mcp.servers.list","params":{"team_id":"T_OTHER"}}, bearer=token)
        self.assertGreaterEqual(rejected.status, 400, rejected.safe_meta)
        self.assertEqual(self.fixture_metadata()["counters"].get("admin.apps.mcp.servers.list"), 1)


    def test_owner_oauth_single_use_state_and_team_user_negatives(self) -> None:
        access = self.client.access_token(email=OWNER_EMAIL, aud=ACCESS_AUD)
        install = self.no_redirect_request("GET", "/owner/slack/install", access_jwt=access, headers={"Origin": self.client.base_url})
        self.assertIn(install.status, {302, 303}, install.safe_meta)
        location = install.headers.get("location", "")
        state = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("state", [""])[0]
        self.assertTrue(state, f"missing state in redirect: {location}")
        wrong_team = self.client.request("GET", f"/owner/slack/callback?{urllib.parse.urlencode({'code': 'fixture-wrong-team', 'state': state})}", access_jwt=access)
        self.assertGreaterEqual(wrong_team.status, 400, wrong_team.safe_meta)

        install2 = self.no_redirect_request("GET", "/owner/slack/install", access_jwt=access, headers={"Origin": self.client.base_url})
        self.assertIn(install2.status, {302, 303}, install2.safe_meta)
        state2 = urllib.parse.parse_qs(urllib.parse.urlparse(install2.headers.get("location", "")).query).get("state", [""])[0]
        install_wrong_user = self.no_redirect_request("GET", "/owner/slack/install", access_jwt=access)
        user_state = urllib.parse.parse_qs(urllib.parse.urlparse(install_wrong_user.headers.get("location", "")).query)["state"][0]
        wrong_user = self.client.request("GET", "/owner/slack/callback?" + urllib.parse.urlencode({"code": "fixture-wrong-user", "state": user_state}), access_jwt=access)
        self.assertEqual(wrong_user.status, 403, wrong_user.safe_meta)
        callback = self.client.request("GET", f"/owner/slack/callback?{urllib.parse.urlencode({'code': 'fixture-code', 'state': state2, 'team': SLACK_TEAM_ID})}", access_jwt=access)
        self.assertLess(callback.status, 400, callback.safe_meta)
        replay = self.client.request("GET", f"/owner/slack/callback?{urllib.parse.urlencode({'code': 'fixture-code', 'state': state2, 'team': SLACK_TEAM_ID})}", access_jwt=access)
        self.assertGreaterEqual(replay.status, 400, replay.safe_meta)
        metadata = self.fixture_metadata()
        self.assertEqual(metadata["counters"].get("oauth.v2.access"), 3)

    def no_redirect_request(self, method: str, path: str, *, body: Any | bytes | None = None, access_jwt: str | None = None, headers: dict[str, str] | None = None) -> HttpResult:
        request_headers = dict(headers or {})
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        if access_jwt is not None:
            request_headers["Cf-Access-Jwt-Assertion"] = access_jwt
        request = urllib.request.Request(f"{self.client.base_url}{path}", data=data, headers=request_headers, method=method)
        opener = urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(request, timeout=20) as response:
                raw = response.read()
                return self.client._result(method, path, response.status, response.headers, raw)
        except urllib.error.HTTPError as error:  # type: ignore[name-defined]
            try:
                raw = error.read()
                return self.client._result(method, path, error.code, error.headers, raw)
            finally:
                error.close()

    def test_question_delivery_idempotency_replay_conflict_cancel_and_control_isolation(self) -> None:
        _owner, _agent_id, token = self.enroll_agent(label=unique_name("qdelivery"))
        create_body = {
            "idempotency_key": f"delivery-{secrets.token_hex(6)}",
            "text": "Delivery question",
            "choices": [{"id": "approve", "text": "Approve", "value": "approve"}],
            "deadline_seconds": 300,
        }
        first = self.client.request("POST", "/api/question/create", create_body, bearer=token)
        data = assert_success(self, first)
        replay = self.client.request("POST", "/api/question/create", create_body, bearer=token)
        replay_data = assert_success(self, replay)
        self.assertEqual(replay_data.get("question", replay_data)["id"], data.get("question", data)["id"])
        changed = dict(create_body, text="Changed question")
        conflict = self.client.request("POST", "/api/question/create", changed, bearer=token)
        self.assertIn(conflict.status, {400, 409}, conflict.safe_meta)
        metadata = self.fixture_metadata()
        self.assertEqual(metadata["counters"].get("conversations.open"), 1)
        self.assertEqual(metadata["counters"].get("chat.postMessage"), 1)
        cancel = self.client.request("POST", "/api/question/cancel", {"id": data.get("question", data)["id"], "reason": "integration test"}, bearer=token)
        cancelled = assert_success(self, cancel)
        self.assertEqual(cancelled.get("question", cancelled).get("state"), "cancelled", cancel.safe_meta)
        schema = self.client.request("POST", "/api/sql", {"sql": "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name", "params": []}, bearer=token)
        sql_data = assert_success(self, schema)
        visible_tables = {row.get("name") for row in rows_of(sql_data)}
        self.assertNotIn("slack_installations", visible_tables)
        self.assertNotIn("questions", visible_tables)

    def test_slack_callback_signature_owner_team_message_duplicate_cas_and_thread_reply_resume(self) -> None:
        _owner, _agent_id, token = self.enroll_agent(label=unique_name("qcallback"))
        question = self.create_question(token, channel="C_GENERAL", text="Callback question")
        message = self.fixture_metadata()["messages"][-1]
        unsigned = self.client.request("POST", "/slack/interactions", json.dumps(self.interaction_payload(question_id=question["id"], message=message)).encode("utf-8"), headers={"Content-Type": "application/json"})
        self.assertGreaterEqual(unsigned.status, 400, unsigned.safe_meta)
        wrong_owner = self.signed_post("/slack/interactions", self.interaction_payload(question_id=question["id"], message=message, user="U_INTRUDER"))
        self.assertEqual(wrong_owner.status, 200, wrong_owner.safe_meta)
        self.assertFalse(coerce_data(wrong_owner).get("accepted"), wrong_owner.safe_meta)
        wrong_team = self.signed_post("/slack/interactions", self.interaction_payload(question_id=question["id"], message=message, team="T_INTRUDER"))
        self.assertGreaterEqual(wrong_team.status, 400, wrong_team.safe_meta)
        wrong_message = dict(message, ts="1700000000.999999")
        mismatch = self.signed_post("/slack/interactions", self.interaction_payload(question_id=question["id"], message=wrong_message))
        self.assertGreaterEqual(mismatch.status, 400, mismatch.safe_meta)

        valid_payload = self.interaction_payload(question_id=question["id"], message=message, answer="approve")
        valid = self.signed_post("/slack/interactions", valid_payload)
        self.assertEqual(valid.status, 200, valid.safe_meta)
        status = self.status_question(token, question["id"])
        self.assertEqual(status.get("state"), "answered", status)
        duplicate = self.signed_post("/slack/interactions", valid_payload)
        self.assertEqual(duplicate.status, 200, duplicate.safe_meta)
        losing_payload = self.interaction_payload(question_id=question["id"], message=message, answer="deny")
        losing = self.signed_post("/slack/interactions", losing_payload)
        self.assertIn(losing.status, {200, 409}, losing.safe_meta)
        after_loser = self.status_question(token, question["id"])
        self.assertEqual(after_loser.get("answer"), status.get("answer"), after_loser)

        thread_question = self.create_question(token, channel="C_GENERAL", text="Reply in thread")
        thread_message = self.fixture_metadata()["messages"][-1]
        event = {
            "type": "event_callback",
            "event_id": "Ev_" + secrets.token_hex(12),
            "team_id": SLACK_TEAM_ID,
            "event": {
                "type": "message",
                "user": OWNER_SLACK_ID,
                "channel": thread_message["channel"],
                "thread_ts": thread_message["ts"],
                "text": "thread answer",
            },
        }
        event_result = self.signed_post("/slack/events", event)
        self.assertEqual(event_result.status, 200, event_result.safe_meta)
        thread_status = self.status_question(token, thread_question["id"])
        self.assertEqual(thread_status.get("state"), "answered", thread_status)

    def test_question_expiry_rejects_late_signed_controls(self) -> None:
        _owner, _agent_id, token = self.enroll_agent(label=unique_name("qexpiry"))
        question = self.create_question(token, channel="C_GENERAL", text="Expire me", deadline_seconds=1)
        message = self.fixture_metadata()["messages"][-1]
        time.sleep(2)
        late = self.signed_post("/slack/interactions", self.interaction_payload(question_id=question["id"], message=message, answer="late"))
        self.assertEqual(late.status, 200, late.safe_meta)
        self.assertFalse(coerce_data(late).get("accepted"), late.safe_meta)
        status = self.status_question(token, question["id"])
        self.assertIn(status.get("state"), {"expired", "cancelled"}, status)

    def test_fresh_enrollment_revocation_and_agent_isolation(self) -> None:
        owner, agent_a, token_a = self.enroll_agent(label=unique_name("isolated_a"))
        _owner2, agent_b, token_b = self.enroll_agent(label=unique_name("isolated_b"))
        self.assertNotEqual(agent_a, agent_b)
        question = self.create_question(token_a, channel="C_GENERAL", text="Agent A only")
        cross = self.client.request("POST", "/api/question/status", {"id": question["id"]}, bearer=token_b)
        self.assertGreaterEqual(cross.status, 400, cross.safe_meta)
        revoked = self.client.request("POST", "/owner/revoke", {"id": agent_a}, bearer=owner)
        self.assertLess(revoked.status, 400, revoked.safe_meta)
        after_revoke = self.client.request("GET", "/agent/me", bearer=token_a)
        self.assertGreaterEqual(after_revoke.status, 400, after_revoke.safe_meta)

    def test_mcp_five_tools_and_codemode_zero_retention_durable_denial(self) -> None:
        _owner, _agent_id, token = self.enroll_agent(label=unique_name("mcp"))
        tools = self.client.request("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, bearer=token)
        data = assert_success(self, tools) if isinstance(tools.json, dict) and tools.json.get("ok") is True else tools.json
        self.assertIsInstance(data, dict, tools.safe_meta)
        names = {tool.get("name") for tool in data.get("result", data).get("tools", []) if isinstance(tool, dict)}
        self.assertGreaterEqual(len(names.intersection({"codemode_search", "codemode_execute", "codemode_execution", "codemode_decide", "codemode_cancel"})), 5, names)
        durable_denied = self.client.request("POST", "/api/codemode/zero-retention/execute", {"code": "return await comms.sql({sql:'CREATE TABLE rts_forbidden(id TEXT)',params:[]})"}, bearer=token)
        denied_state = assert_success(self, durable_denied)
        self.assertEqual(denied_state.get("status"), "failed", denied_state)
        self.assertIn(b"zero-retention", durable_denied.body.lower(), durable_denied.safe_meta)

    def test_zero_retention_search_projection_leaves_no_sqlite_bytes(self) -> None:
        _owner, _agent, token = self.enroll_agent(label=unique_name("memory"))
        needle = "rts-" + secrets.token_hex(18)
        seeded = self.client.request_url(self.client.fixture_url + "/api/chat.postMessage", method="POST", body={"channel": "C_GENERAL", "text": needle})
        self.assertEqual(seeded.status, 200, seeded.safe_meta)
        code = "const r = await comms.slack_invoke({method:'assistant.search.context',params:{query:" + json.dumps(needle) + "}}); const results = r.body.results; return {count:results.length,text:results[results.length - 1].text};"
        memory = self.client.request("POST", "/api/codemode/zero-retention/execute", {"code": code}, bearer=token)
        state = assert_success(self, memory)
        self.assertEqual(state.get("status"), "completed", state)
        self.assertEqual(state["result"], {"count": 1, "text": needle})
        state_root = Path(ARGS.state_dir)
        files = list(state_root.rglob("*.sqlite")) + list(state_root.rglob("*.sqlite-wal"))
        self.assertTrue(files, "No local SQLite state found; pass --state-dir for the Worker persistence directory")
        for path in files:
            self.assertNotIn(needle.encode(), path.read_bytes(), "RTS data persisted in " + str(path))
        persisted = self.client.request("POST", "/api/codemode/execute", {"code": code}, bearer=token)
        durable = assert_success(self, persisted).get("execution", {})
        self.assertIn(durable.get("status"), {"failed", "error"}, durable)
        self.assertIn("zero-retention", json.dumps(durable).lower())
        self.assertEqual(self.fixture_metadata()["counters"].get("assistant.search.context"), 1)

    def test_codemode_pause_slack_reply_and_resume(self) -> None:
        _owner, _agent_id, token = self.enroll_agent(label=unique_name("resume"))
        execution = self.client.request("POST", "/api/codemode/execute", {"code": "return await human.ask({key:'ship', prompt:'Ship it?', choices:[{id:'yes', text:'Yes', value:'yes'}]})"}, bearer=token)
        start = assert_success(self, execution)
        self.assertIsInstance(start, dict, execution.safe_meta)
        execution_id = start.get("execution", start).get("id") or start.get("execution_id")
        self.assertTrue(execution_id, start)
        metadata = self.fixture_metadata()
        self.assertGreaterEqual(len(metadata["messages"]), 1, metadata)
        message = metadata["messages"][-1]
        button = extract_button_value(message)
        question_id = str(button.get("question_id") or button.get("id"))
        self.assertTrue(question_id, button)
        answer = self.signed_post("/slack/interactions", self.interaction_payload(question_id=question_id, message=message, answer="yes"))
        self.assertEqual(answer.status, 200, answer.safe_meta)
        deadline = time.time() + 10
        last: HttpResult | None = None
        while time.time() < deadline:
            last = self.client.request("POST", "/api/codemode/execution", {"id": execution_id}, bearer=token)
            if last.status == 200 and coerce_data(last).get("execution", coerce_data(last)).get("status") in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.25)
        self.assertIsNotNone(last)
        self.assertEqual(last.status, 200, last.safe_meta)
        self.assertIn(b"yes", last.body.lower(), last.safe_meta)


if __name__ == "__main__":
    unittest.main(verbosity=2)
