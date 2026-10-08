#!/usr/bin/env python3
"""Cross-process profile acceptance against the local Worker and native Keychain."""
import argparse
import json
import os
import secrets
import subprocess
import sys
import urllib.parse

original = sys.argv
sys.argv = [sys.argv[0]]
sys.path.insert(0, os.path.dirname(__file__))
from integration import CommsClient, coerce_data
sys.argv = original

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:9411")
    parser.add_argument("--fixture-url", default="http://127.0.0.1:9412")
    parser.add_argument("--cli", default="target/debug/comms")
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise RuntimeError("This acceptance test requires the native macOS Keychain")
    client = CommsClient(args.url, args.fixture_url)
    started = client.request("POST", "/auth/start", {})
    assert started.status == 200, started.safe_meta
    device = coerce_data(started)
    access = client.access_token(email='owner@example.com', aud='comms-local-tests')
    approved = client.request("POST", "/owner/approve", {"user_code": device["user_code"]}, access_jwt=access, headers={"Origin": args.url})
    assert approved.status == 200, approved.safe_meta
    finished = client.request("POST", "/auth/poll", {"device_code": device["device_code"]})
    assert finished.status == 200, finished.safe_meta
    owner = coerce_data(finished)["owner_token"]
    base = args.url.rstrip("/") + "/?profile-acceptance=" + secrets.token_hex(10)
    env = dict(os.environ, COMMS_URL=base, COMMS_OWNER_TOKEN=owner)
    for key in ("COMMS_PROFILE", "COMMS_TOKEN", "COMMS_VAULT_EXECUTABLE"):
        env.pop(key, None)
    profiles = {None, "builder", "injected-builder"}
    enrollment_id = None
    injected_id = None
    def run(*argv, selected=None):
        actual = dict(env)
        if selected is not None:
            actual["COMMS_PROFILE"] = selected
        result = subprocess.run([args.cli, *argv, "--format", "json"], env=actual, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, (argv, result.returncode, result.stderr[:200], json.loads(result.stdout).get("error", {}).get("code"))
        value = json.loads(result.stdout)
        assert value.get("ok", True), list(value)
        assert owner not in result.stdout
        data = value.get("data", value)
        assert not {"token", "renewal", "enrollment", "owner_token"}.intersection(data), list(data)
        return data
    try:
        response = client.request("POST", "/owner/enrollments", {"label": "injected swarm"}, bearer=owner)
        assert response.status == 200, response.safe_meta
        injected = coerce_data(response)
        injected_id = injected["enrollment_id"]
        env["COMMS_ENROLLMENT_SECRET"] = injected["enrollment"]
        joined = run("profile", "join", "--profile", "injected-builder", "--label", "injected builder")
        assert joined["root_enrollment_id"] == injected_id
        env.pop("COMMS_ENROLLMENT_SECRET")
        renewed = run("profile", "join", "--profile", "injected-builder")
        assert joined["agent_id"] == renewed["agent_id"]
        who = run("agent", "whoami", selected="injected-builder")
        assert who["agent_id"] == joined["agent_id"]
        enrollment = run("profile", "enroll", "--label", "profile acceptance")
        enrollment_id = enrollment["enrollment_id"]
        first = run("profile", "join", "--label", "fresh one")
        profiles.add(first["local_profile"])
        second = run("profile", "join", "--label", "fresh two")
        profiles.add(second["local_profile"])
        assert first["agent_id"] != second["agent_id"]
        named = run("profile", "join", "--profile", "builder", "--label", "named")
        reused = run("profile", "join", "--profile", "builder")
        assert named["agent_id"] == reused["agent_id"]
        who = run("agent", "whoami", selected="builder")
        assert who["agent_id"] == named["agent_id"]
        print(json.dumps({"fresh_identities_distinct": True, "named_identity_reused": True, "env_profile_authenticated": True, "injected_enrollment_joined": True, "secret_output": False}))
    finally:
        for revoke_id in (enrollment_id, injected_id):
            if revoke_id:
                client.request("POST", "/owner/revoke", {"id": revoke_id}, bearer=owner)
        for profile in profiles:
            for kind in ("agent", "renewal", "agent-id", "enrollment", "enrollment-id", "owner"):
                account = base + ":" + (profile or "default") + ":" + kind
                cleanup = subprocess.run(["security", "delete-generic-password", "-s", "comms.slack.agent", "-a", account], capture_output=True)
                if cleanup.returncode not in (0, 44):
                    raise RuntimeError("Native fixture credential cleanup failed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
