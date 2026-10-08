#!/usr/bin/env python3
"""Native MCP zero-retention acceptance against the emulator only."""
import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
original = sys.argv[:]
sys.argv = [sys.argv[0]]
from integration import CommsClient, CommsIntegrationTest
sys.argv = original

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://127.0.0.1:9511")
parser.add_argument("--fixture-url", default="http://127.0.0.1:9412")
parser.add_argument("--state-dir", default=".wrangler/state")
args = parser.parse_args()
helper = CommsIntegrationTest()
helper.client = CommsClient(args.url, args.fixture_url)
owner, agent, token = helper.enroll_agent(label="memory-mcp", ttl_seconds=300)
needle = "native-memory-" + secrets.token_hex(16)
seeded = helper.client.request_url(args.fixture_url+"/api/chat.postMessage", method="POST",
    body={"channel":"D_OWNER","text":needle})
assert seeded.status == 200
env = {"COMMS_URL":args.url,"COMMS_TOKEN":token,"COMMS_CODEMODE_RETENTION":"memory",
    "PATH":os.environ.get("PATH","")}
proc = subprocess.Popen(["target/debug/comms","--mcp"], env=env,
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
meta = {"io.modelcontextprotocol/protocolVersion":"2026-07-28",
    "io.modelcontextprotocol/clientCapabilities":{},
    "io.modelcontextprotocol/clientInfo":{"name":"memory-test","version":"1"}}
def rpc(rpc_id, name, arguments):
    helper._send_mcp(proc, {"jsonrpc":"2.0","id":rpc_id,"method":"tools/call",
        "params":{"_meta":meta,"name":name,"arguments":arguments}})
    response = helper._read_mcp(proc)
    assert "error" not in response, response
    return response["result"]
try:
    helper._send_mcp(proc, {"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":meta}})
    discovery = helper._read_mcp(proc)
    assert "error" not in discovery, discovery
    code = "const r = await comms.slack_invoke({method:'assistant.search.context',params:{query:" + json.dumps(needle) + "}}); return {text:r.body.results[0].text};"
    result = rpc(2,"codemode_execute",{"code":code})
    assert not result.get("isError"), result
    execution = helper.mcp_structured_content(result)
    assert execution["status"] == "completed", execution
    assert execution["result"] == {"text":needle}, execution
    for rpc_id, name, arguments in [
        (3,"codemode_execution",{"id":execution["id"]}),
        (4,"codemode_decide",{"id":execution["id"],"seq":0,"decision":"approve"}),
        (5,"codemode_cancel",{"id":execution["id"]}),
    ]:
        denied = rpc(rpc_id,name,arguments)
        assert denied.get("isError"), (name, denied)
        assert "Memory-only" in json.dumps(denied), denied
    files = list(Path(args.state_dir).rglob("*.sqlite")) + list(Path(args.state_dir).rglob("*.sqlite-wal"))
    assert files, "No emulator state inspected"
    for path in files:
        assert needle.encode() not in path.read_bytes(), "Search result retained in "+str(path)
    print(json.dumps({"native_memory_mcp_completed":True,"durable_lifecycle_denied":True,
        "no_search_bytes_in_sqlite":True}))
finally:
    proc.kill()
    proc.communicate(timeout=5)
    helper.client.request("POST","/owner/revoke",{"id":agent},bearer=owner)
