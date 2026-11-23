#!/usr/bin/env python3
"""Smoke-test `itriage --mcp` over real pipes, as an MCP client would.

Usage: check-mcp.py COMMAND [ARG...]
  e.g. check-mcp.py cargo run -q -p itriage-core --example triage -- --mcp

Speaks both protocol generations (a 2026-07-28 request with _meta, and the
2025-11-25 initialize handshake in a second process), runs a preset with a
progress token, checks that a change is refused, and that stdout carries
nothing but JSON-RPC. Exits 1 on the first thing that's wrong.
"""
import json
import subprocess
import sys
import time

META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "check-mcp.py", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def fail(why):
    print(f"::error::MCP smoke test: {why}")
    sys.exit(1)


class Client:
    def __init__(self, command):
        self.p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        self.seen = []

    def send(self, message):
        self.p.stdin.write(json.dumps(message) + "\n")
        self.p.stdin.flush()

    def reply(self, wanted, timeout=300):
        end = time.time() + timeout
        while time.time() < end:
            line = self.p.stdout.readline()
            if not line:
                fail(f"the server closed stdout before answering {wanted}; stderr: {self.p.stderr.read()}")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                fail(f"stdout carried something that isn't JSON: {line!r}")
            self.seen.append(message)
            if message.get("id") == wanted:
                return message
        fail(f"no answer to {wanted} in {timeout} s")

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=120)
        return self.p.returncode, self.p.stderr.read()


def call(client, id_, name, arguments, meta=META):
    client.send({"jsonrpc": "2.0", "id": id_, "method": "tools/call", "params": {"name": name, "arguments": arguments, "_meta": meta}})
    return client.reply(id_)


def main():
    command = sys.argv[1:]
    if not command:
        fail("give the command that starts the server")

    c = Client(command)
    c.send({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": META}})
    d = c.reply(1).get("result") or fail("server/discover failed")
    if "2026-07-28" not in d["supportedVersions"] or d.get("resultType") != "complete":
        fail(f"unexpected discovery result: {d}")

    listed = call(c, 2, "list_checks", {})["result"]["structuredContent"]
    ids = [x["id"] for x in listed["checks"]]
    if "system.memory" not in ids or any(i.startswith(("fix.", "update.apply", "update.firmware")) for i in ids):
        fail(f"the check list is wrong: {ids}")

    refused = call(c, 3, "run_checks", {"checks": ["fix.restart"]})["result"]
    if not refused.get("isError"):
        fail(f"a change wasn't refused: {refused}")

    meta = dict(META, progressToken="smoke")
    run = call(c, 4, "run_checks", {"preset": "health", "ticket": "CI-MCP"}, meta)["result"]
    if run.get("isError"):
        fail(f"the health preset failed: {run}")
    s = run["structuredContent"]
    progress = [m for m in c.seen if m.get("method") == "notifications/progress"]
    if not progress or not s["results"] or s["redacted"] is not True or s.get("ticket") != "CI-MCP":
        fail(f"the run's result is incomplete: {len(progress)} progress, {s}")
    print(f"health preset over MCP: {len(s['results'])} checks, worst {s['worst']}, {len(progress)} progress notes")

    recent = call(c, 5, "recent_runs", {"limit": 1})["result"]
    if recent.get("isError"):
        fail(f"recent_runs failed: {recent}")
    code, stderr = c.close()
    if code != 0 or "MCP server (read-only)" not in stderr:
        fail(f"exit {code}, stderr: {stderr}")

    legacy = Client(command)
    legacy.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "check-mcp.py", "version": "1"}}})
    init = legacy.reply(1)["result"]
    if init["protocolVersion"] != "2025-11-25":
        fail(f"the legacy handshake failed: {init}")
    legacy.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    legacy.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    names = [t["name"] for t in legacy.reply(2)["result"]["tools"]]
    if names != ["list_checks", "run_checks", "recent_runs"]:
        fail(f"unexpected tools: {names}")
    legacy.close()
    print("MCP server: modern and legacy clients served; changes refused; stdout was JSON only")


if __name__ == "__main__":
    main()
