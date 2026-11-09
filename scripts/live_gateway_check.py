#!/usr/bin/env python3
"""Check that a live agentgateway agrees with this library's authorization policies.

For each tool, the library evaluator predicts ALLOW/DENY from the two rules in
templates/agentgateway.yaml (OR semantics). The script then asks the gateway:
is the tool listed, and does tools/call succeed? Any disagreement exits 1.

    python scripts/live_gateway_check.py --url http://127.0.0.1:3199/mcp \
        --tools grant_read_access grant_admin_access [--token JWT]

Without --token no JWT is sent, so `jwt` is empty on both sides. With --token
the gateway must be configured with jwtAuth; the token's (unverified) claims
are passed to the library evaluator as `jwt`.
Stdlib plus this repo's cel_policies (needs the venv with cel-python).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cel_policies as cp  # noqa: E402

RULES = ["authorization/allow_harmless", "authorization/require_operator"]
PROTOCOL = "2024-11-05"


def rpc(url, method, params=None, session=None, notify=False, token=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session:
        headers["Mcp-Session-Id"] = session
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    if not notify:
        body["id"] = 1
    req = urllib.request.Request(url, json.dumps(body).encode(), headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            sid = resp.headers.get("mcp-session-id") or session
            text = resp.read().decode().strip()
            status = resp.status
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read(300).decode(errors="replace")}, session
    if not text:
        return status, {}, sid
    if text.startswith(("event:", "data:")):
        for line in text.splitlines():
            if line.startswith("data:"):
                text = line[5:].strip()
                break
    return status, json.loads(text), sid


def claims_of(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def library_allows(tool: str, claims=None) -> bool:
    data = {"mcp": {"tool": {"name": tool}}}
    if claims is not None:
        data["jwt"] = claims
    return any(cp.evaluate(r, data).verdict == cp.ALLOW for r in RULES)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--tools", nargs="+", required=True)
    ap.add_argument("--token", help="bearer JWT (gateway needs jwtAuth)")
    args = ap.parse_args()
    tok = args.token
    claims = claims_of(tok) if tok else None

    _, init, sid = rpc(args.url, "initialize", {
        "protocolVersion": PROTOCOL, "capabilities": {},
        "clientInfo": {"name": "cel-policies-live-check", "version": "0"},
    }, token=tok)
    if "result" not in init:
        print(f"initialize failed: {init}")
        return 2
    rpc(args.url, "notifications/initialized", session=sid, notify=True, token=tok)
    _, listing, _ = rpc(args.url, "tools/list", {}, session=sid, token=tok)
    listed = {t["name"] for t in listing.get("result", {}).get("tools", [])}
    print(f"gateway lists: {sorted(listed)}")

    disagreements = 0
    for tool in args.tools:
        predicted = library_allows(tool, claims)
        status, out, _ = rpc(args.url, "tools/call",
                             {"name": tool, "arguments": {"contractor": "Ava Chen"}},
                             session=sid, token=tok)
        call_ok = status < 400 and "result" in out and not out["result"].get("isError")
        listed_ok = tool in listed
        if listed_ok != call_ok:
            disagreements += 1
            print(f"DIFF {tool}: tools/list and tools/call disagree "
                  f"(listed={listed_ok}, call_ok={call_ok}, http={status})")
            continue
        ok = predicted == call_ok
        disagreements += 0 if ok else 1
        print(f"{'OK  ' if ok else 'DIFF'} {tool}: library={'ALLOW' if predicted else 'DENY'} "
              f"gateway={'allowed' if call_ok else 'denied'} "
              f"(listed={listed_ok}, http={status})")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
