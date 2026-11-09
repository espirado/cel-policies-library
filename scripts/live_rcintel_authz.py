#!/usr/bin/env python3
"""Authorization policies on the REAL rci-knowledge tool list, with REAL Keycloak tokens.

agentgateway sits in front of the hosted server (45 tools) with templates/agentgateway-rci-knowledge.yaml
(jwtAuth against a Keycloak realm + the two authorization rules) and the result guardrails from
templates/agentgateway-calibration.yaml merged in. For each caller:

  anonymous         sees exactly the lookup_*/list_* tools; lookup_mpfs works; calculate_payment and
                    check_ncci_mue (a real tool no rule allows) are denied
  operator token    additionally sees every calculate_* tool; calculate_payment returns a payment
  viewer/admin/no-role tokens   see the same as anonymous (calculate_* needs the operator role)

and the guardrails still fire in the same config (lookup_opps for CPT 99213 is rejected).

    RCI_API_KEY=... KEYCLOAK_URL=http://127.0.0.1:19180 AGENTGATEWAY_BIN=... python scripts/live_rcintel_authz.py

Read-only tools only. Keys and tokens are never printed; the API key is not written to a file.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

import live_rcintel_gateway as lrg  # noqa: E402
import test_gateway as tg  # noqa: E402

KC = os.environ.get("KEYCLOAK_URL", "http://127.0.0.1:19180").rstrip("/")
REALM = f"{KC}/realms/cel"
TEMPLATE = ROOT / "templates" / "agentgateway-rci-knowledge.yaml"
CCN = "220071"


def keycloak_token(user):
    body = urllib.parse.urlencode({"grant_type": "password", "client_id": "agw", "username": user,
                                   "password": f"pw-{user}", "scope": "openid"}).encode()
    return json.loads(urllib.request.urlopen(f"{REALM}/protocol/openid-connect/token", body, timeout=10).read())["access_token"]


def open_session(url, key, token=None):
    _, init, sid = lrg.rpc(url, key, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": lrg.PROTOCOL, "capabilities": {},
        "clientInfo": {"name": "cel-policies-live", "version": "0"}}}, token=token)
    assert "result" in init, init
    lrg.rpc(url, key, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, token)
    return sid


def tool_names(url, key, sid, token=None):
    _, out, _ = lrg.rpc(url, key, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}, sid, token)
    return {t["name"] for t in out["result"]["tools"]}


def call(url, key, sid, tool, args, token=None):
    _, out, _ = lrg.rpc(url, key, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                    "params": {"name": tool, "arguments": args}}, sid, token)
    return out


def main() -> int:
    key = os.environ.get("RCI_API_KEY", "").strip()
    if not key or not tg.BIN:
        print(__doc__)
        return 2
    failures = 0

    def check(label, ok, detail=""):
        nonlocal failures
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {label} {detail}")

    # the real tool list, straight from the server (no gateway)
    sid = open_session(lrg.UPSTREAM, key)
    everything = tool_names(lrg.UPSTREAM, key, sid)
    open_tools = {t for t in everything if t.startswith(("lookup_", "list_"))}
    calc_tools = {t for t in everything if t.startswith("calculate_")}
    print(f"server exposes {len(everything)} tools: {len(open_tools)} lookup_/list_, {len(calc_tools)} calculate_, "
          f"{len(everything) - len(open_tools) - len(calc_tools)} others\n")

    cfg = yaml.safe_load(TEMPLATE.read_text())
    cfg["mcp"]["policies"]["jwtAuth"]["issuer"] = REALM
    cfg["mcp"]["policies"]["jwtAuth"]["jwks"]["url"] = f"{REALM}/protocol/openid-connect/certs"
    guard = yaml.safe_load(tg.CALIB.read_text())["mcp"]["policies"]["mcpGuardrails"]
    cfg["mcp"]["policies"]["mcpGuardrails"] = guard

    with tempfile.TemporaryDirectory() as d:
        tmpl = Path(d) / "rci.yaml"
        tmpl.write_text(yaml.safe_dump(cfg, width=10_000))
        with tg.Gateway(tmpl, lrg.UPSTREAM, Path(d)) as gw:
            for user in (None, "op", "view", "adm", "norole"):
                tok = keycloak_token(user) if user else None
                label = user or "anonymous"
                sid = open_session(gw.url, key, tok)
                seen = tool_names(gw.url, key, sid, tok)
                expect = open_tools | (calc_tools if user == "op" else set())
                print(f"{label}")
                check(f"tools/list is exactly {len(expect)} tools", seen == expect,
                      f"(extra {sorted(seen - expect)[:3]}, missing {sorted(expect - seen)[:3]})")
                out = call(gw.url, key, sid, "lookup_mpfs", {"code": "99213"}, tok)
                sc = (out.get("result") or {}).get("structuredContent") or {}
                check("lookup_mpfs works, guardrails leave it unchanged", bool(sc.get("results")) and "calibration" not in sc)
                out = call(gw.url, key, sid, "calculate_payment",
                           {"ccn": CCN, "cpt": "99213", "place_of_service": "11", "qpp": False}, tok)
                paid = ((out.get("result") or {}).get("structuredContent") or {}).get("estimated_payment")
                check("calculate_payment " + ("allowed" if user == "op" else "denied"),
                      (paid is not None) if user == "op" else (paid is None),
                      f"estimated_payment={paid}")
                if user is None:
                    out = call(gw.url, key, sid, "check_ncci_mue", {"code": "99213"}, tok)
                    check("check_ncci_mue (real tool, no rule allows it) denied", "result" not in out or (out["result"] or {}).get("isError") is True)
                    out = call(gw.url, key, sid, "lookup_opps", {"code": "99213"}, tok)
                    check("guardrail still rejects lookup_opps 99213 in the same config",
                          "completeness < 0.4" in ((out.get("error") or {}).get("message", "")), str(out.get("error"))[:80])
    print(f"\n{'all checks passed' if not failures else f'{failures} check(s) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
