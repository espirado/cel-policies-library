#!/usr/bin/env python3
"""Enforce the signal policies in agentgateway on REAL rci-knowledge traffic.

Runs processors/signal_processor.py (ExtMCP, in-process) and a throwaway agentgateway whose
mcpGuardrails sends every tools/call to it, in front of the hosted server. Then, in one MCP
session per code:

  1. lookup_mpfs(code)                         -> must pass, unannotated
  2. calculate_payment(code), default qpp=true -> returns a different conversion_factor than step 1,
                                                  so contradiction=true and multi_signal_safety_gate
                                                  must DENY it
  3. calculate_payment(code, qpp=false)        -> agrees with step 1, must pass
  4. calculate_payment(code) in a NEW session  -> no history, must pass

Steps 2 and 3 depend on what the server returns today (see README); a FAIL there means the data
changed, not necessarily that the policy is wrong. Read-only tools only.

    RCI_API_KEY=... AGENTGATEWAY_BIN=/path/to/agentgateway python scripts/live_rcintel_processor.py

The key is read from the environment and sent by this client as X-API-Key. It is NOT forwarded to
the processor (the template sets no requestHeaders) and is never printed or written to a file.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "processors"))
sys.path.insert(0, str(ROOT / "scripts"))

import live_rcintel_gateway as lrg  # noqa: E402
import signal_processor as sp  # noqa: E402
import test_gateway as tg  # noqa: E402

CCN = "220071"  # a public Medicare provider number; calculate_payment needs one
CODES = ["99213", "99214", "97110", "10060"]


def main() -> int:
    key = os.environ.get("RCI_API_KEY", "").strip()
    if not key or not tg.BIN:
        print(__doc__)
        return 2
    config = json.loads((ROOT / "processors" / "signal_processor.example.json").read_text())
    server, port = sp.serve(tg.free_port(), config)
    guard = yaml.safe_load((ROOT / "templates" / "agentgateway-signals.yaml").read_text())["mcp"]["policies"]["mcpGuardrails"]
    guard["processors"][0]["host"] = f"127.0.0.1:{port}"
    failures = 0

    def check(label, ok, detail=""):
        nonlocal failures
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {label} {detail}")

    def session(gw):
        _, init, sid = lrg.rpc(gw.url, key, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": lrg.PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "cel-policies-live", "version": "0"}}})
        assert "result" in init, init
        lrg.rpc(gw.url, key, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
        return sid

    def call(gw, sid, tool, args):
        _, out, _ = lrg.rpc(gw.url, key, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                           "params": {"name": tool, "arguments": args}}, sid)
        return out

    def denial(out):
        res = out.get("result") or {}
        return (out.get("error") or {}).get("message") or (
            (res.get("content") or [{}])[0].get("text", "") if res.get("isError") else "")

    try:
        with tempfile.TemporaryDirectory() as d:
            gw = tg.Gateway(tg.SIGNALS_TEMPLATE, lrg.UPSTREAM, Path(d), {"mcpGuardrails": guard})
            with gw:
                for code in CODES:
                    print(f"{code}")
                    sid = session(gw)
                    out = call(gw, sid, "lookup_mpfs", {"code": code})
                    sc = (out.get("result") or {}).get("structuredContent") or {}
                    check("lookup_mpfs passes unannotated", bool(sc.get("results")) and "calibration" not in sc, denial(out))
                    out = call(gw, sid, "calculate_payment", {"ccn": CCN, "cpt": code, "place_of_service": "11"})
                    msg = denial(out)
                    check("calculate_payment (default qpp) denied for contradiction",
                          "multi_signal_safety_gate" in msg and '"contradiction": true' in msg, msg[:110])
                    out = call(gw, sid, "calculate_payment", {"ccn": CCN, "cpt": code, "place_of_service": "11", "qpp": False})
                    pay = ((out.get("result") or {}).get("structuredContent") or {}).get("estimated_payment")
                    check("calculate_payment (qpp=false) passes", pay is not None and not denial(out), f"estimated_payment={pay}")
                    out = call(gw, session(gw), "calculate_payment", {"ccn": CCN, "cpt": code, "place_of_service": "11"})
                    check("calculate_payment in a new session passes (no history)", not denial(out) and "result" in out)
    finally:
        server.stop(0)
    print(f"\n{'all checks passed' if not failures else f'{failures} check(s) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
