#!/usr/bin/env python3
"""Score REAL tool results from rci-knowledge and run the signal policies on them.

For each code it makes three read-only calls: `lookup_mpfs`, `calculate_payment` (default,
which uses the QPP conversion factor) and `calculate_payment` with qpp=false. The two tools
report overlapping facts (work/PE/MP RVUs, conversion factor), so comparing them gives a real
cross-tool `contradiction` signal.

Signals, computed with mcp-trace-gate's own scoring functions:
  completeness   fraction of 7 requested fields present in the lookup_mpfs row
  contradiction  score_contradiction(calculate_payment vs lookup_mpfs) on RVU/CF keys
  currency       validity-based: 1.0 if list_dataset_snapshots reports the MPFS snapshot as current
                 and effective this calendar year, else 0.0. The linear-decay formula is printed
                 too, to show why it is not used (it scores current annual data as stale).

Each policy is then evaluated three ways and must agree: cel-python (the offline CLI), the
mcp-trace-gate PolicyGate tiers, and agentgateway's own CEL engine (signals sent as tool-call
arguments, expression read from `mcp.params.arguments` in a request-phase guardrail; the only
text change is prefixing the three signal names with `s.`).

    RCI_API_KEY=... AGENTGATEWAY_BIN=/path/to/agentgateway python scripts/live_rcintel_signals.py

Exit code 1 if the engines disagree. Key from the environment only; never printed.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT.parent / "mcp-trace-gate"))

import cel_policies as cp  # noqa: E402
import live_rcintel_gateway as lrg  # noqa: E402  (rpc helper for the hosted server)
import test_gateway as tg  # noqa: E402
from src.calibration import ToolResult, score_completeness, score_contradiction, score_currency  # noqa: E402
from src.gate import PolicyGate  # noqa: E402
from src.span import CalibrationScores  # noqa: E402

POLICIES = [
    "calibration/block_contradiction", "calibration/block_incomplete", "calibration/review_stale_data",
    "combined/multi_signal_safety_gate", "combined/moderate_safety_gate",
]
REQUESTED = ["hcpcs_code", "short_descriptor", "work_rvu", "total_rvu_facility",
             "total_rvu_nonfacility", "conversion_factor", "year"]
KEYS = ["work_rvu", "pe_rvu", "mp_rvu", "conversion_factor"]
CCN = "220071"  # a public Medicare provider number; calculate_payment needs one


class Server:
    def __init__(self, key):
        self.key = key
        _, init, self.sid = lrg.rpc(lrg.UPSTREAM, key, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": lrg.PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "cel-policies-live", "version": "0"}}})
        if "result" not in init:
            raise SystemExit(f"initialize failed: {init}")
        lrg.rpc(lrg.UPSTREAM, key, {"jsonrpc": "2.0", "method": "notifications/initialized"}, self.sid)

    def call(self, name, args):
        _, out, _ = lrg.rpc(lrg.UPSTREAM, self.key, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                                      "params": {"name": name, "arguments": args}}, self.sid)
        res = out.get("result") or {}
        if res.get("isError") or "structuredContent" not in res:
            raise SystemExit(f"{name}{args} failed: {out}")
        return res["structuredContent"]


def gateway_matches(policy: str, vectors: list[dict], mock_url: str, tmp: Path) -> list[bool]:
    expr = tg.normalize((ROOT / "policies" / f"{policy}.cel").read_text())
    bound = re.sub(r"\b(contradiction|completeness|currency)\b", r"s.\1", expr)
    base = tmp / "t.yaml"
    base.write_text("mcp:\n  port: 0\n  policies: {}\n  targets:\n  - name: m\n    mcp:\n      host: x\n")
    pol = {"mcpGuardrails": {"processors": [{
        "kind": "expression", "condition": f"mcp.params.arguments.with(s, {bound})",
        "reject": "MATCH", "methods": {"tools/call": "request"}}]}}
    out = []
    with tg.Gateway(base, mock_url, tmp, pol) as gw:
        sid = gw.session()
        for v in vectors:
            _, resp = gw.call(sid, "lookup_mpfs", {"case": "full", **v})
            res = resp.get("result") or {}
            out.append(res.get("isError") is True and (res.get("content") or [{}])[0].get("text") == "MATCH")
    return out


def main() -> int:
    key = os.environ.get("RCI_API_KEY", "").strip()
    if not key or not tg.BIN:
        print(__doc__)
        return 2
    srv = Server(key)
    today = dt.date.today()

    snap = srv.call("list_dataset_snapshots", {"dataset": "mpfs", "current_only": True})["snapshots"][0]
    eff = dt.date.fromisoformat(snap["effective_date"])
    cy_valid = 1.0 if snap["is_current"] and eff.year == today.year else 0.0
    probe = ToolResult("snapshot", {}, [], [], float((today - eff).days), 365.0)
    print(f"MPFS snapshot {snap['version']}: effective {eff}, is_current={snap['is_current']}")
    print(f"currency: validity-based = {cy_valid}; linear-decay (365-day horizon from effective date) = "
          f"{score_currency(probe)}  <- would flag the current schedule as stale\n")

    rows = []  # (label, signals)
    for code in ["99213", "99214", "97110", "10060"]:
        lookup = srv.call("lookup_mpfs", {"code": code})["results"][0]
        completeness = score_completeness(ToolResult("lookup_mpfs", {}, REQUESTED,
                                                     [f for f in REQUESTED if lookup.get(f) is not None], 0, 365))
        lk = ToolResult("lookup_mpfs", {"work_rvu": lookup["work_rvu"], "pe_rvu": lookup["pe_rvu_nonfacility"],
                                         "mp_rvu": lookup["mp_rvu"], "conversion_factor": lookup["conversion_factor"]},
                        REQUESTED, REQUESTED, 0, 365, contradiction_keys=KEYS)
        for label, qpp in (("calculate_payment default (qpp=true)", None), ("calculate_payment qpp=false", False)):
            args = {"ccn": CCN, "cpt": code, "place_of_service": "11"}
            if qpp is not None:
                args["qpp"] = qpp
            ph = srv.call("calculate_payment", args)["physician"]
            cr = ToolResult("calculate_payment", {k: ph[k if k != "pe_rvu" else "pe_rvu"] for k in KEYS},
                            [], [], 0, 365, contradiction_keys=KEYS)
            diffs = {k: (lookup["pe_rvu_nonfacility"] if k == "pe_rvu" else lookup[k], ph[k])
                     for k in KEYS if (lookup["pe_rvu_nonfacility"] if k == "pe_rvu" else lookup[k]) != ph[k]}
            sig = CalibrationScores(completeness=completeness, currency=cy_valid,
                                    contradiction=score_contradiction(cr, [lk]))
            rows.append((f"{code} vs {label}", sig, diffs))

    vectors = [r[1].as_cel_input() for r in rows]
    gate = PolicyGate()
    with tempfile.TemporaryDirectory() as d:
        mock_port = tg.free_port()
        mock = subprocess.Popen([sys.executable, str(ROOT / "tests/gateway/mock_mcp.py"), "--port", str(mock_port)])
        try:
            tg.wait_port(mock_port, mock)
            gw = {p: gateway_matches(p, vectors, f"http://127.0.0.1:{mock_port}/mcp", Path(d)) for p in POLICIES}
        finally:
            mock.terminate()
            mock.wait()

    disagreements = 0
    for i, (label, sig, diffs) in enumerate(rows):
        v = vectors[i]
        print(f"{label}")
        print(f"   signals {json.dumps({k: round(x, 3) if isinstance(x, float) else x for k, x in v.items()})}"
              f"   trace-gate tier={gate.evaluate(sig)}")
        if diffs:
            print(f"   fields differing between the two tools: {diffs}")
        for p in POLICIES:
            py = cp.evaluate(p, v)
            agree = py.matched == gw[p][i]
            disagreements += 0 if agree else 1
            print(f"   {p:36s} {py.verdict:8s} cel-python={py.matched} agentgateway={gw[p][i]} {'agree' if agree else 'DISAGREE'}")
        # trace-gate's tiers are defined by block.cel / review.cel; check the library reproduces them
        lib_block = any(cp.evaluate(p, v).matched for p in ("calibration/block_contradiction", "calibration/block_incomplete"))
        tier = gate.evaluate(sig)
        if lib_block != (tier == "block"):
            disagreements += 1
            print(f"   DISAGREE with trace-gate: library block={lib_block} tier={tier}")
    print(f"\n{'engines agree on every policy and vector' if not disagreements else f'{disagreements} disagreement(s)'}")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
