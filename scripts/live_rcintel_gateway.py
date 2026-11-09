#!/usr/bin/env python3
"""Validate the result guardrails against the real rci-knowledge MCP server through agentgateway.

Starts throwaway agentgateway instances from templates/agentgateway-calibration.yaml with the
target pointed at the hosted server and calls read-only tools through them.

  A. lookup_mpfs, as shipped: real codes must pass UNCHANGED (an annotation or rejection would be
     a false positive on real data). Unknown codes are 404 tool errors and pass through.
  B. lookup_opps (flat result): CPT 99213 has no OPPS payment fields (status indicator B), so the
     flat completeness rule must REJECT it; CPT 71046 has payment data and must pass. Real data.
  C. list_dataset_snapshots: the snapshot-age rule must ANNOTATE the response and name the
     datasets whose effective_date is over a year old. Real data.
  D. Mechanism check only: the real server never returns an incomplete lookup_mpfs row or a
     superseded fee-schedule year, so those two rules are run on a real payload with ONE parameter
     changed (a required list containing a field that is null in every real row; the year rule
     shifted by one year). This shows the reject/annotate path works on a real payload; it does
     NOT show that the server returns such data.

    RCI_API_KEY=... AGENTGATEWAY_BIN=/path/to/agentgateway python scripts/live_rcintel_gateway.py

Exit code 1 if any check fails. The key is read from the environment, sent by this client as
X-API-Key (the gateway forwards it), and never printed or written to a config file.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import test_gateway as tg  # noqa: E402

UPSTREAM = "https://api.rcintell.com/v1/mcp"
PROTOCOL = "2025-03-26"
FOUND = ["99213", "99214", "36415", "97110", "10060", "27447", "59400", "92014", "0100T", "1000F", "G0008", "J0585"]
NOT_FOUND = ["E0100", "00000"]
REQUIRED_LIST = '["hcpcs_code", "short_descriptor", "work_rvu", "total_rvu_facility",\n            "total_rvu_nonfacility", "conversion_factor", "year"]'


def rpc(url, key, body, sid=None, token=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "goose/1.0",  # the hosted server's Cloudflare rejects urllib's default UA
        "MCP-Protocol-Version": PROTOCOL,
        "X-API-Key": key,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if sid:
        headers["Mcp-Session-Id"] = sid
    req = urllib.request.Request(url, json.dumps(body).encode(), headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            text, status, new = r.read().decode().strip(), r.status, r.headers.get("mcp-session-id")
    except urllib.error.HTTPError as e:
        return e.code, {"http_error": e.read(200).decode(errors="replace")}, sid
    if text.startswith(("event:", "data:")):
        text = next(l[5:].strip() for l in text.splitlines() if l.startswith("data:"))
    return status, (json.loads(text) if text else {}), new or sid


def classify(out):
    res = out.get("result") or {}
    sc = res.get("structuredContent") or {}
    if out.get("error"):
        return "rejected", out["error"].get("message", "")
    if res.get("isError"):
        return "tool_error", (res.get("content") or [{}])[0].get("text", "")[:60]
    if "calibration" in sc:
        return "annotated", sc["calibration"]
    return "unchanged", ""


def run(template_path, key, calls, tmp):
    """calls: list of (tool, arguments). Returns a list of (kind, detail) in order."""
    results = []
    gw = tg.Gateway(template_path, UPSTREAM, tmp)
    with gw:
        _, init, sid = rpc(gw.url, key, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "cel-policies-live", "version": "0"}}})
        if "result" not in init:
            raise SystemExit(f"initialize through gateway failed: {init}")
        rpc(gw.url, key, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
        for tool, args in calls:
            _, out, _ = rpc(gw.url, key, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                           "params": {"name": tool, "arguments": args}}, sid)
            results.append(classify(out))
    return results


def variant(tmp, name, edit):
    text = tg.CALIB.read_text()
    new = edit(text)
    assert new != text, "variant edit did not change the template"
    p = tmp / name
    p.write_text(new)
    return p


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

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)

        calls = ([("lookup_mpfs", {"code": c}) for c in FOUND + NOT_FOUND]
                 + [("lookup_opps", {"code": "99213"}), ("lookup_opps", {"code": "71046"}),
                    ("list_dataset_snapshots", {})])
        res = run(tg.CALIB, key, calls, tmp)

        print("A. lookup_mpfs as shipped (no false positives expected)")
        for code, (kind, detail) in zip(FOUND, res):
            check(f"{code} unchanged", kind == "unchanged", detail)
        for code, (kind, detail) in zip(NOT_FOUND, res[len(FOUND):]):
            check(f"{code} not found -> tool error passes through", kind == "tool_error", detail)

        print("B. lookup_opps (flat result), real incompleteness")
        (k1, d1), (k2, d2) = res[len(FOUND) + len(NOT_FOUND):][:2]
        check("99213 (no OPPS payment fields) rejected", k1 == "rejected" and "completeness < 0.4" in d1, d1)
        check("71046 (payment data present) unchanged", k2 == "unchanged", str(d2))

        print("C. list_dataset_snapshots, real snapshot age")
        kind, detail = res[-1]
        flagged = detail.get("datasets", []) if kind == "annotated" else []
        check("response annotated", kind == "annotated", str(detail)[:120])
        print(f"        datasets flagged (effective_date over 365 days old): {flagged}")
        check("current-year datasets (mpfs, ncci) not flagged", not ({"mpfs", "ncci"} & set(flagged)), str(flagged))

        print("D. mechanism checks on a real lookup_mpfs payload, one parameter changed")
        edit = lambda t: t.replace(REQUIRED_LIST, '["modifier", "hcpcs_code", "no_such_field_a", "no_such_field_b"]')
        res = run(variant(tmp, "d1.yaml", edit), key, [("lookup_mpfs", {"code": c}) for c in ("99213", "99214", "97110")], tmp)
        for code, (kind, detail) in zip(("99213", "99214", "97110"), res):
            check(f"{code} rejected (required list changed)", kind == "rejected" and "completeness < 0.4" in detail, str(detail))
        edit = lambda t: t.replace("int(r.year) < timestamp(request.startTime).getFullYear())",
                                   "int(r.year) < timestamp(request.startTime).getFullYear() + 1)")
        res = run(variant(tmp, "d2.yaml", edit), key, [("lookup_mpfs", {"code": c}) for c in ("99213", "99214", "97110")], tmp)
        for code, (kind, detail) in zip(("99213", "99214", "97110"), res):
            check(f"{code} annotated, call not blocked (year rule shifted)", kind == "annotated", str(detail))

    print(f"\n{'all checks passed' if not failures else f'{failures} check(s) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
