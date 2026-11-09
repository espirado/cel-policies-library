#!/usr/bin/env python3
"""Tiny streamable-HTTP MCP server that returns controllable tool results.

Used to test agentgateway policies against known inputs. One tool, `lookup_mpfs`,
whose `case` argument selects the result shape (modelled on rci-knowledge's
`lookup_mpfs`): full, mid, partial, empty, error, stale.

    python tests/gateway/mock_mcp.py --port 8091
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIELDS = {
    "hcpcs_code": "99213",
    "short_descriptor": "Office o/p est low 20 min",
    "work_rvu": 1.3,
    "total_rvu_facility": 1.72,
    "total_rvu_nonfacility": 2.85,
    "conversion_factor": 33.4009,
    "pe_rvu_nonfacility": 1.46,
    "mp_rvu": 0.09,
}

TOOL = {
    "name": "lookup_mpfs",
    "description": "Fee lookup with controllable result shape.",
    "inputSchema": {
        "type": "object",
        "properties": {"case": {"type": "string"}},
        "required": ["case"],
    },
}
GRANT_TOOLS = [
    {"name": n, "description": "Access grant (mock).",
     "inputSchema": {"type": "object", "properties": {"contractor": {"type": "string"}}}}
    for n in ("grant_read_access", "grant_admin_access")
]
SHAPE_TOOLS = [
    {"name": "lookup_opps", "description": "Flat result (mock of rci-knowledge lookup_opps).",
     "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}}}},
    {"name": "list_dataset_snapshots", "description": "Snapshot list (mock).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "lookup_dme", "description": "Another results-list shape (mock).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "calculate_payment", "description": "Mock of rci-knowledge calculate_payment (physician block).",
     "inputSchema": {"type": "object", "properties": {"cpt": {"type": "string"}, "qpp": {"type": "boolean"}}}},
]


def payment_result(args: dict) -> dict:
    qpp = args.get("qpp", True)  # like the real tool, QPP defaults to true
    sc = {"physician": {"work_rvu": 1.3, "pe_rvu": 1.46, "mp_rvu": 0.09,
                        "conversion_factor": 33.5675 if qpp else 33.4009, "rvu_year": dt.date.today().year}}
    return {"content": [{"type": "text", "text": json.dumps(sc)}], "structuredContent": sc}


def opps_result(code: str) -> dict:
    paid = code == "71046"
    sc = {
        "hcpcs_code": code, "short_descriptor": "mock", "status_indicator": "Q3" if paid else "B",
        "apc_code": "5521" if paid else "",
        "relative_weight": 0.9726 if paid else None, "payment_rate": 88.91 if paid else None,
        "national_unadjusted_copayment": None, "minimum_unadjusted_copayment": 17.79 if paid else None,
        "adjusted_copayment": None,
    }
    return {"content": [{"type": "text", "text": json.dumps(sc)}], "structuredContent": sc}


def snapshots_result() -> dict:
    today = dt.date.today()
    sc = {"snapshots": [
        {"dataset": "old_set", "version": "v1", "effective_date": (today - dt.timedelta(days=500)).isoformat(), "is_current": True},
        {"dataset": "fresh_set", "version": "v2", "effective_date": (today - dt.timedelta(days=30)).isoformat(), "is_current": True},
    ]}
    return {"content": [{"type": "text", "text": json.dumps(sc)}], "structuredContent": sc}


def _period(days_ago: int) -> tuple[int, int]:
    d = dt.date.today() - dt.timedelta(days=days_ago)
    return d.year, (d.month - 1) // 3 + 1


def build_result(case: str) -> dict:
    if case == "error":
        return {"isError": True, "content": [{"type": "text", "text": "unknown code"}]}
    if case == "empty":
        row = None
    else:
        year, quarter = _period(800 if case == "stale" else 0)
        row = {**FIELDS, "year": year, "quarter": quarter}
        if case == "partial":
            row = {k: row[k] for k in ("hcpcs_code", "short_descriptor")}
            row["work_rvu"] = None  # null counts as missing
        elif case == "mid":
            row = {k: row[k] for k in ("hcpcs_code", "short_descriptor", "work_rvu", "year", "quarter")}
        elif case == "mixed":
            full = row
            partial = {k: row[k] for k in ("hcpcs_code", "short_descriptor")}
            results = [full, partial]
            sc = {"results": results, "total_count": len(results)}
            return {"content": [{"type": "text", "text": json.dumps(sc)}], "structuredContent": sc}
    results = [row] if row else []
    sc = {"results": results, "total_count": len(results)}
    return {"content": [{"type": "text", "text": json.dumps(sc)}], "structuredContent": sc}


def handle(msg: dict):
    method, rid = msg.get("method"), msg.get("id")
    if rid is None:
        return None
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "cel-policies-mock", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": [TOOL, *GRANT_TOOLS, *SHAPE_TOOLS]}
    elif method == "tools/call":
        params = msg.get("params") or {}
        if params.get("name", "").startswith("grant_"):
            result = {"content": [{"type": "text", "text": f"{params['name']}: granted"}]}
        elif params.get("name") == "lookup_opps":
            result = opps_result((params.get("arguments") or {}).get("code", "99213"))
        elif params.get("name") == "list_dataset_snapshots":
            result = snapshots_result()
        elif params.get("name") == "calculate_payment":
            result = payment_result(params.get("arguments") or {})
        elif params.get("name") == "lookup_dme":
            sc = {"results": [{"state": "CA", "rate": 12.5, "year": 2020}], "total_count": 1}
            result = {"content": [{"type": "text", "text": json.dumps(sc)}], "structuredContent": sc}
        else:
            args = params.get("arguments") or {}
            result = build_result(args.get("case", "full"))
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no such method"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if self.path == "/health":
            self._send(200, b'{"ok":true}')
        else:
            self._send(405, b"")

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        incoming = self.headers.get("mcp-session-id") or self.headers.get("Mcp-Session-Id")
        # Unique id per initialize. A constant "mock-session" made agentgateway 1.6.0 treat
        # two pytest sessions as one, which we had misread as empty ExtMCP session metadata.
        if body.get("method") == "initialize" or not incoming:
            sid = str(uuid.uuid4())
        else:
            sid = incoming
        out = handle(body)
        if out is None:
            self._send(202, b"", {"Mcp-Session-Id": sid})
        else:
            self._send(200, json.dumps(out).encode(), {"Mcp-Session-Id": sid})

    def _send(self, code, data, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8091)
    args = ap.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
