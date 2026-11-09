#!/usr/bin/env python3
"""Due diligence: ExtMCP `session` on a live Streamable-HTTP MCP, not the mock.

Starts a recorder (always-pass ExtMCP server) and agentgateway in front of a *remote*
MCP. Opens two MCP sessions, one tools/call each. Prints the `session` string the
gateway sent in metadata_context — not our contradiction logic.

  AGENTGATEWAY_BIN=/path/to/agentgateway-1.6.0 python scripts/live_session_metadata.py
  AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 python scripts/live_session_metadata.py

Measured 2026-11-09: both 1.6.0 and 1.7.0 forward a non-empty session that matches
HTTP Mcp-Session-Id and differs across the two sessions. The earlier "empty on
1.3.1–1.6.0" claim was a mock artifact (constant Mcp-Session-Id: mock-session).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "processors"))
sys.path.insert(0, str(ROOT / "scripts"))

import signal_processor as sp  # noqa: E402
import test_gateway as tg  # noqa: E402
from live_public_mcp import UPSTREAM_HEADERS, gateway_call, gateway_session, open_session, rpc  # noqa: E402

TARGETS = [
    {"name": "pathwren", "url": "https://www.pathwren.workers.dev/mcp",
     "tool": "list_crawlers", "args": {}},
    {"name": "plantguide", "url": "https://plantguide.ae/mcp",
     "tool": "list_garden_styles", "args": {}},
]


class SessionRecorder(sp.pb_grpc.ExtMcpServicer):
    """Always pass. Only records metadata_context — independent of SignalProcessor scoring."""

    def __init__(self):
        self.events = []

    def _snap(self, phase, request):
        fields = request.metadata_context.fields
        snap = {
            "phase": phase,
            "method": request.method,
            "metadata_keys": sorted(fields.keys()),
            "session": fields["session"].string_value if "session" in fields else None,
        }
        self.events.append(snap)
        return snap

    def CheckRequest(self, request, context):
        self._snap("request", request)
        return sp._pass_request()

    def CheckResponse(self, request, context):
        self._snap("response", request)
        return sp._pass_response()


def serve_recorder():
    rec = SessionRecorder()
    port = tg.free_port()
    server = sp.grpc.server(sp.futures.ThreadPoolExecutor(max_workers=4))
    sp.pb_grpc.add_ExtMcpServicer_to_server(rec, server)
    server.add_insecure_port(f"127.0.0.1:{port}")
    server.start()
    return rec, server, port


def probe(url: str, tool: str, args: dict, proc_port: int, tmp: Path, rec: SessionRecorder):
    rec.events.clear()
    extra = {"mcpGuardrails": {
        "processors": [{
            "kind": "remote",
            "host": f"127.0.0.1:{proc_port}",
            "failureMode": "failClosed",
            "metadata": {"session": 'default(request.headers["mcp-session-id"], "")'},
            "methods": {"tools/call": "full"},
        }]
    }}
    http_sids = []
    with tg.Gateway(tg.SIGNALS_TEMPLATE, url, tmp, extra, target_policies=UPSTREAM_HEADERS) as gw:
        for i in range(2):
            status, init, sid, proto = gateway_session(gw)
            if not sid:
                return {"ok": False, "error": f"initialize failed: {init}"}
            http_sids.append(sid)
            out = gateway_call(gw, sid, tool, args, proto)
            if out.get("http_error") or out.get("transport_error"):
                return {"ok": False, "error": out, "http_sids": http_sids, "extmcp": list(rec.events)}
    sessions = [e["session"] for e in rec.events]
    nonempty = [s for s in sessions if s]
    return {
        "ok": True,
        "http_sids": http_sids,
        "http_sids_distinct": len(set(http_sids)) == 2,
        "extmcp_events": [dict(e) for e in rec.events],
        "extmcp_sessions": sessions,
        "extmcp_any_nonempty": bool(nonempty),
        "extmcp_distinct_nonempty": len(set(nonempty)),
    }


def classify(ver: tuple, rec: dict) -> str:
    if not rec.get("ok"):
        return "probe_failed"
    if rec["http_sids_distinct"] and rec["extmcp_distinct_nonempty"] >= 2:
        return "isolated_as_expected"
    if rec["http_sids_distinct"] and not rec["extmcp_any_nonempty"]:
        return "empty_extmcp_session"
    if rec["extmcp_any_nonempty"] and rec["extmcp_distinct_nonempty"] < 2:
        return "shared_extmcp_session"
    return "UNEXPECTED_no_http_session"


def main() -> int:
    if not tg.BIN:
        print("set AGENTGATEWAY_BIN")
        return 2
    ver = tg.gateway_version()
    print(f"binary {ver}  {tg.BIN}")
    rec, server, port = serve_recorder()
    report = {"binary": {"version": ".".join(map(str, ver)), "path": tg.BIN}, "targets": []}
    failed = 0
    try:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            for t in TARGETS:
                print(f"\n== {t['name']}  {t['url']}  {t['tool']}")
                tdir = tmp / t["name"]
                tdir.mkdir()
                out = probe(t["url"], t["tool"], t["args"], port, tdir, rec)
                kind = classify(ver, out)
                out["verdict"] = kind
                report["targets"].append({"name": t["name"], "url": t["url"], **out})
                print(f"    HTTP Mcp-Session-Id: {out.get('http_sids')}")
                print(f"    ExtMCP session fields: {out.get('extmcp_sessions')}")
                print(f"    {kind}")
                if not kind.endswith("as_expected") and kind != "probe_failed":
                    failed += 1
                if kind == "probe_failed":
                    failed += 1
                    print(f"    error {out.get('error')}")
    finally:
        server.stop(0)

    dest = ROOT / "evidence" / "runs"
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"session-metadata-{ver[0]}.{ver[1]}.{ver[2]}.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nreport {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
