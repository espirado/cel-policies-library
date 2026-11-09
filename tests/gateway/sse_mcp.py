#!/usr/bin/env python3
"""Controlled upstream for agentgateway#4245 (Streamable HTTP). tools/call `stream` answers with
an SSE stream carrying, before the result: a log notification, a progress notification, and
three server-initiated requests (elicitation/create, sampling/createMessage, roots/list).
tools/call `err` answers with a JSON-RPC error object. Every message has a unique marker so
pass-through can be proven.

    python tests/gateway/sse_mcp.py 8092

Used by scripts/live_pitfalls.py (check A5). Public servers cannot be made to emit these
messages on demand, so this part of #4245 is measured against this upstream, not a live one.
tests/gateway/stdio_mcp.py serves the same messages over stdio.
"""
import json
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARK = {
    "log": "LOG_NOTIF_MARKER_1a2b",
    "progress": "PROGRESS_MARKER_3c4d",
    "elicit": "ELICIT_REQUEST_MARKER_5e6f",
    "sampling": "SAMPLING_REQUEST_MARKER_9i0j",
    "roots": "ROOTS_REQUEST_MARKER_k1l2",          # roots/list has no params; marker goes in _meta
    "result": "RESULT_MARKER_7g8h",
    "error": "JSONRPC_ERROR_MARKER_m3n4",
}

TOOLS = [
    {"name": "stream", "description": "interim messages then a result",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "err", "description": "JSON-RPC error object",
     "inputSchema": {"type": "object", "properties": {}}},
]


def init_result():
    return {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}, "logging": {}},
            "serverInfo": {"name": "marker-upstream", "version": "0"}}


def interim_messages(progress_token):
    return [
        {"jsonrpc": "2.0", "method": "notifications/message",
         "params": {"level": "info", "logger": "marker", "data": MARK["log"]}},
        {"jsonrpc": "2.0", "method": "notifications/progress",
         "params": {"progressToken": progress_token, "progress": 1, "total": 2, "message": MARK["progress"]}},
        {"jsonrpc": "2.0", "id": "srv-elicit", "method": "elicitation/create",
         "params": {"message": MARK["elicit"], "requestedSchema": {"type": "object", "properties": {}}}},
        {"jsonrpc": "2.0", "id": "srv-sampling", "method": "sampling/createMessage",
         "params": {"messages": [{"role": "user", "content": {"type": "text", "text": MARK["sampling"]}}],
                    "maxTokens": 8}},
        {"jsonrpc": "2.0", "id": "srv-roots", "method": "roots/list",
         "params": {"_meta": {"marker": MARK["roots"]}}},
    ]


def call_messages(body):
    """All server messages for one tools/call, terminal last."""
    params = body.get("params") or {}
    rid = body.get("id")
    if params.get("name") == "err":
        return [{"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": MARK["error"]}}]
    token = (params.get("_meta") or {}).get("progressToken", "t")
    return interim_messages(token) + [
        {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": MARK["result"]}]}}]


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, data, sid, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Mcp-Session-Id", sid)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        b = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        m, rid = b.get("method"), b.get("id")
        sid = str(uuid.uuid4()) if m == "initialize" else (self.headers.get("mcp-session-id") or "x")
        if m == "initialize":
            return self._send(200, json.dumps({"jsonrpc": "2.0", "id": rid, "result": init_result()}).encode(), sid)
        if m == "tools/list":
            return self._send(200, json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}).encode(), sid)
        if m == "tools/call":
            msgs = call_messages(b)
            if len(msgs) == 1:
                return self._send(200, json.dumps(msgs[0]).encode(), sid)
            body = "".join(f"event: message\ndata: {json.dumps(x)}\n\n" for x in msgs).encode()
            return self._send(200, body, sid, "text/event-stream")
        if rid is None or "result" in b or "error" in b:   # notification, or client reply to srv-*
            return self._send(202, b"", sid)
        return self._send(200, json.dumps({"jsonrpc": "2.0", "id": rid,
                                           "error": {"code": -32601, "message": "no"}}).encode(), sid)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
