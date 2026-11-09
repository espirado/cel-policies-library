#!/usr/bin/env python3
"""Same controlled upstream as sse_mcp.py, over stdio (newline-delimited JSON-RPC), so the
agentgateway `stdio:` target path can be measured for #4245 too.

    targets:
    - name: m
      stdio:
        cmd: python3
        args: ["tests/gateway/stdio_mcp.py"]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sse_mcp import TOOLS, call_messages, init_result  # noqa: E402


def emit(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        b = json.loads(line)
        m, rid = b.get("method"), b.get("id")
        if m == "initialize":
            emit({"jsonrpc": "2.0", "id": rid, "result": init_result()})
        elif m == "tools/list":
            emit({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        elif m == "tools/call":
            for msg in call_messages(b):
                emit(msg)
        elif rid is None or "result" in b or "error" in b:
            continue   # notification, or client reply to a srv-* request
        else:
            emit({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no"}})


if __name__ == "__main__":
    main()
