#!/usr/bin/env python3
"""Measure what the library's policies cost inside agentgateway.

Each pair runs the SAME tools/call through two gateway configs that differ only
in the policy under test, against a local mock MCP server, over one keep-alive
connection. The reported delta is end-to-end latency added by agentgateway's own
CEL evaluation, not cel-python's.

    AGENTGATEWAY_BIN=/path/to/agentgateway python scripts/bench_gateway.py [--n 2000] [--rounds 3]

Caveats: a Python mock upstream and a loopback client add noise of the same order
as the effect, so read the delta with the spread. Numbers are from one machine.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import test_gateway as tg  # noqa: E402  (Gateway, free_port, wait_port)

BIN = os.environ.get("AGENTGATEWAY_BIN") or shutil.which("agentgateway")


class Conn:
    def __init__(self, port):
        self.c = http.client.HTTPConnection("127.0.0.1", port)
        self.sid = None
        self.h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                  "MCP-Protocol-Version": "2024-11-05"}

    def post(self, body):
        h = dict(self.h)
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        self.c.request("POST", "/mcp", json.dumps(body), h)
        r = self.c.getresponse()
        data = r.read()
        self.sid = r.getheader("mcp-session-id") or self.sid
        return r.status, data

    def init(self):
        self.post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "b", "version": "0"}}})
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})


def measure(gw, tool, args, n, warm=200):
    cn = Conn(gw.port)
    cn.init()
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}}
    for _ in range(warm):
        cn.post(body)
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        status, data = cn.post(body)
        ts.append((time.perf_counter() - t) * 1e6)
        assert status == 200 and b'"error"' not in data, data[:200]
    return sorted(ts)


def q(ts, p):
    return ts[min(len(ts) - 1, int(len(ts) * p))]


def make(template, upstream, tmp, strip=None):
    gw = tg.Gateway(template, upstream, tmp)
    if strip:  # baseline: same config minus the policy under test
        cfg = yaml.safe_load(gw.cfg_path.read_text())
        cfg["mcp"]["policies"].pop(strip)
        gw.cfg_path.write_text(yaml.safe_dump(cfg, width=10_000))
    return gw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--rounds", type=int, default=3)
    args = ap.parse_args()
    if not BIN:
        sys.exit("set AGENTGATEWAY_BIN")
    ver = json.loads(subprocess.run([BIN, "--version"], capture_output=True, text=True).stdout)["version"]

    port = tg.free_port()
    mock = subprocess.Popen([sys.executable, str(ROOT / "tests/gateway/mock_mcp.py"), "--port", str(port)])
    tg.wait_port(port, mock)
    upstream = f"http://127.0.0.1:{port}/mcp"
    pairs = [
        ("mcpAuthorization (2 rules, incl. jwt role check)", tg.AUTHZ, "mcpAuthorization", "grant_read_access", {"contractor": "x"}),
        ("mcpGuardrails (completeness + staleness, response phase)", tg.CALIB, "mcpGuardrails", "lookup_mpfs", {"case": "full"}),
    ]
    print(f"agentgateway {ver}; n={args.n} calls x {args.rounds} rounds per config; mock upstream on loopback\n")
    try:
        for label, template, strip, tool, targs in pairs:
            deltas50, deltas99, base_all, pol_all = [], [], [], []
            for _ in range(args.rounds):
                for with_policy in (False, True):
                    with tempfile.TemporaryDirectory() as d:
                        gw = make(template, upstream, Path(d), None if with_policy else strip)
                        with gw:
                            ts = measure(gw, tool, targs, args.n)
                        (pol_all if with_policy else base_all).append(ts)
            m50b = [statistics.median(t) for t in base_all]
            m50p = [statistics.median(t) for t in pol_all]
            p99b = [q(t, 0.99) for t in base_all]
            p99p = [q(t, 0.99) for t in pol_all]
            print(label)
            print(f"  baseline : median {statistics.median(m50b):7.0f} us  (rounds {', '.join(f'{x:.0f}' for x in m50b)})   p99 {statistics.median(p99b):7.0f} us")
            print(f"  with     : median {statistics.median(m50p):7.0f} us  (rounds {', '.join(f'{x:.0f}' for x in m50p)})   p99 {statistics.median(p99p):7.0f} us")
            print(f"  delta    : median {statistics.median(m50p) - statistics.median(m50b):+7.0f} us   p99 {statistics.median(p99p) - statistics.median(p99b):+7.0f} us\n")
    finally:
        mock.terminate()
        mock.wait()


if __name__ == "__main__":
    main()
