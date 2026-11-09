#!/usr/bin/env python3
"""Re-measure the pitfall claims against live public MCP servers, not tests/gateway/mock_mcp.py.

The ExtMCP session "leak" turned out to be a mock artifact. This script puts every other
pitfall claim through the same check: a real agentgateway binary in front of a real
Streamable-HTTP MCP server, with the exact gateway strings asserted.

  AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 python scripts/live_pitfalls.py

Checks (each prints PASS/FAIL/SKIP and the raw response excerpt):

  A1 unscoped `kind: expression` on a successful foreign result -> error -32603 "guardrail check failed"
  A2 shipped scoped rules (templates/agentgateway-calibration.yaml) on the same result -> unchanged
  A3 unscoped rule on an upstream *tool error* result (isError: true) -> guardrail does run
  A4 `condition: true` reject vs an upstream JSON-RPC *error* object -> passes through untouched
     (independent reproduction of agentgateway#4245; the same rule rejects the success case)
  A5 same reject vs a controlled upstream (tests/gateway/sse_mcp.py over Streamable HTTP, and
     tests/gateway/stdio_mcp.py as a stdio target) that emits, before the result, a log
     notification, a progress notification, and elicitation/create, sampling/createMessage,
     roots/list server requests; plus a tool that returns a JSON-RPC error object. The result
     is rejected; all five interim messages and the error pass through untouched (on the POST
     response for HTTP, on the session GET stream for stdio); `kind: remote` gets no hook for
     any of them
  B  `kind: remote` processor unreachable, failureMode failClosed -> "guardrail check failed"
  C1 original `"operator" in jwt.roles` with a string claim "superoperator" -> gated tool IS listed (the trap)
  C2 shipped has(jwt.roles) && exists() with the same token -> gated tool is NOT listed
  C3 shipped rule with roles ["operator"] -> gated tool IS listed
  C4 shipped rule with no token -> gated tool is NOT listed

No API keys are sent. Tool calls are read-only list/lookup calls with empty or dummy args.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

import test_gateway as tg  # noqa: E402
from live_public_mcp import UPSTREAM_HEADERS, gateway_call, gateway_session, list_tools  # noqa: E402

try:
    sys.path.insert(0, str(ROOT / "processors"))
    import live_session_metadata as _lsm  # noqa: E402  (always-pass ExtMCP recorder)
except Exception:  # grpc missing
    _lsm = None

sys.path.insert(0, str(ROOT / "tests" / "gateway"))
from sse_mcp import MARK as SSE_MARKS  # noqa: E402

# Public servers that returned a successful result with empty args in the 2026-11-09 run.
OK_TARGETS = [
    {"name": "pathwren", "url": "https://www.pathwren.workers.dev/mcp",
     "tool": "list_crawlers", "args": {}, "gated": "changes_since"},
    {"name": "plantguide", "url": "https://plantguide.ae/mcp",
     "tool": "list_garden_styles", "args": {}, "gated": "build_designer_link"},
]
# A server whose tool returns isError with a bad argument (deepwiki wants owner/repo).
ERR_TARGET = {"name": "deepwiki", "url": "https://mcp.deepwiki.com/mcp",
              "tool": "read_wiki_contents", "args": {"repoName": "test"}}
# A server that answers bad arguments with a JSON-RPC *error* object (-32602), not isError.
RPC_ERR_TARGET = {"name": "ottobot-lic", "url": "https://license-changes-mcp.ottobot2025.workers.dev/mcp",
                  "tool": "recent_license_changes", "bad": {"state": "test"}, "good": {"state": "CA"}}

EMPTY = "mcp:\n  port: 0\n  policies: {}\n  targets:\n  - name: m\n    mcp:\n      host: x\n"
FAIL_CLOSED = "guardrail check failed"


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def jwt_material():
    import jwt
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    n = key.public_key().public_numbers()
    b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    jwks = json.dumps({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "t1", "n": b64(n.n), "e": b64(n.e)}]})
    now = int(time.time())

    def token(**claims):
        return jwt.encode({"iss": "live", "aud": "live-aud", "iat": now, "exp": now + 600, **claims},
                          pem, algorithm="RS256", headers={"kid": "t1"})
    return jwks, token


def excerpt(out):
    return json.dumps(out)[:220]


def error_message(out):
    err = out.get("error") or {}
    if isinstance(err, dict) and err.get("message"):
        return err.get("code"), err["message"]
    res = out.get("result") or {}
    if res.get("isError"):
        return None, str((res.get("content") or [{}])[0].get("text", ""))
    return None, ""


class Report:
    def __init__(self):
        self.rows = []

    def add(self, check, target, status, detail, raw=None):
        self.rows.append({"check": check, "target": target, "status": status, "detail": detail, "raw": raw})
        print(f"{status:4} {check:3} {target:12} {detail}")
        if raw is not None:
            print(f"          {excerpt(raw)}")


def call_through(tmpl, url, tmp, policies, tool, args, files=None, token=None):
    gw = tg.Gateway(tmpl, url, tmp, policies, files, target_policies=UPSTREAM_HEADERS)
    v = gw.validate()
    if v.returncode != 0:
        return None, {"validate_error": v.stderr.strip()[:200]}
    with gw:
        st, init, sid, proto = gateway_session(gw)
        if not sid:
            return None, {"init_error": init}
        return proto, gateway_call(gw, sid, tool, args, proto)


def check_a(rep, tmp):
    unscoped = {"mcpGuardrails": {"processors": [{
        "kind": "expression",
        "condition": "size(mcp.result.structuredContent.results) == 0",
        "reject": "unscoped",
        "methods": {"tools/call": "response"},
    }]}}
    tmpl = tmp / "empty.yaml"
    tmpl.write_text(EMPTY)
    for t in OK_TARGETS:
        d = tmp / f"a1-{t['name']}"; d.mkdir()
        _, out = call_through(tmpl, t["url"], d, unscoped, t["tool"], t["args"])
        code, msg = error_message(out)
        ok = code == -32603 and msg == FAIL_CLOSED
        rep.add("A1", t["name"], "PASS" if ok else "FAIL",
                f"unscoped rule on successful {t['tool']} -> {code} {msg!r}", out)

        d = tmp / f"a2-{t['name']}"; d.mkdir()
        _, out = call_through(tg.CALIB, t["url"], d, {}, t["tool"], t["args"])
        res = out.get("result") or {}
        ok = "result" in out and not res.get("isError") and "calibration" not in (res.get("structuredContent") or {})
        rep.add("A2", t["name"], "PASS" if ok else "FAIL",
                f"shipped scoped rules on {t['tool']} -> unchanged={ok}", out)

    d = tmp / "a3"; d.mkdir()
    _, out = call_through(tmpl, ERR_TARGET["url"], d, unscoped, ERR_TARGET["tool"], ERR_TARGET["args"])
    code, msg = error_message(out)
    res = out.get("result") or {}
    if msg == FAIL_CLOSED:
        verdict, status = "guardrail evaluated on the error result and failed closed", "INFO"
    elif res.get("isError"):
        verdict, status = "upstream isError passed through untouched: guardrail did NOT run on an error result", "INFO"
    else:
        verdict, status = "unexpected shape", "FAIL"
    rep.add("A3", ERR_TARGET["name"], status, verdict, out)

    # A4: agentgateway#4245 — guardrails skip JSON-RPC error responses.
    always = {"mcpGuardrails": {"processors": [{
        "kind": "expression", "condition": "true", "reject": "REJECTED_BY_GUARDRAIL",
        "methods": {"tools/call": "response"},
    }]}}
    t = RPC_ERR_TARGET
    d = tmp / "a4"; d.mkdir()
    gw = tg.Gateway(tmpl, t["url"], d, always, target_policies=UPSTREAM_HEADERS)
    with gw:
        st, init, sid, proto = gateway_session(gw)
        if not sid:
            rep.add("A4", t["name"], "FAIL", "initialize failed", init)
            return
        bad = gateway_call(gw, sid, t["tool"], t["bad"], proto)
        good = gateway_call(gw, sid, t["tool"], t["good"], proto)
    bcode, bmsg = error_message(bad)
    gcode, gmsg = error_message(good)
    rejected_success = gcode == -32001 and gmsg == "REJECTED_BY_GUARDRAIL"
    error_passed = bcode == -32602 and "REJECTED_BY_GUARDRAIL" not in bmsg
    if rejected_success and error_passed:
        rep.add("A4", t["name"], "INFO",
                f"#4245 reproduced: success -> {gcode} {gmsg!r}; upstream JSON-RPC error -> {bcode} {bmsg!r} (untouched)",
                {"bad": bad, "good": good})
    elif rejected_success and not error_passed:
        rep.add("A4", t["name"], "INFO", f"#4245 NOT reproduced: error response was also rejected -> {bcode} {bmsg!r}",
                {"bad": bad, "good": good})
    else:
        rep.add("A4", t["name"], "FAIL", f"control failed: success case -> {gcode} {gmsg!r}", {"bad": bad, "good": good})


def _raw_stream_call(url, sid, proto, tool):
    body = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": tool, "arguments": {}, "_meta": {"progressToken": "t"}}}
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": proto, "Mcp-Session-Id": sid}
    req = urllib.request.Request(url, json.dumps(body).encode(), headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace")


def _get_stream(url, sid, proto, out, stop):
    """Session GET channel (server -> client). Stdio targets deliver interim messages here."""
    headers = {"Accept": "text/event-stream", "MCP-Protocol-Version": proto, "Mcp-Session-Id": sid}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers, method="GET"), timeout=4) as r:
            while not stop.is_set():
                c = r.read(1)
                if not c:
                    break
                out.append(c.decode(errors="replace"))
    except Exception as e:  # timeout when the stream idles: expected
        out.append(f"<<{type(e).__name__}>>")


def _markers(text):
    return [k for k, v in SSE_MARKS.items() if v in text]


def _methods(text):
    out = []
    for line in text.splitlines():
        if line.startswith("data:"):
            try:
                j = json.loads(line[5:].strip())
                out.append(j.get("method") or ("result" if "result" in j else "error"))
            except json.JSONDecodeError:
                out.append("?")
    if not out and text.strip().startswith("{"):
        j = json.loads(text)
        out.append(j.get("method") or ("result" if "result" in j else "error"))
    return out


INTERIM = ["log", "progress", "elicit", "sampling", "roots"]
ALWAYS_REJECT = {"mcpGuardrails": {"processors": [{
    "kind": "expression", "condition": "true", "reject": "REJECTED_BY_GUARDRAIL",
    "methods": {"tools/call": "response"}}]}}


def _call_collect(gw, tool):
    """POST tools/call while listening on the session GET stream; return (post_text, get_text)."""
    import threading
    _, _, sid, proto = gateway_session(gw)
    got, stop = [], threading.Event()
    th = threading.Thread(target=_get_stream, args=(gw.url, sid, proto, got, stop), daemon=True)
    th.start(); time.sleep(0.4)
    post = _raw_stream_call(gw.url, sid, proto, tool)
    time.sleep(1.2); stop.set()
    return post, "".join(got)


def _a5_transport(rep, tmp, label, tmpl, upstream):
    """Run control / expression / remote against one upstream transport."""
    d = tmp / f"a5-{label}-pass"; d.mkdir()
    with tg.Gateway(tmpl, upstream, d, {}) as gw:
        post, get = _call_collect(gw, "stream")
        epost, _ = _call_collect(gw, "err")
    both = post + get
    if set(_markers(both)) < set(INTERIM + ["result"]):
        rep.add("A5", label, "FAIL", f"control: not all messages forwarded. POST {_methods(post)} GET {_methods(get)}")
        return
    where = "POST response" if all(SSE_MARKS[k] in post for k in INTERIM) else "session GET stream"
    rep.add("A5", label, "PASS", f"control: all 5 interim messages + result forwarded; interim on {where}; "
            f"error -> {_methods(epost)}")

    if tg.gateway_version() >= (1, 7, 0):
        d = tmp / f"a5-{label}-expr"; d.mkdir()
        with tg.Gateway(tmpl, upstream, d, ALWAYS_REJECT) as gw:
            post, get = _call_collect(gw, "stream")
            epost, _ = _call_collect(gw, "err")
        both = post + get
        interim_through = [k for k in INTERIM if SSE_MARKS[k] in both]
        result_rejected = SSE_MARKS["result"] not in both and "REJECTED_BY_GUARDRAIL" in post
        error_through = SSE_MARKS["error"] in epost and "REJECTED_BY_GUARDRAIL" not in epost
        ok = result_rejected and len(interim_through) == 5 and error_through
        rep.add("A5", label, "INFO" if ok else "FAIL",
                (f"#4245 reproduced (expression): result rejected; interim through untouched {interim_through}; "
                 f"JSON-RPC error through untouched={error_through}") if ok else
                f"unexpected: rejected={result_rejected} interim={interim_through} error_through={error_through}",
                {"post_methods": _methods(post), "get_methods": _methods(get), "err": _methods(epost)})

    if _lsm is not None:
        rec, server, gport = _lsm.serve_recorder()
        guard = {"processors": [{"kind": "remote", "host": f"127.0.0.1:{gport}", "failureMode": "failClosed",
                                 "methods": {"tools/call": "full"}}]}
        d = tmp / f"a5-{label}-remote"; d.mkdir()
        try:
            with tg.Gateway(tmpl, upstream, d, {"mcpGuardrails": guard}) as gw:
                rec.events.clear()
                post, get = _call_collect(gw, "stream")
                stream_phases = [e["phase"] for e in rec.events]
                rec.events.clear()
                epost, _ = _call_collect(gw, "err")
                err_phases = [e["phase"] for e in rec.events]
        finally:
            server.stop(0)
        interim_through = [k for k in INTERIM if SSE_MARKS[k] in post + get]
        ok = stream_phases == ["request", "response"] and err_phases == ["request"] and len(interim_through) == 5 \
            and SSE_MARKS["error"] in epost
        rep.add("A5", label, "INFO" if ok else "FAIL",
                f"#4245 (remote): stream call hooks {stream_phases}, 5 interim messages forwarded with no hook; "
                f"error call hooks {err_phases}, error forwarded untouched",
                {"stream_phases": stream_phases, "err_phases": err_phases, "interim_through": interim_through})


def check_a5(rep, tmp):
    """#4245, notification / server-request half, plus the error object, on Streamable HTTP and stdio."""
    # Streamable HTTP upstream
    port = tg.free_port()
    proc = subprocess.Popen([sys.executable, str(ROOT / "tests" / "gateway" / "sse_mcp.py"), str(port)])
    tg.wait_port(port, proc)
    tmpl = tmp / "empty-a5.yaml"; tmpl.write_text(EMPTY)
    try:
        _a5_transport(rep, tmp, "http-upstream", tmpl, f"http://127.0.0.1:{port}/mcp")
    finally:
        proc.terminate(); proc.wait()
    # stdio upstream: the gateway spawns it
    stdio_tmpl = tmp / "stdio-a5.yaml"
    stdio_tmpl.write_text(
        "mcp:\n  port: 0\n  policies: {}\n  targets:\n  - name: m\n    stdio:\n"
        f"      cmd: {sys.executable}\n      args: ['{ROOT / 'tests' / 'gateway' / 'stdio_mcp.py'}']\n")
    _a5_transport(rep, tmp, "stdio-upstream", stdio_tmpl, "unused")


def check_b(rep, tmp):
    guard = yaml.safe_load(tg.SIGNALS_TEMPLATE.read_text())["mcp"]["policies"]["mcpGuardrails"]
    guard["processors"][0]["host"] = f"127.0.0.1:{tg.free_port()}"   # nothing listens here
    for t in OK_TARGETS[:1]:
        d = tmp / f"b-{t['name']}"; d.mkdir()
        _, out = call_through(tg.SIGNALS_TEMPLATE, t["url"], d, {"mcpGuardrails": guard}, t["tool"], t["args"])
        code, msg = error_message(out)
        # 1.7.0: generic "guardrail check failed". 1.6.0: echoes the connect error.
        ok = code == -32603 and (msg == FAIL_CLOSED or msg.startswith("mcpGuardrails checkRequest failed:"))
        rep.add("B", t["name"], "PASS" if ok else "FAIL",
                f"remote processor down, failClosed -> {code} {msg!r}", out)


def listed_through(tmpl, url, tmp, policies, files, token):
    gw = tg.Gateway(tmpl, url, tmp, policies, files, target_policies=UPSTREAM_HEADERS)
    with gw:
        st, init, sid, proto = gateway_session(gw)
        if not sid:
            return None, init
        # tools/list with the bearer token
        import urllib.request
        body = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": proto, "Mcp-Session-Id": sid}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(gw.url, json.dumps(body).encode(), headers, method="POST")
        with urllib.request.urlopen(req, timeout=25) as r:
            text = r.read().decode().strip()
        if text.startswith(("event:", "data:")):
            text = next((l[5:].strip() for l in text.splitlines() if l.startswith("data:") and l[5:].strip()), "")
        out = json.loads(text)
        return {t["name"] for t in out["result"]["tools"]}, out


def check_c(rep, tmp):
    try:
        jwks, token = jwt_material()
    except ImportError as e:
        rep.add("C", "-", "SKIP", f"pyjwt/cryptography missing: {e}")
        return
    t = OK_TARGETS[0]
    gated, open_tool = t["gated"], t["tool"]
    jwt_policy = {"mode": "optional", "issuer": "live", "audiences": ["live-aud"], "jwks": {"file": "./jwks.json"}}
    original = [f'mcp.tool.name == "{open_tool}"',
                f'mcp.tool.name == "{gated}" && has(jwt.sub) && "operator" in jwt.roles']
    shipped = [f'mcp.tool.name == "{open_tool}"',
               f'mcp.tool.name == "{gated}" && has(jwt.sub) && has(jwt.roles) && jwt.roles.exists(r, r == "operator")']
    tmpl = tmp / "empty-c.yaml"; tmpl.write_text(EMPTY)
    cases = [
        ("C1", original, token(sub="u1", roles="superoperator"), True,  'original rule, roles="superoperator"'),
        ("C2", shipped,  token(sub="u1", roles="superoperator"), False, 'shipped rule, roles="superoperator"'),
        ("C3", shipped,  token(sub="u1", roles=["operator"]),    True,  'shipped rule, roles=["operator"]'),
        ("C4", shipped,  None,                                   False, "shipped rule, no token"),
    ]
    for cid, rules, tok, expect_listed, label in cases:
        d = tmp / cid; d.mkdir()
        pol = {"jwtAuth": jwt_policy, "mcpAuthorization": {"rules": rules}}
        # initialize must also carry the token when jwtAuth is optional? it is optional, so no.
        names, raw = listed_through(tmpl, t["url"], d, pol, {"jwks.json": jwks}, tok)
        if names is None:
            rep.add(cid, t["name"], "FAIL", f"{label}: initialize failed", raw)
            continue
        listed = gated in names
        ok = listed is expect_listed and open_tool in names
        rep.add(cid, t["name"], "PASS" if ok else "FAIL",
                f"{label} -> {gated} listed={listed} (expected {expect_listed}); open tool listed={open_tool in names}",
                sorted(names))


def main() -> int:
    if not tg.BIN:
        print("set AGENTGATEWAY_BIN"); return 2
    ver = tg.gateway_version()
    print(f"binary {ver} {tg.BIN}  started {utcnow()}")
    rep = Report()
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        if ver >= (1, 7, 0):
            check_a(rep, tmp)
        else:
            rep.add("A", "-", "SKIP", f"kind: expression needs 1.7.0 (binary is {'.'.join(map(str, ver))})")
        check_a5(rep, tmp)
        check_b(rep, tmp)
        check_c(rep, tmp)
    fails = [r for r in rep.rows if r["status"] == "FAIL"]
    dest = ROOT / "evidence" / "runs"
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"live-pitfalls-{'.'.join(map(str, ver))}-{utcnow().replace(':', '').replace('-', '')}.json"
    path.write_text(json.dumps({"binary": {"version": ".".join(map(str, ver)), "path": tg.BIN},
                                "finished": utcnow(), "rows": rep.rows}, indent=2) + "\n")
    print(f"\n{len(rep.rows) - len(fails)} ok, {len(fails)} failed  report {path}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
