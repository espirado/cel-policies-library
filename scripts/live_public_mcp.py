#!/usr/bin/env python3
"""Validate the shipped CEL package against public Streamable-HTTP MCP servers.

Puts agentgateway in front of each reachable URL and checks:

  1. Passthrough: tools/list through the gateway matches the direct listing.
  2. Prefix authorization (allow_lookup_tools + require_operator_for_calculate, no JWT):
     listed tools are exactly the lookup_* and list_* names; other tools are denied.
  3. Guardrail scoping (templates/agentgateway-calibration.yaml, needs 1.7.0):
     a read-only call on a tool that is NOT lookup_mpfs / lookup_opps /
     list_dataset_snapshots is not rejected by the rci-knowledge field lists.

No API keys. Read-only tool calls only. Writes a JSON report under evidence/runs/.

    AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 python scripts/live_public_mcp.py
    AGENTGATEWAY_BIN=... python scripts/live_public_mcp.py --discover 30
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

import test_gateway as tg  # noqa: E402

PROTOCOL = "2025-03-26"
FALLBACK_PROTOCOL = "2024-11-05"
REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
REPORT_DIR = ROOT / "evidence" / "runs"

# Known public, no-auth, read-oriented Streamable HTTP endpoints. Mutating /
# paid / OAuth servers are not in this list.
CURATED = [
    {"name": "mcpharbor-search", "url": "https://mcpharbor.app/mcp"},
    {"name": "placeholder-tools", "url": "https://mcp.placeholder.com/mcp"},
    {"name": "superdocs-sbox", "url": "https://superdocs.sboxcool.com/mcp"},
    {"name": "pathwren-crawler-index", "url": "https://www.pathwren.workers.dev/mcp"},
    {"name": "mizan-bans", "url": "https://mizan.ac/mcp"},
    {"name": "tandem-docs", "url": "https://tandem.ac/mcp"},
    {"name": "apex-ai-academy", "url": "https://apexai.academy/mcp"},
    {"name": "ase-periodic-system", "url": "https://ase.academy/mcp"},
    {"name": "service-engineer-ai", "url": "https://api.serviceengineer.academy/mcp"},
    {"name": "brainy-uae-prices", "url": "https://prices.brainy.ae/mcp/v2"},
    {"name": "dubai-real-estate", "url": "https://mcp.datadubai.ae/mcp"},
    {"name": "plantguide-dubai", "url": "https://plantguide.ae/mcp"},
    {"name": "beachclubs-ae", "url": "https://www.beachclubs.ae/mcp"},
    {"name": "deepwiki", "url": "https://mcp.deepwiki.com/mcp"},
    {"name": "grovisor-grotax", "url": "https://mcp.grovisor.ae"},
    {"name": "projectory-uae", "url": "https://mcp.projectory.ae/mcp"},
    {"name": "events-aero", "url": "https://events.aero/mcp/events"},
    {"name": "tide-sui", "url": "https://api.tide.ad/mcp"},
    {"name": "pantheon-ads", "url": "https://mcp.pantheon.ad/mcp"},
    {"name": "1court-state", "url": "https://state.1court.ai/api/mcp"},
    {"name": "4ai", "url": "https://4ai.ai/mcp"},
    {"name": "rci-knowledge-unauthenticated", "url": "https://api.rcintell.com/v1/mcp",
     "note": "hosted domain-specific target; expected to refuse without RCI_API_KEY"},
]

# Outbound headers agentgateway should send to Cloudflare-fronted MCP hosts.
# Direct urllib with this UA works; the gateway's default client fingerprint does not.
UPSTREAM_HEADERS = {
    "requestHeaderModifier": {
        "set": {
            "User-Agent": "cel-policies-library-live/0",
            "Accept": "application/json, text/event-stream",
        }
    }
}

UNSAFE_NAME = re.compile(
    r"(write|create|delete|send|post|update|execute|pay|order|buy|email|"
    r"message|launch|campaign|insert|drop_|grant_|admin|auth|token|secret|"
    r"password|deploy|destroy|mutate|checkout|purchase)",
    re.I,
)
SAFE_NAME = re.compile(
    r"^(list_|lookup_|search_|get_|recent_|classify_|read_|show_|describe_|"
    r"ping|health|whats_changed|list_categories)",
    re.I,
)
GUARDRAIL_TOOLS = {"lookup_mpfs", "lookup_opps", "list_dataset_snapshots"}
PREFIX_OPEN = ("lookup_", "list_")
PREFIX_OPERATOR = ("calculate_",)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rpc(url, body, sid=None, protocol=PROTOCOL, timeout=25):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "cel-policies-library-live/0",
        "MCP-Protocol-Version": protocol,
    }
    if sid:
        headers["Mcp-Session-Id"] = sid
    req = urllib.request.Request(url, json.dumps(body).encode(), headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text, status, new = r.read().decode().strip(), r.status, r.headers.get("mcp-session-id")
    except urllib.error.HTTPError as e:
        return e.code, {"http_error": e.read(400).decode(errors="replace")}, sid
    except Exception as e:
        return 0, {"transport_error": f"{type(e).__name__}: {e}"}, sid
    if text.startswith(("event:", "data:")):
        data_lines = [l[5:].strip() for l in text.splitlines() if l.startswith("data:")]
        text = next((l for l in data_lines if l), "")
    if not text:
        return status, {}, new or sid
    try:
        return status, json.loads(text), new or sid
    except json.JSONDecodeError:
        return status, {"parse_error": text[:200]}, new or sid


def open_session(url, protocol=PROTOCOL):
    status, init, sid = rpc(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": protocol, "capabilities": {},
        "clientInfo": {"name": "cel-policies-live", "version": "0"}}})
    if "result" not in init and protocol != FALLBACK_PROTOCOL:
        return open_session(url, FALLBACK_PROTOCOL)
    if "result" in init:
        rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, protocol)
    return status, init, sid, protocol


def list_tools(url, sid, protocol=PROTOCOL):
    status, out, _ = rpc(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, sid, protocol)
    tools = (out.get("result") or {}).get("tools") or []
    return status, tools, out


def classify_names(names):
    buckets = {"lookup_": [], "list_": [], "calculate_": [], "other": []}
    for n in names:
        for p in ("lookup_", "list_", "calculate_"):
            if n.startswith(p):
                buckets[p].append(n)
                break
        else:
            buckets["other"].append(n)
    return buckets


def prefix_allows(name: str) -> bool:
    return name.startswith(PREFIX_OPEN)


def dummy_args(schema: dict | None) -> dict | None:
    schema = schema or {}
    props = schema.get("properties") or {}
    required = list(schema.get("required") or [])
    args = {}
    samples = {
        "query": "mcp", "q": "mcp", "search": "mcp", "slug": "mcp", "name": "mcp",
        "code": "99213", "topic": "mcp", "category": "developer-tools",
        "limit": 3, "text": "hello", "user_agent": "Mozilla/5.0",
        "ip": "1.1.1.1", "id": "1",
    }
    for key in required:
        spec = props.get(key) or {}
        typ = spec.get("type")
        if key in samples:
            args[key] = samples[key]
        elif typ == "integer" or typ == "number":
            args[key] = 1
        elif typ == "boolean":
            args[key] = False
        elif typ == "array":
            args[key] = []
        elif typ == "object":
            args[key] = {}
        else:
            args[key] = "test"
    return args


def pick_call(tools: list[dict]) -> dict | None:
    ranked = []
    for t in tools:
        name = t.get("name") or ""
        if not name or UNSAFE_NAME.search(name):
            continue
        schema = t.get("inputSchema") or t.get("input_schema") or {}
        required = schema.get("required") or []
        if any(k in {"url", "uri", "endpoint", "webhook"} for k in required):
            continue
        score = 0
        if SAFE_NAME.search(name):
            score += 10
        if not required:
            score += 5
        if name.startswith(PREFIX_OPEN):
            score += 3
        ranked.append((score, name, t))
    if not ranked:
        return None
    ranked.sort(key=lambda x: (-x[0], x[1]))
    _, name, t = ranked[0]
    schema = t.get("inputSchema") or t.get("input_schema") or {}
    return {"name": name, "arguments": dummy_args(schema) or {}}


def classify_call(out: dict) -> tuple[str, str]:
    res = out.get("result") or {}
    sc = res.get("structuredContent") or {}
    if out.get("http_error") or out.get("transport_error"):
        return "transport", str(out)[:160]
    blob = json.dumps(out)
    # Match only agentgateway's own reject strings, not the word "calibration"
    # appearing in an unrelated tool error (seen on achromat.ai).
    if "calibration: result incomplete" in blob or "guardrail check failed" in blob.lower():
        msg = ""
        if out.get("error"):
            err = out["error"]
            msg = err.get("message", "") if isinstance(err, dict) else str(err)
        elif res.get("isError"):
            msg = str((res.get("content") or [{}])[0].get("text", ""))
        return "guardrail_reject", msg[:160]
    if out.get("error"):
        msg = out["error"].get("message", "") if isinstance(out["error"], dict) else str(out["error"])
        return "rpc_error", msg[:160]
    if res.get("isError"):
        text = (res.get("content") or [{}])[0].get("text", "")
        return "tool_error", str(text)[:160]
    if isinstance(sc, dict) and "calibration" in sc:
        return "annotated", json.dumps(sc.get("calibration"))[:160]
    return "unchanged", ""


def gateway_session(gw):
    status, init, sid, protocol = open_session(gw.url)
    return status, init, sid, protocol


def gateway_list(gw, sid, protocol=PROTOCOL):
    status, tools, out = list_tools(gw.url, sid, protocol)
    return {t["name"] for t in tools}, out


def gateway_call(gw, sid, name, args, protocol=PROTOCOL):
    _, out, _ = rpc(gw.url, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                             "params": {"name": name, "arguments": args}}, sid, protocol)
    return out


def empty_template(tmp: Path) -> Path:
    p = tmp / "passthrough.yaml"
    p.write_text(
        "mcp:\n  port: 0\n  policies: {}\n  targets:\n  - name: t\n    mcp:\n      host: x\n"
    )
    return p


def prefix_policies():
    return {"mcpAuthorization": {"rules": [
        tg.normalize((ROOT / "policies/authorization/allow_lookup_tools.cel").read_text()),
        tg.normalize((ROOT / "policies/authorization/require_operator_for_calculate.cel").read_text()),
    ]}}


def check(failures, label, ok, detail=""):
    failures.append(0 if ok else 1)
    print(f"    {'PASS' if ok else 'FAIL'}  {label}{('  ' + detail) if detail else ''}")
    return bool(ok)


def probe_direct(url: str) -> dict:
    t0 = time.time()
    status, init, sid, protocol = open_session(url)
    rec = {
        "http": status,
        "protocol": protocol,
        "elapsed_s": round(time.time() - t0, 3),
        "ok": "result" in init,
        "error": None if "result" in init else init,
        "tools": [],
        "n_tools": 0,
        "prefixes": {},
    }
    if not rec["ok"]:
        return rec
    _, tools, listing = list_tools(url, sid, protocol)
    names = [t.get("name") for t in tools if t.get("name")]
    rec["tools"] = names
    rec["n_tools"] = len(names)
    rec["prefixes"] = {k: v for k, v in classify_names(names).items()}
    rec["listing_error"] = None if names or "result" in listing else listing
    rec["_tools_meta"] = tools
    rec["_sid"] = sid
    rec["_protocol"] = protocol
    return rec


def run_gateway_checks(target: dict, direct: dict, tmp: Path, failures: list) -> dict:
    url = target["url"]
    names = set(direct.get("tools") or [])
    out = {"passthrough": None, "prefix_authz": None, "guardrail_scope": None}

    if not names:
        print("    skip gateway checks (no tools listed)")
        return out

    tmp.mkdir(parents=True, exist_ok=True)
    passthrough = empty_template(tmp)
    pt = tmp / "pt"
    az = tmp / "az"
    gr = tmp / "gr"
    pt.mkdir(parents=True, exist_ok=True)
    az.mkdir(parents=True, exist_ok=True)
    gr.mkdir(parents=True, exist_ok=True)
    try:
        with tg.Gateway(passthrough, url, pt, target_policies=UPSTREAM_HEADERS) as gw:
            st, init, sid, proto = gateway_session(gw)
            if not sid:
                out["passthrough"] = {"ok": False, "error": init}
                check(failures, f"{target['name']} passthrough initialize", False, str(init)[:120])
                return out
            listed, _ = gateway_list(gw, sid, proto)
            match = listed == names
            out["passthrough"] = {
                "ok": match,
                "n_listed": len(listed),
                "n_direct": len(names),
                "only_gateway": sorted(listed - names)[:20],
                "only_direct": sorted(names - listed)[:20],
            }
            check(failures, f"{target['name']} passthrough tools/list == direct", match,
                  f"gw={len(listed)} direct={len(names)}")
    except Exception as e:
        out["passthrough"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        check(failures, f"{target['name']} passthrough", False, str(e)[:160])
        return out

    expected = {n for n in names if prefix_allows(n)}
    denied_sample = next((n for n in sorted(names) if n not in expected), None)
    try:
        with tg.Gateway(passthrough, url, az, extra_policies=prefix_policies(),
                        target_policies=UPSTREAM_HEADERS) as gw:
            st, init, sid, proto = gateway_session(gw)
            if not sid:
                out["prefix_authz"] = {"ok": False, "error": init}
                check(failures, f"{target['name']} prefix-authz initialize", False, str(init)[:120])
            else:
                listed, _ = gateway_list(gw, sid, proto)
                match = listed == expected
                denied_ok = None
                if denied_sample:
                    call_out = gateway_call(gw, sid, denied_sample, {}, proto)
                    kind, detail = classify_call(call_out)
                    # Hidden tools typically return HTTP 400 / unknown tool, not a successful result.
                    denied_ok = kind in {"rpc_error", "transport"} or call_out.get("error")
                    if "result" in call_out and not (call_out.get("result") or {}).get("isError"):
                        denied_ok = False
                allowed_call = None
                pick = pick_call([t for t in (direct.get("_tools_meta") or []) if t.get("name") in expected])
                if pick:
                    kind, detail = classify_call(gateway_call(gw, sid, pick["name"], pick["arguments"], proto))
                    allowed_call = {"tool": pick["name"], "kind": kind, "detail": detail,
                                    "ok": kind in {"unchanged", "annotated", "tool_error"}}
                out["prefix_authz"] = {
                    "ok": match and (denied_ok is not False),
                    "listed": sorted(listed),
                    "expected": sorted(expected),
                    "n_hidden": len(names) - len(expected),
                    "denied_sample": denied_sample,
                    "denied_ok": denied_ok,
                    "allowed_call": allowed_call,
                }
                check(failures, f"{target['name']} prefix-authz listed == lookup_/list_", match,
                      f"listed={len(listed)} expected={len(expected)} hidden={len(names)-len(expected)}")
                if denied_sample:
                    check(failures, f"{target['name']} prefix-authz denies {denied_sample}", bool(denied_ok))
    except Exception as e:
        out["prefix_authz"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        check(failures, f"{target['name']} prefix-authz", False, str(e)[:160])

    # Guardrail scoping: rci-specific expressions must not fail-closed on foreign results.
    pick = pick_call([t for t in (direct.get("_tools_meta") or []) if t.get("name") not in GUARDRAIL_TOOLS])
    if not pick:
        out["guardrail_scope"] = {"ok": True, "skipped": "no non-rci tool to call"}
        print(f"    skip guardrail scoping (no safe non-rci tool)")
        return out
    try:
        gw = tg.Gateway(tg.CALIB, url, gr, target_policies=UPSTREAM_HEADERS)
        if gw.validate().returncode != 0:
            out["guardrail_scope"] = {"ok": False, "skipped": "binary rejects kind: expression"}
            check(failures, f"{target['name']} guardrail template validates", False)
            return out
        with gw:
            st, init, sid, proto = gateway_session(gw)
            if not sid:
                out["guardrail_scope"] = {"ok": False, "error": init}
                check(failures, f"{target['name']} guardrail initialize", False, str(init)[:120])
                return out
            call_out = gateway_call(gw, sid, pick["name"], pick["arguments"], proto)
            kind, detail = classify_call(call_out)
            # A foreign tool may legitimately return a tool_error (bad args). It must not
            # be rejected by the rci-knowledge completeness / year rules.
            ok = kind != "guardrail_reject"
            out["guardrail_scope"] = {
                "ok": ok, "tool": pick["name"], "args": pick["arguments"],
                "kind": kind, "detail": detail,
            }
            check(failures, f"{target['name']} rci guardrails do not reject {pick['name']}", ok, f"{kind} {detail}")
    except Exception as e:
        out["guardrail_scope"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        check(failures, f"{target['name']} guardrail scoping", False, str(e)[:160])
    return out


def discover(limit: int) -> list[dict]:
    """Pull latest registry entries that advertise streamable-http and no required secret header."""
    found, cursor, seen = [], None, set()
    while len(found) < limit:
        url = REGISTRY + "?limit=50"
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        req = urllib.request.Request(url, headers={"User-Agent": "cel-policies-library-live/0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                payload = json.loads(r.read().decode())
        except Exception as e:
            print(f"registry fetch failed: {e}")
            break
        for item in payload.get("servers") or []:
            meta = item.get("_meta") or {}
            official = meta.get("io.modelcontextprotocol.registry/official") or {}
            if official.get("isLatest") is False:
                continue
            server = item.get("server") or {}
            remotes = server.get("remotes") or []
            for remote in remotes:
                if remote.get("type") != "streamable-http":
                    continue
                headers = remote.get("headers") or []
                if any(h.get("isRequired") for h in headers):
                    continue
                u = (remote.get("url") or "").rstrip("/")
                if not u.startswith("https://") or u in seen:
                    continue
                if any(u == c["url"].rstrip("/") for c in CURATED):
                    continue
                seen.add(u)
                found.append({"name": server.get("name") or u, "url": u, "discovered": True})
                if len(found) >= limit:
                    break
            if len(found) >= limit:
                break
        cursor = (payload.get("metadata") or {}).get("nextCursor")
        if not cursor:
            break
    return found


def gateway_version() -> dict:
    if not tg.BIN:
        return {}
    import subprocess
    raw = subprocess.run([tg.BIN, "--version"], capture_output=True, text=True).stdout
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw.strip()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--discover", type=int, default=0,
                    help="also probe N extra registry servers (tools/list only)")
    ap.add_argument("--gateway-discovered", type=int, default=0,
                    help="run full gateway checks on the first N discovered servers that listed tools")
    ap.add_argument("--timeout", type=int, default=25)
    args = ap.parse_args()
    if not tg.BIN:
        print("set AGENTGATEWAY_BIN or put agentgateway on PATH")
        return 2

    failures: list[int] = []
    report = {
        "started": utcnow(),
        "agentgateway": gateway_version(),
        "binary": os.environ.get("AGENTGATEWAY_BIN") or tg.BIN,
        "rci_api_key_present": bool(os.environ.get("RCI_API_KEY", "").strip()),
        "targets": [],
        "discovered": [],
    }
    print(f"agentgateway {report['agentgateway'].get('version')}  binary={report['binary']}")
    print(f"RCI_API_KEY present: {report['rci_api_key_present']}")

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        for target in CURATED:
            print(f"\n== {target['name']}  {target['url']}")
            direct = probe_direct(target["url"])
            rec = {"name": target["name"], "url": target["url"], "note": target.get("note"),
                   "direct": {k: v for k, v in direct.items() if not k.startswith("_")}}
            if not direct["ok"]:
                print(f"    unreachable or auth-gated: http={direct['http']} {direct.get('error')}")
                rec["reachable"] = False
                report["targets"].append(rec)
                continue
            print(f"    direct tools/list: {direct['n_tools']} tools  "
                  f"lookup_={len(direct['prefixes'].get('lookup_', []))} "
                  f"list_={len(direct['prefixes'].get('list_', []))} "
                  f"calculate_={len(direct['prefixes'].get('calculate_', []))} "
                  f"other={len(direct['prefixes'].get('other', []))}")
            rec["reachable"] = True
            rec["gateway"] = run_gateway_checks(target, direct, tmp / target["name"], failures)
            rec["direct"]["prefixes"] = {
                k: (len(v) if k == "other" else v)
                for k, v in direct["prefixes"].items()
            }
            rec["direct"]["tools"] = direct["tools"][:80]
            report["targets"].append(rec)

        if args.discover:
            print(f"\n== registry discovery (up to {args.discover} extra servers, tools/list only)")
            extras = discover(args.discover)
            print(f"    candidates: {len(extras)}")
            gw_budget = args.gateway_discovered
            for target in extras:
                direct = probe_direct(target["url"])
                rec = {"name": target["name"], "url": target["url"],
                       "ok": direct["ok"], "http": direct["http"],
                       "n_tools": direct.get("n_tools", 0),
                       "prefixes": {
                           k: (len(v) if isinstance(v, list) else v)
                           for k, v in (direct.get("prefixes") or {}).items()
                       }}
                status = "ok" if direct["ok"] else f"fail http={direct['http']}"
                print(f"    {status:16} {target['url']}  tools={rec['n_tools']}")
                if gw_budget and direct["ok"] and direct.get("n_tools"):
                    print(f"    -- gateway checks ({gw_budget} remaining)")
                    rec["gateway"] = run_gateway_checks(
                target, direct, tmp / f"disc-{target['name'].replace('/', '_')}", failures)
                    rec["direct_tools"] = (direct.get("tools") or [])[:80]
                    gw_budget -= 1
                report["discovered"].append(rec)
                time.sleep(0.4)

    n_fail = sum(failures)
    reachable = sum(1 for t in report["targets"] if t.get("reachable"))
    report["finished"] = utcnow()
    report["summary"] = {
        "curated": len(CURATED),
        "reachable": reachable,
        "gateway_checks_failed": n_fail,
        "discovered_ok": sum(1 for d in report["discovered"] if d.get("ok")),
        "discovered_n": len(report["discovered"]),
    }
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORT_DIR / f"public-mcp-{stamp}.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nreport: {path}")
    print(json.dumps(report["summary"], indent=2))
    print(f"{'all gateway checks passed' if not n_fail else f'{n_fail} gateway check(s) FAILED'}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
