"""Tests that run the library's policies inside a real agentgateway process.

These are the authoritative tests: agentgateway's own CEL engine evaluates the
rules. The Python tests in test_policies.py use cel-python and only cover the
library's offline CLI.

Needs an agentgateway binary: set AGENTGATEWAY_BIN or put `agentgateway` on PATH.
Tests are skipped (not passed) when no binary is found, or when the binary is too
old for mcpGuardrails (calibration tests).
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import live_gateway_check as g  # noqa: E402  (rpc helper)

BIN = os.environ.get("AGENTGATEWAY_BIN") or shutil.which("agentgateway")
pytestmark = pytest.mark.skipif(not BIN, reason="no agentgateway binary (set AGENTGATEWAY_BIN)")


def gateway_version() -> tuple:
    if not BIN:
        return (0, 0, 0)
    ver = json.loads(subprocess.run([BIN, "--version"], capture_output=True, text=True).stdout)["version"]
    return tuple(int(x) for x in ver.split("-")[0].split("."))

AUTHZ = ROOT / "templates" / "agentgateway.yaml"
PREFIX = ROOT / "templates" / "agentgateway-prefix-authz.yaml"
CALIB = ROOT / "templates" / "agentgateway-calibration.yaml"
SIGNALS_TEMPLATE = ROOT / "templates" / "agentgateway-signals.yaml"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def normalize(expr: str) -> str:
    return " ".join(
        l.strip() for l in expr.splitlines() if l.strip() and not l.lstrip().startswith("//")
    ).replace("( ", "(").replace(" )", ")")


def squash(expr: str) -> str:
    return "".join(normalize(expr).split())


def wait_port(port: int, proc, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise RuntimeError("process exited early")
        with socket.socket() as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"port {port} never opened")


@pytest.fixture(scope="module")
def mock_mcp():
    port = free_port()
    proc = subprocess.Popen([sys.executable, str(ROOT / "tests/gateway/mock_mcp.py"), "--port", str(port)])
    wait_port(port, proc)
    yield f"http://127.0.0.1:{port}/mcp"
    proc.terminate()
    proc.wait()


class Gateway:
    def __init__(self, template: Path, upstream: str, tmp_path: Path, extra_policies=None, files=None,
                 target_policies=None):
        cfg = yaml.safe_load(template.read_text())
        self.port = free_port()
        cfg["mcp"]["port"] = self.port
        if "mcp" in cfg["mcp"]["targets"][0]:        # stdio targets carry their own cmd/args
            cfg["mcp"]["targets"][0]["mcp"]["host"] = upstream
        cfg["mcp"]["policies"].update(extra_policies or {})
        if target_policies:
            tgt = cfg["mcp"]["targets"][0]
            tgt["policies"] = {**(tgt.get("policies") or {}), **target_policies}
        # keep a developer's own gateway (admin :15000) from clashing with the test one. Free
        # ports rather than "off": releases before 1.3 only accept an ip:port here.
        cfg["config"] = {"adminAddr": f"127.0.0.1:{free_port()}", "statsAddr": f"127.0.0.1:{free_port()}",
                         "readinessAddr": f"127.0.0.1:{free_port()}"}
        self.cfg_path = tmp_path / "gw.yaml"
        self.cfg_path.write_text(yaml.safe_dump(cfg, width=10_000))
        for name, content in (files or {}).items():
            (tmp_path / name).write_text(content)
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        self.tmp = tmp_path

    def validate(self) -> subprocess.CompletedProcess:
        return subprocess.run([BIN, "--validate-only", "-f", str(self.cfg_path)],
                              capture_output=True, text=True, cwd=self.tmp)

    def __enter__(self):
        self.proc = subprocess.Popen([BIN, "-f", str(self.cfg_path)], cwd=self.tmp,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_port(self.port, self.proc)
        except BaseException:
            self.proc.terminate()   # do not leak a half-started gateway
            self.proc.wait()
            raise
        return self

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait()

    def session(self, token=None):
        _, init, sid = g.rpc(self.url, "initialize", {
            "protocolVersion": g.PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"}}, token=token)
        assert "result" in init, init
        g.rpc(self.url, "notifications/initialized", session=sid, notify=True, token=token)
        return sid

    def listed(self, sid, token=None):
        _, out, _ = g.rpc(self.url, "tools/list", {}, session=sid, token=token)
        return {t["name"] for t in out["result"]["tools"]}

    def call(self, sid, name, args=None, token=None):
        status, out, _ = g.rpc(self.url, "tools/call", {"name": name, "arguments": args or {}},
                               session=sid, token=token)
        return status, out


# -------------------------------------------------------------- templates ----


def test_templates_pass_validate_only(tmp_path, mock_mcp):
    assert Gateway(AUTHZ, mock_mcp, tmp_path).validate().returncode == 0
    assert Gateway(PREFIX, mock_mcp, tmp_path).validate().returncode == 0
    res = Gateway(CALIB, mock_mcp, tmp_path).validate()
    if res.returncode != 0:
        pytest.skip(f"binary does not accept mcpGuardrails: {res.stderr.strip()[:120]}")


def test_calibration_template_conditions_equal_cel_files():
    procs = yaml.safe_load(CALIB.read_text())["mcp"]["policies"]["mcpGuardrails"]["processors"]
    d = ROOT / "policies" / "guardrails"
    assert squash(procs[0]["condition"]) == squash((d / "block_incomplete_result.cel").read_text())
    assert squash(procs[1]["condition"]) == squash((d / "flag_stale_result.cel").read_text())
    assert squash(procs[1]["transform"]) == squash((d / "flag_stale_result.transform.cel").read_text())
    assert squash(procs[2]["condition"]) == squash((d / "block_incomplete_flat_result.cel").read_text())
    assert squash(procs[3]["condition"]) == squash((d / "flag_stale_snapshot.cel").read_text())
    assert squash(procs[3]["transform"]) == squash((d / "flag_stale_snapshot.transform.cel").read_text())


# ---------------------------------------------------------- authorization ----


def test_authorization_without_jwt(tmp_path, mock_mcp):
    with Gateway(AUTHZ, mock_mcp, tmp_path) as gw:
        sid = gw.session()
        assert gw.listed(sid) == {"grant_read_access"}
        assert gw.call(sid, "grant_read_access", {"contractor": "x"})[0] == 200
        status, out = gw.call(sid, "grant_admin_access", {"contractor": "x"})
        allowed = status == 200 and "result" in out and not (out.get("result") or {}).get("isError")
        assert not allowed, out


def _jwt_material(tmp_path):
    jwt = pytest.importorskip("jwt")
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    ser = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    n = key.public_key().public_numbers()
    b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    jwks = json.dumps({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "t1", "n": b64(n.n), "e": b64(n.e)}]})
    now = int(time.time())

    def token(**claims):
        base = {"iss": "pytest", "aud": "pytest-aud", "iat": now, "exp": now + 600, **claims}
        return jwt.encode(base, pem, algorithm="RS256", headers={"kid": "t1"})

    return jwks, token


@pytest.mark.parametrize(
    "claims,admin_allowed",
    [
        ({"sub": "u1", "roles": ["operator"]}, True),
        ({"sub": "u1", "roles": ["viewer"]}, False),
        ({"sub": "u1", "roles": ["admin"]}, False),   # rule wants "operator"
        ({"sub": "u1"}, False),                       # roles missing: clean non-match (has(jwt.roles))
        ({"sub": "u1", "roles": "superoperator"}, False),  # string claim must not substring-match
        ({"sub": "u1", "roles": "operator"}, False),       # roles must be a list, even if the string is exact
        ({"sub": "u1", "roles": ["viewer", "operator"]}, True),
    ],
)
def test_authorization_with_jwt(tmp_path, mock_mcp, claims, admin_allowed):
    jwks, token = _jwt_material(tmp_path)
    jwt_policy = {"jwtAuth": {"mode": "optional", "issuer": "pytest",
                              "audiences": ["pytest-aud"], "jwks": {"file": "./jwks.json"}}}
    tok = token(**claims)
    with Gateway(AUTHZ, mock_mcp, tmp_path, jwt_policy, {"jwks.json": jwks}) as gw:
        sid = gw.session(tok)
        listed = gw.listed(sid, tok)
        assert "grant_read_access" in listed
        assert ("grant_admin_access" in listed) is admin_allowed
        status, out = gw.call(sid, "grant_admin_access", {"contractor": "x"}, tok)
        assert (status == 200 and "result" in out) is admin_allowed


# ------------------------------------------------------------ calibration ----


def test_original_substring_rule_admits_a_string_roles_claim(tmp_path, mock_mcp):
    """Why require_operator uses exists(): in agentgateway's engine `"operator" in jwt.roles` is a
    substring test when the claim is a string, so the original mcp-judge-seam rule admits a token
    whose roles claim is "superoperator". Documents the weakness; the shipped rules do not have it."""
    jwks, token = _jwt_material(tmp_path)
    policies = {
        "jwtAuth": {"mode": "optional", "issuer": "pytest", "audiences": ["pytest-aud"],
                    "jwks": {"file": "./jwks.json"}},
        "mcpAuthorization": {"rules": [
            'mcp.tool.name == "grant_read_access"',
            'mcp.tool.name == "grant_admin_access" && has(jwt.sub) && "operator" in jwt.roles',
        ]},
    }
    tok = token(sub="u1", roles="superoperator")
    with Gateway(AUTHZ, mock_mcp, tmp_path, policies, {"jwks.json": jwks}) as gw:
        sid = gw.session(tok)
        assert "grant_admin_access" in gw.listed(sid, tok)


def test_require_admin_policy_in_gateway(tmp_path, mock_mcp):
    """require_admin.cel is not in the shipped template, so build the rules from the .cel files."""
    jwks, token = _jwt_material(tmp_path)
    rules = [
        normalize((ROOT / "policies/authorization" / f"{n}.cel").read_text())
        for n in ("allow_harmless", "require_admin")
    ]
    policies = {
        "jwtAuth": {"mode": "optional", "issuer": "pytest", "audiences": ["pytest-aud"],
                    "jwks": {"file": "./jwks.json"}},
        "mcpAuthorization": {"rules": rules},
    }
    for claims, allowed in [
        ({"sub": "u1", "roles": ["admin"]}, True),
        ({"sub": "u1", "roles": ["operator"]}, False),
        ({"sub": "u1"}, False),
    ]:
        tok = token(**claims)
        with Gateway(AUTHZ, mock_mcp, tmp_path, policies, {"jwks.json": jwks}) as gw:
            sid = gw.session(tok)
            assert ("grant_admin_access" in gw.listed(sid, tok)) is allowed, claims
            status, out = gw.call(sid, "grant_admin_access", {"contractor": "x"}, tok)
            assert (status == 200 and "result" in out) is allowed, claims


@pytest.mark.parametrize("policy", [
    "calibration/block_contradiction", "calibration/block_incomplete", "calibration/review_stale_data",
    "combined/multi_signal_safety_gate", "combined/moderate_safety_gate",
])
def test_signal_policies_agree_between_agentgateway_and_cel_python(tmp_path, mock_mcp, policy):
    """Evaluate each signal policy's expression inside agentgateway and compare with cel-python.

    The signals arrive as tool-call arguments and are read from `mcp.params.arguments` in a
    request-phase guardrail. The only change to the policy text is prefixing the three signal
    names with the binding `s.`; this checks the expression semantics in agentgateway's engine,
    it is not a deployment path for these policies.
    """
    import itertools
    import re
    import cel_policies as cp

    expr = normalize((ROOT / "policies" / f"{policy}.cel").read_text())
    bound = re.sub(r"\b(contradiction|completeness|currency)\b", r"s.\1", expr)
    cfg_policies = {"mcpGuardrails": {"processors": [{
        "kind": "expression",
        "condition": f"mcp.params.arguments.with(s, {bound})",
        "reject": "MATCH",
        "methods": {"tools/call": "request"},
    }]}}
    tmpl = tmp_path / "t.yaml"
    tmpl.write_text("mcp:\n  port: 0\n  policies: {}\n  targets:\n  - name: m\n    mcp:\n      host: x\n")
    grid = itertools.product([False, True], [0.0, 0.39, 0.4, 0.74, 0.75, 1.0], [0.0, 0.29, 0.3, 0.59, 0.6, 1.0])
    gw = Gateway(tmpl, mock_mcp, tmp_path, cfg_policies)
    if gw.validate().returncode != 0:
        pytest.skip("binary does not accept mcpGuardrails kind: expression")
    with gw:
        sid = gw.session()
        for c, comp, cur in grid:
            sig = {"contradiction": c, "completeness": comp, "currency": cur}
            _, out = gw.call(sid, "lookup_mpfs", {"case": "full", **sig})
            # a request-phase reject on tools/call comes back as an isError tool result
            res = out.get("result") or {}
            text = (res.get("content") or [{}])[0].get("text")
            gateway_matched = res.get("isError") is True and text == "MATCH"
            assert "error" not in out or out["error"].get("message") != "guardrail check failed", (sig, out)
            assert gateway_matched == cp.evaluate(policy, sig).matched, sig


# ------------------------------------------------------------ calibration ----


@pytest.fixture(scope="module")
def calib_gateway(tmp_path_factory, mock_mcp):
    tmp = tmp_path_factory.mktemp("calib")
    gw = Gateway(CALIB, mock_mcp, tmp)
    if gw.validate().returncode != 0:
        pytest.skip("binary does not accept mcpGuardrails")
    with gw:
        yield gw


def _sc(out):
    return (out.get("result") or {}).get("structuredContent") or {}


@pytest.mark.parametrize("case", ["full", "mid"])
def test_complete_fresh_result_passes_unannotated(calib_gateway, case):
    sid = calib_gateway.session()
    _, out = calib_gateway.call(sid, "lookup_mpfs", {"case": case})
    assert "error" not in out and _sc(out)["results"]
    assert "calibration" not in _sc(out)


@pytest.mark.parametrize("case", ["partial", "empty"])
def test_incomplete_result_is_rejected(calib_gateway, case):
    sid = calib_gateway.session()
    _, out = calib_gateway.call(sid, "lookup_mpfs", {"case": case})
    err = out.get("error") or {}
    assert "completeness < 0.4" in err.get("message", ""), out
    assert "result" not in out


def test_incomplete_later_row_is_rejected(calib_gateway):
    sid = calib_gateway.session()
    _, out = calib_gateway.call(sid, "lookup_mpfs", {"case": "mixed"})
    err = out.get("error") or {}
    assert "completeness < 0.4" in err.get("message", ""), out


def test_stale_result_is_annotated_not_blocked(calib_gateway):
    sid = calib_gateway.session()
    _, out = calib_gateway.call(sid, "lookup_mpfs", {"case": "stale"})
    assert "error" not in out
    sc = _sc(out)
    assert sc["calibration"]["tier"] == "review"
    assert sc["results"][0]["hcpcs_code"] == "99213"  # original data preserved


def test_tool_error_result_passes_through(calib_gateway):
    sid = calib_gateway.session()
    _, out = calib_gateway.call(sid, "lookup_mpfs", {"case": "error"})
    assert out["result"]["isError"] is True


def test_flat_result_without_payment_fields_is_rejected(calib_gateway):
    sid = calib_gateway.session()
    _, out = calib_gateway.call(sid, "lookup_opps", {"code": "99213"})
    assert "completeness < 0.4" in (out.get("error") or {}).get("message", ""), out
    _, out = calib_gateway.call(sid, "lookup_opps", {"code": "71046"})
    assert "error" not in out and out["result"]["structuredContent"]["payment_rate"] == 88.91


def test_snapshot_older_than_a_year_is_flagged_by_name(calib_gateway):
    sid = calib_gateway.session()
    _, out = calib_gateway.call(sid, "list_dataset_snapshots", {})
    sc = _sc(out)
    assert sc["calibration"]["datasets"] == ["old_set"]
    assert [s["dataset"] for s in sc["snapshots"]] == ["old_set", "fresh_set"]  # rows untouched


def test_rules_scoped_to_one_tool_do_not_touch_other_tools(calib_gateway):
    """lookup_dme has a `results` list with different fields and an old year; the lookup_mpfs rules must ignore it."""
    sid = calib_gateway.session()
    _, out = calib_gateway.call(sid, "lookup_dme", {})
    assert "error" not in out and "calibration" not in _sc(out) and _sc(out)["results"][0]["state"] == "CA"
    _, out = calib_gateway.call(sid, "list_dataset_snapshots", {})
    assert "error" not in out  # results-shape rules also skip results-less shapes


def test_unscoped_expression_fails_closed_on_other_tools(tmp_path, mock_mcp):
    """Without a tool and shape guard, indexing `results` on a foreign tool errors and fail-closes.

    This is the pitfall the shipped rules avoid. agentgateway's own toy example
    (examples/mcp-guardrails/expression) uses `has(mcp.result.content)` for a global mask;
    a completeness rule copied without `mcp.tool.name` is not that.
    """
    tmpl = tmp_path / "t.yaml"
    tmpl.write_text("mcp:\n  port: 0\n  policies: {}\n  targets:\n  - name: m\n    mcp:\n      host: x\n")
    policies = {"mcpGuardrails": {"processors": [{
        "kind": "expression",
        "condition": "size(mcp.result.structuredContent.results) == 0",
        "reject": "unscoped",
        "methods": {"tools/call": "response"},
    }]}}
    gw = Gateway(tmpl, mock_mcp, tmp_path, policies)
    if gw.validate().returncode != 0:
        pytest.skip("binary does not accept mcpGuardrails kind: expression")
    with gw:
        sid = gw.session()
        _, out = gw.call(sid, "grant_read_access", {"contractor": "x"})
        # Exact fail-closed string. A plain `reject: unscoped` match would mean the rule
        # evaluated normally, which is not the pitfall. Same strings seen live on
        # pathwren/plantguide/deepwiki (scripts/live_pitfalls.py).
        err = out.get("error") or {}
        assert err.get("code") == -32603 and err.get("message") == "guardrail check failed", out
