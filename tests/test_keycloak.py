"""Authorization policies against a REAL identity provider (Keycloak), validated by agentgateway.

Keycloak issues the access tokens (password grant) and agentgateway verifies them against the
realm's JWKS URL; nothing is signed locally. Needs a running Keycloak with the `cel` realm and
users op/adm/view/norole (see README, "Real identity provider"), reachable at KEYCLOAK_URL
(default http://127.0.0.1:19180). Skipped when it is not reachable or no agentgateway binary is set.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

import live_gateway_check as g  # noqa: E402
import test_gateway as tg  # noqa: E402
from test_gateway import mock_mcp  # noqa: E402,F401  (fixture)

KC = os.environ.get("KEYCLOAK_URL", "http://127.0.0.1:19180").rstrip("/")
REALM = f"{KC}/realms/cel"
pytestmark = pytest.mark.skipif(not tg.BIN, reason="no agentgateway binary (set AGENTGATEWAY_BIN)")


def _reachable() -> bool:
    try:
        urllib.request.urlopen(f"{REALM}/.well-known/openid-configuration", timeout=3).read()
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def tokens():
    if not _reachable():
        pytest.skip(f"no Keycloak realm at {REALM}")
    out = {}
    for user in ("op", "adm", "view", "norole"):
        body = urllib.parse.urlencode({"grant_type": "password", "client_id": "agw", "username": user,
                                       "password": f"pw-{user}", "scope": "openid"}).encode()
        resp = json.loads(urllib.request.urlopen(f"{REALM}/protocol/openid-connect/token", body, timeout=10).read())
        out[user] = resp["access_token"]
    return out


def jwt_policy():
    return {"jwtAuth": {"mode": "optional", "issuer": REALM,
                        "jwks": {"url": f"{REALM}/protocol/openid-connect/certs"}}}


def rules(*names):
    return {"mcpAuthorization": {"rules": [
        tg.normalize((ROOT / "policies/authorization" / f"{n}.cel").read_text()) for n in names]}}


def admin_tool_allowed(gw, tok):
    sid = gw.session(tok)
    listed = "grant_admin_access" in gw.listed(sid, tok)
    status, out = gw.call(sid, "grant_admin_access", {"contractor": "x"}, tok)
    called = status == 200 and "result" in out and not (out["result"] or {}).get("isError")
    assert listed == called, "tools/list and tools/call disagree"
    return called


@pytest.mark.parametrize("rule,expect", [
    ("require_operator", {"op": True, "adm": False, "view": False, "norole": False}),
    ("require_admin", {"op": False, "adm": True, "view": False, "norole": False}),
])
def test_role_rules_with_real_keycloak_tokens(tmp_path, mock_mcp, tokens, rule, expect):
    policies = {**jwt_policy(), **rules("allow_harmless", rule)}
    for user, allowed in expect.items():
        with tg.Gateway(tg.AUTHZ, mock_mcp, tmp_path, policies) as gw:
            assert admin_tool_allowed(gw, tokens[user]) is allowed, (rule, user)


def test_anonymous_caller_gets_only_the_harmless_tool(tmp_path, mock_mcp, tokens):
    with tg.Gateway(tg.AUTHZ, mock_mcp, tmp_path, {**jwt_policy(), **rules("allow_harmless", "require_operator")}) as gw:
        sid = gw.session()
        assert gw.listed(sid) == {"grant_read_access"}


def test_tampered_token_is_rejected_before_authorization(tmp_path, mock_mcp, tokens):
    bad = tokens["op"][:-6] + ("AAAAAA" if not tokens["op"].endswith("AAAAAA") else "BBBBBB")
    with tg.Gateway(tg.AUTHZ, mock_mcp, tmp_path, {**jwt_policy(), **rules("allow_harmless", "require_operator")}) as gw:
        status, out, _ = g.rpc(gw.url, "initialize", {"protocolVersion": g.PROTOCOL, "capabilities": {},
                                                      "clientInfo": {"name": "t", "version": "0"}}, token=bad)
        assert status == 401 or "result" not in out, (status, out)


@pytest.mark.parametrize("user,allowed", [("op", True), ("adm", False), ("view", False), ("norole", False)])
def test_calculate_rule_with_real_tokens(tmp_path, mock_mcp, tokens, user, allowed):
    policies = {**jwt_policy(), **rules("allow_lookup_tools", "require_operator_for_calculate")}
    tok = tokens[user]
    with tg.Gateway(tg.AUTHZ, mock_mcp, tmp_path, policies) as gw:
        sid = gw.session(tok)
        listed = gw.listed(sid, tok)
        assert "lookup_mpfs" in listed and "grant_read_access" not in listed   # only lookup_/calculate_ prefixes
        assert ("calculate_payment" in listed) is allowed
        status, out = gw.call(sid, "calculate_payment", {"cpt": "99213"}, tok)
        assert (status == 200 and "result" in out) is allowed
