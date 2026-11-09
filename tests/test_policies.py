"""Tests for the CEL Policies Library. Every policy is compiled and evaluated
with cel-python; nothing here is mocked."""

import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cel_policies as cp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ALL = [f"{c}/{n}" for c, names in cp.list_policies().items() for n in names]


def jwt_input(tool, jwt):
    d = {"mcp": {"tool": {"name": tool}}}
    if jwt is not None:
        d["jwt"] = jwt
    return d


# ------------------------------------------------------------ structure ----


def test_expected_policy_set():
    assert len(ALL) == 10
    assert set(cp.list_policies()) == {"authorization", "calibration", "combined"}


@pytest.mark.parametrize("pid", ALL)
def test_policy_compiles_and_has_no_hash_comments(pid):
    cp.compile_policy(pid)
    text = (ROOT / "policies" / f"{pid}.cel").read_text()
    assert not [l for l in text.splitlines() if l.lstrip().startswith("#")]


def test_validate_rejects_bad_syntax(tmp_path, monkeypatch):
    d = tmp_path / "policies" / "calibration"
    d.mkdir(parents=True)
    (d / "bad.cel").write_text("completeness &&& 0.4\n")
    monkeypatch.setattr(cp, "POLICIES_DIR", tmp_path / "policies")
    with pytest.raises(cp.PolicyError):
        cp.compile_policy("calibration/bad")


def test_unknown_policy():
    with pytest.raises(cp.PolicyError):
        cp.compile_policy("calibration/nope")


# -------------------------------------------------------- authorization ----


def test_allow_harmless():
    assert cp.evaluate("authorization/allow_harmless", jwt_input("grant_read_access", None)).verdict == cp.ALLOW
    assert cp.evaluate("authorization/allow_harmless", jwt_input("grant_admin_access", None)).verdict == cp.DENY


@pytest.mark.parametrize(
    "policy,role",
    [("authorization/require_operator", "operator"), ("authorization/require_admin", "admin")],
)
def test_role_policies(policy, role):
    tool = "grant_admin_access"
    ok = cp.evaluate(policy, jwt_input(tool, {"sub": "u1", "roles": [role]}))
    assert ok.verdict == cp.ALLOW
    wrong_role = cp.evaluate(policy, jwt_input(tool, {"sub": "u1", "roles": ["viewer"]}))
    assert wrong_role.verdict == cp.DENY
    no_sub = cp.evaluate(policy, jwt_input(tool, {"roles": [role]}))
    assert no_sub.verdict == cp.DENY
    empty_jwt = cp.evaluate(policy, jwt_input(tool, {}))
    assert empty_jwt.verdict == cp.DENY
    other_tool = cp.evaluate(policy, jwt_input("grant_read_access", {"sub": "u1", "roles": [role]}))
    assert other_tool.verdict == cp.DENY


def test_lookup_and_calculate_rules():
    allow = "authorization/allow_lookup_tools"
    for tool, verdict in [("lookup_mpfs", cp.ALLOW), ("list_payers", cp.ALLOW),
                          ("calculate_payment", cp.DENY), ("check_ncci_mue", cp.DENY)]:
        assert cp.evaluate(allow, jwt_input(tool, None)).verdict == verdict, tool
    calc = "authorization/require_operator_for_calculate"
    assert cp.evaluate(calc, jwt_input("calculate_payment", {"sub": "u", "roles": ["operator"]})).verdict == cp.ALLOW
    assert cp.evaluate(calc, jwt_input("calculate_payment", {"sub": "u", "roles": ["viewer"]})).verdict == cp.DENY
    assert cp.evaluate(calc, jwt_input("lookup_mpfs", {"sub": "u", "roles": ["operator"]})).verdict == cp.DENY
    res = cp.evaluate(calc, jwt_input("calculate_payment", {"sub": "u"}))
    assert res.verdict == cp.DENY and res.matched is False and res.detail == ""


@pytest.mark.parametrize(
    "policy",
    ["authorization/require_operator", "authorization/require_admin",
     "authorization/require_operator_for_calculate"],
)
def test_missing_roles_is_clean_deny(policy):
    tool = "calculate_payment" if "calculate" in policy else "grant_admin_access"
    res = cp.evaluate(policy, jwt_input(tool, {"sub": "u1"}))
    assert res.verdict == cp.DENY and res.matched is False and res.detail == ""


def test_role_membership_is_not_substring():
    # In agentgateway's engine `"operator" in jwt.roles` is a SUBSTRING test when roles is a string
    # (verified in tests/test_gateway.py). exists() needs a list, so a string claim is denied.
    for role, claim in [("authorization/require_operator", "superoperator"), ("authorization/require_admin", "administrator")]:
        res = cp.evaluate(role, jwt_input("grant_admin_access", {"sub": "u1", "roles": claim}))
        assert res.verdict == cp.DENY, (role, claim)
    ops = jwt_input("grant_admin_access", {"sub": "u1", "roles": ["operations"]})
    assert cp.evaluate("authorization/require_operator", ops).verdict == cp.DENY
    adminish = jwt_input("grant_admin_access", {"sub": "u1", "roles": ["administrator"]})
    assert cp.evaluate("authorization/require_admin", adminish).verdict == cp.DENY


# ---------------------------------------------------------- calibration ----

SIG = {"contradiction": False, "completeness": 1.0, "currency": 1.0}


def sig(**kw):
    return {**SIG, **kw}


@pytest.mark.parametrize(
    "policy,data,verdict",
    [
        ("calibration/block_contradiction", sig(contradiction=True), cp.BLOCK),
        ("calibration/block_contradiction", sig(contradiction=False, completeness=0.0), cp.PROCEED),
        ("calibration/block_incomplete", sig(completeness=0.39), cp.BLOCK),
        ("calibration/block_incomplete", sig(completeness=0.4), cp.PROCEED),
        ("calibration/review_stale_data", sig(currency=0.59), cp.REVIEW),
        ("calibration/review_stale_data", sig(currency=0.6), cp.PROCEED),
        ("combined/multi_signal_safety_gate", sig(contradiction=True), cp.BLOCK),
        ("combined/multi_signal_safety_gate", sig(completeness=0.39), cp.BLOCK),
        ("combined/multi_signal_safety_gate", sig(currency=0.0), cp.PROCEED),
        ("combined/multi_signal_safety_gate", sig(completeness=0.5, currency=0.5), cp.PROCEED),
        ("combined/moderate_safety_gate", sig(contradiction=True), cp.REVIEW),
        ("combined/moderate_safety_gate", sig(completeness=0.74), cp.REVIEW),
        ("combined/moderate_safety_gate", sig(currency=0.59), cp.REVIEW),
        ("combined/moderate_safety_gate", sig(completeness=0.75, currency=0.6), cp.PROCEED),
    ],
)
def test_calibration_thresholds(policy, data, verdict):
    assert cp.evaluate(policy, data).verdict == verdict


def test_integer_signals_are_accepted():
    # JSON "1" must not crash an int-vs-double comparison.
    assert cp.evaluate("calibration/block_incomplete", {"completeness": 1}).verdict == cp.PROCEED
    assert cp.evaluate("calibration/block_incomplete", {"completeness": 0}).verdict == cp.BLOCK


def test_missing_signal_is_error_not_proceed():
    res = cp.evaluate("calibration/block_incomplete", {})
    assert res.verdict == cp.ERROR
    assert res.verdict not in cp.PERMITTED


def test_combined_is_union_of_components():
    grid = itertools.product([False, True], [0.0, 0.39, 0.4, 0.74, 0.75, 1.0], [0.0, 0.29, 0.3, 0.59, 0.6, 1.0])
    for c, comp, cur in grid:
        d = {"contradiction": c, "completeness": comp, "currency": cur}
        parts = [
            cp.evaluate(p, d).matched
            for p in (
                "calibration/block_contradiction",
                "calibration/block_incomplete",
            )
        ]
        multi = cp.evaluate("combined/multi_signal_safety_gate", d).matched
        assert multi == any(parts)
        moderate = cp.evaluate("combined/moderate_safety_gate", d).matched
        assert moderate == (c or comp < 0.75 or cur < 0.6)


# ------------------------------------------ fidelity to source projects ----

SIBLINGS = ROOT.parent


def _evaluate_source(path: Path, data: dict) -> bool:
    import celpy

    env = celpy.Environment()
    prog = env.program(env.compile(path.read_text()))
    return bool(prog.evaluate(celpy.json_to_cel(data)))


def _expr(path: Path) -> str:
    lines = [l for l in path.read_text().splitlines() if l.strip() and not l.lstrip().startswith(("#", "//"))]
    return " ".join(lines)


@pytest.mark.skipif(not (SIBLINGS / "mcp-judge-seam" / "policies").is_dir(), reason="mcp-judge-seam not present")
def test_authorization_expressions_match_mcp_judge_seam():
    src = SIBLINGS / "mcp-judge-seam" / "policies"
    assert _expr(ROOT / "policies/authorization/allow_harmless.cel") == _expr(src / "allow_read.cel")
    ours = _expr(ROOT / "policies/authorization/require_operator.cel")
    assert "has(jwt.roles)" in ours and "exists(" in ours
    assert "grant_admin_access" in ours and "operator" in ours


@pytest.mark.skipif(not (SIBLINGS / "mcp-trace-gate" / "policies").is_dir(), reason="mcp-trace-gate not present")
def test_calibration_semantics_match_mcp_trace_gate():
    src = SIBLINGS / "mcp-trace-gate" / "policies"
    grid = itertools.product([False, True], [0.0, 0.39, 0.4, 0.74, 0.75, 1.0], [0.0, 0.59, 0.6, 1.0])
    for c, comp, cur in grid:
        d = {"contradiction": c, "completeness": comp, "currency": cur}
        block_src = _evaluate_source(src / "block.cel", d)
        block_lib = (
            cp.evaluate("calibration/block_contradiction", d).matched
            or cp.evaluate("calibration/block_incomplete", d).matched
        )
        assert block_src == block_lib
        review_src = _evaluate_source(src / "review.cel", d)
        review_lib = (
            cp.evaluate("calibration/review_stale_data", d).matched
            or comp < 0.75  # review.cel's completeness arm; not a separate library policy
        )
        assert review_src == review_lib


def test_agentgateway_template_rules_equal_policy_files():
    template = (ROOT / "templates" / "agentgateway.yaml").read_text()
    rules = [
        l.strip()[2:].strip()[1:-1]
        for l in template.splitlines()
        if l.strip().startswith("- '")
    ]
    assert rules == [
        _expr(ROOT / "policies/authorization/allow_harmless.cel"),
        _expr(ROOT / "policies/authorization/require_operator.cel"),
    ]


def test_prefix_authz_template_rules_equal_policy_files():
    import yaml
    expected = [
        _expr(ROOT / "policies/authorization/allow_lookup_tools.cel"),
        _expr(ROOT / "policies/authorization/require_operator_for_calculate.cel"),
    ]
    for name in ("agentgateway-prefix-authz.yaml", "agentgateway-rci-knowledge.yaml"):
        rules = yaml.safe_load((ROOT / "templates" / name).read_text())["mcp"]["policies"]["mcpAuthorization"]["rules"]
        assert rules == expected, name


# ------------------------------------------------------------------ CLI ----


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / "cel-policies"), *args],
        capture_output=True,
        text=True,
    )


def test_cli_exit_codes():
    ok = run_cli("check", "calibration/block_incomplete", json.dumps({"completeness": 0.9}))
    assert ok.returncode == 0 and "PROCEED" in ok.stdout
    blocked = run_cli("check", "calibration/block_incomplete.cel", json.dumps({"completeness": 0.1}))
    assert blocked.returncode == 1 and "BLOCK" in blocked.stdout
    err = run_cli("check", "calibration/block_incomplete", "{}")
    assert err.returncode == 2
    bad = run_cli("check", "calibration/block_incomplete", "not json")
    assert bad.returncode == 2


def test_cli_validate_all_and_list():
    v = run_cli("validate")
    assert v.returncode == 0 and v.stdout.count("OK") == 10
    assert "calibration/block_contradiction" in run_cli("list").stdout
