"""The signal policies enforced inside agentgateway through the ExtMCP processor.

Runs processors/signal_processor.py (a gRPC server) and a real agentgateway process whose
mcpGuardrails sends every tools/call to it, in front of the mock MCP server. Needs an
agentgateway binary (AGENTGATEWAY_BIN) and grpcio; skipped otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

pytest.importorskip("grpc")
pytest.importorskip("grpc_tools")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "processors"))
sys.path.insert(0, str(ROOT / "tests"))

import signal_processor as sp  # noqa: E402
import test_gateway as tg  # noqa: E402  (Gateway, free_port, mock_mcp fixture, BIN)
from test_gateway import mock_mcp  # noqa: E402,F401  (fixture)

pytestmark = pytest.mark.skipif(not tg.BIN, reason="no agentgateway binary (set AGENTGATEWAY_BIN)")

SIGNALS = ROOT / "templates" / "agentgateway-signals.yaml"
CONFIG = json.loads((ROOT / "processors" / "signal_processor.example.json").read_text())


@pytest.fixture()
def stack(tmp_path, mock_mcp):
    server, port = sp.serve(tg.free_port(), CONFIG)
    guard = yaml.safe_load(SIGNALS.read_text())["mcp"]["policies"]["mcpGuardrails"]
    guard["processors"][0]["host"] = f"127.0.0.1:{port}"
    gw = tg.Gateway(SIGNALS, mock_mcp, tmp_path, {"mcpGuardrails": guard})
    if gw.validate().returncode != 0:
        server.stop(0)
        pytest.skip("binary does not accept a remote mcpGuardrails processor")
    with gw:
        yield gw, server
    server.stop(0)


def _denial(out):
    err = out.get("error") or {}
    res = out.get("result") or {}
    text = (res.get("content") or [{}])[0].get("text", "") if res.get("isError") else ""
    return err.get("message") or text


def test_template_validates_and_points_at_processor():
    proc = yaml.safe_load(SIGNALS.read_text())["mcp"]["policies"]["mcpGuardrails"]["processors"][0]
    assert proc["kind"] == "remote" and proc["failureMode"] == "failClosed" and proc["methods"] == {"tools/call": "full"}


def test_cross_tool_contradiction_is_blocked_then_clears(stack):
    gw, _ = stack
    sid = gw.session()
    _, out = gw.call(sid, "lookup_mpfs", {"case": "full", "code": "99213"})
    assert "result" in out and "calibration" not in out["result"]["structuredContent"]

    # calculate_payment defaults to the QPP conversion factor: 33.5675 vs lookup_mpfs' 33.4009
    _, out = gw.call(sid, "calculate_payment", {"cpt": "99213"})
    msg = _denial(out)
    assert "combined/multi_signal_safety_gate" in msg and '"contradiction": true' in msg, out

    # same entity, aligned basis: agrees with the earlier result, so it passes
    _, out = gw.call(sid, "calculate_payment", {"cpt": "99213", "qpp": False})
    assert "result" in out and not out["result"].get("isError"), out


def test_contradiction_is_scoped_to_session_and_entity(stack):
    gw, _ = stack
    sid = gw.session()
    gw.call(sid, "lookup_mpfs", {"case": "full", "code": "99213"})
    _, out = gw.call(sid, "calculate_payment", {"cpt": "99214"})     # different code: nothing to contradict
    assert "result" in out and not _denial(out)
    other = gw.session()                                               # different session
    _, out = gw.call(other, "calculate_payment", {"cpt": "99213"})
    # Isolation is the gateway forwarding distinct Mcp-Session-Id values into ExtMCP
    # metadata. A live remote MCP reproduces that on 1.6.0 and 1.7.0
    # (scripts/live_session_metadata.py). The mock must mint a unique id per initialize;
    # a constant "mock-session" made 1.6.0 look like it leaked.
    assert "result" in out and not _denial(out), out


@pytest.mark.parametrize("case", ["partial", "empty"])
def test_incomplete_result_is_blocked(stack, case):
    gw, _ = stack
    sid = gw.session()
    _, out = gw.call(sid, "lookup_mpfs", {"case": case, "code": "99213"})
    assert "combined/multi_signal_safety_gate" in _denial(out), out


def test_stale_result_is_annotated_for_review_not_blocked(stack):
    gw, _ = stack
    sid = gw.session()
    _, out = gw.call(sid, "lookup_mpfs", {"case": "stale", "code": "99213"})
    cal = out["result"]["structuredContent"]["calibration"]
    assert cal["tier"] == "review" and cal["policy"] == "combined/moderate_safety_gate"
    assert cal["signals"]["currency"] == 0.0
    assert not _denial(out)


def test_mid_completeness_is_annotated_for_review_not_blocked(stack):
    gw, _ = stack
    sid = gw.session()
    _, out = gw.call(sid, "lookup_mpfs", {"case": "mid", "code": "99213"})   # 4 of 7 fields
    cal = out["result"]["structuredContent"]["calibration"]
    assert cal["tier"] == "review" and cal["policy"] == "combined/moderate_safety_gate"
    assert 0.5 < cal["signals"]["completeness"] < 0.6


def test_tools_without_a_config_entry_pass_untouched(stack):
    gw, _ = stack
    sid = gw.session()
    _, out = gw.call(sid, "lookup_opps", {"code": "99213"})   # all-null payment fields, but not configured
    assert "result" in out and "calibration" not in out["result"]["structuredContent"]


def test_fails_closed_when_the_processor_is_down(stack):
    gw, server = stack
    sid = gw.session()
    server.stop(0).wait()
    _, out = gw.call(sid, "lookup_mpfs", {"case": "full", "code": "99213"})
    # Exact strings, so an unrelated upstream error cannot satisfy the test. 1.7.0 returns a
    # generic message; 1.6.0 echoes the connect error. Same strings seen live with a dead
    # processor in front of pathwren (scripts/live_pitfalls.py).
    err = out.get("error") or {}
    assert err.get("code") == -32603, out
    msg = err.get("message", "")
    assert msg == "guardrail check failed" or msg.startswith("mcpGuardrails checkRequest failed:"), out
