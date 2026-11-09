"""Unit tests for SignalProcessor scoring and request/response pairing.

Does not need an agentgateway binary.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("grpc")
pytest.importorskip("grpc_tools")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "processors"))

import signal_processor as sp  # noqa: E402
import ext_mcp_pb2 as pb  # noqa: E402

CONFIG = json.loads((ROOT / "processors" / "signal_processor.example.json").read_text())
TODAY = dt.date(2026, 11, 9)


def _session(msg, session: str):
    msg.metadata_context.fields["session"].string_value = session
    return msg


def _request(session: str, name: str, arguments: dict) -> pb.McpRequest:
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"name": name, "arguments": arguments}).encode(),
    )
    return _session(req, session)


def _response(session: str, result: dict) -> pb.McpResponse:
    req = pb.McpResponse(method="tools/call", mcp_response=json.dumps(result).encode())
    return _session(req, session)


def _mpfs(year=2026, cf=33.4009, extra=None):
    row = {
        "hcpcs_code": "99213", "short_descriptor": "x", "work_rvu": 1.3,
        "total_rvu_facility": 1.72, "total_rvu_nonfacility": 2.85,
        "conversion_factor": cf, "year": year, "pe_rvu_nonfacility": 1.46, "mp_rvu": 0.09,
    }
    if extra:
        row.update(extra)
    return {"structuredContent": {"results": [row]}}


def test_score_missing_year_is_not_fresh():
    proc = sp.SignalProcessor(CONFIG, today=TODAY)
    signals, _, entity = proc.score(
        CONFIG["tools"]["lookup_mpfs"],
        {"results": [{"hcpcs_code": "99213", "short_descriptor": "x", "work_rvu": 1.3,
                      "total_rvu_facility": 1.0, "total_rvu_nonfacility": 1.0,
                      "conversion_factor": 33.4}]},
        {"code": "99213"},
    )
    assert entity == "99213"
    assert signals["currency"] == 0.0
    assert signals["completeness"] < 1.0


def test_score_unparsable_year_is_not_fresh():
    proc = sp.SignalProcessor(CONFIG, today=TODAY)
    signals, _, _ = proc.score(
        CONFIG["tools"]["lookup_mpfs"],
        {"results": [{"year": "CY2026", "hcpcs_code": "99213"}]},
        {"code": "99213"},
    )
    assert signals["currency"] == 0.0


def test_score_omitted_entity_is_none_not_the_string_none():
    proc = sp.SignalProcessor(CONFIG, today=TODAY)
    _, _, entity = proc.score(CONFIG["tools"]["lookup_mpfs"], {"results": [{}]}, {})
    assert entity is None


def test_fifo_pending_pairs_two_in_flight_calls():
    proc = sp.SignalProcessor(CONFIG, today=TODAY)
    proc.CheckRequest(_request("s", "lookup_mpfs", {"code": "99213"}), None)
    proc.CheckRequest(_request("s", "lookup_mpfs", {"code": "99214"}), None)
    first = proc.CheckResponse(_response("s", _mpfs(cf=33.4009)), None)
    second = proc.CheckResponse(_response("s", _mpfs(cf=33.4009)), None)
    assert first.HasField("pass")
    assert second.HasField("pass")
    assert ("s", "99213") in proc._facts
    assert ("s", "99214") in proc._facts


def test_omitted_entity_does_not_share_history():
    proc = sp.SignalProcessor(CONFIG, today=TODAY)
    proc.CheckRequest(_request("s", "lookup_mpfs", {}), None)
    out = proc.CheckResponse(_response("s", _mpfs(cf=33.4009)), None)
    assert out.HasField("pass")
    proc.CheckRequest(_request("s", "calculate_payment", {}), None)
    pay = {"structuredContent": {"physician": {
        "work_rvu": 1.3, "pe_rvu": 1.46, "mp_rvu": 0.09,
        "conversion_factor": 33.5675, "rvu_year": 2026}}}
    out = proc.CheckResponse(_response("s", pay), None)
    assert not out.HasField("error"), out
    assert proc._facts == {}


def test_empty_required_is_incomplete():
    proc = sp.SignalProcessor(CONFIG, today=TODAY)
    signals, _, _ = proc.score({"required": [], "entity": "code"}, {"results": [{}]}, {"code": "1"})
    assert signals["completeness"] == 0.0
    assert signals["currency"] == 0.0
