#!/usr/bin/env python3
"""ExtMCP remote guardrail processor: enforces the library's SIGNAL policies inside agentgateway.

agentgateway calls this gRPC server before and after every `tools/call` (kind: remote in
`mcpGuardrails`; see templates/agentgateway-signals.yaml). On each tool RESULT the processor
computes the three calibration signals, evaluates the library's signal policies, and answers:

  * a BLOCK-list policy matches  -> deny the result (PERMISSION_DENIED, reason names the policy)
  * a REVIEW-list policy matches -> pass the result with a `calibration` annotation merged in
  * otherwise                    -> pass

The upstream tool has already run by the time CheckResponse can BLOCK. This is a result gate,
not a pre-execution safety gate. Use mcpAuthorization to stop a call from reaching the server.

Signals:
  completeness   fraction of the tool's `required` fields that are present and non-null
  currency       1.0 if the record's year field is >= the current calendar year, else 0.0
                 (validity-based; a missing or unparsable year is 0.0, not "fresh")
  contradiction  a fact in this result differs from the same fact in an earlier result for the
                 same entity in the same MCP session. Calls that omit the entity argument are
                 not entered into history.

Default policy lists: BLOCK is combined/multi_signal_safety_gate (contradiction or
completeness < 0.4). REVIEW is combined/moderate_safety_gate, which includes currency < 0.6
so a superseded year is annotated, matching policies/guardrails/flag_stale_result.cel.

Pending request/response pairs are a FIFO queue per session (not a single slot). Responses
that complete out of order can still mis-pair; MCP sessions are typically sequential.

Per-tool configuration comes from a JSON file; see processors/signal_processor.example.json.

    python processors/signal_processor.py --port 9001 --config processors/signal_processor.example.json

Needs grpcio and grpcio-tools. Stubs are generated from processors/ext_mcp.proto on first run.
It is a reference implementation: in-memory state, one instance, plaintext gRPC on loopback.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent import futures
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import cel_policies as cp  # noqa: E402

GEN = HERE / "_gen"
PENDING_TTL_S = 60.0
log = logging.getLogger("signal_processor")


def _ensure_stubs() -> None:
    if not (GEN / "ext_mcp_pb2_grpc.py").exists():
        GEN.mkdir(exist_ok=True)
        subprocess.run(
            [sys.executable, "-m", "grpc_tools.protoc", f"-I{HERE}", f"--python_out={GEN}",
             f"--grpc_python_out={GEN}", str(HERE / "ext_mcp.proto")], check=True)
    sys.path.insert(0, str(GEN))


_ensure_stubs()
import grpc  # noqa: E402
import ext_mcp_pb2 as pb  # noqa: E402
import ext_mcp_pb2_grpc as pb_grpc  # noqa: E402


def _dig(obj, path: str):
    """Follow a dotted path; integer parts index lists. Returns None when anything is missing."""
    for part in path.split(".") if path else []:
        if isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
        if obj is None:
            return None
    return obj


def _deny(reason: str) -> pb.McpResponseResult:
    return pb.McpResponseResult(error=pb.AuthorizationError(
        code=pb.AuthorizationError.PERMISSION_DENIED, reason=reason))


def _pass_request() -> pb.McpRequestResult:
    return pb.McpRequestResult(**{"pass": pb.Pass()})


def _pass_response() -> pb.McpResponseResult:
    return pb.McpResponseResult(**{"pass": pb.Pass()})


class SignalProcessor(pb_grpc.ExtMcpServicer):
    def __init__(self, config: dict, today: dt.date | None = None):
        self.tools = config["tools"]
        self.block = config.get("policies", {}).get("block", ["combined/multi_signal_safety_gate"])
        self.review = config.get("policies", {}).get("review", ["combined/moderate_safety_gate"])
        self.today = today
        self._pending: dict[str, deque[tuple[float, str, dict]]] = {}
        self._facts: dict[tuple[str, str], list[dict]] = {}
        self._lock = threading.Lock()
        self._warned = False

    def _session(self, request) -> str:
        fields = request.metadata_context.fields
        session = fields["session"].string_value if "session" in fields else ""
        if not session and not self._warned:
            self._warned = True
            log.warning(
                "no `session` metadata from the gateway: contradiction history is shared across "
                "all MCP sessions. Map metadata.session to "
                'default(request.headers["mcp-session-id"], "") and confirm the upstream MCP '
                "returns a unique Mcp-Session-Id per initialize")
        return session

    def _prune_pending(self, session: str, now: float) -> None:
        q = self._pending.get(session)
        if not q:
            return
        while q and now - q[0][0] > PENDING_TTL_S:
            q.popleft()
        if not q:
            self._pending.pop(session, None)

    def CheckRequest(self, request, context):
        session = self._session(request)
        if request.method == "tools/call" and request.HasField("mcp_request"):
            try:
                params = json.loads(request.mcp_request)
            except (TypeError, ValueError):
                return pb.McpRequestResult(error=pb.AuthorizationError(
                    code=pb.AuthorizationError.INVALID, reason="calibration: malformed tools/call params"))
            if not isinstance(params, dict):
                return pb.McpRequestResult(error=pb.AuthorizationError(
                    code=pb.AuthorizationError.INVALID, reason="calibration: malformed tools/call params"))
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                args = {}
            now = time.monotonic()
            with self._lock:
                self._prune_pending(session, now)
                self._pending.setdefault(session, deque()).append(
                    (now, str(params.get("name") or ""), args))
        return _pass_request()

    def CheckResponse(self, request, context):
        session = self._session(request)
        if request.method != "tools/call":
            return _pass_response()
        now = time.monotonic()
        with self._lock:
            self._prune_pending(session, now)
            q = self._pending.get(session)
            if q:
                _, tool, args = q.popleft()
                if not q:
                    self._pending.pop(session, None)
            else:
                tool, args = "", {}
        cfg = self.tools.get(tool)
        if cfg is None:
            return _pass_response()
        try:
            result = json.loads(request.mcp_response)
        except (TypeError, ValueError):
            return _deny("calibration: malformed tool result")
        if not isinstance(result, dict):
            return _deny("calibration: malformed tool result")
        sc = result.get("structuredContent")
        if result.get("isError") or not isinstance(sc, dict):
            return _pass_response()  # tool errors already reach the client

        signals, facts, entity = self.score(cfg, sc, args)
        key = (session, entity) if entity is not None else None
        with self._lock:
            history = self._facts.get(key, []) if key is not None else []
            if key is not None:
                signals["contradiction"] = any(
                    k in prior and prior[k] != v for prior in history for k, v in facts.items())
        for policy in self.block:
            res = cp.evaluate(policy, signals)
            if res.matched:
                return _deny(f"calibration: {policy} matched {json.dumps(signals)}")
        if key is not None:
            with self._lock:
                self._facts[key] = (history + [facts])[-100:]
        for policy in self.review:
            if cp.evaluate(policy, signals).matched:
                sc["calibration"] = {"tier": "review", "policy": policy, "signals": signals}
                result["structuredContent"] = sc
                return pb.McpResponseResult(mutated=json.dumps(result).encode())
        return _pass_response()

    def score(self, cfg: dict, sc: dict, args: dict):
        record = _dig(sc, cfg.get("record", ""))
        record = record if isinstance(record, dict) else {}
        required = cfg.get("required") or []
        completeness = (
            sum(record.get(f) is not None for f in required) / len(required) if required else 0.0
        )
        year = record.get(cfg["year"]) if cfg.get("year") else None
        today = self.today or dt.date.today()
        currency = 0.0
        if year is not None:
            try:
                currency = 1.0 if int(year) >= today.year else 0.0
            except (TypeError, ValueError):
                currency = 0.0
        facts = {canon: record[src] for canon, src in cfg.get("facts", {}).items() if record.get(src) is not None}
        entity = None
        field = cfg.get("entity")
        if field:
            raw = args.get(field) if isinstance(args, dict) else None
            if raw is not None and raw != "":
                entity = str(raw)
        return {"completeness": completeness, "currency": currency, "contradiction": False}, facts, entity


def serve(port: int, config: dict, host: str = "127.0.0.1"):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pb_grpc.add_ExtMcpServicer_to_server(SignalProcessor(config), server)
    bound = server.add_insecure_port(f"{host}:{port}")
    server.start()
    return server, bound


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--config", type=Path, default=HERE / "signal_processor.example.json")
    a = ap.parse_args()
    srv, port = serve(a.port, json.loads(a.config.read_text()))
    print(f"signal processor listening on 127.0.0.1:{port}", flush=True)
    srv.wait_for_termination()
