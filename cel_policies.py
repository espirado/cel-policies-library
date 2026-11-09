"""CEL Policies Library: loader, validator and evaluator.

Policies are plain CEL files (``//`` comments allowed). Evaluation uses
cel-python (``celpy``), the same engine mcp-trace-gate uses.

Two kinds of policy, with opposite match semantics:

* ``authorization`` -- an *allow rule*. A match means ALLOW. No match, or an
  evaluation error, means DENY (fail closed). This mirrors agentgateway's
  ``mcpAuthorization.rules`` (OR semantics, a matching rule grants access).
* ``calibration`` / ``combined`` -- a *trigger condition* evaluated by the
  caller against calibration signals (contradiction, completeness, currency).
  A match means the policy's verdict (BLOCK or REVIEW). No match means
  PROCEED. An evaluation error is reported as ERROR and never as PROCEED.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import celpy
except ImportError:  # pragma: no cover - exercised only without the dependency
    celpy = None

ROOT = Path(__file__).resolve().parent
POLICIES_DIR = ROOT / "policies"
# Written for agentgateway's own CEL environment (mcp.result, request.startTime,
# with()); cel-python cannot evaluate them, so the CLI does not list them.
GATEWAY_ONLY = {"guardrails"}

# Verdict emitted when a calibration/combined policy matches.
TRIGGER_VERDICT = {
    "calibration/block_contradiction": "BLOCK",
    "calibration/block_incomplete": "BLOCK",
    "calibration/review_stale_data": "REVIEW",
    "combined/multi_signal_safety_gate": "BLOCK",
    "combined/moderate_safety_gate": "REVIEW",
}

ALLOW, DENY, PROCEED, BLOCK, REVIEW, ERROR = (
    "ALLOW", "DENY", "PROCEED", "BLOCK", "REVIEW", "ERROR",
)
# Verdicts that let the call continue.
PERMITTED = {ALLOW, PROCEED}


class PolicyError(Exception):
    """Policy missing, unreadable, or does not compile."""


@dataclass
class Result:
    policy: str
    matched: Optional[bool]
    verdict: str
    detail: str = ""


def _require_celpy() -> None:
    if celpy is None:
        raise PolicyError(
            "cel-python is required: python3 -m venv .venv && "
            ".venv/bin/pip install -r requirements.txt"
        )


def normalize(policy: str) -> str:
    """Return the canonical ``category/name`` id for a user-supplied path."""
    p = policy
    if p.startswith("policies/"):
        p = p[len("policies/"):]
    if p.endswith(".cel"):
        p = p[: -len(".cel")]
    return p


def policy_path(policy: str) -> Path:
    path = POLICIES_DIR / f"{normalize(policy)}.cel"
    if not path.is_file():
        raise PolicyError(f"policy not found: {policy}")
    return path


def category(policy: str) -> str:
    return normalize(policy).split("/", 1)[0]


def list_policies() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for d in sorted(p for p in POLICIES_DIR.iterdir() if p.is_dir() and p.name not in GATEWAY_ONLY):
        out[d.name] = sorted(f.stem for f in d.glob("*.cel"))
    return out


def compile_policy(policy: str):
    """Compile a policy with celpy. Raises PolicyError on any failure."""
    _require_celpy()
    path = policy_path(policy)
    src = path.read_text()
    env = celpy.Environment()
    try:
        return env.program(env.compile(src))
    except Exception as exc:  # celpy raises several parse/compile types
        raise PolicyError(f"{normalize(policy)} does not compile: {_short(exc)}")


def _short(exc: Exception, limit: int = 160) -> str:
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else repr(exc)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _ints_to_floats(value: Any) -> Any:
    # celpy refuses int < double comparisons; calibration signals are doubles.
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return float(value)
    if isinstance(value, dict):
        return {k: _ints_to_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_ints_to_floats(v) for v in value]
    return value


def evaluate(policy: str, data: dict) -> Result:
    """Evaluate ``policy`` against ``data`` and return a Result."""
    pid = normalize(policy)
    program = compile_policy(pid)
    cat = category(pid)
    if cat != "authorization":
        data = _ints_to_floats(data)
    try:
        raw = program.evaluate(celpy.json_to_cel(data))
    except Exception as exc:
        detail = _short(exc)
        # Fail closed: an authorization error is a DENY, a calibration error
        # is surfaced as ERROR rather than silently treated as PROCEED.
        return Result(pid, None, DENY if cat == "authorization" else ERROR, detail)
    if not isinstance(raw, celpy.celtypes.BoolType):
        return Result(pid, None, ERROR, f"policy returned {type(raw).__name__}, expected bool")
    matched = bool(raw)
    if cat == "authorization":
        return Result(pid, matched, ALLOW if matched else DENY)
    return Result(pid, matched, TRIGGER_VERDICT.get(pid, BLOCK) if matched else PROCEED)


# ---------------------------------------------------------------- CLI ----


def cmd_list(args) -> int:
    policies = list_policies()
    cats = [args.category] if args.category else list(policies)
    for c in cats:
        if c not in policies:
            print(f"unknown category: {c}", file=sys.stderr)
            return 2
        print(c.upper())
        for name in policies[c]:
            print(f"  {c}/{name}")
    return 0


def cmd_show(args) -> int:
    print(policy_path(args.policy).read_text())
    return 0


def cmd_validate(args) -> int:
    targets = args.policy or [
        f"{c}/{n}" for c, names in list_policies().items() for n in names
    ]
    failed = 0
    for t in targets:
        try:
            compile_policy(t)
            print(f"OK    {normalize(t)}")
        except PolicyError as exc:
            failed += 1
            print(f"FAIL  {exc}")
    return 1 if failed else 0


def cmd_check(args) -> int:
    try:
        data = json.loads(args.input)
    except json.JSONDecodeError as exc:
        print(f"invalid JSON input: {exc}", file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print("input must be a JSON object", file=sys.stderr)
        return 2
    res = evaluate(args.policy, data)
    print(f"{res.policy}: {res.verdict}" + (f"  ({res.detail})" if res.detail else ""))
    if res.verdict == ERROR:
        return 2
    return 0 if res.verdict in PERMITTED else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cel-policies",
        description="CEL Policies Library. Exit code: 0 permitted, 1 denied/blocked/review, 2 error.",
    )
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("list", help="list policies")
    s.add_argument("--category")
    s.set_defaults(func=cmd_list)
    s = sub.add_parser("show", help="print a policy file")
    s.add_argument("policy")
    s.set_defaults(func=cmd_show)
    s = sub.add_parser("validate", help="compile policies with cel-python (all if none given)")
    s.add_argument("policy", nargs="*")
    s.set_defaults(func=cmd_validate)
    s = sub.add_parser("check", help="evaluate a policy against JSON input")
    s.add_argument("policy")
    s.add_argument("input", help='JSON object, e.g. \'{"contradiction": true}\'')
    s.set_defaults(func=cmd_check)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
