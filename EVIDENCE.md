# Evidence for claims in this repository

This file says what was **re-run in a given session** versus what is **recorded in the README** from earlier runs. Do not cite a README live-traffic number as if it was reproduced in a later session unless that session’s log is attached.

## This session (2026-11-09, this checkout)

Environment:

- macOS, Python 3.12, `pip install -r requirements.txt` already present in `.venv`
- `agentgateway --version` → **1.4.1** (`163ea214…`) on `PATH`
- Keycloak at `http://127.0.0.1:19180` → **not reachable**
- `RCI_API_KEY` → **unset** (live-traffic scripts were not run)

Command:

```bash
.venv/bin/python -m pytest -q
```

Result: **94 tests collected, 70 passed, 24 skipped.**

| Skip reason | Count | Tests |
|---|---:|---|
| `kind: expression` not accepted (`unknown variant expression, expected remote`) | 16 | `tests/test_gateway.py` calibration / 72-grid / mixed-row |
| no Keycloak realm | 8 | `tests/test_keycloak.py` |

What this session **does** verify:

- Offline CEL compile/evaluate for the 10 CLI policies (`tests/test_policies.py`)
- JWT authorization on agentgateway **1.4.1**, including that the shipped `exists` role rule does **not** treat `"superoperator"` as operator (`tests/test_gateway.py`)
- ExtMCP processor against a mock MCP through agentgateway **1.4.1** (`kind: remote`): contradiction, incompleteness BLOCK, stale year REVIEW, fail-closed when the processor is down (`tests/test_signal_processor.py`)
- Processor unit tests without a gateway: FIFO pending queue, missing entity is not `"None"`, missing year is not currency 1.0 (`tests/test_processor_unit.py`)
- Template strings equal the `.cel` files, including `templates/agentgateway-rci-knowledge.yaml`

What this session **does not** verify:

- agentgateway **1.7.0** (`kind: expression` guardrails)
- Keycloak password-grant tokens
- Hosted rci-knowledge (`https://api.rcintell.com/v1/mcp`)
- Linux aarch64 container install
- Benchmarks in `scripts/bench_gateway.py`
- The llama3.1:8b agent run (that lives in mcp-judge-seam)

## Recorded elsewhere (README)

The README version matrix (1.0.1–1.7.0), the 1.7.0 “94 pass with Keycloak”, Linux aarch64 “84 passed, 10 skipped”, and the rci-knowledge live-traffic tables are **author-recorded** on **2026-11-06** and **re-run 2026-11-09** after the processor/rule edits. Reproduce with:

```bash
AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 tests/keycloak/start.sh
.venv/bin/python -m pytest -q
RCI_API_KEY=… AGENTGATEWAY_BIN=… python scripts/live_rcintel_gateway.py
RCI_API_KEY=… AGENTGATEWAY_BIN=… python scripts/live_rcintel_processor.py
RCI_API_KEY=… AGENTGATEWAY_BIN=… python scripts/live_rcintel_authz.py
```

Live scripts print PASS/FAIL lines and a summary. They do not write the API key to a file.

## Mapping (policy → test)

| Claim | Evidence in-repo |
|---|---|
| Role list membership, not substring | `test_role_membership_is_not_substring`, `test_original_substring_rule_admits_a_string_roles_claim` |
| Missing `roles` is a clean deny | `test_missing_roles_is_clean_deny` |
| Guardrails scoped to one tool | `test_rules_scoped_to_one_tool_do_not_touch_other_tools` (needs 1.7.0) |
| Incomplete later MPFS row is rejected | `test_incomplete_later_row_is_rejected` (needs 1.7.0) |
| Stale year is REVIEW, not BLOCK, in the processor | `test_stale_result_is_annotated_for_review_not_blocked` |
| Contradiction across lookup_mpfs / calculate_payment | `test_cross_tool_contradiction_is_blocked_then_clears` |
| Pre-1.7 empty session metadata shares history | `test_contradiction_is_scoped_to_session_and_entity` |
| Processor down fails closed | `test_fails_closed_when_the_processor_is_down` |
| 72-vector CEL parity | `test_signal_policies_agree_between_agentgateway_and_cel_python` (needs 1.7.0) |
