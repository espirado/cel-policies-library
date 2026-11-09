# Evidence for claims in this repository

This file is the session log. Do not cite a README live-traffic number as if it was reproduced here unless that session’s command and log are attached.

The package is a public MCP policy proxy. Public-MCP rows below are the community-facing evidence. The hosted 45-tool server is one example target, not a product customization.

## This session (2026-11-09)

Environment:

- macOS arm64, Python 3.12, `.venv` with `requirements.txt`
- agentgateway **1.7.0** (`26f5aebe99a3…`) at `bin/agentgateway-1.7.0`
- agentgateway **1.6.0** (`ea5608642b9d…`) at `bin/agentgateway-1.6.0`
- agentgateway **1.4.1** (`163ea2146acb…`) at `/usr/local/bin/agentgateway`
- Keycloak `cel` realm at `http://127.0.0.1:19180`

Published README claims are only the rows in §1a and the public-MCP / Linux numbers below. The 1.0.1–1.2.1 matrix, llama3.1 agent run, and 4-code hosted contradiction table are **not** README claims.

### 1. Full pytest on 1.7.0 with Keycloak

```bash
AGENTGATEWAY_BIN=$PWD/bin/agentgateway-1.7.0 .venv/bin/python -m pytest -q
```

**95 passed, 0 skipped, 7.29s** (includes `test_unscoped_expression_fails_closed_on_other_tools`). Log: [`evidence/runs/pitfalls-20261109.txt`](evidence/runs/pitfalls-20261109.txt).

### 1a. Claim audit: mock-only vs live

After the session-leak retraction (1c), every pitfall claim was re-measured with the same binary in front of **public** Streamable-HTTP MCP servers (`scripts/live_pitfalls.py`). Mock tests were also tightened to the exact gateway strings so an unrelated error cannot satisfy them.

| Claim | Mock test | Live reproduction | Status |
|---|---|---|---|
| Unscoped `kind: expression` fails closed on a foreign tool | `test_unscoped_expression_fails_closed_on_other_tools` (now asserts `-32603` + `guardrail check failed` exactly) | 1.7.0: pathwren `list_crawlers`, plantguide `list_garden_styles` → `-32603 guardrail check failed` | **live-confirmed** |
| Shipped scoped rules leave foreign tools alone | `test_rules_scoped_to_one_tool_do_not_touch_other_tools` | 1.7.0: same two tools through `agentgateway-calibration.yaml` → unchanged; plus 30 of the 35 servers in §2 | **live-confirmed** |
| `kind: remote` processor down, `failClosed` → denied | `test_fails_closed_when_the_processor_is_down` (now asserts exact strings) | 1.7.0 pathwren → `guardrail check failed`; 1.6.0 pathwren → `mcpGuardrails checkRequest failed: upstream call failed: Connect: Connection refused` | **live-confirmed**; 1.6.0 echoes the connect error to the MCP client, 1.7.0 does not |
| `"operator" in jwt.roles` admits string claim `"superoperator"` | `test_original_substring_rule_admits_a_string_roles_claim` | 1.6.0 and 1.7.0, pathwren, local JWKS: original rule lists `changes_since` for `roles="superoperator"`; shipped `has()`+`exists()` rule does not; `["operator"]` does; no token does not | **live-confirmed** (CEL semantics; upstream MCP irrelevant but tested anyway) |
| ExtMCP `session` empty on 1.3.1–1.6.0 | was `test_contradiction_is_scoped_to_session_and_entity` | 1.6.0 live sent distinct non-empty sessions | **retracted** (1c) |
| Guardrail runs on an upstream `isError` tool result | none | 1.7.0 deepwiki `read_wiki_contents(repoName="test")` (upstream returns `result.isError: true`): unscoped rule → `guardrail check failed`, so the expression **is** evaluated on `isError` results | observation; consistent with [PR #4345](https://github.com/agentgateway/agentgateway/pull/4345), which says `isError` results were already inspected |
| Guardrail skips an upstream JSON-RPC **error** object ([#4245](https://github.com/agentgateway/agentgateway/issues/4245)) | none | 1.7.0 ottobot `recent_license_changes`: `condition: true` reject returns `-32001 REJECTED_BY_GUARDRAIL` for `state=CA` (success), but `state=test` (upstream `-32602` error) passes through with the upstream message untouched | **reproduced live** on 1.7.0, one public server, 10-line config (live A4); also with a controlled upstream returning a unique marker, forwarded verbatim; `kind: remote` processors get `CheckRequest` but no `CheckResponse` for the error (1.6.0 and 1.7.0) |
| Guardrail skips upstream **notifications and server-initiated requests** ([#4245](https://github.com/agentgateway/agentgateway/issues/4245), second half) | none | controlled upstreams `tests/gateway/sse_mcp.py` (Streamable HTTP) and `tests/gateway/stdio_mcp.py` (`stdio:` target); public servers cannot be made to emit these. `notifications/message`, `notifications/progress`, `elicitation/create`, `sampling/createMessage`, `roots/list` with unique markers all reach the client untouched while the terminal result is rejected (HTTP: on the POST stream; stdio: on the session GET stream); the JSON-RPC error object passes through on both; `kind: remote` gets no hook for any of them; `methods` keys `tools/*`, `notifications/*` do not change it; code: `handler.rs` `apply_guardrails_response_intercept` matches only `ServerJsonRpcMessage::Response` | **reproduced, controlled upstreams, both transports** on 1.6.0 and 1.7.0 (live A5) |
| Contradiction 33.4009 vs 33.5675 on 4 CPT codes | `test_cross_tool_contradiction_is_blocked_then_clears` | hosted server: 15/16 then HTTP 429 this session | **partial**; README figure is from an earlier session |
| Version matrix 1.0.1–1.5.0, Linux aarch64, benchmark | — | not run this session | **not re-run** |

Logs: [`evidence/runs/live-pitfalls-1.7.0-20261109T185147Z.json`](evidence/runs/live-pitfalls-1.7.0-20261109T185147Z.json), [`evidence/runs/live-pitfalls-1.6.0-20261109T185209Z.json`](evidence/runs/live-pitfalls-1.6.0-20261109T185209Z.json).

Full suites after tightening: 1.7.0 **95 passed**; 1.6.0 **78 passed, 17 skipped**; 1.4.1 **78 passed, 17 skipped**.

### 1b. Two pitfalls, this session

| Finding | Binary | Test | Result |
|---|---|---|---|
| Unscoped expression fail-closes | 1.7.0 | `test_unscoped_expression_fails_closed_on_other_tools` | passed (mock) + live A1 |
| Scoped rules do not touch other tools | 1.7.0 | `test_rules_scoped_to_one_tool_do_not_touch_other_tools` | passed (mock) + live A2 |

### 1c. Session leak — **retracted** (mock artifact, not reproduced on live MCP)

The earlier claim was: agentgateway 1.3.1–1.6.0 send empty ExtMCP `session` metadata, so contradiction history is shared. That was measured only against `tests/gateway/mock_mcp.py`, which returned **`Mcp-Session-Id: mock-session` on every initialize**. 1.6.0 wraps the upstream id (`{"t":"mcp","s":[{"t":"fees","s":"mock-session"}]}`); two pytest sessions were one session.

Live recorder (`scripts/live_session_metadata.py`, always-pass ExtMCP, two public Streamable-HTTP hosts, two sessions each):

| Binary | Hosts | HTTP sids distinct | ExtMCP `session` nonempty + distinct | Verdict |
|---|---|---|---|---|
| 1.7.0 | pathwren, plantguide | yes | yes, matches HTTP sid | isolated |
| 1.6.0 | pathwren, plantguide | yes | yes, matches HTTP sid | isolated (not empty) |

Logs: [`evidence/runs/session-metadata-1.7.0.json`](evidence/runs/session-metadata-1.7.0.json), [`evidence/runs/session-metadata-1.6.0.json`](evidence/runs/session-metadata-1.6.0.json). Not run on the hosted 45-tool server (that run hit rate-limit).

After the mock minted a UUID per initialize:

| Binary | `test_contradiction_is_scoped_to_session_and_entity` |
|---|---|
| 1.7.0 | passed (new session has no history) |
| 1.6.0 | passed (same; no leak) |
| 1.4.1 | passed (same; no leak) |

1.6.0 full suite after the mock fix: **78 passed, 17 skipped**. Do not cite the leak in a discussion, README matrix, or blog post.

### 2. Public MCP servers, real traffic through agentgateway 1.7.0

```bash
AGENTGATEWAY_BIN=$PWD/bin/agentgateway-1.7.0 \
  .venv/bin/python scripts/live_public_mcp.py --discover 40 --gateway-discovered 15
```

Log of record: [`evidence/runs/public-mcp-20261109T171929Z.json`](evidence/runs/public-mcp-20261109T171929Z.json) (started 17:16:03Z, finished 17:19:29Z).

Each reachable server was checked three ways:

| Check | What it proves |
|---|---|
| Passthrough | `tools/list` through the gateway equals the direct listing |
| Prefix authorization | shipped `allow_lookup_tools` + `require_operator_for_calculate` (no JWT): listed names are exactly `lookup_*` / `list_*`; a tool outside that set is denied |
| Guardrail scoping | rci-knowledge `mcpGuardrails` (`lookup_mpfs` / `lookup_opps` / `list_dataset_snapshots` field lists) do **not** reject a foreign tool’s result |

No API keys were sent. Tool calls were read-oriented only; dummy arguments were used, so a `tool_error` from the upstream server is expected and is not a policy failure.

#### Reachability

| Set | n | Result |
|---|---:|---|
| Curated Streamable-HTTP URLs | 22 | **20 reachable**, 321 tools listed |
| Official MCP Registry extras (`isLatest`, no required secret header) | 40 | **17** listed tools with no key, **21** HTTP 401, 1 timeout, 1 HTTP 502 |
| Full gateway checks (passthrough + prefix authz + guardrail scope) | 35 | 20 curated + 15 discovered, **432 tools** behind the gateway |

Auth-gated curated targets (expected, not failures):

- `https://api.rcintell.com/v1/mcp` → HTTP 401 `Missing API key`
- `https://api.serviceengineer.academy/mcp` → HTTP 401 OAuth / personal key

#### Gateway results

| Check | Curated (20) | Discovered (15) | Combined |
|---|---:|---:|---:|
| Passthrough `tools/list` matches direct | 20/20 | 15/15 | **35/35** |
| Prefix authz listed set = `lookup_*`/`list_*` | 20/20 | 15/15 | **35/35** |
| Prefix authz denies a hidden tool | 20/20 | 15/15 | **35/35** |
| rci guardrails do not fail-closed on a foreign tool | 20/20 | 14/15 then 15/15 | **35/35 not rejected**, but only **30/35 are evidence** (below) |

**Audit of the guardrail-scope row.** "Not rejected" is only evidence when a result actually reached the guardrail. Breakdown of the 35 `guardrail_scope` calls in the log:

| Outcome of the foreign tool call | n | Counts as evidence? |
|---|---:|---|
| `unchanged` (successful result, no `calibration` annotation, no reject) | 24 | yes |
| `tool_error` (upstream `isError`, passed through) | 5 | yes — live A3 shows an unscoped rule **does** evaluate on an `isError` result and fail-close, so a scoped rule passing it through is meaningful |
| `guardrail_reject` on achromat (classifier false positive; re-run → `tool_error`) | 1 | yes, after re-run |
| `transport` (upstream HTTP error before any result: mizan, pantheon `invalid_token`, getle) | 3 | **no** — nothing reached the guardrail |
| `rpc_error` (upstream JSON-RPC error, ottobot license-changes) | 1 | **no** — not a `tools/call` result |
| no callable tool picked (ottobot business-contact-finder) | 1 | **no** |

So the defensible statement is: **30 live servers returned a `tools/call` result through the shipped scoped rules and none was rejected or annotated.** Not 35.

The one discovered miss in the JSON log (`achromat.ai` / `achromat_recall`) was a **harness false positive**: the tool’s own input-validation error later contained a substring the first classifier treated as a guardrail reject. Passthrough and prefix authz already passed. Re-run of that host with a classifier that matches only `calibration: result incomplete` and `guardrail check failed` classified the call as `tool_error` and **passed**. The CEL rules did not reject it.

**Audit of the prefix-authz rows.** The listed-set match (35/35) and the hidden-tool deny (35/35) are real for all 35: both are `tools/list` and a `tools/call` to a hidden name, which need no upstream result. The *allowed-call* sub-check (an open `lookup_*`/`list_*` tool actually returns through the gateway) ran on only 17 servers: 14 `unchanged`, 3 `transport`. 18 servers had **zero** `lookup_*`/`list_*` tools, so there was nothing to call; for them the row proves hiding, not pass-through.

#### Prefix rules on real names (not the mock)

These are the interesting naming-convention cases:

| Server | Open to anonymous (`lookup_*` / `list_*`) | Hidden (no JWT) |
|---|---|---|
| pathwren crawler index | `lookup_crawler`, `list_crawlers` | 7 other tools |
| mizan | `lookup_player`, `list_my_communities`, `list_sources` | `check_players`, … |
| 1court | 4 `list_*` tools | `calculate_deadline` (and 4 others) — live `calculate_*` gate without an operator token |
| superdocs | 4 `list_*` | 73 others |
| mcpharbor | `list_categories` | `search_servers`, `get_server`, … |

Servers with **no** `lookup_*`/`list_*` tools correctly listed **zero** tools under the shipped prefix rules (tandem, deepwiki, grovisor, tide, ase, …). That is the rule working, not a gateway outage.

#### Cloudflare / User-Agent

An earlier pass in this session ([`evidence/runs/public-mcp-20261109T171230Z.json`](evidence/runs/public-mcp-20261109T171230Z.json)) failed initialize on Cloudflare-fronted hosts with **Error 1010** (“blocked based on your browser's signature”) until the gateway was given a target `requestHeaderModifier` setting `User-Agent` and `Accept`. Direct urllib with the same UA had worked. Community deploys in front of Cloudflare-protected MCP servers need that header (or an equivalent) on the **outbound** connection; forwarding the client’s `X-API-Key` is not enough if the gateway’s own client fingerprint is blocked.

### 3. Hosted rci-knowledge — not run this session

```
RCI_API_KEY present: false
scripts/live_rcintel_gateway.py → exit 2 (prints usage; does not call the server)
https://api.rcintell.com/v1/mcp initialize without a key → HTTP 401 {"detail":"Missing API key"}
```

`scripts/live_rcintel_processor.py`, `scripts/live_rcintel_authz.py`, and `scripts/live_rcintel_signals.py` were not run. README tables for 12 CPT codes, OPPS 99213/71046, snapshot flags, and cross-tool contradiction are **not** reproduced in this session.

### 4. Linux aarch64, this session

```bash
# python:3.12-slim, linux/arm64, agentgateway-linux-arm64 from the v1.7.0 release
AGENTGATEWAY_BIN=/tmp/agw python -m pytest -q
```

**85 passed, 10 skipped, 4.99s** (Keycloak absent). Log: [`evidence/runs/pytest-linux-aarch64-1.7.0.txt`](evidence/runs/pytest-linux-aarch64-1.7.0.txt).

### 5. Not run this session

- agentgateway 1.0.1, 1.1.0, 1.2.1, 1.3.1, 1.5.0
- x86_64, Windows
- `scripts/bench_gateway.py`
- llama3.1:8b agent run (lives in mcp-judge-seam)

## Mapping (policy → evidence)

| Claim | Evidence this session |
|---|---|
| Role list membership, not substring | pytest `test_role_membership_is_not_substring`, `test_original_substring_rule_admits_a_string_roles_claim`, Keycloak `test_role_rules_with_real_keycloak_tokens` |
| Missing `roles` is a clean deny | pytest `test_missing_roles_is_clean_deny` + Keycloak |
| Guardrails scoped to one tool | pytest `test_rules_scoped_to_one_tool_do_not_touch_other_tools`, live A2 (pathwren, plantguide), and 30 of 35 live servers that returned a result |
| Prefix authz is a naming convention | 35 live servers: listed set always equalled `lookup_*`/`list_*` and a hidden tool was denied; an open tool returned through the gateway on 14 (3 upstream transport errors; 18 had no matching tool) |
| Processor down fails closed (exact string) | pytest + live B on 1.6.0 and 1.7.0 |
| Role membership, not substring (live) | live C1–C4 on 1.6.0 and 1.7.0 (pathwren, local JWKS) |
| Incomplete later MPFS row is rejected | pytest `test_incomplete_later_row_is_rejected` (mock, 1.7.0) |
| Stale year is REVIEW, not BLOCK, in the processor | pytest `test_stale_result_is_annotated_for_review_not_blocked` |
| Contradiction across tools | pytest `test_cross_tool_contradiction_is_blocked_then_clears` (mock) |
| Processor down fails closed | pytest `test_fails_closed_when_the_processor_is_down` |
| 72-vector CEL parity | pytest `test_signal_policies_agree_between_agentgateway_and_cel_python` on 1.7.0 |
| Unscoped expression fail-closes on a foreign tool | `test_unscoped_expression_fails_closed_on_other_tools` (1.7.0) + live A1 on pathwren, plantguide |
| ExtMCP session leak on &lt; 1.7.0 | **retracted** — live 1.6.0 isolated; mock used a constant session id. Isolation test now expects no leak on 1.4.1, 1.6.0, 1.7.0 |
| rci-knowledge completeness / staleness on real fee-schedule rows | partial this session: `live_rcintel_gateway.py` all passed; processor 15/16 then rate-limited; authz/signals 429. See `evidence/runs/rci-knowledge-live.txt` |

## Reproduce

```bash
tests/keycloak/start.sh
AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 .venv/bin/python -m pytest -q
AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 \
  .venv/bin/python scripts/live_public_mcp.py --discover 40 --gateway-discovered 15
AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 .venv/bin/python scripts/live_pitfalls.py
AGENTGATEWAY_BIN=/path/to/agentgateway-1.6.0 .venv/bin/python scripts/live_pitfalls.py
AGENTGATEWAY_BIN=/path/to/agentgateway-1.6.0 .venv/bin/python scripts/live_session_metadata.py
# optional, needs a key:
RCI_API_KEY=… AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 python scripts/live_rcintel_gateway.py
RCI_API_KEY=… AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 python scripts/live_rcintel_processor.py
RCI_API_KEY=… AGENTGATEWAY_BIN=/path/to/agentgateway-1.7.0 python scripts/live_rcintel_authz.py
```

Live scripts print PASS/FAIL lines. They do not write API keys to a file.
