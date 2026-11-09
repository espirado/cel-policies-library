# CEL policies for agentgateway MCP

A **library + notes** for [agentgateway](https://agentgateway.dev) MCP: CEL policies, rebindable YAML, tests that run inside the gateway, and two measured pitfalls. It is not a fork of agentgateway and not a second copy of [`examples/mcp-guardrails/expression`](https://github.com/agentgateway/agentgateway/tree/main/examples/mcp-guardrails/expression) (the toy: stdio `everything`, deny `DO_NOT_SEND`, mask emails/secrets).

Point the gateway at **your** Streamable-HTTP MCP server. Tool names and field lists in the example files are bindings you replace. One hosted 45-tool server is an example target, not the product.

Validated inside agentgateway (v1.7.0, plus a version matrix back to 1.0.1) and against public MCP servers. What upstream already covers, and what this pack does not (Entra, remote OAuth, webhooks, [#4245](https://github.com/agentgateway/agentgateway/issues/4245)), is in [UPSTREAM.md](UPSTREAM.md). The unpublished discussion text is [DISCUSSION_DRAFT.md](DISCUSSION_DRAFT.md) — do not post it until [EVIDENCE.md](EVIDENCE.md) matches the tests it cites.

| Layer | agentgateway feature | Question it answers | Policies |
|---|---|---|---|
| Who may call which tool | `mcpAuthorization` rules | Is this caller allowed to use this tool? | 5 |
| Is the tool result fit to use | `mcpGuardrails` CEL expression processors, response phase | Is this result complete, and not out of date? | 4 |
| Do results agree across calls | `mcpGuardrails` remote (ExtMCP) processor | Does this result contradict an earlier one? Is it too incomplete or stale to use? | 5 signal policies + a processor |

Extracted from [mcp-judge-seam](https://github.com/espirado/mcp-judge-seam) (two authorization rules) and [mcp-trace-gate](https://github.com/espirado/mcp-trace-gate) (the signal thresholds).

What already exists in agentgateway (toy `examples/mcp-guardrails/expression`, JWT authz example, Entra/OAuth discussions) and what this pack does **not** cover is in [UPSTREAM.md](UPSTREAM.md). Read that before posting anything.

## Use it

| Need | Template | Needs |
|---|---|---|
| exact tool-name authorization | [templates/agentgateway.yaml](templates/agentgateway.yaml) | agentgateway 1.0.1+ |
| prefix authorization (`lookup_*` / `list_*` / `calculate_*`) | [templates/agentgateway-prefix-authz.yaml](templates/agentgateway-prefix-authz.yaml) | 1.0.1+ |
| result guardrails (example field lists) | [templates/agentgateway-calibration.yaml](templates/agentgateway-calibration.yaml) | 1.7.0+ (`kind: expression`) |
| cross-call signal policies | [templates/agentgateway-signals.yaml](templates/agentgateway-signals.yaml) + `processors/signal_processor.py` | 1.3.1+ (`kind: remote`); `kind: expression` still needs 1.7.0 |

[templates/agentgateway-rci-knowledge.yaml](templates/agentgateway-rci-knowledge.yaml) is the prefix-authz template pointed at one example host, with optional OIDC. Copy it; change `host`, issuer and JWKS.

Check any config with `agentgateway --validate-only -f your.yaml`. Bind `mcp.tool.name` and required fields to **your** tools. Unscoped result rules fail closed on every other tool.

## The policies

### Authorization (`mcpAuthorization`, allow rules with OR semantics; a tool no rule allows is hidden from `tools/list`)

| Policy | Expression | Origin |
|---|---|---|
| `allow_harmless` | `mcp.tool.name == "grant_read_access"` | identical to mcp-judge-seam `allow_read.cel`; this exact tool only |
| `require_operator` | `... && has(jwt.roles) && jwt.roles.exists(r, r == "operator")` | judge-seam `allow_admin.cel` plus `has(jwt.roles)` and list membership (not substring `in`) |
| `require_admin` | same, `"admin"` role | new variant |
| `allow_lookup_tools` | `lookup_*` or `list_*` | new; a naming-convention rule, only as safe as the server's naming |
| `require_operator_for_calculate` | `calculate_*` and `has(jwt.roles)` and `jwt.roles.exists(...)` | new; missing `roles` is a clean non-match; roles must be a list |

### Result guardrails (`mcpGuardrails` expression processors on `mcp.result`)

| Policy | Tool | Action |
|---|---|---|
| `block_incomplete_result` | `lookup_mpfs` (a `results` list) | reject when there are no rows, or any row has under 40% of the required fields non-null |
| `block_incomplete_flat_result` | `lookup_opps` (a flat record) | same threshold, on the payment fields |
| `flag_stale_result` | `lookup_mpfs` | annotate (`calibration.tier = "review"`) when the row's `year` is before the request's calendar year |
| `flag_stale_snapshot` | `list_dataset_snapshots` | annotate and list the datasets whose `effective_date` is over 365 days old |

Each rule is guarded by `mcp.tool.name` and by the result shape. Without those guards a rule runs on every tool's result and, because expression errors fail closed, rejects any result it cannot parse. A multi-tool test caught this.

### Signal policies, enforced by the ExtMCP processor

| Policy | Expression | Verdict |
|---|---|---|
| `calibration/block_contradiction` | `contradiction == true` | BLOCK |
| `calibration/block_incomplete` | `completeness < 0.4` | BLOCK |
| `calibration/review_stale_data` | `currency < 0.6` | REVIEW |
| `combined/multi_signal_safety_gate` | `contradiction \|\| completeness < 0.4` | BLOCK |
| `combined/moderate_safety_gate` | `contradiction \|\| completeness < 0.75 \|\| currency < 0.6` | REVIEW |

[processors/signal_processor.py](processors/signal_processor.py) is a gRPC server for agentgateway's `kind: remote` guardrail. It remembers each call at request time (a FIFO queue per session) and scores the result at response time: completeness (required fields present), currency (1.0 if the record year is this calendar year or later, else 0.0 — a missing or unparsable year is 0.0), and contradiction (a fact differs from an earlier result for the same entity in the same MCP session; calls that omit the entity argument are not stored). BLOCK denies the result after the upstream tool has already run; REVIEW annotates it. A superseded year is REVIEW, matching `flag_stale_result`. Per-tool settings are in [processors/signal_processor.example.json](processors/signal_processor.example.json). It is a reference implementation: in-memory state, one instance, plaintext gRPC on loopback.

Thresholds are mcp-trace-gate's demo defaults.

## What was validated, and how

Which numbers were re-run in a given session, and which tests back each claim, is in [EVIDENCE.md](EVIDENCE.md). Gateway tests (`tests/test_gateway.py`, `tests/test_signal_processor.py`, `tests/test_keycloak.py`) run real agentgateway processes with a mock MCP server and, for Keycloak, real tokens. `scripts/live_public_mcp.py` puts the gateway in front of public Streamable-HTTP MCP servers (no key). A separate example pack of scripts talks to one hosted 45-tool server when `RCI_API_KEY` is set; that server is a validation target, not a dependency of the package.

| Policy | In agentgateway with controlled inputs | Real traffic |
|---|---|---|
| `allow_harmless` | yes | yes: `llama3.1:8b` agent through the gateway; the read tool was granted |
| `require_operator` | yes, with Keycloak tokens: operator allowed; viewer, admin and no-role denied | the same agent's `grant_admin_access` attempt was denied |
| `require_admin` | yes, with Keycloak tokens: admin allowed; operator, viewer and no-role denied | no, because the rci-knowledge server has no admin tool |
| `allow_lookup_tools`, `require_operator_for_calculate` | yes, with Keycloak tokens | yes: on the real 45-tool list, anonymous callers saw exactly the 16 `lookup_`/`list_` tools, the operator token saw 20 (adding the 4 `calculate_` tools), and viewer, admin and no-role tokens saw 16; `lookup_mpfs` worked for everyone, `calculate_payment` returned a payment only for the operator, and `check_ncci_mue` (a real tool no rule allows) was denied |
| `block_incomplete_result` | yes | no false positives on 12 real codes. The server never returned an incomplete `lookup_mpfs` row, so the reject path was run on a real payload with the required list changed to include a field that is null in every real row (mechanism check) |
| `block_incomplete_flat_result` | yes | **yes**: `lookup_opps` for CPT 99213 returns null payment fields and was rejected; CPT 71046 has payment data and passed |
| `flag_stale_result` | yes | no false positives on 12 real codes. The server holds only CY2026, so no superseded row exists; the annotate path was run on a real payload with the rule shifted one year (mechanism check) |
| `flag_stale_snapshot` | yes | **yes**: `list_dataset_snapshots` was annotated and named `ipps`, `medi_cal_aprdrg`, `medi_cal_supplies`, `ms_drg` and `umls` (effective dates over a year old); `mpfs` and `ncci` (2026-01-01) were not flagged |
| the 5 signal policies | yes: each evaluated in agentgateway's engine and in cel-python over 72 signal combinations with identical results; enforced through the ExtMCP processor against the mock | **yes, enforced in the gateway on real traffic** (see below) |

**Real contradiction, enforced.** In one MCP session per code, the processor let `lookup_mpfs` through, then denied `calculate_payment` called with its default arguments (`combined/multi_signal_safety_gate matched ... "contradiction": true`), then allowed `calculate_payment` with `qpp: false`, and allowed a default call in a new session (no history). This held for all 4 codes tested (99213, 99214, 97110, 10060). The trigger is that `lookup_mpfs` returned `conversion_factor` 33.4009 while `calculate_payment` returned 33.5675 by default; with `qpp: false` it returned 33.4009. The tool's own parameter description says `qpp` defaults to true, which fits the difference, but the cause was not confirmed with the data owner. The three engines (cel-python, mcp-trace-gate's tiers, agentgateway) agreed on every policy for every real signal vector.

### Agentgateway versions

The same suite ran against each release (macOS arm64):

| Release | Result (suite re-run 2026-11-09 with the current rules) |
|---|---|
| 1.0.1, 1.1.0, 1.2.1 | authorization passes, including with real Keycloak tokens (70 passed, the 24 guardrail and processor tests skipped). The original `"operator" in jwt.roles` form failed the JWT allow cases on 1.0.1; the `exists` form passes |
| 1.3.1, 1.4.1, 1.5.0, 1.6.0 | authorization passes (1.6.0 re-run 2026-11-09: 78 passed, 17 skipped). `kind: remote` works. Contradiction is scoped to the MCP session when the upstream server mints a unique `Mcp-Session-Id` per initialize. `kind: expression` is not accepted |
| 1.7.0 | everything passes (94 tests) |

1.3.0, 1.4.0, 1.5.0 betas, 1.6.0 pre-releases and patch releases in between were not run. Also run: Linux aarch64 (a `python:3.12-slim` container with the Linux v1.7.0 binary), clean `pip install -r requirements.txt`: 84 passed, 10 skipped (Keycloak and the two sibling repos are absent there).

### What testing against real systems changed

These are defects the mock tests did not show:

1. **A linear-decay staleness rule flagged current data.** The first version scored `currency = 1 - age / 365 days` and flagged under 0.6. It flagged every CY2026 result in November, although the server's `list_dataset_snapshots` reports MPFS CY2026 as current. It was replaced by a year-validity rule. The same formula applied to the real snapshot gives currency 0.153, so a `currency < 0.6` policy fed that value would also flag current data; how `currency` is computed is the caller's responsibility.
2. **Unscoped guardrails rejected other tools' results.** With several tools behind one gateway, rules without a tool and shape guard errored on results with no `results` list and failed closed. Fixed with the guards; a regression test covers it.
3. **`requirements.txt` was missing `grpcio`.** Found by a clean install in a Linux container.
4. **The original role rule admitted a string `roles` claim.** In agentgateway 1.7.0, `"operator" in jwt.roles` is a substring test when the claim is a string: a token whose `roles` is `"superoperator"` was allowed to call `grant_admin_access` (`test_original_substring_rule_admits_a_string_roles_claim`). The same rule also errored when a token had `sub` but no `roles`. The role rules now use `has(jwt.roles)` and `jwt.roles.exists(r, r == "operator")`, so a missing claim is a clean non-match and a string claim is denied. mcp-judge-seam's own `allow_admin.cel` and `agentgateway.yaml` still use the original form.
5. **A constant mock `Mcp-Session-Id` looked like a 1.6.0 session leak.** `tests/gateway/mock_mcp.py` used to return `mock-session` on every initialize. agentgateway 1.6.0 wraps that upstream id, so two pytest "sessions" were one session and contradiction history was shared. Live MCP on 1.6.0 (pathwren, plantguide) forwarded distinct non-empty ExtMCP `session` values. The mock now mints a UUID per initialize; isolation holds on 1.4.1, 1.6.0, and 1.7.0. See [EVIDENCE.md](EVIDENCE.md).
6. **Test harness:** `adminAddr: "off"` is rejected by releases before 1.3, so the harness uses free ports.

### Behaviour observed in agentgateway

- A guardrail `reject` on `tools/call` comes back as a JSON-RPC error `-32001` in the response phase and as a tool result with `isError: true` in the request phase.
- A tool no `mcpAuthorization` rule allows is missing from `tools/list`; calling it returns HTTP 400 (`Unknown tool` on 1.4.1, `unknown resource` on 1.7.0).
- An expression error fails closed: `-32603 guardrail check failed` for guardrails, deny for authorization. A guardrail expression is evaluated on an upstream `result.isError: true` (seen live on deepwiki) but **not** on an upstream JSON-RPC `error` object, a notification, or a server-initiated request in the same stream; those pass through untouched on 1.6.0 and 1.7.0, for `kind: expression` and `kind: remote` alike, on Streamable-HTTP and stdio targets (this is [agentgateway#4245](https://github.com/agentgateway/agentgateway/issues/4245), fix pending in [#4345](https://github.com/agentgateway/agentgateway/pull/4345); `scripts/live_pitfalls.py` A4/A5).
- A `kind: remote` processor that is unreachable with `failureMode: failClosed` is denied with `guardrail check failed` on 1.7.0; 1.6.0 echoes the connect error (`mcpGuardrails checkRequest failed: upstream call failed: Connect: Connection refused`).
- Indexing a list with a JSON number needs `int(...)`.
- The client's `X-API-Key` header reaches the upstream server through the gateway. The processor does not receive it unless `requestHeaders` is set.
- Keycloak puts realm roles under `realm_access.roles`; the tests map them to a top-level `roles` claim, which is what these rules read.

### Cost

`scripts/bench_gateway.py` runs the same `tools/call` through two configs that differ only in the policy and compares end-to-end latency (loopback, Python mock upstream, one MacBook Air, 3000 calls per round, 7 rounds). The effect is below the noise: round medians vary by about ±100 µs and the median difference was between −1 and +63 µs for authorization and between −53 and +33 µs for the guardrails across four runs. It is "no measurable overhead at this resolution". The ExtMCP processor adds a gRPC round trip per call and was not benchmarked.

## Run it

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
tests/keycloak/start.sh                  # optional: real-IdP tests (Docker); `docker rm -f cel-keycloak` to stop
AGENTGATEWAY_BIN=/path/to/agentgateway .venv/bin/python -m pytest -q   # 94 pass on 1.7.0 with Keycloak running
```

Without a binary the gateway tests skip. Without Keycloak its 8 tests skip. Release binaries: <https://github.com/agentgateway/agentgateway/releases>.

`scripts/live_public_mcp.py` is the community live path (no API key). The `live_rcintel_*.py` scripts are one example host; they need `RCI_API_KEY` and are not required to use the templates:

| Script | What it checks | Needs |
|---|---|---|
| `scripts/live_public_mcp.py` | passthrough, prefix authorization, and rci guardrail scoping against public Streamable-HTTP MCP servers | `AGENTGATEWAY_BIN` (1.7.0). `--discover N` adds registry URLs; `--gateway-discovered N` runs the full checks on those |
| `scripts/live_rcintel_gateway.py` | result guardrails on `lookup_mpfs`, `lookup_opps`, `list_dataset_snapshots`, plus two labelled mechanism checks | `RCI_API_KEY` |
| `scripts/live_rcintel_processor.py` | the signal processor enforcing contradiction on real traffic | `RCI_API_KEY` |
| `scripts/live_rcintel_authz.py` | authorization with Keycloak tokens on the real tool list, guardrails merged in | `RCI_API_KEY`, Keycloak |
| `scripts/live_rcintel_signals.py` | real signals scored with mcp-trace-gate; each policy evaluated in cel-python, trace-gate and agentgateway | `RCI_API_KEY` |
| `scripts/bench_gateway.py` | gateway overhead | |
| `scripts/live_gateway_check.py` | the offline evaluator's authorization predictions against a running gateway | |

The authorization real-model run used mcp-judge-seam's `run_live.py --gateway http://127.0.0.1:3199/mcp` with the library's rules in the gateway. That script rewrites the tracked `examples/live_output.json` in mcp-judge-seam.

## Offline CLI (secondary)

For authoring checks without a gateway. It uses cel-python, not agentgateway's engine, so the gateway tests are authoritative.

```bash
.venv/bin/python tools/cel-policies list
.venv/bin/python tools/cel-policies validate
.venv/bin/python tools/cel-policies check combined/moderate_safety_gate \
  '{"contradiction": false, "completeness": 0.6, "currency": 0.9}'   # REVIEW, exit 1
```

Exit codes: 0 permitted (ALLOW or PROCEED), 1 DENY, BLOCK or REVIEW, 2 error. It does not load `policies/guardrails/` (they use agentgateway-only variables).

## Known gaps

- **Example pack vs product.** Result-guardrail field lists and `processors/signal_processor.example.json` are bound to one example server's tools. Prefix authorization is a naming convention. Point the same layers at your MCP server and rebind names and fields.
- **Public MCP traffic.** Passthrough and prefix hide/deny were run through agentgateway 1.7.0 against 35 public Streamable-HTTP servers; 30 of them returned a result through the scoped guardrails with no reject ([EVIDENCE.md](EVIDENCE.md) has the breakdown of the other 5). The fail-closed, processor-down, and substring-role pitfalls were each reproduced live (`scripts/live_pitfalls.py`), not only on the mock. That does not test your tools' result shapes.
- **One deep example host.** Completeness/staleness/contradiction on real fee-schedule rows used one hosted 45-tool server and one production-tier API key, read-only tools. That host is optional.
- **The server's data cannot trigger two paths.** It never returns an incomplete `lookup_mpfs` row or a row from a superseded year (it holds only CY2026). Those two rules were run on a real payload with one parameter changed; the other incompleteness and snapshot-age rules were triggered by real data.
- **Identity.** Tokens come from a local Keycloak container through the password grant, not from a production or cloud identity provider. A top-level `roles` claim is assumed.
- **Platforms and versions.** macOS arm64 and Linux aarch64. No x86_64 or Windows. Releases listed above only.
- **The processor is a reference implementation.** In-memory state, a single instance, plaintext gRPC, no load or failure testing beyond "fails closed when it is down", no per-tool configuration beyond the JSON file. Pending calls are a FIFO queue per session; responses that complete out of order in one session can still mis-pair. BLOCK happens after the upstream tool has already run. Tools not listed in the JSON config are not scored.
- **Thresholds and field lists are defaults.** They are mcp-trace-gate's demo values and rci-knowledge's field names.
- **`allow_lookup_tools` trusts naming.** It was checked against the 45 real tool names, not against what each tool does.
- **One local model** (`llama3.1:8b`) drove the authorization traffic. The rules do not depend on the model.
- Does not replace judges or tracing; it adds deterministic checks at the tool-call boundary.
- **Not Entra, not remote MCP OAuth, not webhook prompt-guards, not [#4245](https://github.com/agentgateway/agentgateway/issues/4245).** Those are open upstream asks. See [UPSTREAM.md](UPSTREAM.md).

## License

MIT. See [LICENSE](LICENSE). `processors/ext_mcp.proto` is a copy of agentgateway's ExtMCP definition (v1.7.0, Apache-2.0).
