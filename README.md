# CEL policies for agentgateway MCP

A **library + notes** for [agentgateway](https://agentgateway.dev) MCP: CEL policies, rebindable YAML, and tests that run inside the gateway. It is not a fork of agentgateway and not a second copy of [`examples/mcp-guardrails/expression`](https://github.com/agentgateway/agentgateway/tree/main/examples/mcp-guardrails/expression) (the toy: stdio `everything`, deny `DO_NOT_SEND`, mask emails/secrets).

Point the gateway at **your** Streamable-HTTP MCP server. Tool names and field lists in the example files are bindings you replace.

This pack does not add Entra, remote MCP OAuth, or webhook prompt-guards. Guardrails skipping JSON-RPC errors and server-initiated messages is [agentgateway#4245](https://github.com/agentgateway/agentgateway/issues/4245); the fix is [#4345](https://github.com/agentgateway/agentgateway/pull/4345), not this repo. Numbers and logs: [EVIDENCE.md](EVIDENCE.md).

| Layer | agentgateway feature | Question it answers |
|---|---|---|
| Who may call which tool | `mcpAuthorization` | Is this caller allowed to use this tool? |
| Is the tool result fit to use | `mcpGuardrails` `kind: expression` | Is this result complete, and not out of date? |
| Do results agree across calls | `mcpGuardrails` `kind: remote` (ExtMCP) | Does this result contradict an earlier one in the same session? |

## Use it

| Need | Template | Needs |
|---|---|---|
| exact tool-name authorization | [templates/agentgateway.yaml](templates/agentgateway.yaml) | 1.4.1+ (also ran on 1.6.0, 1.7.0) |
| prefix authorization (`lookup_*` / `list_*` / `calculate_*`) | [templates/agentgateway-prefix-authz.yaml](templates/agentgateway-prefix-authz.yaml) | same |
| result guardrails (example field lists) | [templates/agentgateway-calibration.yaml](templates/agentgateway-calibration.yaml) | 1.7.0+ (`kind: expression`) |
| cross-call signal policies | [templates/agentgateway-signals.yaml](templates/agentgateway-signals.yaml) + `processors/signal_processor.py` | 1.4.1+ (`kind: remote`); `kind: expression` still needs 1.7.0 |

[templates/agentgateway-rci-knowledge.yaml](templates/agentgateway-rci-knowledge.yaml) is the prefix-authz template pointed at one example host. Copy it; change `host`, issuer and JWKS.

```bash
agentgateway --validate-only -f your.yaml
```

Bind `mcp.tool.name` and required fields to **your** tools. Unscoped result rules fail closed on every other tool.

## The policies

### Authorization (`mcpAuthorization`; a tool no rule allows is hidden from `tools/list`)

| Policy | Expression | Origin |
|---|---|---|
| `allow_harmless` | `mcp.tool.name == "grant_read_access"` | mcp-judge-seam `allow_read.cel` |
| `require_operator` | `has(jwt.roles) && jwt.roles.exists(r, r == "operator")` | judge-seam `allow_admin.cel` plus `has()` and list membership (not substring `in`) |
| `require_admin` | same, `"admin"` | variant |
| `allow_lookup_tools` | `lookup_*` or `list_*` | naming convention; only as safe as the server's naming |
| `require_operator_for_calculate` | `calculate_*` and list membership | missing `roles` is a clean non-match; roles must be a list |

### Result guardrails (`mcpGuardrails` on `mcp.result`)

| Policy | Tool | Action |
|---|---|---|
| `block_incomplete_result` | `lookup_mpfs` (`results` list) | reject when there are no rows, or any row has under 40% of the required fields non-null |
| `block_incomplete_flat_result` | `lookup_opps` (flat record) | same threshold, on the payment fields |
| `flag_stale_result` | `lookup_mpfs` | annotate when the row's `year` is before the request's calendar year |
| `flag_stale_snapshot` | `list_dataset_snapshots` | annotate datasets whose `effective_date` is over 365 days old |

Each rule is guarded by `mcp.tool.name` and by the result shape. Without those guards a rule runs on every tool and, because expression errors fail closed, rejects any result it cannot parse.

### Signal policies (ExtMCP processor)

| Policy | Expression | Verdict |
|---|---|---|
| `calibration/block_contradiction` | `contradiction == true` | BLOCK |
| `calibration/block_incomplete` | `completeness < 0.4` | BLOCK |
| `calibration/review_stale_data` | `currency < 0.6` | REVIEW |
| `combined/multi_signal_safety_gate` | `contradiction \|\| completeness < 0.4` | BLOCK |
| `combined/moderate_safety_gate` | `contradiction \|\| completeness < 0.75 \|\| currency < 0.6` | REVIEW |

[processors/signal_processor.py](processors/signal_processor.py) is a reference gRPC server: in-memory, one instance, plaintext on loopback. It scores completeness, currency (1.0 if the record year is this calendar year or later, else 0.0), and contradiction (same entity, same MCP session). BLOCK happens after the upstream tool has already run. Thresholds are mcp-trace-gate's demo defaults. Per-tool settings: [processors/signal_processor.example.json](processors/signal_processor.example.json).

## What was measured (2026-11-09)

Logs and commands: [EVIDENCE.md](EVIDENCE.md). Gateway tests start a real `agentgateway` process. Public-MCP scripts send no API keys.

| Check | Where | Result |
|---|---|---|
| Full pytest + Keycloak | macOS arm64, **1.7.0** | **95 passed** |
| Same suite | **1.6.0**, **1.4.1** | **78 passed, 17 skipped** (`kind: expression` not accepted) |
| Clean `pip install -r requirements.txt` | Linux aarch64 container, Linux **1.7.0** binary | **85 passed, 10 skipped** (no Keycloak) |
| Prefix hide/deny through the gateway | 35 public Streamable-HTTP servers | listed set = `lookup_*`/`list_*`; a hidden tool denied, **35/35** |
| Scoped guardrails do not reject a foreign tool | same campaign | **30/35** returned a `tools/call` result with no reject; 5 never reached the guardrail (transport / RPC error / no callable tool) |
| Unscoped expression fail-closes | pytest + live pathwren, plantguide | `-32603 guardrail check failed` |
| Shipped scoped rules leave those tools alone | pytest + live | unchanged |
| Processor down, `failClosed` | pytest + live pathwren | 1.7.0: `guardrail check failed`; 1.6.0 echoes `Connection refused` |
| `"operator" in jwt.roles` is substring on a string claim | pytest + live pathwren, 1.6.0 and 1.7.0 | original rule lists the gated tool for `roles="superoperator"`; shipped `has()`+`exists()` does not |
| [#4245](https://github.com/agentgateway/agentgateway/issues/4245) JSON-RPC `error` skipped | live public server + controlled upstream | success rejected; `-32602` forwarded verbatim |
| #4245 notifications and server-initiated requests skipped | controlled HTTP and `stdio:` upstreams | result rejected; log, progress, elicitation, sampling, `roots/list` forwarded; ExtMCP has no hook for them |

A constant mock `Mcp-Session-Id` had been misread as a 1.6.0 session leak. Live 1.6.0 isolated sessions; the mock now mints a UUID per initialize.

Example-host scripts (`scripts/live_rcintel_*.py`) need `RCI_API_KEY`. They are optional. Completeness/staleness/contradiction on real fee-schedule rows from that host are **not** claimed here; this session's processor run hit HTTP 429.

Releases other than 1.4.1, 1.6.0 and 1.7.0 were not run for this publish. x86_64 and Windows were not run. Linux aarch64 was the container run above.

### Behaviour in agentgateway

- Guardrail `reject` on `tools/call`: JSON-RPC `-32001` in the response phase; `isError: true` in the request phase.
- A tool no `mcpAuthorization` rule allows is missing from `tools/list`; calling it returns HTTP 400.
- Expression errors fail closed (`-32603 guardrail check failed`). The expression **is** evaluated on `result.isError: true`. It is **not** evaluated on a JSON-RPC `error`, a notification, or a server-initiated request ([#4245](https://github.com/agentgateway/agentgateway/issues/4245)).
- Indexing a list with a JSON number needs `int(...)`.
- Keycloak puts realm roles under `realm_access.roles`; these rules read a top-level `roles` claim.

## Run it

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
tests/keycloak/start.sh                  # optional: real-IdP tests (Docker)
AGENTGATEWAY_BIN=/path/to/agentgateway .venv/bin/python -m pytest -q
```

Without a binary the gateway tests skip. Without Keycloak its tests skip. Binaries: <https://github.com/agentgateway/agentgateway/releases>.

| Script | What it checks |
|---|---|
| `scripts/live_public_mcp.py` | passthrough, prefix authorization, scoped guardrails on public MCP servers (no key) |
| `scripts/live_pitfalls.py` | fail-closed, substring roles, processor down, #4245 |
| `scripts/live_session_metadata.py` | ExtMCP `session` on a live MCP |
| `scripts/live_rcintel_*.py` | one example host; needs `RCI_API_KEY` |

## Offline CLI (secondary)

Uses cel-python, not agentgateway's engine. Gateway tests are authoritative.

```bash
.venv/bin/python tools/cel-policies list
.venv/bin/python tools/cel-policies validate
.venv/bin/python tools/cel-policies check combined/moderate_safety_gate \
  '{"contradiction": false, "completeness": 0.6, "currency": 0.9}'
```

Exit codes: 0 permitted (ALLOW or PROCEED), 1 DENY, BLOCK or REVIEW, 2 error. It does not load `policies/guardrails/` (agentgateway-only variables).

## Known gaps

- Field lists and `signal_processor.example.json` are bound to example tool names. Rebind them.
- Prefix authorization trusts naming, not what each tool does.
- Public MCP checks do not test your result shapes.
- Tokens in tests come from a local Keycloak password grant, not a production IdP.
- The processor is a reference implementation (in-memory, FIFO pending per session, BLOCK after the tool has run).

### Not live-tested, and why

These are not missing runs of this pack. They are either a different product surface, a different machine, or a host that refused the call.

| Item | Why it was not live-tested here |
|---|---|
| Entra ID + MCP | This pack does not implement Entra. Tests use local Keycloak (password grant, top-level `roles`). Upstream already tracks Entra separately. |
| OAuth to a remote MCP | The live scripts forward `X-API-Key` or no auth. They do not run the MCP Authorization / `.well-known` dance against an Atlassian-style host. |
| Webhook / `promptGuard` | Wrong API. These rules are `mcpAuthorization` and `mcpGuardrails`, not `ai.promptGuard`. |
| agentgateway 1.0.1–1.3.1, 1.5.0 | This publish used the binaries on the machine: **1.4.1**, **1.6.0**, **1.7.0**. Those three already split the features (authz / remote / expression). Older releases were not downloaded again. |
| x86_64, Windows | The runner is macOS arm64. Linux was `python:3.12-slim` on **linux/arm64**. No x86 or Windows host. |
| Hosted 45-tool completeness / contradiction table | Optional example host. `live_rcintel_gateway.py` passed; processor/authz/signals then hit **HTTP 429**. The README does not claim those rows. |
| `llama3.1:8b` through the gateway | That driver lives in mcp-judge-seam, not this repo. Authorization here is pytest + Keycloak + public MCP. |
| `scripts/bench_gateway.py` | Loopback microbenchmark, not live MCP. Not re-run for this publish. |

## License

MIT. See [LICENSE](LICENSE). `processors/ext_mcp.proto` is a copy of agentgateway's ExtMCP definition (v1.7.0, Apache-2.0).
