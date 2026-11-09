# Relation to agentgateway examples and open work

Read this before posting a discussion, PR, or ambassador issue. The pack does **not** fill every gap people already asked about. Claiming that it does will get questioned immediately.

Checked against agentgateway `main` (example paths as of 2026-11-09) and the linked issues/discussions.

## Already in upstream (do not present as new)

| Upstream | What it is | Overlap with this pack |
|---|---|---|
| [`examples/mcp-authorization`](https://github.com/agentgateway/agentgateway/tree/main/examples/mcp-authorization) | JWT + `mcpAuthorization` on exact names (`echo`, `get-sum`) | Same layer as `templates/agentgateway.yaml`. Ours adds `has(jwt.roles)` + `exists` (substring trap) and a prefix pattern. |
| [`examples/mcp-guardrails/expression`](https://github.com/agentgateway/agentgateway/tree/main/examples/mcp-guardrails/expression) | Toy: stdio `@modelcontextprotocol/server-everything`, request deny on `DO_NOT_SEND`, email mask, response regex mask of `demo-secret-*` | Same **feature** (`kind: expression`). Different **job**: they mask/deny on `echo`. We gate result fitness and document fail-closed when a rule is unscoped. |
| [`examples/mcp-authentication`](https://github.com/agentgateway/agentgateway/tree/main/examples/mcp-authentication) | MCP Authorization spec: resource metadata, Keycloak, remote MCP + external AS | We use `jwtAuth` (password-grant Keycloak in tests). We do **not** implement `mcpAuthentication` / `.well-known/oauth-protected-resource`. |
| [`examples/mcp-authzen`](https://github.com/agentgateway/agentgateway/tree/main/examples/mcp-authzen) | AuthZEN for tool calls | Not this pack. |

The toy expression example is the right comparison for a discussion post. Cite it. Then say what this pack adds: version matrix, remote Streamable-HTTP targets, scoped result rules. Do **not** claim ExtMCP `session` is empty before 1.7.0 — that was a mock artifact (see below).

## Open community asks this pack does **not** answer

| Ask | Where | This pack |
|---|---|---|
| Working Entra ID + MCP | [Discussion #2978](https://github.com/agentgateway/agentgateway/discussions/2978), [PR #2408](https://github.com/agentgateway/agentgateway/pull/2408) | No Entra. Local Keycloak only. |
| OAuth to a **remote** MCP | [Discussion #1259](https://github.com/agentgateway/agentgateway/discussions/1259), `examples/mcp-authentication` scenario B | No. We forward `X-API-Key`; we do not run the MCP OAuth dance to Atlassian-style hosts. |
| Webhook / prompt-guard guardrails | `ai.promptGuard` webhooks, not `mcpGuardrails` | No. Wrong API. |
| mcpGuardrails skip errors and server-initiated messages | [#4245](https://github.com/agentgateway/agentgateway/issues/4245) (open), [PR #4345](https://github.com/agentgateway/agentgateway/pull/4345) (open, ZYZ666-RGB) | **Reproduced live on 1.7.0**, not fixed here. `scripts/live_pitfalls.py` A4: a `condition: true` reject fires on a success (`-32001`) but an upstream JSON-RPC `-32602` error passes through verbatim. `isError` tool results *are* inspected (A3), which matches the PR's description. Our shipped rules only make sense on successful results, so the gap does not change their behaviour; it does mean a "mask secrets in every response" rule copied from the toy example will miss error text until #4345 lands. |
| MCP guardrails docs (audit-record guide) | [#3485](https://github.com/agentgateway/agentgateway/issues/3485), follows [#3230](https://github.com/agentgateway/agentgateway/issues/3230) | Not a website PR. `capsule-emit` / hash-chained audit is a different project. |
| A2A guardrails parity | [#3610](https://github.com/agentgateway/agentgateway/issues/3610) | MCP only. |

If a reviewer asks “does this cover Entra / remote OAuth / webhooks / error-path masking?”, the answer is **no**.

## What is worth posting (measured here)

These are gateway behaviours, not a new product feature. Tests pin them.

### 1. Unscoped `kind: expression` rules fail closed

A completeness condition that indexes `mcp.result.structuredContent.results` without `mcp.tool.name` and a shape guard errors on any other tool and denies the call (`guardrail check failed`). Test: `test_unscoped_expression_fails_closed_on_other_tools`. The shipped rules are scoped; `test_rules_scoped_to_one_tool_do_not_touch_other_tools` is the regression. Live (`scripts/live_pitfalls.py`, 1.7.0): the unscoped rule returned `-32603 guardrail check failed` on pathwren and plantguide; the scoped rules left the same results unchanged; 30 of 35 public servers returned a result through the scoped rules with no reject.

### 2. `"operator" in jwt.roles` is substring on a string claim

`test_original_substring_rule_admits_a_string_roles_claim`. Shipped rules use `has(jwt.roles)` and `exists`. Live (`scripts/live_pitfalls.py` C1–C4, 1.6.0 and 1.7.0, pathwren): the original rule listed the gated tool for `roles="superoperator"`; the shipped rule did not; `["operator"]` did; no token did not.

### 3. #4245 reproduction (comment on the issue, not a new discussion)

**Policy:** agentgateway's `CODE_OF_CONDUCT.md` Generative AI Policy says "Refrain from generating issues, comments, or PR descriptions with AI" and "When using (non-trivial) AI assistance, please indicate this." The comment must be written by a human. The facts below are verified; the words are yours.

Verified facts (2026-11-09, logs `evidence/runs/live-pitfalls-1.7.0-20261109T185147Z.json`, `evidence/runs/live-pitfalls-1.6.0-20261109T185209Z.json`; reproduce with `scripts/live_pitfalls.py`):

- Release: v1.7.0 (`26f5aebe99a3`), the latest release at the time. Remote-processor results also on 1.6.0.
- Config: `mcpGuardrails` `kind: expression`, `condition: "true"`, `reject: "REJECTED_BY_GUARDRAIL"`, `methods: {tools/call: response}`, in front of a Streamable-HTTP target.
- Control: success case → `-32001 REJECTED_BY_GUARDRAIL` (the rule fires).
- **JSON-RPC `error` object** from upstream (`-32602`) → forwarded to the client verbatim. Two ways: a public server (`license-changes-mcp.ottobot2025.workers.dev`, `recent_license_changes` with `state=test`), and a controlled upstream returning a unique marker string, which came back unchanged.
- **Notifications and server-initiated requests**: a controlled upstream emits, before the result, `notifications/message`, `notifications/progress`, `elicitation/create`, `sampling/createMessage`, and `roots/list`, each with a unique marker. With the reject-everything rule the result is replaced by the reject and **all five** interim messages reach the client untouched (the gateway rewrites server-request ids to `agw_m_s_…`, so it is handling them, just not inspecting them). `methods` keys `tools/*` and `notifications/*` do not change this. Public servers cannot be made to emit these on demand, so this half is controlled-upstream only; say so.
- **Both target transports.** Streamable HTTP upstream (`tests/gateway/sse_mcp.py`): interim messages arrive on the `tools/call` POST response stream. **stdio** upstream (`tests/gateway/stdio_mcp.py`, spawned by the gateway as a `stdio:` target): interim messages arrive on the session's GET SSE stream instead. Same bypass on both; the JSON-RPC error object passes through untouched on both.
- **`kind: remote`** (ExtMCP) has the same gap for all of the above on both transports: `CheckRequest` and the terminal `CheckResponse` fire; there is no `CheckResponse` for a JSON-RPC error and no hook at all for the interim messages. 1.6.0 and 1.7.0.
- `result.isError: true` tool results **are** inspected (deepwiki `read_wiki_contents` with a bad `repoName`; an unscoped expression fail-closed on it). Matches PR #4345's description.
- Code location, v1.7.0 `crates/agentgateway/src/mcp/handler.rs`, `apply_guardrails_response_intercept`: `let ServerJsonRpcMessage::Response(resp) = msg else { return None; };` — `Error`, `Notification`, and `Request` variants skip every processor. The comment above it says the stream is request-scoped so the only `Response` is the terminal one, which is why the other variants were ignored.
- Not claimed: a fix; `resources/updated` or task-status notifications (not emitted by the controlled upstream); A2A.

### 4. `failClosed` message differs by release

Remote processor unreachable: 1.7.0 returns `-32603 guardrail check failed`; 1.6.0 returns `-32603 mcpGuardrails checkRequest failed: upstream call failed: Connect: Connection refused (os error 61)`, i.e. the connect error is echoed to the MCP client. Both fail closed. Measured on mock and live (pathwren). Minor; mention only if asked.

## If we post to agentgateway

Use [DISCUSSION_DRAFT.md](DISCUSSION_DRAFT.md) only. One discussion: policies plus the fail-closed and substring notes, citing the toy example. Not “we added MCP guardrails.” Not Entra/OAuth. Not a session-metadata leak on 1.6.0.

Do not open that discussion, a PR, or an AAIF ambassador issue until `EVIDENCE.md` for the current session lists the fail-closed test on 1.7.0 as re-run, and does **not** claim the retracted session leak.

**Retracted:** “ExtMCP `session` empty on 1.3.1–1.6.0.” Live probes on 1.6.0 (`scripts/live_session_metadata.py`, pathwren + plantguide) sent distinct non-empty session fields matching HTTP `Mcp-Session-Id`. The mock had returned a constant `mock-session`; 1.6.0 wraps the upstream id, so two tests shared one session. After unique mock ids, `test_contradiction_is_scoped_to_session_and_entity` isolates on 1.4.1, 1.6.0, and 1.7.0.
