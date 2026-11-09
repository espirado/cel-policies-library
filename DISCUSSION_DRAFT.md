# Unpublished — agentgateway discussion draft

Do **not** open a GitHub discussion, PR, or an AAIF ambassador issue from this file until `EVIDENCE.md` for the current session lists the fail-closed test as re-run on 1.7.0. Do **not** claim ExtMCP `session` is empty before 1.7.0; that finding was a mock artifact.

Title: **CEL MCP policies: unscoped expressions fail closed; role membership is not substring**

## Body (paste later)

Upstream already has the feature. The toy is [`examples/mcp-guardrails/expression`](https://github.com/agentgateway/agentgateway/blob/main/examples/mcp-guardrails/expression/config.yaml) (stdio everything server: deny `DO_NOT_SEND`, mask emails, mask `demo-secret-*`). This is not a second copy of that example, and it does not add Entra, remote MCP OAuth, or webhook `promptGuard`.

Public pack: https://github.com/espirado/cel-policies-library — YAML you rebind (`templates/agentgateway-prefix-authz.yaml`, `templates/agentgateway-calibration.yaml`), tests that run **inside** agentgateway, notes below.

**1. Unscoped `kind: expression` fail-closes.** A condition that indexes `mcp.result.structuredContent.results` without `mcp.tool.name` and a shape guard errors on any other tool. agentgateway returns `-32603 guardrail check failed`. Reproduced on 1.7.0 against the mock (`test_unscoped_expression_fails_closed_on_other_tools`) and against two public MCP servers (`scripts/live_pitfalls.py`). It also evaluates on an upstream `isError` result. The shipped rules are scoped; `test_rules_scoped_to_one_tool_do_not_touch_other_tools` is the regression, and 30 public servers returned results through them with no reject. The toy’s `has(mcp.result.content)` mask is a different, safer global condition.

**2. `"operator" in jwt.roles` is a substring test when `roles` is a string.** A claim `"superoperator"` matches. Shipped rules use `has(jwt.roles)` and `exists`. `test_original_substring_rule_admits_a_string_roles_claim`, and live on 1.6.0 and 1.7.0 with a local JWKS in front of a public server.

Not in this pack: Entra MCP ([#2978](https://github.com/agentgateway/agentgateway/discussions/2978)), OAuth to a remote MCP ([#1259](https://github.com/agentgateway/agentgateway/discussions/1259)), webhook prompt-guards. [#4245](https://github.com/agentgateway/agentgateway/issues/4245) (guardrails skip JSON-RPC errors) reproduces on 1.7.0 against a public server with the probe in this repo; the rules here only act on successful results, so it does not change them, and the fix is [#4345](https://github.com/agentgateway/agentgateway/pull/4345), not this pack.

Non-goals and overlap table: `UPSTREAM.md` in the repo.
