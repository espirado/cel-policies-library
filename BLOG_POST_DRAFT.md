# Blog outline: CEL policies for agentgateway MCP

Working title: **A public CEL pack for agentgateway MCP: authorize the tool, gate the result**

Every claim is from a run in this repo (agentgateway v1.7.0 unless stated) or a linked project. Reproduce with `pytest` and the scripts in the README. Keep the README's "Known gaps" section as the post's limits. This is a public tool; do not frame it as an RCIntel product or as a stolen-credential control.

## Angle

The judge-versus-enforcement contrast is already published ([agent-sec](https://espiradev.org/blog/llm-judge-partial-compliance.html), [mcp-judge-seam](https://espiradev.org/blog/mcp-judge-seam.html)). This is the practical follow-up: a **library + notes**, not a new gateway feature. Cite upstream [`examples/mcp-guardrails/expression`](https://github.com/agentgateway/agentgateway/tree/main/examples/mcp-guardrails/expression) as the toy, then unscoped fail-closed, the substring `roles` trap, and rebindable YAML. One 45-tool host is an example target. Do not retell the research. Do not claim Entra, remote OAuth, webhooks, LLMjacking, or an ExtMCP session leak on 1.6.0. Unpublished until [EVIDENCE.md](EVIDENCE.md) matches.

## 1. Three layers

| Layer | Config | Question |
|---|---|---|
| `mcpAuthorization` | `rules:` list | May this caller use this tool? |
| `mcpGuardrails` `kind: expression` | `condition` + `reject` / `transform` on `mcp.result` | Is this one result fit to use? |
| `mcpGuardrails` `kind: remote` (ExtMCP) | a gRPC server | Does this result agree with earlier ones in the session? |

## 2. Authorization, on the real tool list

- Real tokens from Keycloak (a realm-role mapper produces the top-level `roles` claim the rules read).
- On the real server's 45 tools: anonymous callers see 16 `lookup_`/`list_` tools; the operator token sees 20; viewer, admin and no-role tokens see 16. A real tool no rule allows (`check_ncci_mue`) is hidden and denied.
- Role rules use `has(jwt.roles)` and `jwt.roles.exists(r, r == "operator")`. A missing `roles` claim is a clean non-match. A string claim such as `"superoperator"` does not match. The original `"operator" in jwt.roles` form is a substring test on strings; that is documented by `test_original_substring_rule_admits_a_string_roles_claim` and is not the shipped rule.

## 3. Result guardrails

- Four expressions: incomplete `results` list, incomplete flat record, superseded year, old snapshots. Show them and the table of results.
- Real triggers: `lookup_opps` for CPT 99213 (null payment fields) is rejected; `list_dataset_snapshots` names the datasets effective over a year ago (ipps, medi_cal_*, ms_drg, umls).
- Say plainly which two paths the real server cannot trigger and that those were checked with one parameter changed.

## 4. Things real testing broke (the useful section)

1. My first staleness rule (linear decay, flag under 0.6) flagged every current CY2026 result. The server's own `list_dataset_snapshots` says it is current. Annual schedules do not decay.
2. Guardrails without a tool and shape guard rejected other tools' results (expression errors fail closed). Found only when several tools sat behind one gateway.
3. A clean `pip install` in a Linux container showed a missing dependency.
4. Do **not** claim 1.3.1–1.6.0 send empty ExtMCP `session` metadata. That was our mock returning a constant `Mcp-Session-Id`. Live 1.6.0 on public MCP isolated sessions. After unique mock ids, isolation holds on 1.4.1, 1.6.0, and 1.7.0.

## 5. A real contradiction, enforced in the gateway

- `lookup_mpfs` returned conversion factor 33.4009; `calculate_payment` returned 33.5675 by default and 33.4009 with `qpp: false`. State the values and what happened; do not state CMS facts or the cause as established.
- The processor let the lookup through, denied the default `calculate_payment`, allowed the `qpp: false` call, and allowed a default call in a new session. Same result for 4 codes. This is the signal a stateless CEL expression cannot compute.

## 6. Versions and platforms

The matrix from the README (1.0.1 through 1.7.0) and Linux aarch64. Say which releases were not run.

## 7. Cost

Same call with and without the policy: below the noise (about ±100 µs round to round; −53 to +63 µs medians across four runs). Say "no measurable overhead at this resolution". The processor's gRPC hop was not benchmarked.

## Do not include

- "Judges miss 40 to 60%". The measured effect (agent-sec WRITEUP section 5) is +14.8 to +30.5 points when the partial action is present.
- "Production-tested", or any cel-python microsecond figure.
- Goose or OpenSandbox integration. Nothing exists or was tried.
- Any claim that CY2026 MPFS data is stale, that the IPPS or Medi-Cal snapshots are wrong, or a causal explanation of the conversion-factor difference. The server reported them as current; the data owner must confirm.
