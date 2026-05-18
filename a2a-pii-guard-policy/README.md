# A2A PII Guard Policy

A MuleSoft Omni Gateway custom policy that detects personally identifiable information (PII) in [Agent-to-Agent (A2A)](https://google.github.io/A2A/) JSON-RPC traffic and applies configurable per-entity actions on the request path. The response path is monitored read-only.

Built with the [Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) **1.8.0** as a standalone, split-model project.

## Focus

Agent-to-agent traffic carries free-form natural-language content authored by humans and other agents. It is exactly the surface where PII leaks happen: an end user pastes a customer SSN into a chat with a billing agent, an upstream agent forwards a credit card number in a task description, an artifact streamed back from a tool call contains an email address that should never have left the trust boundary.

This policy is the **enforcement gate at the A2A perimeter**. Specifically:

- **Scope is A2A, not generic HTTP.** It understands the JSON-RPC 2.0 envelope and the canonical A2A payload shapes (`message.parts[].text`, `task.parts[].text`, `task.description`, plus the response-side `result.status.message.parts`, `result.artifact.parts`, `result.task.*`). Non-A2A traffic — and A2A methods that don't carry user-authored content — passes through untouched.
- **Detection, not redaction.** The goal is *block or audit*, not silently rewrite content. Rewriting agent-authored text changes the meaning of the conversation; that's a separate policy concern.
- **Per-entity policy, not a single switch.** Operators control each PII type (predefined or custom regex) independently: which entities to look for, which action to take (`Log`, `Reject`, or both), and whether logging alone should surface as a policy violation in Anypoint Monitoring. This matters because regulatory regimes treat entities differently (a US SSN in a request is a hard reject; an email might just be logged).
- **JSON-RPC-correct rejections.** Blocked requests return HTTP 200 with a JSON-RPC error envelope, echoing the original request id and using a configurable error code in the A2A-reserved range `[-32099, -32008]`. Calling agents see a structured failure they can reason about — not a transport error.
- **Asymmetric request vs. response treatment.** The request path can block; the response path **only logs**. Blocking responses mid-stream would corrupt SSE conversations and is operationally worse than the leak it prevents — observability plus violation reporting is the right tool for the response side.
- **Standalone and side-effect-free.** No external service calls, no shared cache, no cross-replica state. The policy is fail-safe by construction: if the regex engine errors on a payload the request continues (logged as a warning), so a malformed pattern can't take the gateway down.

## Project layout

```
a2a-pii-guard-policy/
├── a2a-pii-guard-policy-definition/   # GCL schema + Exchange metadata
│   ├── exchange.json
│   ├── gcl.yaml
│   └── Makefile
└── a2a-pii-guard-policy-flex/         # Rust implementation (compiles to wasm32-wasip1)
    ├── Cargo.toml
    ├── Makefile
    ├── src/
    │   ├── lib.rs              # entrypoint + filter wiring
    │   ├── pii.rs              # detector primitives (predefined + custom regexes)
    │   ├── request.rs          # request-path PII inspection
    │   ├── response.rs         # response-path PII inspection (log-only, never blocks)
    │   ├── jsonrpc.rs          # minimal JSON-RPC 2.0 envelope types
    │   ├── a2a.rs              # A2A method-name constants
    │   ├── http_utils.rs       # MIME / header helpers
    │   ├── access_log.rs       # access-log helpers
    │   ├── sse.rs              # SSE adapter for streaming responses
    │   └── generated/          # auto-generated config struct from gcl.yaml
    ├── playground/             # Docker-based local Flex Gateway for `make run`
    └── tests/                  # integration tests (pdk-test)
```

## Behaviour

### Configuration (gcl.yaml)

* `predefinedEntities[]` — list of `{ type, actions, reportPolicyViolationOnLog }`. `type` is one of `Email`, `US SSN`, `Credit Card`, `Phone Number`.
* `customEntities[]` — list of `{ name, regex, actions, reportPolicyViolationOnLog }`. Custom regexes without explicit anchors are wrapped in `\b…\b`. Doubled escape sequences (`\\d`, `\\s`, …) are normalised to single escapes so configuration sources don't need to round-trip them.
* `actions` per entity is a non-empty subset of `{ Log, Reject }`.
* `reportPolicyViolationOnLog` controls whether a `Log` action also generates a policy violation visible in Anypoint Monitoring. `Reject` actions always generate a violation.
* `errorCodeOnReject` — JSON-RPC 2.0 error code in the A2A reserved range `[-32099, -32008]`. Default `-32023`.

### Request path

For `POST` requests carrying `application/json` and a JSON-RPC 2.0 envelope whose `method` is one of `message/send`, `message/stream`, `tasks/get`, `tasks/stream`, or `tasks/resubscribe`, the policy walks the canonical text locations:

* `params.message.parts[].text` (when `kind`/`type` is `text`)
* `params.task.parts[].text`
* `params.task.description`

For each match, it applies the configured `actions`. If any matched entity has `Reject`, the request is short-circuited with a JSON-RPC 2.0 error response (HTTP 200, `application/json`):

```json
{
  "jsonrpc": "2.0",
  "id": <echoed from request, if present>,
  "error": {
    "code": <errorCodeOnReject>,
    "message": "Policy violation: PII detected in request",
    "data": [ { "pii_type": "Email", "value": "...", "start": 0, "end": 7 }, ... ]
  }
}
```

All other requests are forwarded upstream unchanged. The upstream timeout header is cleared so SSE streams aren't truncated.

### Response path

Inspects JSON and SSE responses, walking `result.status.message.parts[].text`, `result.artifact.parts[].text`, `result.task.parts[].text`, `result.task.description`, and `result.task.status`. Findings are logged and (when configured) reported as policy violations, but the response **is never modified or blocked**.

### Integration tests

Integration tests live under `a2a-pii-guard-policy-flex/tests/`. They use [`pdk-test`](https://docs.mulesoft.com/pdk/latest/policies-pdk-integration-tests) to spin up a containerised Flex Gateway plus a backend `httpmock`. A `tests/config/registration.yaml` produced via `anypoint-cli-v4 registration create-local` is required (it is `.gitignore`d).

## Local debugging

`a2a-pii-guard-policy-flex/playground/config/api.yaml` ships with an example configuration combining predefined and custom entities. The `playground/` directory provides a Docker-based local Flex Gateway plus an `httpbin` upstream on port `8185`.

