# MS Omni Gateway Policies

A monorepo of custom **MuleSoft Omni Gateway** policies built with the [Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview).

Each policy is a self-contained subproject with two halves:

- `*-definition/` — the policy schema (Anypoint Exchange metadata: `gcl.yaml`, `exchange.json`, `HOME.md`, `icon.png`).
- `*-flex/` — the Rust implementation compiled to a WebAssembly (WASM) module that runs inside Flex Gateway.

## Policies

| Policy | Path | Purpose |
|---|---|---|
| Slack Request Verification | [`slack-request-verification/`](./slack-request-verification/) | Validates incoming Slack requests by verifying their HMAC-SHA256 signatures using the Slack app's signing secret. Implements the [Slack request verification](https://docs.slack.dev/authentication/verifying-requests-from-slack/) algorithm with replay-attack protection. |
| Instance ID Header Injection | [`instance-id-header-injection/`](./instance-id-header-injection/) | Injects `x-anypoint-api-instance-id` with the API instance ID into every incoming request. Useful for request tracing, multi-instance correlation, and stitching standalone agents into the **Agent Visualizer** when calling MCP servers without an Agent Network. |
| A2A PII Guard | [`a2a-pii-guard-policy/`](./a2a-pii-guard-policy/) | Detects PII in [Agent-to-Agent (A2A)](https://google.github.io/A2A/) JSON-RPC traffic (`message/send`, `message/stream`, `tasks/{get,stream,resubscribe}`) and applies configurable per-entity actions (`Log`, `Reject`) on the request path. Response path (including SSE streams) is monitored read-only and never modified. Rejections return JSON-RPC error envelopes in the A2A-reserved code range. |

> Additional policies live alongside in this repo and will be documented here over time.

## Repository layout

The repo root holds shared metadata; each policy lives in its own top-level directory and follows the same split-model shape. Using **slack-request-verification** as the example:

```
ms-omni-gateway-policies/
├── README.md                          # (this file)
├── LICENSE
├── .gitignore                         # Common ignores for the whole monorepo
└── <policy-name>/                     # e.g. slack-request-verification/
    ├── README.md                      # Policy overview & how it works
    ├── docs/                          # (optional) Per-policy guides
    │   ├── APPLYING_POLICY.md         # How to apply the policy to an API instance
    │   └── LOCAL_TESTING_GUIDE.md     # Step-by-step manual test guide
    ├── <policy-name>-definition/      # Anypoint Exchange asset (schema)
    │   ├── gcl.yaml                   # Policy schema
    │   ├── exchange.json              # Anypoint Exchange asset coordinates
    │   ├── HOME.md                    # Exchange landing page
    │   ├── icon.png                   # Exchange icon
    │   ├── README.md                  # PDK definition build/publish reference
    │   └── Makefile                   # build / publish / release / release-local
    └── <policy-name>-flex/            # Rust → WASM implementation
        ├── Cargo.toml                 # Rust crate manifest (PDK metadata)
        ├── src/lib.rs                 # Policy entrypoint & filters
        ├── tests/                     # Integration tests (pdk-test + httpmock)
        ├── playground/                # Local Docker playground (Flex + httpbin)
        ├── README.md                  # PDK flex build/run/test reference
        └── Makefile                   # build / run / test / publish / release
```

Individual policies may add or omit pieces (e.g. an empty-config policy can skip `docs/`, the `definition/` half can ship without a custom `icon.png`). See each policy's own `README.md` for specifics.

## Prerequisites (development)

- [Rust toolchain](https://rustup.rs/) with the `wasm32-wasip1` target
  ```bash
  rustup target add wasm32-wasip1
  ```
- [`cargo-anypoint`](https://crates.io/crates/cargo-anypoint) — installed by `make setup` inside each `*-flex/` project.
- [`anypoint-cli-v4`](https://docs.mulesoft.com/anypoint-cli/latest/) authenticated against your Anypoint org.
- Docker + Docker Compose (for running the local playground).
- A registered Flex Gateway instance — see each policy's `docs/LOCAL_TESTING_GUIDE.md` for the registration handoff.

## Common workflows

All commands below run from inside a specific policy's `*-flex/` directory unless noted.

```bash
# One-time setup (installs cargo-anypoint locally)
make setup

# Generate config bindings from the policy definition
make build-asset-files

# Compile the WASM policy
make build

# Run integration tests
make test

# Boot the local Docker playground (Flex Gateway + httpbin backend)
make run

# Publish a development build to Anypoint Exchange
make publish

# Publish a release build to Anypoint Exchange
make release
```

For the policy **definition** half, run from `*-definition/`:

```bash
make build           # Build the definition
make release-local   # Publish to local Exchange cache (needed before flex build)
make release         # Publish to Anypoint Exchange
```

## Secrets & local registration

Local Flex Gateway registration produces files (`registration.yaml`, `certificate.yaml`) that contain real TLS certificates, private keys, and tenant identifiers. **These are gitignored at the repo root** — do not commit them.

To register a Flex Gateway in local mode:

1. Go to **Anypoint Platform → Runtime Manager → Flex Gateway → Add Gateway**.
2. Pick **Docker**, copy the registration command, change `--connected=true` to `--connected=false`.
3. Run the command from inside the policy's `playground/config/` directory.

## License

Copyright © 2026 Salesforce, Inc.

Licensed under the **Apache License, Version 2.0** (the "License"). You may not use the contents of this repository except in compliance with the License. See [`LICENSE`](./LICENSE) for the full terms or obtain a copy at <http://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. The per-file `Copyright ... All rights reserved.` notices are the copyright-notice clause required by Apache-2.0 §4(c); they do not withdraw the license grant above.
