# Slack Request Verification Policy - Local Testing Guide

This guide walks you through manually testing the Slack Request Verification policy using the PDK local Docker playground.

## Prerequisites

- Docker and Docker Compose installed and running
- Rust toolchain with `wasm32-wasip1` target
- `cargo-anypoint` CLI (`cargo install cargo-anypoint@1.7.0`)
- `anypoint-cli-v4` installed
- A Flex Gateway registration file (`registration.yaml`) in the playground config directory
- `openssl` available on your shell (used to compute HMAC signatures)

## Project Structure

```
slack-request-verification/
  slack-request-verification-definition/   # Policy schema & Exchange metadata
  slack-request-verification-flex/         # Policy implementation (Rust/WASM)
    playground/
      config/
        api.yaml                  # Primary API instance (strict mode, /strict/)
        api-test-scenarios.yaml   # Additional test instances (/log-only/, /short-tolerance/)
        logging.yaml              # Debug-level logging
        registration.yaml         # Flex Gateway registration (you provide this)
        custom-policies/          # Compiled policy binary (auto-generated)
      docker-compose.yaml         # Flex Gateway + httpbin backend
```

## Step 1 - Register Flex Gateway (one-time)

If you don't already have a `registration.yaml`, generate one:

1. Go to **Anypoint Platform > Runtime Manager > Flex Gateway**.
2. Click **Add Gateway**, select **Docker**.
3. Copy the registration command but change `--connected=true` to `--connected=false`.
4. Run the command inside the `playground/config/` directory so `registration.yaml` is created there.

## Step 2 - Release the Policy Definition Locally

Before building the implementation, you must publish the policy definition to your local Exchange cache. From the `slack-request-verification-definition/` directory:

```bash
make release-local
```

This builds the definition and publishes it to the local filesystem cache, allowing the implementation project to resolve it during `build-asset-files`. You only need to re-run this when the definition (`gcl.yaml` or `exchange.json`) changes.

## Step 3 - Build and Start the Playground

From the `slack-request-verification-flex/` directory:

```bash
make run
```

This will:
1. Build the WASM binary.
2. Install the policy into the playground.
3. Start Docker Compose with Flex Gateway (port `8081`) and an httpbin backend.

Wait until the Flex Gateway logs show it is ready before sending requests.

## Step 4 - Playground API Instances

The playground defines three API instances on port `8081`, each on a different subpath with a different policy configuration. All share the same signing secret `8f742231b10e8888abcd99yyyzzz85a5` and route to httpbin at `/anything/echo/`.

The primary instance lives in `api.yaml` (single-document YAML required by `make run` for policy ref patching). Additional test scenarios are in `api-test-scenarios.yaml`, which Flex Gateway loads automatically from the same config directory.

| Subpath              | `rejectOnFailure` | `timestampToleranceSeconds` | Purpose                   |
|----------------------|--------------------|-----------------------------|---------------------------|
| `/strict/`           | `true`             | `300`                       | Default - reject invalid  |
| `/log-only/`         | `false`            | `300`                       | Log warnings, allow all   |
| `/short-tolerance/`  | `true`             | `60`                        | Tighter replay protection |

## Step 5 - Run Test Cases

### 5.1 Strict Mode (/strict/)

#### Test 1: Valid Signature (expect `200 OK`)

```bash
SIGNING_SECRET="8f742231b10e8888abcd99yyyzzz85a5"
BODY="token=test_token&team_id=T1234&text=hello"
TIMESTAMP=$(date +%s)

BASESTRING="v0:${TIMESTAMP}:${BODY}"
SIGNATURE="v0=$(echo -n "$BASESTRING" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" | awk '{print $2}')"

curl -v -X POST http://localhost:8081/strict/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: ${TIMESTAMP}" \
  -H "X-Slack-Signature: ${SIGNATURE}" \
  -d "${BODY}"
```

**Expected:** HTTP `200` with the httpbin echo response.

#### Test 2: Invalid Signature (expect `401 Unauthorized`)

```bash
curl -v -X POST http://localhost:8081/strict/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: $(date +%s)" \
  -H "X-Slack-Signature: v0=invalidsignaturehash" \
  -d "token=test"
```

**Expected:** HTTP `401`.

#### Test 3: Missing Signature Header (expect `401 Unauthorized`)

```bash
curl -v -X POST http://localhost:8081/strict/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: $(date +%s)" \
  -d "token=test"
```

**Expected:** HTTP `401`.

#### Test 4: Expired Timestamp / Replay Attack (expect `401 Unauthorized`)

Use a timestamp older than the tolerance window (300s):

```bash
SIGNING_SECRET="8f742231b10e8888abcd99yyyzzz85a5"
BODY="token=test"
OLD_TIMESTAMP=$(($(date +%s) - 600))

BASESTRING="v0:${OLD_TIMESTAMP}:${BODY}"
SIGNATURE="v0=$(echo -n "$BASESTRING" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" | awk '{print $2}')"

curl -v -X POST http://localhost:8081/strict/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: ${OLD_TIMESTAMP}" \
  -H "X-Slack-Signature: ${SIGNATURE}" \
  -d "${BODY}"
```

**Expected:** HTTP `401`. The signature is mathematically correct but the timestamp is too old.

#### Test 5: Missing Timestamp Header (expect `401 Unauthorized`)

```bash
curl -v -X POST http://localhost:8081/strict/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Signature: v0=anything" \
  -d "token=test"
```

**Expected:** HTTP `401`.

### 5.2 Log-Only Mode (/log-only/)

With `rejectOnFailure=false`, invalid requests are logged but allowed through.

#### Test 6: Invalid Signature in Log-Only Mode (expect `200 OK`)

```bash
curl -v -X POST http://localhost:8081/log-only/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: $(date +%s)" \
  -H "X-Slack-Signature: v0=invalidsignaturehash" \
  -d "token=test"
```

**Expected:** HTTP `200`. Check Docker Compose logs for warning: `Slack request signature mismatch` followed by `Allowing request despite verification failure`.

#### Test 7: Missing Signature in Log-Only Mode (expect `200 OK`)

```bash
curl -v -X POST http://localhost:8081/log-only/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: $(date +%s)" \
  -d "token=test"
```

**Expected:** HTTP `200`. Check logs for: `Missing X-Slack-Signature header` followed by `Allowing request despite verification failure`.

#### Test 8: Expired Timestamp in Log-Only Mode (expect `200 OK`)

```bash
SIGNING_SECRET="8f742231b10e8888abcd99yyyzzz85a5"
BODY="token=test"
OLD_TIMESTAMP=$(($(date +%s) - 600))

BASESTRING="v0:${OLD_TIMESTAMP}:${BODY}"
SIGNATURE="v0=$(echo -n "$BASESTRING" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" | awk '{print $2}')"

curl -v -X POST http://localhost:8081/log-only/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: ${OLD_TIMESTAMP}" \
  -H "X-Slack-Signature: ${SIGNATURE}" \
  -d "${BODY}"
```

**Expected:** HTTP `200`. Check logs for: `Request timestamp too old` followed by `Allowing request despite verification failure`.

### 5.3 Short Tolerance (/short-tolerance/)

With `timestampToleranceSeconds=60`, requests older than 60 seconds are rejected.

#### Test 9: Within Short Tolerance (expect `200 OK`)

Use a timestamp 30 seconds old (within the 60s window):

```bash
SIGNING_SECRET="8f742231b10e8888abcd99yyyzzz85a5"
BODY="token=test"
TIMESTAMP=$(($(date +%s) - 30))

BASESTRING="v0:${TIMESTAMP}:${BODY}"
SIGNATURE="v0=$(echo -n "$BASESTRING" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" | awk '{print $2}')"

curl -v -X POST http://localhost:8081/short-tolerance/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: ${TIMESTAMP}" \
  -H "X-Slack-Signature: ${SIGNATURE}" \
  -d "${BODY}"
```

**Expected:** HTTP `200`.

#### Test 10: Beyond Short Tolerance (expect `401 Unauthorized`)

Use a timestamp 90 seconds old (beyond the 60s window):

```bash
SIGNING_SECRET="8f742231b10e8888abcd99yyyzzz85a5"
BODY="token=test"
OLD_TIMESTAMP=$(($(date +%s) - 90))

BASESTRING="v0:${OLD_TIMESTAMP}:${BODY}"
SIGNATURE="v0=$(echo -n "$BASESTRING" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" | awk '{print $2}')"

curl -v -X POST http://localhost:8081/short-tolerance/anything/echo/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Slack-Request-Timestamp: ${OLD_TIMESTAMP}" \
  -H "X-Slack-Signature: ${SIGNATURE}" \
  -d "${BODY}"
```

**Expected:** HTTP `401`. The 90-second age exceeds the 60-second tolerance.

## Step 6 - Verify Log Output

In the Docker Compose terminal output, look for these log messages to confirm policy behavior:

| Log message                                              | Meaning                                  |
|----------------------------------------------------------|------------------------------------------|
| `Slack request signature verified successfully`           | Valid request passed through             |
| `Slack request signature mismatch`                        | Invalid signature detected               |
| `Request timestamp too old`                               | Replay attack blocked                    |
| `Missing X-Slack-Signature header`                        | Signature header absent                  |
| `Missing X-Slack-Request-Timestamp header`                | Timestamp header absent                  |
| `Allowing request despite verification failure`           | Log-only mode allowed an invalid request |

## Step 7 - Stop the Playground

Press `Ctrl+C` in the Docker Compose terminal, or run:

```bash
docker compose -f ./playground/docker-compose.yaml down
```

## Customizing the Configuration

Edit `playground/config/api.yaml` or `playground/config/api-test-scenarios.yaml` to change policy parameters:

- **`signingSecret`** - Replace with your own Slack app signing secret (found in **Slack App > Basic Information > Signing Secret**).
- **`rejectOnFailure`** - Set to `false` to log warnings instead of rejecting invalid requests (useful for initial rollout).
- **`timestampToleranceSeconds`** - Adjust the replay-protection window (1-600 seconds).

After editing, restart the playground with `make run`.
