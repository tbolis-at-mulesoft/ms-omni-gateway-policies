# Applying the Slack Request Verification Policy

This guide covers how to apply the Slack Request Verification policy to an API instance on Flex Gateway, both via the Anypoint Platform UI and using a local declarative configuration.

## Prerequisites

- The policy definition and implementation must be published to Exchange (see the main [README](../README.md) for build and publish instructions).
- A Flex Gateway instance (Connected or Local mode).
- Your Slack app's **Signing Secret**, found under your app's **Basic Information** page at [api.slack.com/apps](https://api.slack.com/apps).

## Option 1: Apply via Anypoint Platform UI (Connected Mode)

1. Navigate to **API Manager** in Anypoint Platform.
2. Select your API instance running on Flex Gateway.
3. Go to **Policies** > **Add policy**.
4. Search for **Slack Request Verification** under the **Security** category.
5. Configure the policy parameters:

| Parameter                   | Description                                                    | Recommended Value            |
|-----------------------------|----------------------------------------------------------------|------------------------------|
| **Signing Secret**          | Your Slack app's signing secret                                | *(from Slack app settings)*  |
| **Reject on Failure**       | Reject requests with invalid signatures (401)                  | `true`                       |
| **Timestamp Tolerance (s)** | Max age of request timestamp for replay protection (1–600)     | `300` (5 minutes)            |

6. Under **Method & resource conditions**, add the following rules:

| Methods | Resource           |
|---------|--------------------|
| POST    | `/api/events`      |
| POST    | `/api/interaction`  |

7. Click **Apply**.

The policy is now active and will verify all incoming requests against Slack's HMAC-SHA256 signature algorithm.

## Option 2: Apply via Declarative Configuration (Local Mode)

Add the policy to your API instance's declarative YAML configuration.

### Step 1: Ensure the policy is installed

If you published the policy to Exchange, Flex Gateway will download it automatically in Connected mode. For Local mode, install the policy binary manually:

```bash
cd slack-request-verification-flex
make build
anypoint-cli-v4 pdk install-policy \
  --target ./playground/config/custom-policies \
  --path target/slack_request_verification/implementation/
```

### Step 2: Add the policy to your API definition

Create or edit your API instance YAML file (e.g., `api.yaml`):

```yaml
---
apiVersion: gateway.mulesoft.com/v1alpha1
kind: ApiInstance
metadata:
  name: my-slack-api
spec:
  address: http://0.0.0.0:8081
  services:
    upstream:
      address: http://your-backend-service:port
      routes:
        - config:
            destinationPath: /
  policies:
    - policyRef:
        name: slack-request-verification-flex-v1-1
        namespace: default
      config:
        signingSecret: "<your-slack-signing-secret>"
        rejectOnFailure: true
        timestampToleranceSeconds: 300
```

**Key fields:**
- `policyRef.name` — The policy implementation reference name. Run `make show-policy-ref-name` in the `slack-request-verification-flex/` directory to get the exact value.
- `policyRef.namespace` — Use `default`.
- `config.signingSecret` — Your Slack app's signing secret (keep this secure; consider using a secrets manager or environment variable injection).

### Step 3: Deploy

Place the YAML file in your Flex Gateway's configuration directory and restart the gateway, or if using Docker:

```bash
docker compose up
```

## Configuration Scenarios

### Strict mode (default) — reject invalid requests

```yaml
config:
  signingSecret: "<your-signing-secret>"
  rejectOnFailure: true
  timestampToleranceSeconds: 300
```

Invalid requests receive a `401 Unauthorized` response:

```json
{
  "error": "unauthorized",
  "message": "Invalid Slack request signature"
}
```

### Log-only mode — allow all requests, log failures

```yaml
config:
  signingSecret: "<your-signing-secret>"
  rejectOnFailure: false
  timestampToleranceSeconds: 300
```

Useful for initial rollout or debugging. Failed verifications are logged as warnings but requests are forwarded to the upstream service.

### Tight timestamp tolerance — stricter replay protection

```yaml
config:
  signingSecret: "<your-signing-secret>"
  rejectOnFailure: true
  timestampToleranceSeconds: 30
```

Reduces the replay window to 30 seconds. Use only if your infrastructure has minimal clock drift.

## How Verification Works

When the policy receives a request, it:

1. Reads the `X-Slack-Request-Timestamp` header.
2. Checks the timestamp is within the configured tolerance window (rejects stale requests to prevent replay attacks).
3. Reads the raw request body.
4. Constructs the basestring: `v0:<timestamp>:<body>`.
5. Computes `HMAC-SHA256(signingSecret, basestring)`.
6. Compares `v0=<computed_hex>` against the `X-Slack-Signature` header using constant-time comparison.

For full details, see [Slack's verification documentation](https://docs.slack.dev/authentication/verifying-requests-from-slack/).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| All requests rejected with 401 | Wrong signing secret | Verify the secret matches your Slack app's **Signing Secret** (not the Bot Token or Client Secret) |
| Requests rejected with "timestamp expired" | Clock drift or slow network | Increase `timestampToleranceSeconds` or sync server clock with NTP |
| Policy not appearing in API Manager | Not published to Exchange | Run `make release` in both `definition/` and `flex/` directories |
| Signature mismatch on valid requests | Request body modified by another policy | Ensure this policy runs **first** in the policy chain (before any body-transforming policies) |
