# Slack Request Verification Policy

Validates incoming Slack requests by verifying their HMAC-SHA256 signatures using your Slack app's signing secret. Implements the official [Slack request verification](https://docs.slack.dev/authentication/verifying-requests-from-slack/) algorithm.

## Overview

When applied to an API instance, this policy intercepts every incoming request and:

1. Extracts the `X-Slack-Request-Timestamp` and `X-Slack-Signature` headers.
2. Validates the timestamp is within the configured tolerance window to prevent replay attacks.
3. Computes `HMAC-SHA256` over `v0:<timestamp>:<request_body>` using your signing secret.
4. Performs a constant-time comparison of the computed signature against the provided `X-Slack-Signature`.

Verified requests are forwarded to the upstream service. Invalid requests are rejected with `401 Unauthorized` or optionally logged and allowed through.

## Configuration

| Parameter                   | Type      | Required | Default | Description                                                                   |
|-----------------------------|-----------|----------|---------|-------------------------------------------------------------------------------|
| **Signing Secret**          | `string`  | Yes      | —       | Your Slack app's signing secret (found under **Basic Information** in the Slack app settings) |
| **Reject on Failure**       | `boolean` | No       | `true`  | If `true`, reject requests with invalid signatures (`401`). If `false`, log a warning and allow through |
| **Timestamp Tolerance (s)** | `integer` | No       | `300`   | Maximum allowed age of request timestamp in seconds (`1`–`600`)               |

## Usage Scenarios

### Strict Mode (Recommended)

Reject all requests that fail signature verification. This is the default behavior.

```
Signing Secret:          <your-slack-signing-secret>
Reject on Failure:       true
Timestamp Tolerance (s): 300
```

Rejected requests receive:

```json
{
  "error": "unauthorized",
  "message": "Invalid Slack request signature"
}
```

### Log-Only Mode

Allow all requests through but log verification failures as warnings. Useful during initial rollout or debugging.

```
Signing Secret:          <your-slack-signing-secret>
Reject on Failure:       false
Timestamp Tolerance (s): 300
```

### Tight Replay Protection

Reduce the timestamp tolerance window for environments with minimal clock drift.

```
Signing Secret:          <your-slack-signing-secret>
Reject on Failure:       true
Timestamp Tolerance (s): 30
```

## Where to Find Your Signing Secret

1. Go to [api.slack.com/apps](https://api.slack.com/apps).
2. Select your Slack app.
3. Navigate to **Basic Information**.
4. Under **App Credentials**, copy the **Signing Secret**.

> **Important:** The signing secret is different from the Bot Token or Client Secret. Make sure you use the correct value.

## Policy Ordering

This policy reads the raw request body to compute the signature. If other policies in the chain modify the request body before this policy runs, verification will fail.

**Recommendation:** Place this policy **first** in the policy chain, before any body-transforming policies.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| All requests return `401` | Incorrect signing secret | Verify the secret matches your Slack app's **Signing Secret** |
| `Request timestamp expired` | Clock drift between Slack and your server | Increase **Timestamp Tolerance** or sync your server clock with NTP |
| Signature mismatch on valid Slack requests | Request body modified by upstream policy | Move this policy to the **first** position in the policy chain |
| Requests from non-Slack sources rejected | Missing Slack headers | This is expected — only Slack sends the required `X-Slack-Signature` and `X-Slack-Request-Timestamp` headers |
