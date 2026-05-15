# Slack Request Verification Policy

A custom Omni Gateway policy that validates incoming Slack requests by verifying their HMAC-SHA256 signatures using the Slack app's signing secret. It implements the [Slack request verification](https://docs.slack.dev/authentication/verifying-requests-from-slack/) algorithm.

## How It Works

For each incoming request the policy:

1. Extracts the `X-Slack-Request-Timestamp` header
2. Checks the timestamp is within the configured tolerance window (replay attack protection)
3. Builds the basestring: `v0:{timestamp}:{raw_request_body}`
4. Computes HMAC-SHA256 using the configured signing secret
5. Performs a constant-time comparison against the `X-Slack-Signature` header

Valid requests are forwarded to the upstream service. Invalid requests are either rejected with `401 Unauthorized` or logged and allowed through, depending on configuration.

## Configuration Parameters

| Parameter                   | Type      | Required | Default | Description                                                                 |
|-----------------------------|-----------|----------|---------|-----------------------------------------------------------------------------|
| `signingSecret`             | `string`  | Yes      | -       | Slack app signing secret (sensitive, masked in UI)                          |
| `rejectOnFailure`           | `boolean` | No       | `true`  | If `true`, reject invalid requests (401). If `false`, log and allow through |
| `timestampToleranceSeconds` | `integer` | No       | `300`   | Max allowed age of request timestamp in seconds (1-600)                     |

## Local Testing

See [docs/LOCAL_TESTING_GUIDE.md](docs/LOCAL_TESTING_GUIDE.md) for a step-by-step guide with curl test cases covering strict mode, log-only mode, and configurable timestamp tolerance.

## Applying the Policy

See [docs/APPLYING_POLICY.md](docs/APPLYING_POLICY.md) for example `policyRef` snippets.
