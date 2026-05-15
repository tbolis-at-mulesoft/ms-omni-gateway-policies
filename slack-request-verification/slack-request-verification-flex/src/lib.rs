// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Slack Request Verification Policy for Flex Gateway
//!
//! Validates incoming Slack requests by verifying HMAC-SHA256 signatures
//! using the app's signing secret. Implements the verification algorithm
//! described at https://docs.slack.dev/authentication/verifying-requests-from-slack/
//!
//! Verification steps:
//! 1. Extract X-Slack-Request-Timestamp header
//! 2. Check timestamp is within tolerance (replay attack protection)
//! 3. Build basestring: v0:{timestamp}:{raw_request_body}
//! 4. Compute HMAC-SHA256 using the signing secret
//! 5. Compare v0={hex_digest} with X-Slack-Signature header

mod generated;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;

use crate::generated::config::Config;

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_TIMESTAMP_TOLERANCE_SECONDS: i64 = 300;
const SLACK_SIGNATURE_VERSION: &str = "v0";

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    policy_violations: PolicyViolations,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    let reject_on_failure = config.reject_on_failure.unwrap_or(true);
    let tolerance = config
        .timestamp_tolerance_seconds
        .unwrap_or(DEFAULT_TIMESTAMP_TOLERANCE_SECONDS);

    logger::info!(
        "Slack request verification policy initialized (reject_on_failure={}, timestamp_tolerance={}s)",
        reject_on_failure,
        tolerance
    );

    let filter = on_request(|rs| request_filter(rs, &config, &policy_violations));
    launcher.launch(filter).await?;
    Ok(())
}

async fn request_filter(
    request_state: RequestState,
    config: &Config,
    policy_violations: &PolicyViolations,
) -> Flow<()> {
    let reject_on_failure = config.reject_on_failure.unwrap_or(true);
    let tolerance = config
        .timestamp_tolerance_seconds
        .unwrap_or(DEFAULT_TIMESTAMP_TOLERANCE_SECONDS);

    let headers_state = request_state.into_headers_state().await;
    let handler = headers_state.handler();

    // Extract X-Slack-Request-Timestamp header
    let timestamp_str = match handler.header("x-slack-request-timestamp") {
        Some(ts) => ts,
        None => {
            logger::warn!("Missing X-Slack-Request-Timestamp header");
            return handle_failure(policy_violations, reject_on_failure, "Missing X-Slack-Request-Timestamp header");
        }
    };

    // Parse timestamp
    let timestamp: i64 = match timestamp_str.parse() {
        Ok(ts) => ts,
        Err(_) => {
            logger::warn!("Invalid X-Slack-Request-Timestamp value: {}", timestamp_str);
            return handle_failure(
                policy_violations,
                reject_on_failure,
                "Invalid X-Slack-Request-Timestamp header",
            );
        }
    };

    // Check timestamp age for replay attack protection
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let age = (now - timestamp).abs();
    if age > tolerance {
        logger::warn!(
            "Request timestamp too old: age={}s, tolerance={}s",
            age,
            tolerance
        );
        return handle_failure(policy_violations, reject_on_failure, "Request timestamp expired");
    }

    // Extract X-Slack-Signature header
    let slack_signature = match handler.header("x-slack-signature") {
        Some(sig) => sig,
        None => {
            logger::warn!("Missing X-Slack-Signature header");
            return handle_failure(policy_violations, reject_on_failure, "Missing X-Slack-Signature header");
        }
    };

    // Read request body
    let body_state = headers_state.into_body_state().await;
    let body = body_state.handler().body();
    let body_str = String::from_utf8_lossy(&body);

    // Build basestring: v0:{timestamp}:{body}
    let basestring = format!("{}:{}:{}", SLACK_SIGNATURE_VERSION, timestamp_str, body_str);

    // Compute HMAC-SHA256
    let mut mac = match HmacSha256::new_from_slice(config.signing_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            logger::error!("Failed to initialize HMAC with signing secret");
            return handle_failure(policy_violations, reject_on_failure, "Internal signature verification error");
        }
    };
    mac.update(basestring.as_bytes());
    let result = mac.finalize();
    let computed_hex = hex::encode(result.into_bytes());
    let computed_signature = format!("{}={}", SLACK_SIGNATURE_VERSION, computed_hex);

    // Constant-time comparison
    if computed_signature
        .as_bytes()
        .ct_eq(slack_signature.as_bytes())
        .into()
    {
        logger::debug!("Slack request signature verified successfully");
        Flow::Continue(())
    } else {
        logger::warn!("Slack request signature mismatch");
        handle_failure(policy_violations, reject_on_failure, "Invalid Slack request signature")
    }
}

fn handle_failure(
    policy_violations: &PolicyViolations,
    reject: bool,
    message: &str,
) -> Flow<()> {
    if reject {
        policy_violations.generate_policy_violation();
        Flow::Break(
            Response::new(401)
                .with_headers(vec![(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )])
                .with_body(
                    serde_json::json!({
                        "error": "unauthorized",
                        "message": message
                    })
                    .to_string()
                    .into_bytes(),
                ),
        )
    } else {
        logger::warn!("Allowing request despite verification failure: {}", message);
        Flow::Continue(())
    }
}
