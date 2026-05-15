// Copyright 2026 Salesforce, Inc. All rights reserved.

mod common;

use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};

use common::*;

const FLEX_PORT: Port = 8081;
const TEST_SIGNING_SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";

fn build_policy_config(reject_on_failure: bool) -> PolicyConfig {
    PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(serde_json::json!({
            "signingSecret": TEST_SIGNING_SECRET,
            "rejectOnFailure": reject_on_failure,
            "timestampToleranceSeconds": 300
        }))
        .build()
}

async fn setup_test(
    reject_on_failure: bool,
) -> anyhow::Result<(TestComposite, String, MockServer)> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let policy_config = build_policy_config(reject_on_failure);

    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(FLEX_PORT)
        .policies([policy_config])
        .build();

    let flex_config = FlexConfig::builder()
        .version("1.12.1")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();

    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let flex_url = flex.external_url(FLEX_PORT).unwrap();

    let httpmock: HttpMock = composite.service()?;
    let mock_server = MockServer::connect_async(httpmock.socket()).await;

    Ok((composite, flex_url, mock_server))
}

fn compute_signature(secret: &str, timestamp: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let basestring = format!("v0:{}:{}", timestamp, body);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(basestring.as_bytes());
    let result = mac.finalize();
    format!("v0={}", hex::encode(result.into_bytes()))
}

fn current_timestamp() -> String {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

#[pdk_test]
async fn valid_signature_passes() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = setup_test(true).await?;

    mock_server
        .mock_async(|when, then| {
            when.path_contains("/hello");
            then.status(200).body("OK");
        })
        .await;

    let body = "token=test&text=hello";
    let timestamp = current_timestamp();
    let signature = compute_signature(TEST_SIGNING_SECRET, &timestamp, body);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/hello"))
        .header("x-slack-request-timestamp", &timestamp)
        .header("x-slack-signature", &signature)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    Ok(())
}

#[pdk_test]
async fn missing_signature_rejected() -> anyhow::Result<()> {
    let (_composite, flex_url, _mock_server) = setup_test(true).await?;

    let timestamp = current_timestamp();

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/hello"))
        .header("x-slack-request-timestamp", &timestamp)
        .body("token=test")
        .send()
        .await?;

    assert_eq!(response.status(), 401);
    Ok(())
}

#[pdk_test]
async fn invalid_signature_rejected() -> anyhow::Result<()> {
    let (_composite, flex_url, _mock_server) = setup_test(true).await?;

    let timestamp = current_timestamp();

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/hello"))
        .header("x-slack-request-timestamp", &timestamp)
        .header("x-slack-signature", "v0=invalid_signature_hash")
        .body("token=test")
        .send()
        .await?;

    assert_eq!(response.status(), 401);
    Ok(())
}

#[pdk_test]
async fn missing_timestamp_rejected() -> anyhow::Result<()> {
    let (_composite, flex_url, _mock_server) = setup_test(true).await?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/hello"))
        .header("x-slack-signature", "v0=somesig")
        .body("token=test")
        .send()
        .await?;

    assert_eq!(response.status(), 401);
    Ok(())
}

#[pdk_test]
async fn expired_timestamp_rejected() -> anyhow::Result<()> {
    let (_composite, flex_url, _mock_server) = setup_test(true).await?;

    // Timestamp from 10 minutes ago (exceeds 300s tolerance)
    let old_timestamp = (std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 600)
        .to_string();

    let body = "token=test";
    let signature = compute_signature(TEST_SIGNING_SECRET, &old_timestamp, body);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/hello"))
        .header("x-slack-request-timestamp", &old_timestamp)
        .header("x-slack-signature", &signature)
        .body(body)
        .send()
        .await?;

    assert_eq!(response.status(), 401);
    Ok(())
}

#[pdk_test]
async fn log_only_mode_allows_invalid_signature() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = setup_test(false).await?;

    mock_server
        .mock_async(|when, then| {
            when.path_contains("/hello");
            then.status(200).body("OK");
        })
        .await;

    let timestamp = current_timestamp();

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/hello"))
        .header("x-slack-request-timestamp", &timestamp)
        .header("x-slack-signature", "v0=invalid_signature")
        .body("token=test")
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    Ok(())
}
