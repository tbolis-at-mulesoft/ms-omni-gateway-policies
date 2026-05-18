// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test setup helpers: build a Flex+httpmock TestComposite with a configurable
//! policy config, plus convenience constructors for common policy
//! configurations and helpers to mock JSON-RPC backend responses.

use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::TestComposite;

use super::{COMMON_CONFIG_DIR, POLICY_DIR, POLICY_NAME};

pub const FLEX_PORT: Port = 8081;

/// Build a `PolicyConfig` from a JSON value containing the gcl.yaml-shaped
/// configuration. The caller fully controls the schema (predefinedEntities,
/// customEntities, errorCodeOnReject) so tests can exercise any combination.
pub fn build_policy_config(config: serde_json::Value) -> PolicyConfig {
    PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(config)
        .build()
}

/// Spin up a Flex Gateway with the given policy configuration plus an
/// httpmock acting as the upstream A2A backend. Returns the composite so
/// the caller can keep the containers alive, the public Flex URL to target,
/// and a connected `MockServer` for setting up mock expectations.
pub async fn setup_test(
    policy_config: serde_json::Value,
) -> anyhow::Result<(TestComposite, String, MockServer)> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let policy_config = build_policy_config(policy_config);

    let api_config = ApiConfig::builder()
        .name("a2aApi")
        .upstream(&httpmock_config)
        .path("/")
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

/// Mock the upstream backend to return a JSON-RPC 2.0 success response with
/// the given `result` value. Matches any path so the Flex's policy is the
/// only thing under test.
pub async fn mock_jsonrpc_success(mock_server: &MockServer, result: serde_json::Value) {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": result,
    })
    .to_string();
    mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(body);
        })
        .await;
}

/// Mock the upstream backend to return an SSE stream with one or more
/// JSON-RPC 2.0 events. Each event is encoded as `data: <json>` per the SSE
/// wire format.
pub async fn mock_sse_events(mock_server: &MockServer, events: Vec<serde_json::Value>) {
    let body = events
        .into_iter()
        .map(|e| format!("data: {}\n\n", e))
        .collect::<String>();
    mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST);
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(body);
        })
        .await;
}

/// Predefined-entity config helper. Each entry is `(type, actions, report_on_log)`.
pub fn predefined(entries: &[(&str, &[&str], bool)]) -> serde_json::Value {
    serde_json::Value::Array(
        entries
            .iter()
            .map(|(t, actions, rep)| {
                serde_json::json!({
                    "type": t,
                    "actions": actions.to_vec(),
                    "reportPolicyViolationOnLog": rep,
                })
            })
            .collect(),
    )
}

/// Custom-entity config helper. Each entry is `(name, regex, actions, report_on_log)`.
pub fn custom(entries: &[(&str, &str, &[&str], bool)]) -> serde_json::Value {
    serde_json::Value::Array(
        entries
            .iter()
            .map(|(n, r, actions, rep)| {
                serde_json::json!({
                    "name": n,
                    "regex": r,
                    "actions": actions.to_vec(),
                    "reportPolicyViolationOnLog": rep,
                })
            })
            .collect(),
    )
}
