// Copyright 2026 Salesforce, Inc. All rights reserved.
//
// Test setup helpers: build a Flex+httpmock TestComposite for the
// instance-id-header-injection policy.

use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::TestComposite;

use super::{COMMON_CONFIG_DIR, POLICY_DIR, POLICY_NAME};

pub const FLEX_PORT: Port = 8081;

/// Spin up a Flex Gateway with the policy applied plus an httpmock acting
/// as the upstream backend. Returns the composite (so the caller can keep
/// the containers alive), the public Flex URL to target, and a connected
/// `MockServer` for setting up mock expectations.
pub async fn setup_test() -> anyhow::Result<(TestComposite, String, MockServer)> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let policy_config = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(serde_json::json!({}))
        .build();

    let api_config = ApiConfig::builder()
        .name("instanceIdHeaderApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(FLEX_PORT)
        .policies([policy_config])
        .build();

    let flex_config = FlexConfig::builder()
        .version("1.12.1")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([
            (POLICY_DIR, "policy"),
            (COMMON_CONFIG_DIR, "common"),
        ])
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
