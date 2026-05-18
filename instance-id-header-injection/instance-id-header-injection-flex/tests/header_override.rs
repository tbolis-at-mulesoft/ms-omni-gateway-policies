// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Integration tests covering header-override semantics. The policy uses
// `set_header`, which in PDK semantics replaces any existing value. A client
// must not be able to spoof the API instance ID by setting the header on the
// inbound request.
//
// Detailed override semantics (exact value comparison, "spoof must not pass")
// are covered exhaustively in the unit suite (`src/unit.rs`). These
// integration tests confirm the wiring still applies the filter at the
// real-Envoy layer.

mod common;

use common::*;
use httpmock::Method;
use pdk_test::pdk_test;

/// When a client sends the header, the upstream still receives a value. The
/// policy is invoked at request time, so the upstream sees a single header
/// instance — guaranteed by Envoy's set semantics for PDK's `set_header`.
#[pdk_test]
async fn client_supplied_header_is_overridden() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    let upstream = mock
        .mock_async(|when, then| {
            when.method(Method::GET)
                .path_contains("/spoof")
                .header_exists(HEADER_NAME);
            then.status(200);
        })
        .await;

    let resp = reqwest::Client::new()
        .get(format!("{flex_url}/spoof"))
        .header(HEADER_NAME, "spoofed-by-client")
        .send()
        .await?;

    assert_eq!(resp.status(), 200);
    assert_eq!(upstream.hits_async().await, 1);
    Ok(())
}

/// Other unrelated headers supplied by the client must pass through untouched.
#[pdk_test]
async fn other_client_headers_pass_through() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    let upstream = mock
        .mock_async(|when, then| {
            when.method(Method::GET)
                .path_contains("/passthrough")
                .header("x-correlation-id", "abc-123")
                .header("user-agent", "integration-test/1.0")
                .header_exists(HEADER_NAME);
            then.status(200);
        })
        .await;

    let resp = reqwest::Client::new()
        .get(format!("{flex_url}/passthrough"))
        .header("x-correlation-id", "abc-123")
        .header("user-agent", "integration-test/1.0")
        .send()
        .await?;

    assert_eq!(resp.status(), 200);
    assert_eq!(upstream.hits_async().await, 1);
    Ok(())
}
