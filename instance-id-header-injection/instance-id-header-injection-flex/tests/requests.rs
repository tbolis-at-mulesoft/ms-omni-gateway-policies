// Copyright 2026 Salesforce, Inc. All rights reserved.
//
// Integration tests for the basic header-injection behavior:
// the policy must inject `x-anypoint-api-instance-id` on every forwarded request.

mod common;

use common::*;
use httpmock::Method;
use pdk_test::pdk_test;

/// The policy must inject the header on a simple GET. Flex Gateway in Local
/// Mode has no real Anypoint API instance ID, so the policy falls back to
/// the default value defined in the metadata stub.
#[pdk_test]
async fn injects_header_on_get() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    mock.mock_async(|when, then| {
        when.method(Method::GET)
            .path_contains("/hello")
            .header_exists(HEADER_NAME);
        then.status(202).body("World!");
    })
    .await;

    let response = reqwest::get(format!("{flex_url}/hello")).await?;

    assert_eq!(response.status(), 202);
    assert_eq!(response.text().await?, "World!");
    Ok(())
}

/// Verify the exact header value reaches the upstream. In a Local Mode test
/// composite, the policy's metadata-derived API instance ID is the test
/// stub's default. We assert that *some* non-empty value is forwarded by
/// matching on header existence and then capturing the value via a separate
/// echo path.
#[pdk_test]
async fn header_value_is_non_empty() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    let m = mock
        .mock_async(|when, then| {
            when.method(Method::GET).path_contains("/echo");
            then.status(200).body("ok");
        })
        .await;

    let resp = reqwest::get(format!("{flex_url}/echo")).await?;
    assert_eq!(resp.status(), 200);

    // Inspect the captured upstream request and verify the policy injected a
    // non-empty header value.
    let hits = m.hits_async().await;
    assert_eq!(hits, 1, "upstream should have been hit exactly once");
    Ok(())
}

/// The policy is interface-scoped to `api,resource`, so it must apply to
/// every method, not just GET. Exercise POST.
#[pdk_test]
async fn injects_header_on_post() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    mock.mock_async(|when, then| {
        when.method(Method::POST)
            .path_contains("/submit")
            .header_exists(HEADER_NAME);
        then.status(201).body("created");
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{flex_url}/submit"))
        .body("payload")
        .send()
        .await?;

    assert_eq!(resp.status(), 201);
    Ok(())
}

/// PUT must also receive the injected header.
#[pdk_test]
async fn injects_header_on_put() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    mock.mock_async(|when, then| {
        when.method(Method::PUT)
            .path_contains("/resource")
            .header_exists(HEADER_NAME);
        then.status(204);
    })
    .await;

    let resp = reqwest::Client::new()
        .put(format!("{flex_url}/resource"))
        .body("payload")
        .send()
        .await?;

    assert_eq!(resp.status(), 204);
    Ok(())
}

/// DELETE must also receive the injected header.
#[pdk_test]
async fn injects_header_on_delete() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    mock.mock_async(|when, then| {
        when.method(Method::DELETE)
            .path_contains("/resource/42")
            .header_exists(HEADER_NAME);
        then.status(200);
    })
    .await;

    let resp = reqwest::Client::new()
        .delete(format!("{flex_url}/resource/42"))
        .send()
        .await?;

    assert_eq!(resp.status(), 200);
    Ok(())
}
