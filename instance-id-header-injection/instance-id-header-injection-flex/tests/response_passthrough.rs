// Copyright 2026 Salesforce, Inc. All rights reserved.
//
// The policy registers only an `on_request` filter. Responses must pass
// through unmodified — including status codes, bodies, and any headers the
// upstream sets.

mod common;

use common::*;
use httpmock::Method;
use pdk_test::pdk_test;

#[pdk_test]
async fn upstream_status_passes_through() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    mock.mock_async(|when, then| {
        when.method(Method::GET).path_contains("/teapot");
        then.status(418).body("I'm a teapot");
    })
    .await;

    let resp = reqwest::get(format!("{flex_url}/teapot")).await?;
    assert_eq!(resp.status(), 418);
    assert_eq!(resp.text().await?, "I'm a teapot");
    Ok(())
}

#[pdk_test]
async fn upstream_5xx_passes_through() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    mock.mock_async(|when, then| {
        when.method(Method::GET).path_contains("/oops");
        then.status(503).body("upstream down");
    })
    .await;

    let resp = reqwest::get(format!("{flex_url}/oops")).await?;
    assert_eq!(resp.status(), 503);
    Ok(())
}

#[pdk_test]
async fn upstream_response_headers_pass_through() -> anyhow::Result<()> {
    let (_c, flex_url, mock) = setup::setup_test().await?;

    mock.mock_async(|when, then| {
        when.method(Method::GET).path_contains("/headers");
        then.status(200)
            .header("x-upstream-marker", "set-by-upstream")
            .header("content-type", "application/json")
            .body(r#"{"ok":true}"#);
    })
    .await;

    let resp = reqwest::get(format!("{flex_url}/headers")).await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-upstream-marker")
            .and_then(|v| v.to_str().ok()),
        Some("set-by-upstream"),
    );
    assert_eq!(resp.text().await?, r#"{"ok":true}"#);
    Ok(())
}
