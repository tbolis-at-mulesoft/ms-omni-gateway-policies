// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the A2A PII Guard policy.
//!
//! All integration tests live in this single binary — keeping them in one
//! compilation unit drastically shortens the test build time compared to the
//! one-binary-per-file default. Tests are grouped by concern under section
//! banners; each group used to live in its own `tests/<name>.rs`.

mod common;

use common::request_bodies::*;
use common::setup::*;
use pdk_test::pdk_test;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Reusable "Reject on Email" config — the cheapest way to trigger a reject.
fn reject_email_cfg() -> Value {
    json!({ "predefinedEntities": predefined(&[("Email", &["Reject"], true)]) })
}

/// POST a JSON-RPC body to the Flex URL and return the raw response.
async fn post_jsonrpc(flex_url: &str, body: Value) -> anyhow::Result<reqwest::Response> {
    Ok(reqwest::Client::new()
        .post(format!("{flex_url}/"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await?)
}

/// POST a JSON-RPC body and parse the response body as JSON.
async fn post_jsonrpc_body(flex_url: &str, body: Value) -> anyhow::Result<Value> {
    Ok(post_jsonrpc(flex_url, body).await?.json().await?)
}

// ---------------------------------------------------------------------------
// basic_detection — predefined PII detection on the request path
// ---------------------------------------------------------------------------

fn cfg_email_log_ssn_reject() -> Value {
    json!({
        "predefinedEntities": predefined(&[
            ("Email", &["Log"], true),
            ("US SSN", &["Reject"], true),
        ])
    })
}

#[pdk_test]
async fn email_with_log_action_passes_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(cfg_email_log_ssn_reject()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let resp = post_jsonrpc(&url, message_send("Contact me at user@example.com")).await?;
    assert_eq!(resp.status(), 200); // Log-only must not block.
    Ok(())
}

#[pdk_test]
async fn ssn_with_reject_action_blocks_with_jsonrpc_error() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(cfg_email_log_ssn_reject()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let resp = post_jsonrpc(&url, message_send("My SSN is 123-45-6789")).await?;
    assert_eq!(resp.status(), 200); // JSON-RPC: HTTP 200 + error in body.
    let body: Value = resp.json().await?;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["error"]["code"], -32023);
    assert!(body["error"]["message"].as_str().unwrap().contains("PII"));
    Ok(())
}

#[pdk_test]
async fn credit_card_reject_blocks_request() -> anyhow::Result<()> {
    let cfg = json!({ "predefinedEntities": predefined(&[("Credit Card", &["Reject"], true)]) });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_send("Card: 4111-1111-1111-1111")).await?;
    let data = body["error"]["data"].as_array().unwrap();
    assert_eq!(data[0]["pii_type"], "Credit Card");
    Ok(())
}

#[pdk_test]
async fn phone_number_log_passes_through() -> anyhow::Result<()> {
    let cfg = json!({ "predefinedEntities": predefined(&[("Phone Number", &["Log"], true)]) });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let resp = post_jsonrpc(&url, message_send("Call me at +1 (555) 123-4567")).await?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[pdk_test]
async fn clean_text_passes_when_predefined_configured() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(cfg_email_log_ssn_reject()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let resp = post_jsonrpc(&url, message_send("Hello world, no sensitive data here.")).await?;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await?;
    assert_eq!(body["result"]["ok"], true);
    Ok(())
}

// ---------------------------------------------------------------------------
// custom_patterns — custom regex naming, word-boundary, escape normalisation
// ---------------------------------------------------------------------------

#[pdk_test]
async fn custom_pattern_with_reject_blocks_request() -> anyhow::Result<()> {
    let cfg = json!({
        "customEntities": custom(&[
            ("Italian Car Plate", "[A-Z]{2}\\d{3}[A-Z]{2}", &["Reject"], true)
        ])
    });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_send("Plate AB123CD spotted")).await?;
    let data = body["error"]["data"].as_array().unwrap();
    assert_eq!(data[0]["pii_type"], "Italian Car Plate");
    assert_eq!(data[0]["value"], "AB123CD");
    Ok(())
}

#[pdk_test]
async fn custom_pattern_log_only_passes_through() -> anyhow::Result<()> {
    let cfg = json!({
        "customEntities": custom(&[
            ("Codice Fiscale", "[A-Z]{6}\\d{2}[A-Z]\\d{2}[A-Z]\\d{3}[A-Z]", &["Log"], false)
        ])
    });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let resp = post_jsonrpc(&url, message_send("CF: RSSMRA80A01H501U")).await?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[pdk_test]
async fn custom_pattern_word_boundary_avoids_partial_match() -> anyhow::Result<()> {
    let cfg = json!({
        "customEntities": custom(&[("Plate", "[A-Z]{2}\\d{3}[A-Z]{2}", &["Reject"], true)])
    });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    // Adjacent word chars break word boundaries — must not match.
    let resp = post_jsonrpc(&url, message_send("PrefixAB123CDsuffix not a plate")).await?;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await?;
    assert!(body["result"].is_object());
    Ok(())
}

#[pdk_test]
async fn predefined_and_custom_combined() -> anyhow::Result<()> {
    let cfg = json!({
        "predefinedEntities": predefined(&[("Email", &["Log"], true)]),
        "customEntities": custom(&[("Plate", "[A-Z]{2}\\d{3}[A-Z]{2}", &["Reject"], true)])
    });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    // Email -> Log; Plate -> Reject.
    let body =
        post_jsonrpc_body(&url, message_send("Email me at a@b.com about plate AB123CD")).await?;
    let data = body["error"]["data"].as_array().unwrap();
    assert!(data.iter().any(|d| d["pii_type"] == "Plate"));
    assert!(!data.iter().any(|d| d["pii_type"] == "Email"));
    Ok(())
}

// ---------------------------------------------------------------------------
// a2a_methods — every inspectable A2A method and task payload location
// ---------------------------------------------------------------------------

#[pdk_test]
async fn message_send_inspects_message_parts() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_send("Email a@b.com")).await?;
    assert!(body["error"].is_object());
    Ok(())
}

#[pdk_test]
async fn message_stream_inspects_message_parts() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_stream("Email a@b.com")).await?;
    assert!(body["error"].is_object());
    Ok(())
}

#[pdk_test]
async fn tasks_get_inspects_task_parts() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, tasks_get_with_parts("Email a@b.com")).await?;
    assert!(body["error"].is_object());
    Ok(())
}

#[pdk_test]
async fn tasks_get_inspects_task_description() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body =
        post_jsonrpc_body(&url, tasks_get_with_description("Contact a@b.com please")).await?;
    assert!(body["error"].is_object());
    Ok(())
}

#[pdk_test]
async fn tasks_stream_inspects_task_parts() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, tasks_stream_with_parts("Email a@b.com")).await?;
    assert!(body["error"].is_object());
    Ok(())
}

#[pdk_test]
async fn tasks_resubscribe_inspects_task_parts() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, tasks_resubscribe_with_parts("Email a@b.com")).await?;
    assert!(body["error"].is_object());
    Ok(())
}

#[pdk_test]
async fn legacy_part_type_field_is_inspected() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_send_legacy_type("Email a@b.com")).await?;
    assert!(body["error"].is_object());
    Ok(())
}

#[pdk_test]
async fn unrelated_method_is_passed_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    // tasks/cancel is not in the inspectable set; PII in params is ignored.
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/cancel",
        "params": { "id": "user a@b.com" }
    });
    let body = post_jsonrpc_body(&url, req).await?;
    assert!(body["result"].is_object());
    Ok(())
}

#[pdk_test]
async fn multiple_text_parts_first_match_wins() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(
        &url,
        message_send_multi(&["clean text", "Email a@b.com", "more clean"]),
    )
    .await?;
    assert!(body["error"].is_object());
    Ok(())
}

// ---------------------------------------------------------------------------
// passthrough — non-POST, non-JSON, malformed JSON, missing params, no config
// ---------------------------------------------------------------------------

#[pdk_test]
async fn get_request_passes_through_unmodified() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock.mock_async(|when, then| {
        when.method(httpmock::Method::GET);
        then.status(200).body("upstream-get");
    })
    .await;

    let resp = reqwest::get(format!("{url}/?a@b.com")).await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await?, "upstream-get");
    Ok(())
}

#[pdk_test]
async fn non_json_content_type_passes_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock.mock_async(|when, then| {
        when.method(httpmock::Method::POST);
        then.status(200).body("upstream-text");
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{url}/"))
        .header("content-type", "text/plain")
        .body("My email is a@b.com")
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await?, "upstream-text");
    Ok(())
}

#[pdk_test]
async fn malformed_json_passes_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let resp = reqwest::Client::new()
        .post(format!("{url}/"))
        .header("content-type", "application/json")
        .body("{not valid json a@b.com")
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[pdk_test]
async fn missing_params_passes_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send" });
    let body = post_jsonrpc_body(&url, req).await?;
    assert!(body["result"].is_object());
    Ok(())
}

#[pdk_test]
async fn no_pii_configured_means_full_passthrough() -> anyhow::Result<()> {
    // Empty config: no predefined + no custom entities -> nothing to match.
    let (_c, url, mock) = setup_test(json!({})).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body =
        post_jsonrpc_body(&url, message_send("Email me at a@b.com SSN 123-45-6789")).await?;
    assert_eq!(body["result"]["ok"], true);
    Ok(())
}

// ---------------------------------------------------------------------------
// reject_response — JSON-RPC error envelope shape on Reject
// ---------------------------------------------------------------------------

#[pdk_test]
async fn rejection_returns_http_200_with_jsonrpc_envelope() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;

    let resp = post_jsonrpc(&url, message_send("hi a@b.com")).await?;
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("application/json"));
    let body: Value = resp.json().await?;
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(body["error"].is_object());
    assert!(body["result"].is_null() || body.get("result").is_none());
    Ok(())
}

#[pdk_test]
async fn rejection_echoes_string_id() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(
        &url,
        message_send_with_id(json!("req-abc-123"), "Email a@b.com"),
    )
    .await?;
    assert_eq!(body["id"], "req-abc-123");
    Ok(())
}

#[pdk_test]
async fn rejection_echoes_integer_id() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body =
        post_jsonrpc_body(&url, message_send_with_id(json!(42), "Email a@b.com")).await?;
    assert_eq!(body["id"], 42);
    Ok(())
}

#[pdk_test]
async fn custom_error_code_is_used() -> anyhow::Result<()> {
    let cfg = json!({
        "predefinedEntities": predefined(&[("Email", &["Reject"], true)]),
        "errorCodeOnReject": -32069
    });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_send("Email a@b.com")).await?;
    assert_eq!(body["error"]["code"], -32069);
    Ok(())
}

#[pdk_test]
async fn default_error_code_is_minus_32023() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_send("Email a@b.com")).await?;
    assert_eq!(body["error"]["code"], -32023);
    Ok(())
}

#[pdk_test]
async fn rejection_data_lists_matched_entities() -> anyhow::Result<()> {
    let cfg = json!({
        "predefinedEntities": predefined(&[
            ("Email", &["Reject"], true),
            ("US SSN", &["Reject"], true),
        ])
    });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_send("Email a@b.com SSN 123-45-6789")).await?;
    let data = body["error"]["data"].as_array().unwrap();
    let names: Vec<&str> = data.iter().map(|d| d["pii_type"].as_str().unwrap()).collect();
    assert!(names.contains(&"Email"));
    assert!(names.contains(&"US SSN"));
    Ok(())
}

// ---------------------------------------------------------------------------
// response_scanning — response path **never blocks**; SSE + JSON locations
// ---------------------------------------------------------------------------

fn cfg_email_log() -> Value {
    json!({ "predefinedEntities": predefined(&[("Email", &["Log"], true)]) })
}

/// Stub the upstream to return the given JSON body with `application/json`.
async fn mock_json_response(mock: &httpmock::MockServer, body: Value) {
    let body = body.to_string();
    mock.mock_async(|when, then| {
        when.method(httpmock::Method::POST);
        then.status(200)
            .header("content-type", "application/json")
            .body(body);
    })
    .await;
}

#[pdk_test]
async fn response_with_pii_in_message_parts_passes_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(cfg_email_log()).await?;
    mock_json_response(&mock, response_with_message_parts("Reply: contact a@b.com")).await;

    let resp = post_jsonrpc(&url, message_send("clean text")).await?;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await?;
    assert_eq!(
        body["result"]["status"]["message"]["parts"][0]["text"],
        "Reply: contact a@b.com"
    );
    Ok(())
}

#[pdk_test]
async fn response_with_pii_in_artifact_parts_passes_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(cfg_email_log()).await?;
    mock_json_response(&mock, response_with_artifact_parts("Artifact mentions a@b.com")).await;
    let body = post_jsonrpc_body(&url, message_send("clean")).await?;
    assert_eq!(
        body["result"]["artifact"]["parts"][0]["text"],
        "Artifact mentions a@b.com"
    );
    Ok(())
}

#[pdk_test]
async fn response_with_pii_in_task_description_passes_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(cfg_email_log()).await?;
    mock_json_response(
        &mock,
        response_with_task_description("Description with a@b.com inside"),
    )
    .await;
    let body = post_jsonrpc_body(&url, message_send("clean")).await?;
    assert!(body["result"]["task"]["description"]
        .as_str()
        .unwrap()
        .contains("a@b.com"));
    Ok(())
}

#[pdk_test]
async fn sse_response_with_pii_streams_through() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(cfg_email_log()).await?;
    let evt = response_with_message_parts("SSE chunk: a@b.com");
    mock_sse_events(&mock, vec![evt.clone(), evt]).await;

    let resp = post_jsonrpc(&url, message_stream("clean")).await?;
    assert_eq!(resp.status(), 200);
    // Raw SSE stream — PII is logged but not removed.
    assert!(resp.text().await?.contains("a@b.com"));
    Ok(())
}

#[pdk_test]
async fn response_path_does_not_block_even_with_reject_configured() -> anyhow::Result<()> {
    // Reject is request-side only; the response path only logs.
    let (_c, url, mock) = setup_test(reject_email_cfg()).await?;
    mock_json_response(&mock, response_with_message_parts("Reply: contact a@b.com")).await;
    let body = post_jsonrpc_body(&url, message_send("clean")).await?;
    assert!(body["result"].is_object());
    Ok(())
}

#[pdk_test]
async fn non_json_non_sse_response_is_untouched() -> anyhow::Result<()> {
    let (_c, url, mock) = setup_test(cfg_email_log()).await?;
    mock.mock_async(|when, then| {
        when.method(httpmock::Method::POST);
        then.status(200)
            .header("content-type", "text/plain")
            .body("Plaintext mentioning a@b.com");
    })
    .await;

    let resp = post_jsonrpc(&url, message_send("clean")).await?;
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await?.contains("a@b.com"));
    Ok(())
}

// ---------------------------------------------------------------------------
// violation_reporting — per-entity reportPolicyViolationOnLog semantics
// ---------------------------------------------------------------------------

#[pdk_test]
async fn log_with_report_on_log_true_does_not_block() -> anyhow::Result<()> {
    let cfg = json!({ "predefinedEntities": predefined(&[("Email", &["Log"], true)]) });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let resp = post_jsonrpc(&url, message_send("Email a@b.com")).await?;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await?;
    assert!(body["result"].is_object());
    Ok(())
}

#[pdk_test]
async fn log_with_report_on_log_false_does_not_block() -> anyhow::Result<()> {
    let cfg = json!({ "predefinedEntities": predefined(&[("Email", &["Log"], false)]) });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let resp = post_jsonrpc(&url, message_send("Email a@b.com")).await?;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await?;
    assert!(body["result"].is_object());
    Ok(())
}

#[pdk_test]
async fn reject_action_always_blocks_regardless_of_flag() -> anyhow::Result<()> {
    let cfg = json!({ "predefinedEntities": predefined(&[("Email", &["Reject"], false)]) });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    let body = post_jsonrpc_body(&url, message_send("Email a@b.com")).await?;
    assert!(body["error"].is_object());
    Ok(())
}

#[pdk_test]
async fn unmatched_entity_in_text_does_not_block() -> anyhow::Result<()> {
    let cfg = json!({ "predefinedEntities": predefined(&[("US SSN", &["Reject"], true)]) });
    let (_c, url, mock) = setup_test(cfg).await?;
    mock_jsonrpc_success(&mock, json!({"ok": true})).await;
    // Email is in the text but not in the configured entities — must pass.
    let body = post_jsonrpc_body(&url, message_send("Just an email a@b.com here")).await?;
    assert!(body["result"].is_object());
    Ok(())
}
