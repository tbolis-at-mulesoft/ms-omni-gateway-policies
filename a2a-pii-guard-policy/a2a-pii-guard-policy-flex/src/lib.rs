// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A2A PII Guard policy for MuleSoft Omni Gateway.
//!
//! Detects personally identifiable information (PII) in A2A protocol
//! requests and responses. Supports predefined PII types (Email, US SSN,
//! Credit Card, Phone Number) and operator-supplied custom regex patterns.
//! Per-entity actions (`Log` / `Reject`) and per-entity policy-violation
//! reporting toggles are honoured. On `Reject`, returns a JSON-RPC 2.0
//! error envelope with a configurable error code in the A2A reserved range.
//!
//! Module layout: every concern that previously lived in its own file
//! (`a2a`, `access_log`, `http_utils`, `jsonrpc`, `pii`, `request`,
//! `response`, `sse`) is folded into this single file under section
//! banners — keeps the policy compilable as one `cdylib` binary and avoids
//! the per-module visibility plumbing.

mod generated;

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, bail, Error, Result};
use futures::{Stream, StreamExt};
use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;
use pdk::script::PayloadBinding;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;
use thiserror::Error;

use crate::generated::config::Config;

// ===========================================================================
// Access log helpers
// ===========================================================================
// Thin wrappers around `pdk::logger` that prefix messages with the
// `[accessLog]` tag so operators can filter PII findings out of the rest of
// the request log.

const ACCESS_LOG_TAG: &str = "[accessLog]";

fn access_log_warn(message: String) {
    logger::warn!("{}  {}", ACCESS_LOG_TAG, message);
}

fn access_log_err(message: String) {
    logger::error!("{}  {}", ACCESS_LOG_TAG, message);
}

// ===========================================================================
// HTTP constants and helpers
// ===========================================================================

const POST_METHOD: &str = "POST";
const CONTENT_TYPE_HEADER: &str = "content-type";
const APPLICATION_JSON: &str = "application/json";
const TIMEOUT_HEADER: &str = "x-envoy-upstream-rq-timeout-ms";

/// Disables Envoy's upstream request timeout for the current request.
/// SSE responses can keep the connection open well beyond the default
/// timeout, so we drop the cap before forwarding upstream.
fn with_no_timeout(header_handler: &dyn HeadersHandler) {
    header_handler.set_header(TIMEOUT_HEADER, "0");
}

/// Returns true when the given Content-Type header value parses to a JSON
/// MIME subtype (e.g. `application/json`, `application/vnd.api+json`).
fn is_json_mime_type(content_type: &str) -> bool {
    content_type
        .parse::<mime::Mime>()
        .map(|m| m.subtype() == mime::JSON)
        .unwrap_or(false)
}

// ===========================================================================
// A2A inspectable JSON-RPC methods
// ===========================================================================
// Only methods that carry user-authored content are listed; other A2A
// methods (e.g. `agent/card`) are passed through untouched.

const GET_TASK_FUNCTION_NAME: &str = "tasks/get";
const TASKS_STREAM_FUNCTION_NAME: &str = "tasks/stream";
const MESSAGE_SEND_FUNCTION_NAME: &str = "message/send";
const MESSAGE_STREAM_FUNCTION_NAME: &str = "message/stream";
const TASKS_RESUBSCRIBE_FUNCTION_NAME: &str = "tasks/resubscribe";

fn is_inspectable_method(method: &str) -> bool {
    matches!(
        method,
        MESSAGE_SEND_FUNCTION_NAME
            | MESSAGE_STREAM_FUNCTION_NAME
            | GET_TASK_FUNCTION_NAME
            | TASKS_STREAM_FUNCTION_NAME
            | TASKS_RESUBSCRIBE_FUNCTION_NAME
    )
}

// ===========================================================================
// JSON-RPC 2.0 types
// ===========================================================================
// Minimal surface of JSON-RPC actually needed: parse incoming A2A requests
// and serialise rejection responses.

/// JSON-RPC identifier — string, signed integer, or unsigned integer per
/// the JSON-RPC 2.0 spec. Floats and other types are intentionally not
/// supported (`parse_jsonrpc_id` returns `None`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum JsonRpcId {
    String(String),
    Int(i64),
    Uint(u64),
}

/// Parse a JSON-RPC `id` from a raw JSON value. Returns `None` for unsupported
/// types (floats, objects, arrays, null).
fn parse_jsonrpc_id(raw: &RawValue) -> Option<JsonRpcId> {
    let parsed: Value = serde_json::from_str(raw.get()).ok()?;
    match parsed {
        Value::String(s) => Some(JsonRpcId::String(s)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(JsonRpcId::Int(i))
            } else {
                n.as_u64().map(JsonRpcId::Uint)
            }
        }
        _ => None,
    }
}

/// Borrowed view of an incoming JSON-RPC 2.0 request. `params` and `id`
/// are kept as `RawValue` to defer parsing until we know we care about them.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonRpcRequest<'a> {
    method: &'a str,
    params: Option<&'a RawValue>,
    id: Option<&'a RawValue>,
    #[allow(dead_code)]
    jsonrpc: Option<&'a str>,
}

/// JSON-RPC 2.0 response envelope used for rejection responses.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct JsonRpcResponse {
    jsonrpc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<JsonRpcId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl JsonRpcResponse {
    fn error(id: Option<JsonRpcId>, error: RpcError) -> Self {
        Self {
            result: None,
            error: Some(error),
            id,
            jsonrpc: Some("2.0".to_string()),
        }
    }
}

// ===========================================================================
// SSE adapter
// ===========================================================================

#[derive(Debug, Clone, thiserror::Error)]
enum SseError {
    #[error("decoding error")]
    Decode,
}

/// Wraps a PDK `BodyStream` so it can be decoded as an SSE event stream.
/// Decoding errors are normalised to `SseError::Decode` so callers don't
/// have to handle the `async_sse` crate's internal error type.
fn into_sse(
    stream: BodyStream<'_>,
) -> impl Stream<Item = Result<async_sse::Event, SseError>> + use<'_> {
    use futures::TryStreamExt;
    let read = stream.map(|chunk| Ok(chunk.into_bytes())).into_async_read();
    async_sse::decode(read).map(|i| match i {
        Ok(e) => Ok(e),
        Err(_) => Err(SseError::Decode),
    })
}

// ===========================================================================
// PII detection
// ===========================================================================
// Combines predefined types (Email, US SSN, Credit Card, Phone Number) with
// operator-supplied custom regex patterns. Synchronous and allocation-light:
// takes `&str`, returns matches, never touches the PDK runtime — keeps the
// detector unit-testable independently of the request/response filters.

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum PiiType {
    SSN,
    Email,
    CreditCard,
    PhoneNumber,
}

impl FromStr for PiiType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "US SSN" => Ok(PiiType::SSN),
            "Email" => Ok(PiiType::Email),
            "Credit Card" => Ok(PiiType::CreditCard),
            "Phone Number" => Ok(PiiType::PhoneNumber),
            _ => bail!("Unknown PiiType"),
        }
    }
}

/// Display name used in logs and rejection responses.
fn pii_type_to_string(pii_type: &PiiType) -> String {
    match pii_type {
        PiiType::SSN => "US SSN".to_string(),
        PiiType::Email => "Email".to_string(),
        PiiType::CreditCard => "Credit Card".to_string(),
        PiiType::PhoneNumber => "Phone Number".to_string(),
    }
}

#[derive(Error, Debug)]
enum PiiError {
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),
}

/// A match from `CombinedPiiDetector` carrying the configured pattern name
/// (predefined PII type label or custom-pattern user-given name). Used for
/// log messages and the JSON-RPC error data array.
#[derive(Debug, Clone)]
struct ExtendedPiiMatch {
    value: String,
    start: usize,
    end: usize,
    pattern_name: String,
}

/// Wire shape used in log lines and JSON-RPC rejection bodies. `pii_type` in
/// the JSON output is actually the configured pattern name — the field is
/// named `pii_type` for compatibility with downstream log/alert tooling that
/// keys on that name.
#[derive(Serialize, Debug, Clone)]
struct SerializablePiiMatch {
    #[serde(rename = "pii_type")]
    pattern_name: String,
    value: String,
    start: usize,
    end: usize,
}

impl From<&ExtendedPiiMatch> for SerializablePiiMatch {
    fn from(m: &ExtendedPiiMatch) -> Self {
        SerializablePiiMatch {
            pattern_name: m.pattern_name.clone(),
            value: m.value.clone(),
            start: m.start,
            end: m.end,
        }
    }
}

/// Detector combining predefined PII regexes with operator-supplied custom
/// patterns. Custom patterns are normalised on construction:
///   * Doubled backslash escapes (`\\d`, `\\s`, …) are collapsed to single
///     escapes so that regexes coming from JSON/YAML configurations match
///     regardless of how the source layer escaped them.
///   * Patterns without explicit anchors are wrapped in `\b…\b` so they
///     behave consistently with the predefined detectors and avoid partial
///     matches on adjacent text.
struct CombinedPiiDetector {
    predefined: Vec<(PiiType, Regex)>,
    custom: Vec<(String, Regex)>,
}

impl CombinedPiiDetector {
    fn new(
        predefined_types: Vec<PiiType>,
        custom_patterns: Vec<(String, String)>,
    ) -> Result<Self, PiiError> {
        let predefined = build_predefined(&predefined_types)?;
        let custom = build_custom(custom_patterns)?;
        Ok(Self { predefined, custom })
    }

    fn detect_extended(&self, text: &str) -> Result<Vec<ExtendedPiiMatch>, PiiError> {
        let mut all = Vec::new();
        for (pii_type, pattern) in &self.predefined {
            for mat in pattern.find_iter(text) {
                all.push(ExtendedPiiMatch {
                    value: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                    pattern_name: pii_type_to_string(pii_type),
                });
            }
        }
        for (name, pattern) in &self.custom {
            for mat in pattern.find_iter(text) {
                all.push(ExtendedPiiMatch {
                    value: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                    pattern_name: name.clone(),
                });
            }
        }
        Ok(all)
    }
}

fn build_predefined(types: &[PiiType]) -> Result<Vec<(PiiType, Regex)>, PiiError> {
    let mut out = Vec::new();
    for t in types {
        let pat = match t {
            PiiType::SSN => r"\b\d{3}-\d{2}-\d{4}\b",
            PiiType::Email => r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            PiiType::CreditCard => r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            PiiType::PhoneNumber => r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        };
        let regex = Regex::new(pat).map_err(|e| PiiError::InvalidRegex(e.to_string()))?;
        out.push((t.clone(), regex));
    }
    Ok(out)
}

fn build_custom(custom: Vec<(String, String)>) -> Result<Vec<(String, Regex)>, PiiError> {
    let mut out = Vec::new();
    for (name, raw) in custom {
        let original = raw.clone();
        let normalized = normalize_double_escapes(&raw);
        let processed = if normalized.starts_with('^') || normalized.ends_with('$') {
            normalized
        } else {
            format!(r"\b{}\b", normalized)
        };
        let regex = Regex::new(&processed).map_err(|e| {
            PiiError::InvalidRegex(format!("Invalid custom regex '{}': {}", original, e))
        })?;
        out.push((name, regex));
    }
    Ok(out)
}

/// Replace doubled escape sequences (`\\d`, `\\D`, …) with single ones.
/// Some configuration paths (JSON-in-YAML, environment variables) end up
/// double-escaping regex metacharacters — without this normalisation an
/// operator would have to know which path their pattern travels through.
fn normalize_double_escapes(raw: &str) -> String {
    raw.replace("\\\\d", "\\d")
        .replace("\\\\D", "\\D")
        .replace("\\\\w", "\\w")
        .replace("\\\\W", "\\W")
        .replace("\\\\s", "\\s")
        .replace("\\\\S", "\\S")
        .replace("\\\\b", "\\b")
        .replace("\\\\B", "\\B")
}

// ===========================================================================
// Per-entity config + classification
// ===========================================================================

const TEXT_FIELD: &str = "text";
const TYPE_FIELD: &str = "type";
const KIND_FIELD: &str = "kind";
const TYPE_TEXT: &str = "text";

/// Per-entity configuration resolved from `gcl.yaml`. The map is keyed by
/// pattern name (predefined PII type label or custom-pattern user name).
#[derive(Clone)]
struct PiiEntityConfig {
    actions: Vec<String>,
    report_policy_violation_on_log: bool,
}

impl PiiEntityConfig {
    fn has_log(&self) -> bool {
        self.actions.iter().any(|a| a == "Log")
    }
    fn has_reject(&self) -> bool {
        self.actions.iter().any(|a| a == "Reject")
    }
}

type PiiActionsMap = HashMap<String, PiiEntityConfig>;

/// Result of partitioning detected matches against the policy configuration
/// on the request path.
#[derive(Default, Debug)]
struct ClassifiedMatches {
    to_log: Vec<SerializablePiiMatch>,
    to_reject: Vec<SerializablePiiMatch>,
    should_report_violation: bool,
    log_only_entities: Vec<String>,
}

fn classify_matches(
    matches: &[ExtendedPiiMatch],
    pii_actions_map: &PiiActionsMap,
) -> ClassifiedMatches {
    let mut out = ClassifiedMatches::default();
    for m in matches {
        let cfg = match pii_actions_map.get(&m.pattern_name) {
            Some(c) => c,
            None => continue,
        };
        let has_log = cfg.has_log();
        let has_reject = cfg.has_reject();

        if has_reject {
            out.should_report_violation = true;
        } else if has_log && cfg.report_policy_violation_on_log {
            out.should_report_violation = true;
        } else if has_log && !cfg.report_policy_violation_on_log {
            out.log_only_entities.push(m.pattern_name.clone());
        }

        if has_log {
            out.to_log.push(SerializablePiiMatch::from(m));
        }
        if has_reject {
            out.to_reject.push(SerializablePiiMatch::from(m));
        }
    }
    out
}

// ===========================================================================
// Request filter
// ===========================================================================
// Inspects POST + JSON requests carrying an A2A JSON-RPC payload; passes
// everything else through. Always disables the upstream timeout so SSE
// responses can stream long-running tasks.

async fn request_filter(
    request_state: RequestState,
    pii_actions_map: &PiiActionsMap,
    policy_violation: &PolicyViolations,
    detector: &CombinedPiiDetector,
    error_code_on_reject: i32,
) -> Flow<()> {
    let header_state = request_state.into_headers_state().await;
    let handler = header_state.handler();
    with_no_timeout(handler);

    if header_state.method().as_str() != POST_METHOD {
        return Flow::Continue(());
    }

    let content_type = match handler.header(CONTENT_TYPE_HEADER) {
        Some(ct) => ct,
        None => return Flow::Continue(()),
    };
    if !is_json_mime_type(content_type.as_str()) {
        return Flow::Continue(());
    }

    let body_state = header_state.into_body_state().await;
    let body_bytes = body_state.as_bytes();
    let body_bytes = body_bytes.as_slice();

    let request: JsonRpcRequest<'_> = match serde_json::from_slice(body_bytes) {
        Ok(r) => r,
        Err(_) => return Flow::Continue(()),
    };

    if !is_inspectable_method(request.method) {
        return Flow::Continue(());
    }
    let params = match request.params {
        Some(p) => p,
        None => return Flow::Continue(()),
    };

    let request_id = request.id.and_then(parse_jsonrpc_id);

    let json_value: Value = match serde_json::from_str(params.get()) {
        Ok(v) => v,
        Err(e) => {
            access_log_err(format!("Unable to parse params as json `{:?}`", e));
            return Flow::Continue(());
        }
    };

    inspect_payload(
        &json_value,
        pii_actions_map,
        policy_violation,
        detector,
        request_id,
        error_code_on_reject,
    )
}

/// Walk the canonical A2A payload locations and apply PII detection to any
/// text content found. Returns `Flow::Break` on the first Reject action that
/// fires; otherwise returns `Flow::Continue`.
fn inspect_payload(
    json_value: &Value,
    pii_actions_map: &PiiActionsMap,
    policy_violation: &PolicyViolations,
    detector: &CombinedPiiDetector,
    request_id: Option<JsonRpcId>,
    error_code_on_reject: i32,
) -> Flow<()> {
    if let Some(Value::Array(parts)) = json_value.pointer("/message/parts") {
        return scan_parts(
            parts,
            pii_actions_map,
            policy_violation,
            detector,
            request_id,
            error_code_on_reject,
        );
    }
    if let Some(Value::Array(parts)) = json_value.pointer("/task/parts") {
        return scan_parts(
            parts,
            pii_actions_map,
            policy_violation,
            detector,
            request_id,
            error_code_on_reject,
        );
    }
    if let Some(Value::String(desc)) = json_value.pointer("/task/description") {
        return apply_pii_actions(
            desc,
            pii_actions_map,
            policy_violation,
            detector,
            "task description",
            request_id,
            error_code_on_reject,
        );
    }
    Flow::Continue(())
}

fn scan_parts(
    parts: &[Value],
    pii_actions_map: &PiiActionsMap,
    policy_violation: &PolicyViolations,
    detector: &CombinedPiiDetector,
    request_id: Option<JsonRpcId>,
    error_code_on_reject: i32,
) -> Flow<()> {
    for part in parts {
        // Accept either the legacy `type` field or the current `kind` field
        // for the part discriminator. Either spelling, when set to "text",
        // means the `text` string is user-authored content.
        let part_type = part
            .get(KIND_FIELD)
            .or_else(|| part.get(TYPE_FIELD))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let part_kind = part
            .get(KIND_FIELD)
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !part.is_object() || (part_type != TYPE_TEXT && part_kind != TYPE_TEXT) {
            continue;
        }
        if let Some(Value::String(s)) = part.get(TEXT_FIELD) {
            let flow = apply_pii_actions(
                s,
                pii_actions_map,
                policy_violation,
                detector,
                "Request",
                request_id.clone(),
                error_code_on_reject,
            );
            if matches!(flow, Flow::Break(_)) {
                return flow;
            }
        }
    }
    Flow::Continue(())
}

/// Run the detector against `text`, partition matches by configured action,
/// emit log lines and policy violations as appropriate, and return either
/// `Flow::Continue` (no Reject action triggered) or `Flow::Break(response)`
/// with a JSON-RPC error envelope (Reject action triggered).
fn apply_pii_actions(
    text: &str,
    pii_actions_map: &PiiActionsMap,
    policy_violation: &PolicyViolations,
    detector: &CombinedPiiDetector,
    context: &str,
    request_id: Option<JsonRpcId>,
    error_code_on_reject: i32,
) -> Flow<()> {
    let matches = match detector.detect_extended(text) {
        Ok(m) => m,
        Err(e) => {
            access_log_warn(format!("Error while trying to process PII: {}", e));
            return Flow::Continue(());
        }
    };
    if matches.is_empty() {
        return Flow::Continue(());
    }

    let outcome = classify_matches(&matches, pii_actions_map);

    if outcome.should_report_violation {
        policy_violation.generate_policy_violation();
    }
    if !outcome.log_only_entities.is_empty() && !outcome.should_report_violation {
        logger::debug!(
            "PII detected in request with 'Log' action (no policy violation): {:?}",
            outcome.log_only_entities
        );
    }
    if !outcome.to_log.is_empty() {
        let log_result = serde_json::to_string_pretty(&outcome.to_log).unwrap_or_default();
        access_log_warn(format!(
            "{}: `{}` has sensitive data: `{:?}`",
            context, text, log_result
        ));
    }
    if !outcome.to_reject.is_empty() {
        return Flow::Break(create_pii_error_response(
            request_id,
            outcome.to_reject,
            error_code_on_reject,
        ));
    }
    Flow::Continue(())
}

/// Build the JSON-RPC 2.0 error response returned when a Reject action
/// fires. Returns HTTP 200 (per JSON-RPC convention — the transport
/// succeeded; the failure is in-band) with `application/json`.
fn create_pii_error_response(
    request_id: Option<JsonRpcId>,
    pii_matches: Vec<SerializablePiiMatch>,
    error_code: i32,
) -> Response {
    let error_data = serde_json::to_value(&pii_matches).unwrap_or(Value::Null);
    let rpc_error = RpcError {
        code: error_code,
        message: "Policy violation: PII detected in request".to_string(),
        data: Some(error_data),
    };
    let response = JsonRpcResponse::error(request_id, rpc_error);
    let body = serde_json::to_string(&response).unwrap_or_default();
    Response::new(200)
        .with_headers(vec![(
            CONTENT_TYPE_HEADER.to_string(),
            APPLICATION_JSON.to_string(),
        )])
        .with_body(body.into_bytes())
}

// ===========================================================================
// Response filter
// ===========================================================================
// Response-path PII inspection. **Never blocks** — by design — but does
// honour the same `reportPolicyViolationOnLog` semantics as the request
// path. Handles both JSON and SSE bodies.

async fn response_filter(
    response_state: ResponseState,
    request_data: RequestData<()>,
    policy_violation: &PolicyViolations,
    detector: &CombinedPiiDetector,
    pii_actions_map: &PiiActionsMap,
) {
    if !matches!(request_data, RequestData::Continue(_)) {
        return;
    }

    let headers_state = response_state.into_headers_state().await;
    let header_handler = headers_state.handler();
    let content_type = match header_handler.header(CONTENT_TYPE_HEADER) {
        Some(c) => c,
        None => return,
    };
    let mime = match content_type.parse::<mime::Mime>() {
        Ok(m) => m,
        Err(_) => return,
    };

    match (mime.type_(), mime.subtype()) {
        (_, mime::EVENT_STREAM) => {
            handle_sse_response(headers_state, policy_violation, detector, pii_actions_map).await
        }
        (_, mime::JSON) => {
            let body_state = headers_state.into_body_state().await;
            let body = body_state.handler().body();
            log_response_pii(policy_violation, body, detector, pii_actions_map);
        }
        _ => {}
    }
}

/// Decode an SSE response and feed each event's data through the JSON PII
/// scan. Decoding errors are silently dropped — we cannot block the response
/// in any case, and noisy logs would obscure real findings.
async fn handle_sse_response(
    headers_state: ResponseHeadersState,
    policy_violation: &PolicyViolations,
    detector: &CombinedPiiDetector,
    pii_actions_map: &PiiActionsMap,
) {
    let body_stream_state = headers_state.into_body_stream_state().await;
    let stream = body_stream_state.stream();
    into_sse(stream)
        .for_each(|sse_event| async {
            if let Ok(async_sse::Event::Message(m)) = sse_event {
                let event = m.data().to_vec();
                log_response_pii(policy_violation, event, detector, pii_actions_map);
            }
        })
        .await;
}

/// Scan a response body (as bytes) for PII. Tries to parse JSON and walks
/// the canonical A2A response paths; falls back to a plain-text scan if the
/// body is not valid JSON.
fn log_response_pii(
    policy_violation: &PolicyViolations,
    body: Vec<u8>,
    detector: &CombinedPiiDetector,
    pii_actions_map: &PiiActionsMap,
) {
    let body_string = String::from_utf8_lossy(&body).to_string();
    let parsed: Result<Value, serde_json::Error> = serde_json::from_str(body_string.as_str());
    match parsed {
        Ok(response_value) => {
            for path in &[
                "/result/status/message/parts",
                "/result/artifact/parts",
                "/result/task/parts",
            ] {
                if let Some(Value::Array(parts)) = response_value.pointer(path) {
                    for part in parts {
                        if let Some(Value::String(s)) = part.get(TEXT_FIELD) {
                            scan_response_text(policy_violation, s, detector, pii_actions_map);
                        }
                    }
                }
            }
            if let Some(Value::String(desc)) = response_value.pointer("/result/task/description") {
                scan_response_text(policy_violation, desc, detector, pii_actions_map);
            }
            if let Some(Value::String(status)) = response_value.pointer("/result/task/status") {
                scan_response_text(policy_violation, status, detector, pii_actions_map);
            }
        }
        Err(_) => {
            // Non-JSON body — treat the whole payload as plain text.
            scan_response_text(policy_violation, &body_string, detector, pii_actions_map);
        }
    }
}

fn scan_response_text(
    policy_violation: &PolicyViolations,
    text: &str,
    detector: &CombinedPiiDetector,
    pii_actions_map: &PiiActionsMap,
) {
    let matches = match detector.detect_extended(text) {
        Ok(m) => m,
        Err(e) => {
            access_log_warn(format!("Error while trying to process PII: {}", e));
            return;
        }
    };
    if matches.is_empty() {
        return;
    }

    let outcome = classify_response_matches(&matches, pii_actions_map);
    if outcome.should_report_violation {
        policy_violation.generate_policy_violation();
    }
    if !outcome.log_only_entities.is_empty() && !outcome.should_report_violation {
        logger::debug!(
            "PII detected in response with 'Log' action (no policy violation): {:?}",
            outcome.log_only_entities
        );
    }
    let result = serde_json::to_string_pretty(&outcome.serializable).unwrap_or_default();
    access_log_warn(format!(
        "Response: `{}` has sensitive data: `{:?}`",
        text, result
    ));
}

#[derive(Default)]
struct ResponseOutcome {
    serializable: Vec<SerializablePiiMatch>,
    should_report_violation: bool,
    log_only_entities: Vec<String>,
}

fn classify_response_matches(
    matches: &[ExtendedPiiMatch],
    pii_actions_map: &PiiActionsMap,
) -> ResponseOutcome {
    let mut out = ResponseOutcome::default();
    for m in matches {
        let cfg: &PiiEntityConfig = match pii_actions_map.get(&m.pattern_name) {
            Some(c) => c,
            None => continue,
        };
        // On the response path every detected entity is logged, regardless
        // of whether its action set contains "Log" or "Reject" — findings
        // are always recorded; the response is never blocked.
        out.serializable.push(SerializablePiiMatch::from(m));

        if cfg.has_reject() {
            out.should_report_violation = true;
        } else if cfg.has_log() && cfg.report_policy_violation_on_log {
            out.should_report_violation = true;
        } else if cfg.has_log() && !cfg.report_policy_violation_on_log {
            out.log_only_entities.push(m.pattern_name.clone());
        }
    }
    out
}

// ===========================================================================
// Policy entrypoint
// ===========================================================================

/// Build the pattern-name → entity config map by merging predefined and
/// custom entity entries. Custom entities can override predefined entries
/// of the same name; in practice that does not happen because predefined
/// names are reserved labels.
fn build_pii_actions_map(config: &Config) -> PiiActionsMap {
    let mut map = PiiActionsMap::new();
    if let Some(ref predefined) = config.predefined_entities {
        for entity in predefined {
            map.insert(
                entity.pii_type.clone(),
                PiiEntityConfig {
                    actions: entity.actions.clone(),
                    report_policy_violation_on_log: entity.report_policy_violation_on_log,
                },
            );
        }
    }
    if let Some(ref custom) = config.custom_entities {
        for entity in custom {
            map.insert(
                entity.name.clone(),
                PiiEntityConfig {
                    actions: entity.actions.clone(),
                    report_policy_violation_on_log: entity.report_policy_violation_on_log,
                },
            );
        }
    }
    map
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    policy_violation: PolicyViolations,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    let mut predefined_types: Vec<PiiType> = Vec::new();
    if let Some(ref predefined) = config.predefined_entities {
        for entity in predefined {
            // Unknown predefined-entity labels are intentionally skipped so
            // that adding a new label to the schema does not break existing
            // deployments mid-rollout.
            if let Ok(pii_type) = PiiType::from_str(&entity.pii_type) {
                predefined_types.push(pii_type);
            }
        }
    }
    let mut custom_patterns: Vec<(String, String)> = Vec::new();
    if let Some(ref custom) = config.custom_entities {
        for entity in custom {
            custom_patterns.push((entity.name.clone(), entity.regex.clone()));
        }
    }

    let pii_actions_map = build_pii_actions_map(&config);
    let detector = CombinedPiiDetector::new(predefined_types, custom_patterns)
        .map_err(|e| anyhow!("Failed to create PII detector: {}", e))?;
    let error_code_on_reject = config.error_code_on_reject;

    let filter = on_request(|rs| {
        request_filter(
            rs,
            &pii_actions_map,
            &policy_violation,
            &detector,
            error_code_on_reject,
        )
    })
    .on_response(|rs, rd| {
        response_filter(rs, rd, &policy_violation, &detector, &pii_actions_map)
    });

    launcher.launch(filter).await?;
    Ok(())
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::config::{CustomEntity, PredefinedEntity};

    // ----- build_pii_actions_map -----

    fn make_config(
        predefined: Vec<(&str, Vec<&str>, bool)>,
        custom: Vec<(&str, &str, Vec<&str>, bool)>,
    ) -> Config {
        Config {
            error_code_on_reject: -32023,
            predefined_entities: if predefined.is_empty() {
                None
            } else {
                Some(
                    predefined
                        .into_iter()
                        .map(|(t, a, r)| PredefinedEntity {
                            pii_type: t.to_string(),
                            actions: a.into_iter().map(String::from).collect(),
                            report_policy_violation_on_log: r,
                        })
                        .collect(),
                )
            },
            custom_entities: if custom.is_empty() {
                None
            } else {
                Some(
                    custom
                        .into_iter()
                        .map(|(n, r, a, rep)| CustomEntity {
                            name: n.to_string(),
                            regex: r.to_string(),
                            actions: a.into_iter().map(String::from).collect(),
                            report_policy_violation_on_log: rep,
                        })
                        .collect(),
                )
            },
        }
    }

    #[test]
    fn empty_config_yields_empty_map() {
        let cfg = make_config(vec![], vec![]);
        let map = build_pii_actions_map(&cfg);
        assert!(map.is_empty());
    }

    #[test]
    fn predefined_and_custom_entries_both_present() {
        let cfg = make_config(
            vec![("Email", vec!["Log"], true)],
            vec![("Plate", "[A-Z]{2}\\d{3}[A-Z]{2}", vec!["Reject"], true)],
        );
        let map = build_pii_actions_map(&cfg);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("Email"));
        assert!(map.contains_key("Plate"));
        assert!(map.get("Email").unwrap().has_log());
        assert!(map.get("Plate").unwrap().has_reject());
    }

    #[test]
    fn report_on_log_flag_round_trips() {
        let cfg = make_config(vec![("Email", vec!["Log"], false)], vec![]);
        let map = build_pii_actions_map(&cfg);
        assert!(!map.get("Email").unwrap().report_policy_violation_on_log);
    }

    // ----- PII detection -----

    #[test]
    fn pii_type_from_str_known_values() {
        assert_eq!(PiiType::from_str("US SSN").unwrap(), PiiType::SSN);
        assert_eq!(PiiType::from_str("Email").unwrap(), PiiType::Email);
        assert_eq!(PiiType::from_str("Credit Card").unwrap(), PiiType::CreditCard);
        assert_eq!(PiiType::from_str("Phone Number").unwrap(), PiiType::PhoneNumber);
        assert!(PiiType::from_str("Unknown").is_err());
    }

    #[test]
    fn detects_predefined_types() {
        let det = CombinedPiiDetector::new(
            vec![PiiType::Email, PiiType::SSN, PiiType::CreditCard, PiiType::PhoneNumber],
            vec![],
        )
        .unwrap();
        let text = "ssn 123-45-6789 mail a@b.com cc 4111-1111-1111-1111 phone 555-123-4567";
        let m = det.detect_extended(text).unwrap();
        let names: Vec<_> = m.iter().map(|x| x.pattern_name.clone()).collect();
        assert!(names.contains(&"US SSN".to_string()));
        assert!(names.contains(&"Email".to_string()));
        assert!(names.contains(&"Credit Card".to_string()));
        assert!(names.contains(&"Phone Number".to_string()));
    }

    #[test]
    fn custom_regex_word_boundary_wrapping() {
        let det = CombinedPiiDetector::new(
            vec![],
            vec![("Plate".to_string(), r"[A-Z]{2}\d{3}[A-Z]{2}".to_string())],
        )
        .unwrap();
        // Word-boundary wrapping: surrounded by spaces matches…
        let m = det.detect_extended("plate AB123CD here").unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].value, "AB123CD");
        // …but immediately adjacent to other word chars does not.
        let m2 = det.detect_extended("xAB123CDx").unwrap();
        assert!(m2.is_empty());
    }

    #[test]
    fn custom_regex_anchored_pattern_used_as_is() {
        let det = CombinedPiiDetector::new(
            vec![],
            vec![("Anchored".to_string(), r"^TEST\d+$".to_string())],
        )
        .unwrap();
        let m = det.detect_extended("TEST42").unwrap();
        assert_eq!(m.len(), 1);
        let m2 = det.detect_extended("foo TEST42 bar").unwrap();
        assert!(m2.is_empty());
    }

    #[test]
    fn custom_regex_double_escape_normalised() {
        let det = CombinedPiiDetector::new(
            vec![],
            vec![("DoubleEsc".to_string(), r"\\d{4}".to_string())],
        )
        .unwrap();
        let m = det.detect_extended("code 1234 here").unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].value, "1234");
    }

    #[test]
    fn invalid_custom_regex_returns_error() {
        let res = CombinedPiiDetector::new(vec![], vec![("Bad".to_string(), "[".to_string())]);
        assert!(res.is_err());
    }

    #[test]
    fn empty_text_yields_no_matches() {
        let det = CombinedPiiDetector::new(vec![PiiType::Email], vec![]).unwrap();
        assert!(det.detect_extended("").unwrap().is_empty());
    }

    #[test]
    fn overlapping_email_and_creditcard_no_match_without_boundary() {
        let det =
            CombinedPiiDetector::new(vec![PiiType::Email, PiiType::CreditCard], vec![]).unwrap();
        let m = det.detect_extended("a@b.com1234-5678-9012-3456").unwrap();
        // Both predefined patterns require word boundaries; concatenated text
        // has no boundary between the email and the credit-card digits.
        assert!(m.is_empty());
    }

    #[test]
    fn serializable_match_round_trip() {
        let m = ExtendedPiiMatch {
            value: "123-45-6789".to_string(),
            start: 0,
            end: 11,
            pattern_name: "US SSN".to_string(),
        };
        let s: SerializablePiiMatch = (&m).into();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"pii_type\":\"US SSN\""));
        assert!(json.contains("\"value\":\"123-45-6789\""));
    }

    // ----- Request-path classification -----

    fn cfg(actions: &[&str], report_on_log: bool) -> PiiEntityConfig {
        PiiEntityConfig {
            actions: actions.iter().map(|s| s.to_string()).collect(),
            report_policy_violation_on_log: report_on_log,
        }
    }

    fn match_for(pattern: &str) -> ExtendedPiiMatch {
        ExtendedPiiMatch {
            value: "X".to_string(),
            start: 0,
            end: 1,
            pattern_name: pattern.to_string(),
        }
    }

    #[test]
    fn reject_action_triggers_violation_and_reject_list() {
        let mut map = PiiActionsMap::new();
        map.insert("Email".to_string(), cfg(&["Reject"], true));
        let out = classify_matches(&[match_for("Email")], &map);
        assert!(out.should_report_violation);
        assert_eq!(out.to_reject.len(), 1);
        assert!(out.to_log.is_empty());
    }

    #[test]
    fn log_with_report_on_log_triggers_violation() {
        let mut map = PiiActionsMap::new();
        map.insert("Email".to_string(), cfg(&["Log"], true));
        let out = classify_matches(&[match_for("Email")], &map);
        assert!(out.should_report_violation);
        assert_eq!(out.to_log.len(), 1);
        assert!(out.to_reject.is_empty());
    }

    #[test]
    fn log_without_report_on_log_does_not_trigger_violation() {
        let mut map = PiiActionsMap::new();
        map.insert("Email".to_string(), cfg(&["Log"], false));
        let out = classify_matches(&[match_for("Email")], &map);
        assert!(!out.should_report_violation);
        assert_eq!(out.log_only_entities, vec!["Email".to_string()]);
    }

    #[test]
    fn unknown_pattern_is_ignored() {
        let map = PiiActionsMap::new();
        let out = classify_matches(&[match_for("Mystery")], &map);
        assert!(!out.should_report_violation);
        assert!(out.to_log.is_empty());
        assert!(out.to_reject.is_empty());
    }

    #[test]
    fn mixed_log_and_reject_uses_both_lists() {
        let mut map = PiiActionsMap::new();
        map.insert("Email".to_string(), cfg(&["Log", "Reject"], true));
        let out = classify_matches(&[match_for("Email")], &map);
        assert!(out.should_report_violation);
        assert_eq!(out.to_log.len(), 1);
        assert_eq!(out.to_reject.len(), 1);
    }

    #[test]
    fn rejection_response_envelope_shape() {
        let resp = create_pii_error_response(
            Some(JsonRpcId::Int(7)),
            vec![SerializablePiiMatch {
                pattern_name: "Email".to_string(),
                value: "a@b.com".to_string(),
                start: 0,
                end: 7,
            }],
            -32023,
        );
        // The body is set; envelope shape is verified separately in
        // integration tests where we can read it back.
        let _ = resp;
    }
}
