// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the instance-id-header-injection policy. These exercise the
// full request lifecycle without a running Envoy proxy, container, or
// network — they run as ordinary `cargo test` cases.

use std::rc::Rc;

use pdk_unit::{
    TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTest, UnitTestBuilder,
};

use crate::{FALLBACK_VALUE, HEADER_NAME};

/// Build a tester with the given API instance ID injected into the `Metadata`
/// stub and the provided trace backend. Pass `None` to simulate the
/// local-mode case where no API instance ID is provided by the gateway.
fn tester_with(
    api_instance_id: Option<&str>,
    backend: Rc<TraceBackend<UnitHttpResponse>>,
) -> UnitTest {
    let id = api_instance_id.map(|s| s.to_string());
    UnitTestBuilder::default()
        .with_config(r#"{}"#)
        .with_backend(backend)
        .metadata(move |m| {
            m.api_metadata.id = id.clone();
        })
        .with_entrypoint(crate::configure)
}

fn ok_backend() -> Rc<TraceBackend<UnitHttpResponse>> {
    Rc::new(TraceBackend::new(UnitHttpResponse::new(200)))
}

/// When the gateway provides an API instance ID, the policy must inject it
/// verbatim under `x-anypoint-api-instance-id`.
#[test]
fn injects_real_api_instance_id_when_present() {
    let backend = ok_backend();
    let mut tester = tester_with(Some("api-instance-12345"), backend.clone());

    let response = tester.request(UnitHttpRequest::get().with_path("/anything"));

    assert_eq!(response.status_code(), 200);

    let upstream = backend.next().expect("upstream should have been called");
    assert_eq!(
        upstream.header(HEADER_NAME),
        Some("api-instance-12345"),
        "policy must forward the metadata-provided API instance ID"
    );
}

/// When no API instance ID is available from the gateway metadata (e.g. a
/// local-mode standalone Flex), the policy falls back to a stable default
/// rather than dropping the header altogether.
#[test]
fn falls_back_when_metadata_has_no_id() {
    let backend = ok_backend();
    let mut tester = tester_with(None, backend.clone());

    tester.request(UnitHttpRequest::get().with_path("/anything"));

    let upstream = backend.next().expect("upstream should have been called");
    assert_eq!(
        upstream.header(HEADER_NAME),
        Some(FALLBACK_VALUE),
        "policy must inject the fallback value when metadata.id is None"
    );
}

/// A client-supplied value for the same header must be replaced, not
/// appended. This guards against client spoofing of the API instance ID.
#[test]
fn overrides_client_supplied_header() {
    let backend = ok_backend();
    let mut tester = tester_with(Some("trusted-id"), backend.clone());

    tester.request(
        UnitHttpRequest::get()
            .with_path("/anything")
            .with_header(HEADER_NAME, "spoofed-by-client"),
    );

    let upstream = backend.next().expect("upstream should have been called");
    assert_eq!(
        upstream.header(HEADER_NAME),
        Some("trusted-id"),
        "client-supplied header must be replaced with the trusted value"
    );
}

/// The policy must not interfere with other client-supplied headers.
#[test]
fn unrelated_client_headers_pass_through() {
    let backend = ok_backend();
    let mut tester = tester_with(Some("trusted-id"), backend.clone());

    tester.request(
        UnitHttpRequest::get()
            .with_path("/anything")
            .with_header("x-correlation-id", "abc-123")
            .with_header("user-agent", "test/1.0"),
    );

    let upstream = backend.next().expect("upstream should have been called");
    assert_eq!(upstream.header("x-correlation-id"), Some("abc-123"));
    assert_eq!(upstream.header("user-agent"), Some("test/1.0"));
    assert_eq!(upstream.header(HEADER_NAME), Some("trusted-id"));
}

/// The policy registers no response filter, so the upstream's response
/// status, body, and headers must surface to the client unchanged.
#[test]
fn response_passes_through_unchanged() {
    let backend = Rc::new(TraceBackend::new(
        UnitHttpResponse::new(418)
            .with_header("x-upstream-marker", "set-by-upstream")
            .with_body("I'm a teapot"),
    ));
    let mut tester = tester_with(Some("any-id"), backend);

    let response = tester.request(UnitHttpRequest::get().with_path("/anything"));

    assert_eq!(response.status_code(), 418);
    assert_eq!(
        response.header("x-upstream-marker"),
        Some("set-by-upstream"),
    );
    assert_eq!(response.body(), b"I'm a teapot");
}

/// The policy must apply on every method, not just GET (the gcl.yaml
/// declares `interfaceScope: api,resource` so the filter runs on all
/// methods routed through the API).
#[test]
fn applies_on_post_request() {
    let backend = Rc::new(TraceBackend::new(UnitHttpResponse::new(201)));
    let mut tester = tester_with(Some("post-id"), backend.clone());

    let response = tester.request(
        UnitHttpRequest::post()
            .with_path("/submit")
            .with_body("payload"),
    );

    assert_eq!(response.status_code(), 201);
    let upstream = backend.next().expect("upstream should have been called");
    assert_eq!(upstream.header(HEADER_NAME), Some("post-id"));
}

#[test]
fn applies_on_put_request() {
    let backend = Rc::new(TraceBackend::new(UnitHttpResponse::new(204)));
    let mut tester = tester_with(Some("put-id"), backend.clone());

    let response = tester.request(
        UnitHttpRequest::put()
            .with_path("/resource/1")
            .with_body("body"),
    );

    assert_eq!(response.status_code(), 204);
    let upstream = backend.next().expect("upstream should have been called");
    assert_eq!(upstream.header(HEADER_NAME), Some("put-id"));
}

#[test]
fn applies_on_delete_request() {
    let backend = ok_backend();
    let mut tester = tester_with(Some("delete-id"), backend.clone());

    let response = tester.request(UnitHttpRequest::delete().with_path("/resource/1"));

    assert_eq!(response.status_code(), 200);
    let upstream = backend.next().expect("upstream should have been called");
    assert_eq!(upstream.header(HEADER_NAME), Some("delete-id"));
}

/// An empty string from the gateway metadata is treated as "no ID" and
/// triggers the fallback, same as `None`. This guards against blank
/// header values reaching the upstream.
#[test]
fn empty_metadata_id_triggers_fallback() {
    let backend = ok_backend();
    let mut tester = tester_with(Some(""), backend.clone());

    tester.request(UnitHttpRequest::get().with_path("/anything"));

    let upstream = backend.next().expect("upstream should have been called");
    assert_eq!(
        upstream.header(HEADER_NAME),
        Some(FALLBACK_VALUE),
        "empty id must trigger the fallback rather than emit a blank header"
    );
}

/// Each request gets its own header injection. Sequential requests on
/// the same configured policy must all carry the header.
#[test]
fn injects_on_every_request() {
    let backend = ok_backend();
    let mut tester = tester_with(Some("steady-id"), backend.clone());

    for path in ["/a", "/b", "/c"] {
        tester.request(UnitHttpRequest::get().with_path(path));
    }

    for _ in 0..3 {
        let upstream = backend.next().expect("each call must reach the backend");
        assert_eq!(upstream.header(HEADER_NAME), Some("steady-id"));
    }
    assert!(backend.next().is_none(), "no extra upstream calls expected");
}
