// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers building A2A JSON-RPC request bodies for tests.

use serde_json::{json, Value};

/// Build a `message/send` request whose `message.parts` array contains a
/// single `text` part with the given content.
pub fn message_send(text: &str) -> Value {
    message_send_with_id(json!(1), text)
}

pub fn message_send_with_id(id: Value, text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "message/send",
        "params": {
            "message": {
                "parts": [
                    { "kind": "text", "text": text }
                ]
            }
        }
    })
}

/// Build a `message/send` request using the legacy `type: "text"` part
/// discriminator instead of `kind: "text"`.
pub fn message_send_legacy_type(text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "parts": [
                    { "type": "text", "text": text }
                ]
            }
        }
    })
}

/// `message/stream` variant — same shape as `message/send`.
pub fn message_stream(text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/stream",
        "params": {
            "message": {
                "parts": [
                    { "kind": "text", "text": text }
                ]
            }
        }
    })
}

/// `tasks/get` request with a text part inside `task.parts`.
pub fn tasks_get_with_parts(text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/get",
        "params": {
            "task": {
                "parts": [
                    { "kind": "text", "text": text }
                ]
            }
        }
    })
}

/// Build a `tasks/get` request using the `task.description` string.
pub fn tasks_get_with_description(description: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/get",
        "params": {
            "task": {
                "description": description
            }
        }
    })
}

/// `tasks/stream` request with a text part inside `task.parts`.
pub fn tasks_stream_with_parts(text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/stream",
        "params": {
            "task": {
                "parts": [
                    { "kind": "text", "text": text }
                ]
            }
        }
    })
}

/// `tasks/resubscribe` with a text part inside `task.parts`.
pub fn tasks_resubscribe_with_parts(text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/resubscribe",
        "params": {
            "task": {
                "parts": [
                    { "kind": "text", "text": text }
                ]
            }
        }
    })
}

/// Multiple text parts in a single `message/send` request.
pub fn message_send_multi(parts: &[&str]) -> Value {
    let parts_json: Vec<Value> = parts
        .iter()
        .map(|p| json!({ "kind": "text", "text": p }))
        .collect();
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": { "parts": parts_json }
        }
    })
}

/// A response body containing PII inside `result.status.message.parts`.
pub fn response_with_message_parts(text: &str) -> Value {
    json!({
        "result": {
            "status": {
                "message": {
                    "parts": [
                        { "text": text }
                    ]
                }
            }
        }
    })
}

/// A response body containing PII inside `result.artifact.parts`.
pub fn response_with_artifact_parts(text: &str) -> Value {
    json!({
        "result": {
            "artifact": {
                "parts": [
                    { "text": text }
                ]
            }
        }
    })
}

/// A response body with PII in `result.task.description`.
pub fn response_with_task_description(description: &str) -> Value {
    json!({
        "result": {
            "task": {
                "description": description
            }
        }
    })
}
