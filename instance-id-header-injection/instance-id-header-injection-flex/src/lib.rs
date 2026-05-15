// Copyright 2026 Salesforce, Inc. All rights reserved.
mod generated;

use anyhow::{anyhow, Result};

use pdk::hl::*;
use pdk::logger;
use pdk::metadata::Metadata;

use crate::generated::config::Config;

/// Header name injected by this policy on every forwarded request.
pub const HEADER_NAME: &str = "x-anypoint-api-instance-id";

/// Fallback value used when no API instance ID is present in the gateway
/// metadata (typical of local-mode / standalone deployments).
pub const FALLBACK_VALUE: &str = "default-instance-id";

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    metadata: Metadata,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;
    let filter = on_request(|rs| request_filter(rs, &config, &metadata));
    launcher.launch(filter).await?;
    Ok(())
}

/// Injects the `x-anypoint-api-instance-id` header on every incoming request,
/// using the API instance ID from the gateway metadata, or a stable fallback
/// when none is available.
async fn request_filter(request_state: RequestState, _config: &Config, metadata: &Metadata) {
    let headers_state = request_state.into_headers_state().await;

    let api_instance_id = metadata
        .api_metadata
        .id
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(FALLBACK_VALUE);

    headers_state
        .handler()
        .set_header(HEADER_NAME, api_instance_id);

    logger::info!(
        "Injected {} header with value: {}",
        HEADER_NAME,
        api_instance_id
    );
}

#[cfg(test)]
mod unit;
