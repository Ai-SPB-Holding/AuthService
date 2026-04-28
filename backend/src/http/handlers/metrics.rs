use std::sync::Arc;

use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use prometheus::{Encoder, TextEncoder};

use crate::services::app_state::AppState;

pub async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(expected) = &state.config.metrics.bypass_token {
        let Some(auth) = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()) else {
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        };
        let want = format!("Bearer {expected}");
        if auth != want.as_str() {
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    }

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    if encoder.encode(&metric_families, &mut buffer).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "failed to encode metrics").into_response();
    }

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            encoder.format_type().to_string(),
        )],
        String::from_utf8_lossy(&buffer).to_string(),
    )
        .into_response()
}
