use axum::{Json, http::StatusCode, response::{IntoResponse, Response}};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("redis error")]
    Redis(#[from] redis::RedisError),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    /// Forbidden with a public-facing reason (e.g. policy), returned as `{"error": ...}`.
    #[error("forbidden: {0}")]
    ForbiddenWithReason(String),
    #[error("not found")]
    NotFound,
    #[error("validation error: {0}")]
    Validation(String),
    #[error("too many requests")]
    TooManyRequests,
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            Self::ForbiddenWithReason(s) => (StatusCode::FORBIDDEN, s.clone()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            Self::Validation(v) => (StatusCode::BAD_REQUEST, v.clone()),
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too many requests".to_string()),
            Self::Database(e) => {
                tracing::error!(error = %e, "database");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            Self::Redis(e) => {
                tracing::error!(error = %e, "redis");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            Self::Config(v) | Self::Internal(v) => {
                tracing::error!(error = %v, "internal");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
        };

        (status, Json(json!({"error": msg}))).into_response()
    }
}
