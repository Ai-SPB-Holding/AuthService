use std::sync::Arc;

use axum::{Json, extract::State};
use http::header::AUTHORIZATION;
use serde::Deserialize;
use uuid::Uuid;

use crate::services::app_state::AppState;
use crate::services::errors::AppError;

fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let h = headers.get(AUTHORIZATION)?.to_str().ok()?;
    h.strip_prefix("Bearer ").map(str::trim)
}

/// POST /email/send-code — resend 6-digit email (register flow).  
/// Authorization: `email-verification` JWT *or* access token with `email_verified: false`.
pub async fn send_code(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(tok) = bearer(&headers) else {
        return Err(AppError::Unauthorized);
    };
    if let Ok(c) = state.auth.jwt.verify_email_verification(tok) {
        let user_id = Uuid::parse_str(&c.sub).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?;
        let email: String =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&state.pool)
                .await?;
        let (jwt, exp) = state
            .ev
            .resend_registration(user_id, tenant_id, &email)
            .await?;
        return Ok(Json(serde_json::json!({
            "email_verification_token": jwt,
            "expires_in": exp,
            "token_type": "email_verification"
        })));
    }
    if let Ok(claims) = state.auth.jwt.verify_access_any_audience(tok) {
        if claims.roles.iter().any(|r| r == "refresh") {
            return Err(AppError::Unauthorized);
        }
        if claims.email_verified {
            return Err(AppError::Validation("email already verified".to_string()));
        }
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Unauthorized)?;
        let email: String =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&state.pool)
                .await?;
        let (jwt, exp) = state
            .ev
            .resend_registration(user_id, tenant_id, &email)
            .await?;
        return Ok(Json(serde_json::json!({
            "email_verification_token": jwt,
            "expires_in": exp,
            "token_type": "email_verification"
        })));
    }
    Err(AppError::Unauthorized)
}

#[derive(Debug, Deserialize)]
pub struct VerifyCodeRequest {
    pub code: String,
    /// OAuth audience for issued access/refresh (default `auth-service`).
    #[serde(default = "default_audience")]
    pub audience: String,
}

fn default_audience() -> String {
    "auth-service".to_string()
}

/// POST /email/verify-code
pub async fn verify_code(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(b): Json<VerifyCodeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(tok) = bearer(&headers) else {
        return Err(AppError::Unauthorized);
    };
    let c = state.auth.jwt.verify_email_verification(tok)?;
    let user_id = Uuid::parse_str(&c.sub).map_err(|_| AppError::Unauthorized)?;
    let tenant_id = Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?;
    let verification_id = Uuid::parse_str(&c.jti).map_err(|_| AppError::Unauthorized)?;
    let pair = state
        .auth
        .complete_email_verification(user_id, tenant_id, verification_id, &b.code, &b.audience)
        .await?;
    let v = serde_json::to_value(&pair).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(v))
}
