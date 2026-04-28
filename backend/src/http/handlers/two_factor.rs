use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::domain::auth::TokenPair;
use crate::middleware::user::BearerPrincipal;
use crate::security::jwt::AccessClaims;
use crate::services::{app_state::AppState, errors::AppError};

use super::admin_portal::insert_audit_log;

#[derive(Debug, Deserialize)]
pub struct TwoFaVerifyBody {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct Client2faByPublicId {
    /// Public OAuth `client_id` (string) from `clients.client_id`.
    pub oauth_client_id: String,
}

fn principal_user_tenant(p: &BearerPrincipal) -> Result<(Uuid, Uuid), AppError> {
    match p {
        BearerPrincipal::Access(c) => Ok((
            Uuid::parse_str(&c.sub).map_err(|_| AppError::Unauthorized)?,
            Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?,
        )),
        BearerPrincipal::TotpEnroll(c) => Ok((
            Uuid::parse_str(&c.sub).map_err(|_| AppError::Unauthorized)?,
            Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?,
        )),
    }
}

/// POST /2fa/setup
pub async fn setup_2fa(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<BearerPrincipal>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (sub, tenant_id) = principal_user_tenant(&principal)?;
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
        .bind(sub)
        .bind(tenant_id)
        .fetch_one(&state.pool)
        .await?;
    let (url, base32) = state.totp.begin_setup(sub, tenant_id, &email).await?;
    Ok(Json(serde_json::json!({
        "otpauth_url": url,
        "secret_base32": base32,
    })))
}

/// POST /2fa/verify
pub async fn verify_2fa(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<BearerPrincipal>,
    Json(b): Json<TwoFaVerifyBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (sub, tenant_id) = principal_user_tenant(&principal)?;
    state.totp.complete_setup(sub, tenant_id, &b.code).await?;
    if let BearerPrincipal::TotpEnroll(ref c) = principal {
        let pair: TokenPair = state
            .auth
            .issue_session_after_totp_enrollment(sub, tenant_id, c.login_audience.as_str())
            .await?;
        return Ok(Json(serde_json::json!({
            "ok": true,
            "totp_enabled": true,
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "token_type": pair.token_type,
            "expires_in": pair.expires_in,
        })));
    }
    Ok(Json(serde_json::json!({ "ok": true, "totp_enabled": true })))
}

#[derive(Debug, Deserialize)]
pub struct TwoFaDisableBody {
    pub code: String,
}

/// POST /2fa/disable
pub async fn disable_2fa(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(b): Json<TwoFaDisableBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Unauthorized)?;
    state.totp.disable(sub, tenant_id, &b.code).await?;
    Ok(Json(serde_json::json!({ "ok": true, "totp_enabled": false })))
}

/// POST /2fa/client/setup — TOTP for a specific OAuth client (see `client_user_mfa`).
pub async fn client_setup_2fa(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(b): Json<Client2faByPublicId>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Unauthorized)?;
    let public = b.oauth_client_id.trim();
    if public.is_empty() {
        return Err(AppError::Validation("oauth_client_id is required".to_string()));
    }
    let row = sqlx::query(
        "SELECT id, COALESCE(allow_client_totp_enrollment, true) AS allow_en
         FROM clients WHERE client_id = $1 AND tenant_id = $2",
    )
    .bind(public)
    .bind(tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Validation("unknown oauth_client_id".to_string()))?;
    let id: Uuid = row.get("id");
    let allow: bool = row.get("allow_en");
    if !allow {
        return Err(AppError::Forbidden);
    }
    let (url, base32) = state.totp.begin_client_setup(sub, tenant_id, id, public).await?;
    let actor = Uuid::parse_str(&claims.sub).ok();
    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client_mfa.setup",
        Some(&id.to_string()),
        Some(serde_json::json!({ "oauth_client_id": public, "self_service": true })),
    )
    .await;
    Ok(Json(serde_json::json!({
        "otpauth_url": url,
        "secret_base32": base32,
    })))
}

/// POST /2fa/client/verify
pub async fn client_verify_2fa(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(b): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let public = b
        .get("oauth_client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("oauth_client_id is required".to_string()))?
        .trim();
    if public.is_empty() {
        return Err(AppError::Validation("oauth_client_id is required".to_string()));
    }
    let code = b
        .get("code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("code is required".to_string()))?;
    let sub = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Unauthorized)?;
    let id: Uuid = sqlx::query_scalar("SELECT id FROM clients WHERE client_id = $1 AND tenant_id = $2")
        .bind(public)
        .bind(tenant_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Validation("unknown oauth_client_id".to_string()))?;
    state.totp.complete_client_setup(sub, tenant_id, id, public, code).await?;
    let actor = Uuid::parse_str(&claims.sub).ok();
    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client_mfa.verify",
        Some(&id.to_string()),
        Some(serde_json::json!({ "oauth_client_id": public, "self_service": true })),
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true, "client_totp_enabled": true })))
}

/// POST /2fa/client/disable
pub async fn client_disable_2fa(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(b): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let public = b
        .get("oauth_client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("oauth_client_id is required".to_string()))?
        .trim();
    if public.is_empty() {
        return Err(AppError::Validation("oauth_client_id is required".to_string()));
    }
    let code = b
        .get("code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("code is required".to_string()))?;
    let sub = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Unauthorized)?;
    let id: Uuid = sqlx::query_scalar("SELECT id FROM clients WHERE client_id = $1 AND tenant_id = $2")
        .bind(public)
        .bind(tenant_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Validation("unknown oauth_client_id".to_string()))?;
    state.totp.disable_client(sub, tenant_id, id, public, code).await?;
    let actor = Uuid::parse_str(&claims.sub).ok();
    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client_mfa.disable",
        Some(&id.to_string()),
        Some(serde_json::json!({ "oauth_client_id": public, "self_service": true })),
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true, "client_totp_enabled": false })))
}
