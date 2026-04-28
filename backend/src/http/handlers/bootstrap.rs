use std::sync::Arc;

use axum::http::{StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};
use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::services::app_state::AppState;
use crate::services::auth_service::RegisterCommand;
use crate::services::errors::AppError;

#[derive(Debug, Deserialize)]
pub struct BootstrapAdminRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
}

/// Create the very first admin user when there are zero users in the database.
///
/// Guard:
/// - requires `AUTH__BOOTSTRAP_ADMIN_TOKEN` to be set
/// - requires `Authorization: Bearer <token>` matching the configured token
/// - only works when `SELECT COUNT(*) FROM users` is zero
pub async fn bootstrap_admin(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BootstrapAdminRequest>,
) -> Result<Response, AppError> {
    let token_cfg = state
        .config
        .auth
        .bootstrap_admin_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Forbidden)?;

    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let got = auth.strip_prefix("Bearer ").unwrap_or("").trim();
    if got.is_empty() || got != token_cfg {
        return Err(AppError::Forbidden);
    }

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await?;
    if n != 0 {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({"error":"BOOTSTRAP_NOT_ALLOWED","message":"users table is not empty"})),
        )
            .into_response());
    }

    let tenant_id = req.tenant_id.unwrap_or_else(Uuid::new_v4);

    // Create user (+ email verification token) using the same service as /auth/register.
    let pending = state
        .auth
        .register(RegisterCommand {
            tenant_id,
            email: req.email,
            password: req.password,
            registration_source: Some("bootstrap-admin".to_string()),
        })
        .await?;

    // Promote to admin role in DB (same logic as Makefile.release user-promote-admin).
    sqlx::query(
        "INSERT INTO roles (id, tenant_id, name)
         SELECT uuid_generate_v4(), $1, 'admin'
         WHERE NOT EXISTS (SELECT 1 FROM roles WHERE tenant_id = $1 AND name = 'admin')",
    )
    .bind(tenant_id)
    .execute(&state.pool)
    .await?;

    sqlx::query(
        "INSERT INTO user_roles (tenant_id, user_id, role_id)
         SELECT $1, $2, r.id FROM roles r
         WHERE r.tenant_id = $1 AND r.name = 'admin'
         ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(pending.user_id)
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "tenant_id": tenant_id,
            "user_id": pending.user_id,
            "email_verification_token": pending.email_verification_token,
            "token_type": pending.token_type,
            "expires_in": pending.expires_in
        })),
    )
        .into_response())
}
