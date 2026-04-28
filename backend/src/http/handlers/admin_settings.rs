//! `GET/PUT /admin/settings` and `GET /admin/session`.

use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::Serialize;
use uuid::Uuid;

use crate::security::jwt::AccessClaims;
use crate::services::app_state::AppState;
use crate::services::errors::AppError;
use crate::services::settings_service::{
    SettingsUpdate, SettingsView, apply_settings_update, load_settings_view, would_touch_sensitive,
};

#[derive(Debug, Serialize)]
pub struct AdminSessionResponse {
    pub is_admin: bool,
    pub is_client_settings_member: bool,
    /// `AUTH__GLOBAL_ADMIN_USER_IDS` / `AUTH__AUTH_SERVICE_DEPLOYMENT_ADMINS` allowlist: full-tenant admin API scope.
    pub is_deployment_global_admin: bool,
}

pub async fn get_admin_session(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
) -> Result<Json<AdminSessionResponse>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("invalid sub in token".to_string()))?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;

    let is_admin = claims.roles.iter().any(|r| r == "admin");
    let is_deployment_global_admin = state.config.is_global_service_admin(claims.sub.as_str());
    let is_client_settings_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM client_user_membership
            WHERE tenant_id = $1 AND user_id = $2
        )",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(AdminSessionResponse {
        is_admin,
        is_client_settings_member,
        is_deployment_global_admin,
    }))
}

pub async fn get_settings(
    State(state): State<Arc<AppState>>,
    Extension(_claims): Extension<AccessClaims>,
) -> Result<Json<SettingsView>, AppError> {
    let path = resolve_env_path(&state.config.auth.env_file_path)?;
    let mut view = load_settings_view(&state.config, &path)?;
    view.restart_required_note = None;
    Ok(Json(view))
}

pub async fn put_settings(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(mut body): Json<SettingsUpdate>,
) -> Result<Json<serde_json::Value>, AppError> {
    let is_admin = claims.roles.iter().any(|r| r == "admin");
    if !is_admin {
        body.require_login_2fa = None;
        body.client_mfa_enforce = None;
    }

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("invalid sub in token".to_string()))?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;

    let totp_user_enabled: bool =
        sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .unwrap_or(false);

    let need_totp = state.config.auth.require_login_2fa || totp_user_enabled;
    if would_touch_sensitive(&body) && need_totp {
        let code = body
            .totp_code
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let Some(code) = code else {
            return Err(AppError::Validation(
                "totp_code is required for sensitive settings when 2FA is enabled".to_string(),
            ));
        };
        state
            .totp
            .verify_login_totp(user_id, tenant_id, code)
            .await?;
    }

    let (view, restart) =
        apply_settings_update(&state.config, &state.pool, tenant_id, user_id, body).await?;

    Ok(Json(serde_json::json!({
        "settings": view,
        "restart_required": restart,
    })))
}

fn resolve_env_path(raw: &str) -> Result<std::path::PathBuf, AppError> {
    let env_path = std::path::PathBuf::from(raw.trim());
    if env_path.is_absolute() {
        Ok(env_path)
    } else {
        Ok(std::env::current_dir()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .join(env_path))
    }
}
