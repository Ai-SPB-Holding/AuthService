//! OAuth clients listing, audit log, refresh-token sessions (admin API).

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::security::jwt::AccessClaims;
use crate::services::{app_state::AppState, errors::AppError};

use sqlx::Error as SqlxError;

fn is_missing_relation(err: &SqlxError) -> bool {
    if err
        .as_database_error()
        .is_some_and(|e| e.code() == Some(std::borrow::Cow::Borrowed("42P01")))
    {
        return true;
    }
    let s = err.to_string();
    s.contains("does not exist")
}

pub fn mask_client_secret(secret: &str) -> String {
    if secret.len() <= 4 {
        "••••".to_string()
    } else {
        format!("••••••••{}", &secret[secret.len().saturating_sub(4)..])
    }
}

pub async fn insert_audit_log(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    actor_user_id: Option<Uuid>,
    action: &str,
    target: Option<&str>,
    details: Option<serde_json::Value>,
) {
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_log (tenant_id, actor_user_id, action, target, details) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant_id)
    .bind(actor_user_id)
    .bind(action)
    .bind(target)
    .bind(details)
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, "audit_log insert failed; apply migration 0003");
    }
}

#[derive(Debug, Serialize)]
pub struct ClientRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub client_type: String,
    pub client_secret_masked: String,
    pub redirect_uri: String,
    pub allowed_redirect_uris: serde_json::Value,
    pub scopes: String,
    pub allow_user_registration: bool,
    pub mfa_policy: String,
    pub allow_client_totp_enrollment: bool,
    pub embedded_login_enabled: bool,
    pub embedded_token_audience: Option<String>,
    pub embedded_parent_origins: serde_json::Value,
    /// When true, v2 `postMessage` envelope (see `docs/EMBEDDED_IFRAME_PROTOCOL.md`).
    pub embedded_protocol_v2: bool,
    pub embedded_ui_theme: Option<serde_json::Value>,
    /// Override access JWT TTL (seconds); `None` = server default.
    pub access_ttl_seconds: Option<i32>,
    /// Override refresh token TTL (seconds); `None` = server default.
    pub refresh_ttl_seconds: Option<i32>,
    pub user_schema: Vec<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_clients(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
) -> Result<Json<Vec<ClientRow>>, AppError> {
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global =
        crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);

    let rows = if global {
        sqlx::query(
            "SELECT id, tenant_id, client_id, client_type, client_secret_argon2, redirect_uri,
                COALESCE(allowed_redirect_uris, '[]'::jsonb) AS allowed_redirect_uris,
                COALESCE(scopes, 'openid profile email') AS scopes,
                COALESCE(allow_user_registration, false) AS allow_user_registration,
                COALESCE(mfa_policy, 'off') AS mfa_policy,
                COALESCE(allow_client_totp_enrollment, true) AS allow_client_totp_enrollment,
                COALESCE(embedded_login_enabled, false) AS embedded_login_enabled,
                embedded_token_audience,
                COALESCE(embedded_parent_origins, '[]'::jsonb) AS embedded_parent_origins,
                COALESCE(embedded_protocol_v2, false) AS embedded_protocol_v2,
                embedded_ui_theme,
                access_ttl_seconds,
                refresh_ttl_seconds,
                created_at
         FROM clients ORDER BY tenant_id, client_id",
        )
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT id, tenant_id, client_id, client_type, client_secret_argon2, redirect_uri,
                COALESCE(allowed_redirect_uris, '[]'::jsonb) AS allowed_redirect_uris,
                COALESCE(scopes, 'openid profile email') AS scopes,
                COALESCE(allow_user_registration, false) AS allow_user_registration,
                COALESCE(mfa_policy, 'off') AS mfa_policy,
                COALESCE(allow_client_totp_enrollment, true) AS allow_client_totp_enrollment,
                COALESCE(embedded_login_enabled, false) AS embedded_login_enabled,
                embedded_token_audience,
                COALESCE(embedded_parent_origins, '[]'::jsonb) AS embedded_parent_origins,
                COALESCE(embedded_protocol_v2, false) AS embedded_protocol_v2,
                embedded_ui_theme,
                access_ttl_seconds,
                refresh_ttl_seconds,
                created_at
         FROM clients WHERE tenant_id = $1 ORDER BY client_id",
        )
        .bind(tenant_id)
        .fetch_all(&state.pool)
        .await?
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(client_row_from_row(&state.pool, &row).await?);
    }
    Ok(Json(out))
}

/// Same columns as the list and single-client queries (`client_secret_argon2` for confidential masking).
async fn client_row_from_row(pool: &sqlx::PgPool, row: &PgRow) -> Result<ClientRow, AppError> {
    let id: Uuid = row.get("id");
    let secret_argon: Option<String> = row.try_get("client_secret_argon2").ok().flatten();
    let client_type: String = row
        .try_get::<String, _>("client_type")
        .unwrap_or_else(|_| "public".to_string());
    let schema_rows = sqlx::query(
        "SELECT field_name, field_type, is_auth, is_required
         FROM client_user_schema WHERE client_id = $1 ORDER BY field_name",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let mut user_schema = Vec::with_capacity(schema_rows.len());
    for r in schema_rows {
        user_schema.push(serde_json::json!({
            "field_name": r.get::<String, _>("field_name"),
            "field_type": r.get::<String, _>("field_type"),
            "is_auth": r.get::<bool, _>("is_auth"),
            "is_required": r.get::<bool, _>("is_required"),
        }));
    }
    Ok(ClientRow {
        id,
        tenant_id: row.get("tenant_id"),
        client_id: row.get("client_id"),
        client_type: client_type.clone(),
        client_secret_masked: if client_type == "confidential" {
            match secret_argon.as_deref().filter(|s| !s.is_empty()) {
                Some(s) => mask_client_secret(s),
                None => "••••(stored as hash)".to_string(),
            }
        } else {
            "—".to_string()
        },
        redirect_uri: row.get("redirect_uri"),
        allowed_redirect_uris: row.get::<serde_json::Value, _>("allowed_redirect_uris"),
        scopes: row.get("scopes"),
        allow_user_registration: row.try_get("allow_user_registration").unwrap_or(false),
        mfa_policy: row
            .try_get::<String, _>("mfa_policy")
            .unwrap_or_else(|_| "off".to_string()),
        allow_client_totp_enrollment: row.try_get("allow_client_totp_enrollment").unwrap_or(true),
        embedded_login_enabled: row.try_get("embedded_login_enabled").unwrap_or(false),
        embedded_token_audience: row.try_get("embedded_token_audience").ok().flatten(),
        embedded_parent_origins: row
            .try_get::<serde_json::Value, _>("embedded_parent_origins")
            .unwrap_or_else(|_| serde_json::json!([])),
        embedded_protocol_v2: row.try_get("embedded_protocol_v2").unwrap_or(false),
        embedded_ui_theme: row.try_get("embedded_ui_theme").ok().flatten(),
        access_ttl_seconds: row.try_get("access_ttl_seconds").ok().flatten(),
        refresh_ttl_seconds: row.try_get("refresh_ttl_seconds").ok().flatten(),
        user_schema,
        created_at: row.get("created_at"),
    })
}

pub async fn get_client(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<ClientRow>, AppError> {
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global =
        crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let row = if global {
        sqlx::query(
            "SELECT id, tenant_id, client_id, client_type, client_secret_argon2, redirect_uri,
                COALESCE(allowed_redirect_uris, '[]'::jsonb) AS allowed_redirect_uris,
                COALESCE(scopes, 'openid profile email') AS scopes,
                COALESCE(allow_user_registration, false) AS allow_user_registration,
                COALESCE(mfa_policy, 'off') AS mfa_policy,
                COALESCE(allow_client_totp_enrollment, true) AS allow_client_totp_enrollment,
                COALESCE(embedded_login_enabled, false) AS embedded_login_enabled,
                embedded_token_audience,
                COALESCE(embedded_parent_origins, '[]'::jsonb) AS embedded_parent_origins,
                COALESCE(embedded_protocol_v2, false) AS embedded_protocol_v2,
                embedded_ui_theme,
                access_ttl_seconds,
                refresh_ttl_seconds,
                created_at
         FROM clients WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT id, tenant_id, client_id, client_type, client_secret_argon2, redirect_uri,
                COALESCE(allowed_redirect_uris, '[]'::jsonb) AS allowed_redirect_uris,
                COALESCE(scopes, 'openid profile email') AS scopes,
                COALESCE(allow_user_registration, false) AS allow_user_registration,
                COALESCE(mfa_policy, 'off') AS mfa_policy,
                COALESCE(allow_client_totp_enrollment, true) AS allow_client_totp_enrollment,
                COALESCE(embedded_login_enabled, false) AS embedded_login_enabled,
                embedded_token_audience,
                COALESCE(embedded_parent_origins, '[]'::jsonb) AS embedded_parent_origins,
                COALESCE(embedded_protocol_v2, false) AS embedded_protocol_v2,
                embedded_ui_theme,
                access_ttl_seconds,
                refresh_ttl_seconds,
                created_at
         FROM clients WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.pool)
        .await?
    };
    let Some(row) = row else {
        return Err(AppError::NotFound);
    };
    Ok(Json(client_row_from_row(&state.pool, &row).await?))
}

#[derive(Debug, Deserialize, Default)]
pub struct ListAuditQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AuditListItem {
    pub id: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub action: String,
    pub user_id: Option<Uuid>,
    pub success: Option<bool>,
    pub target: Option<String>,
    pub details: Option<serde_json::Value>,
}

pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Query(q): Query<ListAuditQuery>,
) -> Result<Json<Vec<AuditListItem>>, AppError> {
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global =
        crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let limit = q.limit.unwrap_or(100).min(500).max(1);

    let mut items: Vec<AuditListItem> = Vec::new();

    let audit_q = if global {
        sqlx::query(
            "SELECT id, actor_user_id, action, target, details, created_at
         FROM audit_log ORDER BY created_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT id, actor_user_id, action, target, details, created_at
         FROM audit_log WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&state.pool)
        .await
    };

    match audit_q {
        Ok(rows) => {
            for row in rows {
                let id: Uuid = row.get("id");
                items.push(AuditListItem {
                    id: id.to_string(),
                    occurred_at: row.get("created_at"),
                    source: "admin".to_string(),
                    action: row.get::<String, _>("action"),
                    user_id: row.get("actor_user_id"),
                    success: None,
                    target: row.get("target"),
                    details: row.get("details"),
                });
            }
        }
        Err(e) if is_missing_relation(&e) => {}
        Err(e) => return Err(e.into()),
    }

    let ae_limit = (limit * 2).min(200);
    let ae_rows = if global {
        sqlx::query(
            "SELECT id, user_id, success, event_kind, created_at
         FROM auth_events ORDER BY created_at DESC LIMIT $1",
        )
        .bind(ae_limit)
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT id, user_id, success, event_kind, created_at
         FROM auth_events WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(tenant_id)
        .bind(ae_limit)
        .fetch_all(&state.pool)
        .await
    };
    match ae_rows {
        Ok(rows) => {
            for row in rows {
                let id: Uuid = row.get("id");
                let success: bool = row.get("success");
                let kind: String = row.get("event_kind");
                items.push(AuditListItem {
                    id: format!("ae-{id}"),
                    occurred_at: row.get("created_at"),
                    source: "auth".to_string(),
                    action: kind,
                    user_id: row.get("user_id"),
                    success: Some(success),
                    target: None,
                    details: None,
                });
            }
        }
        Err(e) if is_missing_relation(&e) => {}
        Err(e) => return Err(e.into()),
    }

    items.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
    items.truncate(limit as usize);
    Ok(Json(items))
}

#[derive(Debug, Serialize)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_email: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoked: bool,
    pub is_active: bool,
}

pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
) -> Result<Json<Vec<SessionRow>>, AppError> {
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global =
        crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);

    let rows = if global {
        sqlx::query(
            "SELECT rt.id, rt.user_id, rt.expires_at, rt.revoked, rt.session_status, rt.created_at, u.email AS user_email
         FROM refresh_tokens rt
         LEFT JOIN users u ON u.id = rt.user_id AND u.tenant_id = rt.tenant_id
         ORDER BY rt.created_at DESC
         LIMIT 300",
        )
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT rt.id, rt.user_id, rt.expires_at, rt.revoked, rt.session_status, rt.created_at, u.email AS user_email
         FROM refresh_tokens rt
         LEFT JOIN users u ON u.id = rt.user_id AND u.tenant_id = rt.tenant_id
         WHERE rt.tenant_id = $1
         ORDER BY rt.created_at DESC
         LIMIT 300",
        )
        .bind(tenant_id)
        .fetch_all(&state.pool)
        .await?
    };

    let now = chrono::Utc::now();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
        let revoked: bool = row.get("revoked");
        let session_status: String = row
            .try_get::<String, _>("session_status")
            .unwrap_or_else(|_| "active".to_string());
        let is_active = !revoked && session_status == "active" && expires_at > now;
        out.push(SessionRow {
            id: row.get("id"),
            user_id: row.get("user_id"),
            user_email: row.get("user_email"),
            created_at: row.get("created_at"),
            expires_at,
            revoked,
            is_active,
        });
    }
    Ok(Json(out))
}

pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global =
        crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let actor = Uuid::parse_str(&claims.sub).ok();

    let row_tid: Option<Uuid> =
        sqlx::query_scalar("SELECT tenant_id FROM refresh_tokens WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    let Some(token_tenant) = row_tid else {
        return Err(AppError::NotFound);
    };
    if !global && token_tenant != actor_tenant {
        return Err(AppError::NotFound);
    }

    let n = if global {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked = true, session_status = 'revoked', revoked_at = NOW() WHERE id = $1",
        )
            .bind(id)
            .execute(&state.pool)
            .await?
            .rows_affected()
    } else {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked = true, session_status = 'revoked', revoked_at = NOW() WHERE id = $1 AND tenant_id = $2",
        )
            .bind(id)
            .bind(actor_tenant)
            .execute(&state.pool)
            .await?
            .rows_affected()
    };
    if n == 0 {
        return Err(AppError::NotFound);
    }

    insert_audit_log(
        &state.pool,
        token_tenant,
        actor,
        "session.revoke",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true })))
}
