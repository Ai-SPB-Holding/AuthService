use std::sync::Arc;

use axum::{Extension, Json, extract::{Path, Query, State}};
use serde::Deserialize;
use serde::Serialize;
use sqlx::{Error as SqlxError, PgPool, Row};
use uuid::Uuid;

use crate::domain::mfa_client_policy::parse_mfa_policy;
use crate::domain::registration_source::{self, parse_registration_source};
use crate::security::jwt::AccessClaims;
use crate::security::password::hash_password;
use crate::services::{app_state::AppState, errors::AppError};

use super::admin_portal::insert_audit_log;

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub q: Option<String>,
    /// `created_at` | `email` | `registration_source`
    pub sort: Option<String>,
    /// `asc` | `desc` (defaults: `desc` for `created_at`, `asc` for text columns)
    pub order: Option<String>,
}

fn users_list_order_clause(sort: Option<&str>, order: Option<&str>) -> (&'static str, &'static str) {
    let col = match sort {
        Some("email") => "email",
        Some("registration_source") => "registration_source",
        _ => "created_at",
    };
    let dir = match order {
        Some(s) if s.eq_ignore_ascii_case("asc") => "ASC",
        Some(s) if s.eq_ignore_ascii_case("desc") => "DESC",
        _ if col == "created_at" => "DESC",
        _ => "ASC",
    };
    (col, dir)
}

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    /// If set, create the OAuth client in this tenant (only allowed to differ from the token when `AUTH__GLOBAL_ADMIN_USER_IDS` applies).
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub client_type: Option<String>,
    pub redirect_uri: Option<String>,
    pub redirect_urls: Option<Vec<String>>,
    /// Space-separated OIDC scopes (default `openid profile email` if omitted).
    pub scopes: Option<String>,
    /// Allowed redirect URI list; if omitted, a single entry matching `redirect_uri` is stored.
    pub allowed_redirect_uris: Option<Vec<String>>,
    pub allow_user_registration: Option<bool>,
    pub user_schema: Option<Vec<UserSchemaField>>,
    /// `off` | `optional` | `required` — per-client Authenticator (TOTP) policy.
    #[serde(default)]
    pub mfa_policy: Option<String>,
    #[serde(default)]
    pub allow_client_totp_enrollment: Option<bool>,
    /// Enable `GET /embedded-login?client_id=...` for this OAuth client.
    #[serde(default)]
    pub embedded_login_enabled: Option<bool>,
    /// Override JWT `aud` for embedded login; default is public `client_id`.
    #[serde(default)]
    pub embedded_token_audience: Option<String>,
    /// Allowed parent page origins (exact or `https://*.example.com`) for CSP and postMessage.
    #[serde(default)]
    pub embedded_parent_origins: Option<Vec<String>>,
    /// When true, v2 `postMessage` envelope + INIT / EMBED_READY (see docs/EMBEDDED_IFRAME_PROTOCOL.md).
    #[serde(default)]
    pub embedded_protocol_v2: Option<bool>,
    /// Whitelisted design tokens; validated (see `domain::embedded_ui_theme`).
    #[serde(default)]
    pub embedded_ui_theme: Option<serde_json::Value>,
    /// `none` | `client_secret_basic` | `client_secret_post` | `private_key_jwt` | `tls_client_auth` (defaults by client_type).
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub require_pkce: Option<bool>,
    #[serde(default)]
    pub pkce_methods: Option<Vec<String>>,
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// `code_exchange` | `bff_cookie` | `legacy_postmessage`
    #[serde(default)]
    pub embedded_flow_mode: Option<String>,
    #[serde(default)]
    pub client_jwks_uri: Option<String>,
    #[serde(default)]
    pub client_jwks: Option<serde_json::Value>,
    #[serde(default)]
    pub default_max_age_seconds: Option<i32>,
    #[serde(default)]
    pub use_v2_endpoints_only: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserSchemaField {
    pub field_name: String,
    pub field_type: String,
    #[serde(default)]
    pub is_auth: bool,
    #[serde(default)]
    pub is_required: bool,
}

#[derive(Debug, Serialize)]
pub struct GenerateClientIdResponse {
    pub client_id: String,
}

fn normalize_client_type(v: Option<&str>) -> Result<&'static str, AppError> {
    match v.unwrap_or("public").trim().to_ascii_lowercase().as_str() {
        "public" => Ok("public"),
        "confidential" => Ok("confidential"),
        _ => Err(AppError::Validation("client_type must be public or confidential".to_string())),
    }
}

fn normalize_token_endpoint_auth_method(v: Option<&str>, client_type: &str) -> Result<String, AppError> {
    let d = if client_type == "confidential" {
        "client_secret_basic"
    } else {
        "none"
    };
    let s = v.map(str::trim).filter(|s| !s.is_empty()).unwrap_or(d);
    let out = match s.to_ascii_lowercase().as_str() {
        "none" | "client_secret_basic" | "client_secret_post" | "private_key_jwt" | "tls_client_auth" => {
            s.to_ascii_lowercase()
        }
        _ => {
            return Err(AppError::Validation(
                "token_endpoint_auth_method must be none, client_secret_basic, client_secret_post, private_key_jwt, or tls_client_auth"
                    .to_string(),
            ));
        }
    };
    if client_type == "confidential" && out == "none" {
        return Err(AppError::Validation(
            "confidential clients must use a client-authentication method other than none".to_string(),
        ));
    }
    Ok(out)
}

fn normalize_embedded_flow_mode(v: Option<&str>) -> Result<&'static str, AppError> {
    match v.unwrap_or("code_exchange").trim().to_ascii_lowercase().as_str() {
        "code_exchange" => Ok("code_exchange"),
        "bff_cookie" => Ok("bff_cookie"),
        "legacy_postmessage" => Ok("legacy_postmessage"),
        _ => Err(AppError::Validation(
            "embedded_flow_mode must be code_exchange, bff_cookie, or legacy_postmessage".to_string(),
        )),
    }
}

fn is_localhost(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

fn validate_redirect_urls(uris: &[String]) -> Result<(), AppError> {
    if uris.is_empty() {
        return Err(AppError::Validation("at least one redirect URL is required".to_string()));
    }
    for u in uris {
        if u.contains('*') {
            return Err(AppError::Validation("redirect URLs must not contain wildcards".to_string()));
        }
        let parsed = url::Url::parse(u).map_err(|_| AppError::Validation(format!("invalid redirect URL: {u}")))?;
        if parsed.fragment().is_some() {
            return Err(AppError::Validation("redirect URLs must not include URL fragments".to_string()));
        }
        match parsed.scheme() {
            "https" => {}
            "http" if is_localhost(parsed.host_str().unwrap_or_default()) => {}
            _ => {
                return Err(AppError::Validation(
                    "redirect URLs must use https, except localhost on http".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn merge_redirect_urls(req: &CreateClientRequest) -> Result<Vec<String>, AppError> {
    let mut urls = Vec::new();
    if let Some(primary) = req.redirect_uri.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        urls.push(primary.to_string());
    }
    if let Some(v) = &req.redirect_urls {
        urls.extend(v.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    if let Some(v) = &req.allowed_redirect_uris {
        urls.extend(v.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    urls.dedup();
    validate_redirect_urls(&urls)?;
    Ok(urls)
}

fn normalized_client_schema(allow_registration: bool, schema: Option<&Vec<UserSchemaField>>) -> Result<Vec<UserSchemaField>, AppError> {
    if !allow_registration {
        return Ok(Vec::new());
    }
    let mut out = if let Some(s) = schema {
        s.clone()
    } else {
        vec![
            UserSchemaField {
                field_name: "email".to_string(),
                field_type: "string".to_string(),
                is_auth: true,
                is_required: true,
            },
            UserSchemaField {
                field_name: "password_hash".to_string(),
                field_type: "password".to_string(),
                is_auth: true,
                is_required: true,
            },
        ]
    };
    for f in &mut out {
        f.field_name = f.field_name.trim().to_ascii_lowercase();
        f.field_type = f.field_type.trim().to_ascii_lowercase();
    }
    out.retain(|f| !f.field_name.is_empty() && !f.field_type.is_empty());
    if out.is_empty() {
        return Err(AppError::Validation("user schema must contain at least one field".to_string()));
    }
    if out.iter().any(|f| f.field_name.len() > 64) {
        return Err(AppError::Validation("field_name max length is 64".to_string()));
    }
    let mut seen = std::collections::HashSet::new();
    if out.iter().any(|f| !seen.insert(f.field_name.clone())) {
        return Err(AppError::Validation("duplicate field_name in user schema".to_string()));
    }
    let auth_count = out.iter().filter(|f| f.is_auth).count();
    if auth_count == 0 {
        return Err(AppError::Validation("at least one auth field is required".to_string()));
    }
    if out.iter().any(|f| f.is_auth && f.field_name == "password_hash") && !out.iter().any(|f| f.field_name == "password_hash" && f.is_required)
    {
        return Err(AppError::Validation("password_hash must be required when used for auth".to_string()));
    }
    if !out.iter().any(|f| f.field_name == "email" && f.is_auth) && auth_count < 1 {
        return Err(AppError::Validation("email can be removed from auth only if another auth field exists".to_string()));
    }
    Ok(out)
}

fn generate_base62_client_id(len: usize) -> String {
    use rand::{Rng, distributions::Alphanumeric};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn normalize_mfa_policy(v: Option<&str>) -> Result<&'static str, AppError> {
    parse_mfa_policy(v).map_err(AppError::Validation)
}

/// Validates entries for `clients.embedded_parent_origins` (exact origins or `https://*.host`).
fn validate_embedded_parent_origins(origins: &[String]) -> Result<(), AppError> {
    if origins.len() > 48 {
        return Err(AppError::Validation("embedded_parent_origins: at most 48 entries".to_string()));
    }
    for raw in origins {
        let t = raw.trim();
        if t.is_empty() {
            return Err(AppError::Validation("embedded_parent_origins: empty entry".to_string()));
        }
        if t.contains('*') && !t.starts_with("https://*.") && !t.starts_with("http://*.") {
            return Err(AppError::Validation(format!("invalid embedded origin: {t}")));
        }
        if let Some(dom) = t.strip_prefix("https://*.") {
            if dom.is_empty() || dom.contains('/') || dom.contains('*') {
                return Err(AppError::Validation(format!("invalid wildcard origin: {t}")));
            }
            continue;
        }
        if let Some(dom) = t.strip_prefix("http://*.") {
            if dom.is_empty() || dom.contains('/') || dom.contains('*') {
                return Err(AppError::Validation(format!("invalid wildcard origin: {t}")));
            }
            continue;
        }
        let u = url::Url::parse(t).map_err(|_| AppError::Validation(format!("invalid origin: {t}")))?;
        let path = u.path();
        if !path.is_empty() && path != "/" {
            return Err(AppError::Validation(format!("embedded origin must have no path: {t}")));
        }
        match u.scheme() {
            "https" => {}
            "http" if u.host_str().is_some_and(is_localhost) => {}
            _ => {
                return Err(AppError::Validation(
                    "embedded origins must use https (http only for localhost)".to_string(),
                ));
            }
        }
    }
    Ok(())
}

async fn generate_unique_client_id(pool: &PgPool) -> Result<String, AppError> {
    for _ in 0..20 {
        let candidate = generate_base62_client_id(10);
        let exists: Option<String> = sqlx::query_scalar("SELECT client_id FROM clients WHERE client_id = $1")
            .bind(&candidate)
            .fetch_optional(pool)
            .await?;
        if exists.is_none() {
            return Ok(candidate);
        }
    }
    Err(AppError::Internal("failed to generate unique client_id".to_string()))
}

pub async fn generate_client_id(
    State(state): State<Arc<AppState>>,
    Extension(_claims): Extension<AccessClaims>,
) -> Result<Json<GenerateClientIdResponse>, AppError> {
    let client_id = generate_unique_client_id(&state.pool).await?;
    Ok(Json(GenerateClientIdResponse { client_id }))
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub tenant_id: Uuid,
    pub email: String,
    #[serde(default)]
    pub password: Option<String>,
    /// Legacy admin clients that pre-hash passwords may still send this.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// Saved as `users.registration_source` (e.g. `dashboard` default).
    #[serde(default)]
    pub registration_source: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PatchUserRequest {
    pub email: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub is_locked: Option<bool>,
    pub is_active: Option<bool>,
}

#[derive(Debug, serde::Serialize)]
pub struct GenerateTenantIdResponse {
    pub tenant_id: Uuid,
}

fn actor_tenant(claims: &AccessClaims) -> Result<Uuid, AppError> {
    Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Validation("invalid tenant in token".to_string()))
}

fn actor_user_id(claims: &AccessClaims) -> Option<Uuid> {
    Uuid::parse_str(&claims.sub).ok()
}

/// Returns a new random tenant identifier (UUID v4). Uniqueness follows UUID collision guarantees.
pub async fn generate_tenant_id(
    Extension(_claims): Extension<AccessClaims>,
) -> Result<Json<GenerateTenantIdResponse>, AppError> {
    Ok(Json(GenerateTenantIdResponse {
        tenant_id: Uuid::new_v4(),
    }))
}

async fn relocate_user_tenant(
    pool: &PgPool,
    user_id: Uuid,
    old_tenant: Uuid,
    new_tenant: Uuid,
) -> Result<(), AppError> {
    if old_tenant == new_tenant {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE users SET tenant_id = $1 WHERE id = $2 AND tenant_id = $3")
        .bind(new_tenant)
        .bind(user_id)
        .bind(old_tenant)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        tx.rollback().await.ok();
        return Err(AppError::NotFound);
    }
    sqlx::query("UPDATE credentials SET tenant_id = $1 WHERE user_id = $2 AND tenant_id = $3")
        .bind(new_tenant)
        .bind(user_id)
        .bind(old_tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE refresh_tokens SET tenant_id = $1 WHERE user_id = $2 AND tenant_id = $3")
        .bind(new_tenant)
        .bind(user_id)
        .bind(old_tenant)
        .execute(&mut *tx)
        .await?;
    let _ = sqlx::query("UPDATE email_verifications SET tenant_id = $1 WHERE user_id = $2 AND tenant_id = $3")
        .bind(new_tenant)
        .bind(user_id)
        .bind(old_tenant)
        .execute(&mut *tx)
        .await;
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2")
        .bind(user_id)
        .bind(old_tenant)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub tenant_id: Uuid,
    pub role_name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub tenant_id: Uuid,
    pub permission_name: String,
}

pub async fn create_client(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let target_tenant = req.tenant_id.unwrap_or(actor_tenant);
    if !global && target_tenant != actor_tenant {
        return Err(AppError::Forbidden);
    }
    let tenant_id = target_tenant;
    let actor = Uuid::parse_str(&claims.sub).ok();
    let id = Uuid::new_v4();
    let client_type = normalize_client_type(req.client_type.as_deref())?;
    let allow_registration = req.allow_user_registration.unwrap_or(false);
    let redirect_urls = merge_redirect_urls(&req)?;
    let primary_redirect = redirect_urls[0].clone();
    let allowed_redirect: serde_json::Value = serde_json::to_value(&redirect_urls).map_err(|e| AppError::Validation(e.to_string()))?;
    let user_schema = normalized_client_schema(allow_registration, req.user_schema.as_ref())?;
    let client_id = if let Some(cid) = req.client_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if cid.len() < 6 || cid.len() > 12 || !cid.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(AppError::Validation("client_id must be 6..12 base62 chars".to_string()));
        }
        cid.to_string()
    } else {
        generate_unique_client_id(&state.pool).await?
    };
    let client_secret_plain = if client_type == "confidential" {
        Some(Uuid::new_v4().to_string() + &Uuid::new_v4().to_string())
    } else {
        None
    };
    let client_secret_argon2 = if let Some(secret) = client_secret_plain.as_ref() {
        Some(hash_password(secret).map_err(AppError::Internal)?)
    } else {
        None
    };
    let scopes = req
        .scopes
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("openid profile email");
    let mfa_policy = normalize_mfa_policy(req.mfa_policy.as_deref())?;
    let allow_ctotp = req.allow_client_totp_enrollment.unwrap_or(true);
    let emb_en = req.embedded_login_enabled.unwrap_or(false);
    let emb_origins_vec = req.embedded_parent_origins.clone().unwrap_or_default();
    validate_embedded_parent_origins(&emb_origins_vec)?;
    let emb_origins_json =
        serde_json::to_value(&emb_origins_vec).map_err(|e| AppError::Validation(e.to_string()))?;
    let emb_aud = req
        .embedded_token_audience
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let emb_v2 = req.embedded_protocol_v2.unwrap_or(false);
    let emb_theme = crate::domain::embedded_ui_theme::validate_embedded_ui_theme(req.embedded_ui_theme.as_ref())
        .map_err(AppError::Validation)?;
    let token_method = normalize_token_endpoint_auth_method(req.token_endpoint_auth_method.as_deref(), client_type)?;
    let grant_types = req
        .grant_types
        .clone()
        .unwrap_or_else(|| {
            vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "embedded_session".to_string(),
            ]
        });
    let response_types = req
        .response_types
        .clone()
        .unwrap_or_else(|| vec!["code".to_string()]);
    let require_pkce = req.require_pkce.unwrap_or(true);
    let pkce_methods = req
        .pkce_methods
        .clone()
        .unwrap_or_else(|| vec!["S256".to_string()]);
    let post_logout = serde_json::to_value(req.post_logout_redirect_uris.clone().unwrap_or_default())
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let embedded_flow = normalize_embedded_flow_mode(req.embedded_flow_mode.as_deref())?;
    let client_jwks_uri = req
        .client_jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let client_jwks = req.client_jwks.clone();
    let default_max_age = req.default_max_age_seconds;
    let use_v2_only = req.use_v2_endpoints_only.unwrap_or(false);

    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_argon2, client_type, redirect_uri, scopes, allowed_redirect_uris, allow_user_registration, mfa_policy, allow_client_totp_enrollment, embedded_login_enabled, embedded_token_audience, embedded_parent_origins, embedded_protocol_v2, embedded_ui_theme, token_endpoint_auth_method, grant_types, response_types, require_pkce, pkce_methods, post_logout_redirect_uris, embedded_flow_mode, client_jwks_uri, client_jwks, default_max_age_seconds, use_v2_endpoints_only)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(&client_id)
    .bind(client_secret_argon2)
    .bind(client_type)
    .bind(&primary_redirect)
    .bind(scopes)
    .bind(allowed_redirect)
    .bind(allow_registration)
    .bind(mfa_policy)
    .bind(allow_ctotp)
    .bind(emb_en)
    .bind(emb_aud)
    .bind(emb_origins_json)
    .bind(emb_v2)
    .bind(emb_theme)
    .bind(&token_method)
    .bind(&grant_types)
    .bind(&response_types)
    .bind(require_pkce)
    .bind(&pkce_methods)
    .bind(post_logout)
    .bind(embedded_flow)
    .bind(client_jwks_uri)
    .bind(client_jwks)
    .bind(default_max_age)
    .bind(use_v2_only)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "client insert; apply migration 0005 for client_secret_argon2");
        AppError::Internal("client create failed (migrations applied?)".to_string())
    })?;

    for field in &user_schema {
        sqlx::query(
            "INSERT INTO client_user_schema (id, client_id, field_name, field_type, is_auth, is_required)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(&field.field_name)
        .bind(&field.field_type)
        .bind(field.is_auth)
        .bind(field.is_required)
        .execute(&state.pool)
        .await?;
    }

    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client.create",
        Some(&id.to_string()),
        Some(serde_json::json!({ "client_id": client_id, "client_type": client_type, "allow_registration": allow_registration })),
    )
    .await;

    Ok(Json(serde_json::json!({
        "id": id,
        "ok": true,
        "client_id": client_id,
        "client_type": client_type,
        "allow_user_registration": allow_registration,
        "client_secret": client_secret_plain,
        "message": if client_type == "confidential" { "Store client_secret securely; it is not shown again." } else { "Public client created." }
    })))
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    if !global && req.tenant_id != actor_tid {
        return Err(AppError::Forbidden);
    }
    let target_tenant = req.tenant_id;
    let actor = actor_user_id(&claims);
    let id = Uuid::new_v4();

    let password_hash = if let Some(ref p) = req.password {
        if p.len() < 8 {
            return Err(AppError::Validation("password must be at least 8 characters".to_string()));
        }
        hash_password(p).map_err(AppError::Internal)?
    } else if let Some(ref h) = req.password_hash {
        if h.is_empty() {
            return Err(AppError::Validation("password or password_hash is required".to_string()));
        }
        h.clone()
    } else {
        return Err(AppError::Validation("password or password_hash is required".to_string()));
    };

    let email = req.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::Validation("invalid email".to_string()));
    }

    let registration_source = parse_registration_source(
        req.registration_source.as_deref(),
        registration_source::DEFAULT_DASHBOARD,
    )
    .map_err(AppError::Validation)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, is_active, is_locked, email_verified, registration_source)
         VALUES ($1, $2, $3, true, false, false, $4)",
    )
    .bind(id)
    .bind(target_tenant)
    .bind(&email)
    .bind(&registration_source)
    .execute(&mut *tx)
    .await?;

    sqlx::query("INSERT INTO credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(target_tenant)
        .bind(password_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    insert_audit_log(
        &state.pool,
        target_tenant,
        actor,
        "user.create",
        Some(&id.to_string()),
        Some(serde_json::json!({ "email": email })),
    )
    .await;

    Ok(Json(serde_json::json!({"id": id})))
}

pub async fn create_role(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    if !global && req.tenant_id != tid {
        return Err(AppError::Forbidden);
    }
    sqlx::query("INSERT INTO roles (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(req.tenant_id)
        .bind(req.role_name)
        .execute(&state.pool)
        .await?;

    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn create_permission(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    if !global && req.tenant_id != tid {
        return Err(AppError::Forbidden);
    }
    sqlx::query("INSERT INTO permissions (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(req.tenant_id)
        .bind(req.permission_name)
        .execute(&state.pool)
        .await?;

    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn update_client(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let client_tenant: Option<Uuid> = if global {
        sqlx::query_scalar("SELECT tenant_id FROM clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
    } else {
        sqlx::query_scalar("SELECT tenant_id FROM clients WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(actor_tenant)
            .fetch_optional(&state.pool)
            .await?
    };
    let Some(tenant_id) = client_tenant else {
        return Err(AppError::NotFound);
    };
    let actor = Uuid::parse_str(&claims.sub).ok();
    let redirect_urls = merge_redirect_urls(&req)?;
    let primary_redirect = redirect_urls[0].clone();
    let allowed_redirect: serde_json::Value = serde_json::to_value(&redirect_urls).map_err(|e| AppError::Validation(e.to_string()))?;
    let allow_registration = req.allow_user_registration.unwrap_or(false);
    let user_schema = normalized_client_schema(allow_registration, req.user_schema.as_ref())?;
    let client_id = req
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
    let scopes = req
        .scopes
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("openid profile email");
    let mfa_policy = normalize_mfa_policy(req.mfa_policy.as_deref())?;
    let allow_ctotp = req.allow_client_totp_enrollment.unwrap_or(true);

    let cur = sqlx::query(
        "SELECT COALESCE(embedded_login_enabled, false) AS embedded_login_enabled, embedded_token_audience,
                COALESCE(embedded_parent_origins, '[]'::jsonb) AS embedded_parent_origins,
                COALESCE(embedded_protocol_v2, false) AS embedded_protocol_v2,
                embedded_ui_theme
         FROM clients WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;
    let cur_en: bool = cur.try_get("embedded_login_enabled").unwrap_or(false);
    let cur_aud: Option<String> = cur.try_get("embedded_token_audience").ok().flatten();
    let cur_origins_val: serde_json::Value = cur
        .try_get("embedded_parent_origins")
        .unwrap_or_else(|_| serde_json::json!([]));
    let cur_origins: Vec<String> = serde_json::from_value(cur_origins_val).unwrap_or_default();
    let cur_v2: bool = cur.try_get("embedded_protocol_v2").unwrap_or(false);
    let cur_theme: Option<serde_json::Value> = cur.try_get("embedded_ui_theme").ok().flatten();

    let emb_en = req.embedded_login_enabled.unwrap_or(cur_en);
    let emb_origins_vec = if let Some(ref v) = req.embedded_parent_origins {
        v.clone()
    } else {
        cur_origins
    };
    validate_embedded_parent_origins(&emb_origins_vec)?;
    let emb_origins_json =
        serde_json::to_value(&emb_origins_vec).map_err(|e| AppError::Validation(e.to_string()))?;
    let emb_aud = match &req.embedded_token_audience {
        None => cur_aud,
        Some(s) if s.trim().is_empty() => None,
        Some(s) => Some(s.trim().to_string()),
    };

    let emb_v2 = req.embedded_protocol_v2.unwrap_or(cur_v2);
    let emb_theme = if req.embedded_ui_theme.is_some() {
        crate::domain::embedded_ui_theme::validate_embedded_ui_theme(req.embedded_ui_theme.as_ref())
            .map_err(AppError::Validation)?
    } else {
        cur_theme
    };

    let n = sqlx::query(
        "UPDATE clients SET client_id = $2, redirect_uri = $3, scopes = $4, allowed_redirect_uris = $5, allow_user_registration = $6, mfa_policy = $7, allow_client_totp_enrollment = $8,
            embedded_login_enabled = $10, embedded_token_audience = $11, embedded_parent_origins = $12,
            embedded_protocol_v2 = $13, embedded_ui_theme = $14
         WHERE id = $1 AND tenant_id = $9",
    )
    .bind(id)
    .bind(client_id)
    .bind(&primary_redirect)
    .bind(scopes)
    .bind(allowed_redirect)
    .bind(allow_registration)
    .bind(mfa_policy)
    .bind(allow_ctotp)
    .bind(tenant_id)
    .bind(emb_en)
    .bind(emb_aud)
    .bind(emb_origins_json)
    .bind(emb_v2)
    .bind(emb_theme)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }

    sqlx::query("DELETE FROM client_user_schema WHERE client_id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;
    for field in &user_schema {
        sqlx::query(
            "INSERT INTO client_user_schema (id, client_id, field_name, field_type, is_auth, is_required)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(&field.field_name)
        .bind(&field.field_type)
        .bind(field.is_auth)
        .bind(field.is_required)
        .execute(&state.pool)
        .await?;
    }

    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client.update",
        Some(&id.to_string()),
        Some(serde_json::json!({ "client_id": client_id, "allow_registration": allow_registration })),
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Rotate `client_secret` for a confidential OAuth client (plaintext returned once).
pub async fn rotate_client_secret(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let tenant_id: Uuid = if global {
        sqlx::query_scalar("SELECT tenant_id FROM clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?
    } else {
        sqlx::query_scalar("SELECT tenant_id FROM clients WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(actor_tenant)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?
    };
    let ctype: String = sqlx::query_scalar("SELECT COALESCE(client_type,'public')::text FROM clients WHERE id = $1")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    if ctype != "confidential" {
        return Err(AppError::Validation(
            "only confidential OAuth clients support client_secret rotation".to_string(),
        ));
    }
    let new_plain = Uuid::new_v4().to_string() + &Uuid::new_v4().to_string();
    let h = hash_password(&new_plain).map_err(AppError::Internal)?;
    let n = sqlx::query(
        "UPDATE clients SET client_secret_argon2 = $1 WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&h)
    .bind(id)
    .bind(tenant_id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    let actor = Uuid::parse_str(&claims.sub).ok();
    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client.rotate_secret",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "client_secret": new_plain,
        "message": "Store client_secret securely; it is not shown again."
    })))
}

pub async fn delete_client(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let tenant_id: Uuid = if global {
        sqlx::query_scalar("SELECT tenant_id FROM clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?
    } else {
        let row: Option<Uuid> = sqlx::query_scalar("SELECT tenant_id FROM clients WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(actor_tenant)
            .fetch_optional(&state.pool)
            .await?;
        row.ok_or(AppError::NotFound)?
    };
    let actor = Uuid::parse_str(&claims.sub).ok();

    let n = sqlx::query("DELETE FROM clients WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }

    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client.delete",
        Some(&id.to_string()),
        None,
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<UserRow>, AppError> {
    let tenant_id = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let row = if global {
        sqlx::query(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, registration_source, created_at
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, registration_source, created_at
             FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&state.pool)
        .await?
    };
    let Some(row) = row else {
        return Err(AppError::NotFound);
    };
    Ok(Json(user_row_from_pg(&row)?))
}

/// Legacy PUT: updates email only (tenant from token; **or** user’s tenant if `AUTH__GLOBAL_ADMIN_USER_IDS`).
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let user_tenant: Uuid = if global {
        sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?
    } else {
        actor_tenant
    };
    let actor = actor_user_id(&claims);
    let email = req.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::Validation("invalid email".to_string()));
    }
    let n = sqlx::query("UPDATE users SET email = $2 WHERE id = $1 AND tenant_id = $3")
        .bind(id)
        .bind(&email)
        .bind(user_tenant)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    insert_audit_log(
        &state.pool,
        user_tenant,
        actor,
        "user.update_email",
        Some(&id.to_string()),
        Some(serde_json::json!({ "email": email })),
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn patch_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchUserRequest>,
) -> Result<Json<UserRow>, AppError> {
    let actor_tenant_id = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let actor = actor_user_id(&claims);

    if req.email.is_none() && req.tenant_id.is_none() && req.is_locked.is_none() && req.is_active.is_none() {
        return Err(AppError::Validation("no fields to update".to_string()));
    }

    let row = if global {
        sqlx::query(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, registration_source, created_at
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, registration_source, created_at
             FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(actor_tenant_id)
        .fetch_optional(&state.pool)
        .await?
    };
    let Some(mut current) = row else {
        return Err(AppError::NotFound);
    };

    if let Some(new_tenant) = req.tenant_id {
        let old: Uuid = current.get("tenant_id");
        relocate_user_tenant(&state.pool, id, old, new_tenant).await?;
        insert_audit_log(
            &state.pool,
            old,
            actor,
            "user.relocate_tenant",
            Some(&id.to_string()),
            Some(serde_json::json!({ "from": old, "to": new_tenant })),
        )
        .await;
        current = sqlx::query(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, registration_source, created_at
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    }

    if let Some(email) = &req.email {
        let email = email.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(AppError::Validation("invalid email".to_string()));
        }
        let tid: Uuid = current.get("tenant_id");
        let n = sqlx::query("UPDATE users SET email = $2 WHERE id = $1 AND tenant_id = $3")
            .bind(id)
            .bind(&email)
            .bind(tid)
            .execute(&state.pool)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound);
        }
        insert_audit_log(
            &state.pool,
            tid,
            actor,
            "user.update_email",
            Some(&id.to_string()),
            Some(serde_json::json!({ "email": email })),
        )
        .await;
        current = sqlx::query(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, registration_source, created_at
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    }

    if let Some(locked) = req.is_locked {
        let tid: Uuid = current.get("tenant_id");
        if locked {
            state.user_repo.lock_user(id, tid).await?;
        } else {
            state.user_repo.unlock_user(id, tid).await?;
        }
        insert_audit_log(
            &state.pool,
            tid,
            actor,
            if locked { "user.lock" } else { "user.unlock" },
            Some(&id.to_string()),
            None,
        )
        .await;
        current = sqlx::query(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, registration_source, created_at
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    }

    if let Some(active) = req.is_active {
        let tid: Uuid = current.get("tenant_id");
        let n = sqlx::query("UPDATE users SET is_active = $2 WHERE id = $1 AND tenant_id = $3")
            .bind(id)
            .bind(active)
            .bind(tid)
            .execute(&state.pool)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound);
        }
        insert_audit_log(
            &state.pool,
            tid,
            actor,
            "user.set_active",
            Some(&id.to_string()),
            Some(serde_json::json!({ "is_active": active })),
        )
        .await;
        current = sqlx::query(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, registration_source, created_at
             FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    }

    Ok(Json(user_row_from_pg(&current)?))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let actor = actor_user_id(&claims);

    let audit_tenant = if global {
        sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?
    } else {
        actor_tenant
    };

    let n = if global {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&state.pool)
            .await?
            .rows_affected()
    } else {
        sqlx::query("DELETE FROM users WHERE id = $1 AND tenant_id = $2")
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
        audit_tenant,
        actor,
        "user.delete",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn admin_send_verification_email(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let actor = actor_user_id(&claims);
    let row = if global {
        sqlx::query("SELECT id, email, email_verified, tenant_id FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
    } else {
        sqlx::query("SELECT id, email, email_verified, tenant_id FROM users WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(actor_tenant)
            .fetch_optional(&state.pool)
            .await?
    };
    let Some(row) = row else {
        return Err(AppError::NotFound);
    };
    let tenant_id: Uuid = row.get("tenant_id");
    let verified: bool = row.get("email_verified");
    if verified {
        return Err(AppError::Validation("email is already verified".to_string()));
    }
    let email: String = row.get("email");
    state.ev.resend_registration(id, tenant_id, &email).await?;
    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "user.send_verification_email",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn admin_verify_email(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let actor = actor_user_id(&claims);
    let user_tenant: Uuid = if global {
        sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?
    } else {
        actor_tenant
    };
    let n = sqlx::query("UPDATE users SET email_verified = true WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(user_tenant)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    let _ = sqlx::query("DELETE FROM email_verifications WHERE user_id = $1")
        .bind(id)
        .execute(&state.pool)
        .await;
    insert_audit_log(
        &state.pool,
        user_tenant,
        actor,
        "user.verify_email_admin",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn admin_reset_email_verification(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor_tenant = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let actor = actor_user_id(&claims);
    let user_tenant: Uuid = if global {
        sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?
    } else {
        actor_tenant
    };
    let n = sqlx::query("UPDATE users SET email_verified = false WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(user_tenant)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    let _ = sqlx::query("DELETE FROM email_verifications WHERE user_id = $1")
        .bind(id)
        .execute(&state.pool)
        .await;
    insert_audit_log(
        &state.pool,
        user_tenant,
        actor,
        "user.reset_email_verification",
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn get_role(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let row = if global {
        sqlx::query("SELECT id, tenant_id, name FROM roles WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
    } else {
        sqlx::query("SELECT id, tenant_id, name FROM roles WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tid)
            .fetch_optional(&state.pool)
            .await?
    };
    Ok(Json(serde_json::json!({"role": row.is_some()})))
}

pub async fn update_role(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    if !global && req.tenant_id != tid {
        return Err(AppError::Forbidden);
    }
    sqlx::query("UPDATE roles SET name = $2 WHERE id = $1 AND tenant_id = $3")
        .bind(id)
        .bind(req.role_name)
        .bind(req.tenant_id)
        .execute(&state.pool)
        .await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let n = if global {
        sqlx::query("DELETE FROM roles WHERE id = $1")
            .bind(id)
            .execute(&state.pool)
            .await?
            .rows_affected()
    } else {
        sqlx::query("DELETE FROM roles WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tid)
            .execute(&state.pool)
            .await?
            .rows_affected()
    };
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn get_permission(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let row = if global {
        sqlx::query("SELECT id, tenant_id, name FROM permissions WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
    } else {
        sqlx::query("SELECT id, tenant_id, name FROM permissions WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tid)
            .fetch_optional(&state.pool)
            .await?
    };
    Ok(Json(serde_json::json!({"permission": row.is_some()})))
}

pub async fn update_permission(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    if !global && req.tenant_id != tid {
        return Err(AppError::Forbidden);
    }
    sqlx::query("UPDATE permissions SET name = $2 WHERE id = $1 AND tenant_id = $3")
        .bind(id)
        .bind(req.permission_name)
        .bind(req.tenant_id)
        .execute(&state.pool)
        .await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn delete_permission(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tid = actor_tenant(&claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);
    let n = if global {
        sqlx::query("DELETE FROM permissions WHERE id = $1")
            .bind(id)
            .execute(&state.pool)
            .await?
            .rows_affected()
    } else {
        sqlx::query("DELETE FROM permissions WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tid)
            .execute(&state.pool)
            .await?
            .rows_affected()
    };
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({"ok": true})))
}

#[derive(Debug, serde::Serialize)]
pub struct RbacEntity {
    pub id: Uuid,
    pub name: String,
    /// Set when [AUTH__GLOBAL_ADMIN_USER_IDS] is used so names from different tenants are distinguishable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, serde::Serialize)]
pub struct RbacMappingRow {
    pub role_id: Uuid,
    pub role_name: String,
    pub permission_id: Uuid,
    pub permission_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, serde::Serialize)]
pub struct RbacResponse {
    pub roles: Vec<RbacEntity>,
    pub permissions: Vec<RbacEntity>,
    pub role_permissions: Vec<RbacMappingRow>,
}

/// Full RBAC snapshot for the token tenant, or for **all** tenants if `sub` is in `AUTH__GLOBAL_ADMIN_USER_IDS`.
pub async fn get_rbac(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
) -> Result<Json<RbacResponse>, AppError> {
    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);

    let role_rows = if global {
        sqlx::query("SELECT id, name, tenant_id FROM roles ORDER BY tenant_id, name")
            .fetch_all(&state.pool)
            .await?
    } else {
        sqlx::query("SELECT id, name FROM roles WHERE tenant_id = $1 ORDER BY name")
            .bind(tenant_id)
            .fetch_all(&state.pool)
            .await?
    };
    let mut roles = Vec::with_capacity(role_rows.len());
    for row in role_rows {
        roles.push(RbacEntity {
            id: row.get("id"),
            name: row.get("name"),
            tenant_id: if global { Some(row.get("tenant_id")) } else { None },
        });
    }

    let perm_rows = if global {
        sqlx::query("SELECT id, name, tenant_id FROM permissions ORDER BY tenant_id, name")
            .fetch_all(&state.pool)
            .await?
    } else {
        sqlx::query("SELECT id, name FROM permissions WHERE tenant_id = $1 ORDER BY name")
            .bind(tenant_id)
            .fetch_all(&state.pool)
            .await?
    };
    let mut permissions = Vec::with_capacity(perm_rows.len());
    for row in perm_rows {
        permissions.push(RbacEntity {
            id: row.get("id"),
            name: row.get("name"),
            tenant_id: if global { Some(row.get("tenant_id")) } else { None },
        });
    }

    let link_rows = if global {
        sqlx::query(
            "SELECT rp.tenant_id, rp.role_id, r.name AS role_name, rp.permission_id, p.name AS permission_name
             FROM role_permissions rp
             INNER JOIN roles r ON r.id = rp.role_id AND r.tenant_id = rp.tenant_id
             INNER JOIN permissions p ON p.id = rp.permission_id AND p.tenant_id = rp.tenant_id
             ORDER BY rp.tenant_id, r.name, p.name",
        )
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT rp.role_id, r.name AS role_name, rp.permission_id, p.name AS permission_name
             FROM role_permissions rp
             INNER JOIN roles r ON r.id = rp.role_id AND r.tenant_id = rp.tenant_id
             INNER JOIN permissions p ON p.id = rp.permission_id AND p.tenant_id = rp.tenant_id
             WHERE rp.tenant_id = $1
             ORDER BY r.name, p.name",
        )
        .bind(tenant_id)
        .fetch_all(&state.pool)
        .await?
    };
    let mut role_permissions = Vec::with_capacity(link_rows.len());
    for row in link_rows {
        role_permissions.push(RbacMappingRow {
            role_id: row.get("role_id"),
            role_name: row.get("role_name"),
            permission_id: row.get("permission_id"),
            permission_name: row.get("permission_name"),
            tenant_id: if global { Some(row.get("tenant_id")) } else { None },
        });
    }

    Ok(Json(RbacResponse {
        roles,
        permissions,
        role_permissions,
    }))
}

#[derive(Debug, serde::Serialize)]
pub struct DashboardStats {
    pub user_count: i64,
    pub oauth_clients_count: i64,
    pub roles_count: i64,
    pub active_users_24h: i64,
    pub logins_last_hour: i64,
    pub auth_failures_last_hour: i64,
}

/// PostgreSQL `42P01` = undefined_table.
fn is_missing_relation(err: &SqlxError) -> bool {
    if err
        .as_database_error()
        .is_some_and(|e| e.code() == Some(std::borrow::Cow::Borrowed("42P01")))
    {
        return true;
    }
    let s = err.to_string();
    s.contains("auth_events") && s.contains("does not exist")
}

async fn event_metric_or_zero(
    pool: &PgPool,
    sql: &str,
    tenant_id: Uuid,
) -> Result<i64, AppError> {
    match sqlx::query_scalar(sql).bind(tenant_id).fetch_one(pool).await {
        Ok(n) => Ok(n),
        Err(e) if is_missing_relation(&e) => {
            tracing::info!(
                "auth_events is missing; apply backend/migrations/0002_auth_stats.sql (event metrics will show 0 until then)"
            );
            Ok(0)
        }
        Err(e) => Err(e.into()),
    }
}

async fn event_metric_all_tenants_or_zero(pool: &PgPool, sql: &str) -> Result<i64, AppError> {
    match sqlx::query_scalar(sql).fetch_one(pool).await {
        Ok(n) => Ok(n),
        Err(e) if is_missing_relation(&e) => Ok(0),
        Err(e) => Err(e.into()),
    }
}

pub async fn get_dashboard_stats(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
) -> Result<Json<DashboardStats>, AppError> {
    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);

    let (user_count, oauth_clients_count, roles_count) = if global {
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM users")
            .fetch_one(&state.pool)
            .await?;
        let oauth_clients_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM clients")
            .fetch_one(&state.pool)
            .await?;
        let roles_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM roles")
            .fetch_one(&state.pool)
            .await?;
        (user_count, oauth_clients_count, roles_count)
    } else {
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM users WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&state.pool)
            .await?;
        let oauth_clients_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM clients WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&state.pool)
            .await?;
        let roles_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM roles WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&state.pool)
            .await?;
        (user_count, oauth_clients_count, roles_count)
    };

    let active_users_24h: i64 = if global {
        event_metric_all_tenants_or_zero(
            &state.pool,
            "SELECT COUNT(DISTINCT user_id)::bigint FROM auth_events
             WHERE success = true AND user_id IS NOT NULL
               AND created_at > NOW() - INTERVAL '24 hours'",
        )
        .await?
    } else {
        event_metric_or_zero(
            &state.pool,
            "SELECT COUNT(DISTINCT user_id)::bigint FROM auth_events
             WHERE tenant_id = $1 AND success = true AND user_id IS NOT NULL
               AND created_at > NOW() - INTERVAL '24 hours'",
            tenant_id,
        )
        .await?
    };

    let logins_last_hour: i64 = if global {
        event_metric_all_tenants_or_zero(
            &state.pool,
            "SELECT COUNT(*)::bigint FROM auth_events
             WHERE success = true AND event_kind = 'password_login'
               AND created_at > NOW() - INTERVAL '1 hour'",
        )
        .await?
    } else {
        event_metric_or_zero(
            &state.pool,
            "SELECT COUNT(*)::bigint FROM auth_events
             WHERE tenant_id = $1 AND success = true AND event_kind = 'password_login'
               AND created_at > NOW() - INTERVAL '1 hour'",
            tenant_id,
        )
        .await?
    };

    let auth_failures_last_hour: i64 = if global {
        event_metric_all_tenants_or_zero(
            &state.pool,
            "SELECT COUNT(*)::bigint FROM auth_events
             WHERE success = false AND event_kind = 'password_login'
               AND created_at > NOW() - INTERVAL '1 hour'",
        )
        .await?
    } else {
        event_metric_or_zero(
            &state.pool,
            "SELECT COUNT(*)::bigint FROM auth_events
             WHERE tenant_id = $1 AND success = false AND event_kind = 'password_login'
               AND created_at > NOW() - INTERVAL '1 hour'",
            tenant_id,
        )
        .await?
    };

    Ok(Json(DashboardStats {
        user_count,
        oauth_clients_count,
        roles_count,
        active_users_24h,
        logins_last_hour,
        auth_failures_last_hour,
    }))
}

#[derive(Debug, serde::Serialize)]
pub struct UserRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub is_active: bool,
    pub is_locked: bool,
    pub email_verified: bool,
    pub totp_enabled: bool,
    pub registration_source: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Query(q): Query<ListUsersQuery>,
) -> Result<Json<Vec<UserRow>>, AppError> {
    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, &claims);

    let needle = q
        .q
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let (ord_col, ord_dir) = users_list_order_clause(q.sort.as_deref(), q.order.as_deref());

    let sql = if global {
        if needle.is_some() {
            format!(
                "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, \
                 registration_source, created_at FROM users \
                 WHERE email ILIKE $1 ORDER BY {ord_col} {ord_dir} LIMIT 500"
            )
        } else {
            format!(
                "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, \
                 registration_source, created_at FROM users \
                 ORDER BY {ord_col} {ord_dir} LIMIT 500"
            )
        }
    } else if needle.is_some() {
        format!(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, \
             registration_source, created_at FROM users \
             WHERE tenant_id = $1 AND email ILIKE $2 ORDER BY {ord_col} {ord_dir} LIMIT 500"
        )
    } else {
        format!(
            "SELECT id, tenant_id, email, is_active, is_locked, email_verified, totp_enabled, \
             registration_source, created_at FROM users \
             WHERE tenant_id = $1 ORDER BY {ord_col} {ord_dir} LIMIT 500"
        )
    };

    let rows = if global {
        if let Some(needle) = needle {
            let pattern = format!("%{needle}%");
            sqlx::query(&sql).bind(pattern).fetch_all(&state.pool).await?
        } else {
            sqlx::query(&sql).fetch_all(&state.pool).await?
        }
    } else if let Some(needle) = needle {
        let pattern = format!("%{needle}%");
        sqlx::query(&sql).bind(tenant_id).bind(pattern).fetch_all(&state.pool).await?
    } else {
        sqlx::query(&sql).bind(tenant_id).fetch_all(&state.pool).await?
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(user_row_from_pg(&row)?);
    }

    Ok(Json(out))
}

fn user_row_from_pg(row: &sqlx::postgres::PgRow) -> Result<UserRow, AppError> {
    Ok(UserRow {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        email: row.get("email"),
        is_active: row.get("is_active"),
        is_locked: row.get("is_locked"),
        email_verified: row.get("email_verified"),
        totp_enabled: row.get("totp_enabled"),
        registration_source: row
            .try_get::<String, _>("registration_source")
            .unwrap_or_else(|_| "unknown".to_string()),
        created_at: row.get("created_at"),
    })
}

// ---- Admin: per-OAuth-client TOTP for a user (Google Authenticator) ----

async fn client_row_tenant_for_admin(
    pool: &PgPool,
    state: &AppState,
    claims: &AccessClaims,
    client_row_id: Uuid,
) -> Result<Uuid, AppError> {
    let actor_tenant = actor_tenant(claims)?;
    let global = crate::http::handlers::admin_scope::is_deployment_global_admin(&state.config, claims);
    if global {
        sqlx::query_scalar("SELECT tenant_id FROM clients WHERE id = $1")
            .bind(client_row_id)
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound)
    } else {
        sqlx::query_scalar("SELECT tenant_id FROM clients WHERE id = $1 AND tenant_id = $2")
            .bind(client_row_id)
            .bind(actor_tenant)
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound)
    }
}

/// GET /admin/clients/:client_row_id/users/:user_id/2fa
pub async fn admin_client_user_2fa_status(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path((client_row_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = client_row_tenant_for_admin(&state.pool, &state, &claims, client_row_id).await?;
    let u_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;
    if !u_exists {
        return Err(AppError::NotFound);
    }
    let client_totp_enabled = state
        .totp
        .is_client_totp_enabled(user_id, tenant_id, client_row_id)
        .await?;
    Ok(Json(serde_json::json!({ "client_totp_enabled": client_totp_enabled })))
}

/// POST /admin/clients/:client_row_id/users/:user_id/2fa/setup
pub async fn admin_client_user_2fa_setup(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path((client_row_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = client_row_tenant_for_admin(&state.pool, &state, &claims, client_row_id).await?;
    let actor = Uuid::parse_str(&claims.sub).ok();
    let public: String = sqlx::query_scalar("SELECT client_id::text FROM clients WHERE id = $1")
        .bind(client_row_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
    let u_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;
    if !u_exists {
        return Err(AppError::NotFound);
    }
    let (url, base32) = state
        .totp
        .begin_client_setup(user_id, tenant_id, client_row_id, &public)
        .await?;
    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client_mfa.admin_setup",
        Some(&client_row_id.to_string()),
        Some(serde_json::json!({ "user_id": user_id, "oauth_client_id": public })),
    )
    .await;
    Ok(Json(serde_json::json!({
        "otpauth_url": url,
        "secret_base32": base32,
    })))
}

#[derive(Debug, Deserialize)]
pub struct AdminClient2faCode {
    pub code: String,
}

/// POST /admin/clients/:client_row_id/users/:user_id/2fa/verify
pub async fn admin_client_user_2fa_verify(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path((client_row_id, user_id)): Path<(Uuid, Uuid)>,
    Json(b): Json<AdminClient2faCode>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = client_row_tenant_for_admin(&state.pool, &state, &claims, client_row_id).await?;
    let actor = Uuid::parse_str(&claims.sub).ok();
    let public: String = sqlx::query_scalar("SELECT client_id::text FROM clients WHERE id = $1")
        .bind(client_row_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
    let u_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;
    if !u_exists {
        return Err(AppError::NotFound);
    }
    state
        .totp
        .complete_client_setup(user_id, tenant_id, client_row_id, &public, &b.code)
        .await?;
    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client_mfa.admin_verify",
        Some(&client_row_id.to_string()),
        Some(serde_json::json!({ "user_id": user_id })),
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true, "client_totp_enabled": true })))
}

/// POST /admin/clients/:client_row_id/users/:user_id/2fa/disable
pub async fn admin_client_user_2fa_disable(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AccessClaims>,
    Path((client_row_id, user_id)): Path<(Uuid, Uuid)>,
    Json(b): Json<AdminClient2faCode>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tenant_id = client_row_tenant_for_admin(&state.pool, &state, &claims, client_row_id).await?;
    let actor = Uuid::parse_str(&claims.sub).ok();
    let public: String = sqlx::query_scalar("SELECT client_id::text FROM clients WHERE id = $1")
        .bind(client_row_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
    let u_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;
    if !u_exists {
        return Err(AppError::NotFound);
    }
    state
        .totp
        .disable_client(user_id, tenant_id, client_row_id, &public, &b.code)
        .await?;
    insert_audit_log(
        &state.pool,
        tenant_id,
        actor,
        "client_mfa.admin_disable",
        Some(&client_row_id.to_string()),
        Some(serde_json::json!({ "user_id": user_id })),
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true, "client_totp_enabled": false })))
}
