//! Embedded iframe login: `GET /embedded-login`, `POST /api/login`,
//! `POST /api/register`, `POST /api/register/verify-email`, `POST /api/register/resend-code`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::header::{HOST, ORIGIN, REFERER, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::security::password;
use crate::services::app_state::AppState;
use crate::services::auth_service::{LoginCommand, LoginResult, RegisterCommand};
use crate::services::errors::AppError;

use super::qr_svg::otpauth_url_qr_svg_base64;

const CSRF_COOKIE: &str = "embedded_csrf";
const CSRF_TTL_SECS: i64 = 1800;

#[derive(Debug, Deserialize)]
pub struct EmbeddedLoginQuery {
    pub client_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EmbeddedLoginBody {
    pub email: String,
    pub password: String,
    pub client_id: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct EmbeddedSessionCodeBody {
    /// Short-lived `access_token` from `POST /api/login` (iframe-only).
    pub access_token: String,
    pub client_id: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct EmbeddedRegisterBody {
    pub email: String,
    pub password: String,
    pub client_id: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct EmbeddedRegisterVerifyBody {
    pub client_id: String,
    pub csrf_token: String,
    pub code: String,
    pub email_verification_token: String,
}

#[derive(Debug, Deserialize)]
pub struct EmbeddedRegisterResendBody {
    pub client_id: String,
    pub csrf_token: String,
    pub email_verification_token: String,
}

#[derive(Debug, Deserialize)]
pub struct EmbeddedRegisterTotpSetupBody {
    pub client_id: String,
    pub csrf_token: String,
    pub enrollment_token: String,
}

#[derive(Debug, Deserialize)]
pub struct EmbeddedRegisterTotpVerifyBody {
    pub client_id: String,
    pub csrf_token: String,
    pub enrollment_token: String,
    pub code: String,
}

#[derive(Debug, Clone)]
struct EmbeddedClient {
    client_row_id: Uuid,
    tenant_id: Uuid,
    client_id: String,
    token_audience: String,
    parent_origins: Vec<String>,
    allow_user_registration: bool,
    mfa_policy: String,
    allow_client_totp_enrollment: bool,
    /// When true, use v1 envelope + INIT/EMBED_READY; legacy flat AUTH_* otherwise.
    protocol_v2: bool,
    /// Validated design tokens; may be `None`.
    ui_theme: Option<serde_json::Value>,
}

enum EmbeddedResolve {
    /// No row with this public `client_id`.
    UnknownClient,
    /// Client exists but `embedded_login_enabled` is false.
    Disabled,
    Ok(EmbeddedClient),
}

fn parse_site_origin(url_str: &str) -> Option<String> {
    let u = url::Url::parse(url_str.trim()).ok()?;
    let scheme = u.scheme();
    let host = u.host_str()?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let def_port: u16 = if scheme == "https" { 443 } else { 80 };
    let port = u.port().unwrap_or(def_port);
    if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        Some(format!("{scheme}://{host}"))
    } else {
        Some(format!("{scheme}://{host}:{port}"))
    }
}

fn request_parent_origin(headers: &HeaderMap) -> Option<String> {
    if let Some(o) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
        let t = o.trim();
        if !t.is_empty() && t != "null" {
            return parse_site_origin(t).or_else(|| Some(t.to_string()));
        }
    }
    if let Some(r) = headers.get(REFERER).and_then(|v| v.to_str().ok()) {
        return parse_site_origin(r);
    }
    None
}

/// Exact match, or `https://*.example.com` style suffix for one subdomain level.
fn origin_allowed(site: &str, pattern: &str) -> bool {
    let site = site.trim_end_matches('/');
    let pattern = pattern.trim_end_matches('/');
    if site == pattern {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("https://*.") {
        let rest = suffix.trim_start_matches('.');
        if let Some(host_part) = site.strip_prefix("https://") {
            let host = host_part.split('/').next().unwrap_or(host_part);
            let host = host.split(':').next().unwrap_or(host);
            if host == rest || host.ends_with(&format!(".{rest}")) {
                return true;
            }
        }
    }
    if let Some(suffix) = pattern.strip_prefix("http://*.") {
        let rest = suffix.trim_start_matches('.');
        if let Some(host_part) = site.strip_prefix("http://") {
            let host = host_part.split('/').next().unwrap_or(host_part);
            let host = host.split(':').next().unwrap_or(host);
            if host == rest || host.ends_with(&format!(".{rest}")) {
                return true;
            }
        }
    }
    false
}

fn parent_origin_ok(site: Option<&str>, allowed: &[String], relax: bool) -> bool {
    if relax {
        return true;
    }
    if allowed.is_empty() {
        return false;
    }
    let Some(site) = site.filter(|s| !s.is_empty()) else {
        return false;
    };
    allowed.iter().any(|p| origin_allowed(site, p))
}

/// `fetch()` from JS inside the iframe sends `Origin: <auth service>` (the frame URL), not the parent app.
/// Parent origins list the embedding app (e.g. `http://127.0.0.1:9999`), so API POSTs would fail without this.
fn origin_same_as_request_host(site: &str, host_header: Option<&str>) -> bool {
    let Some(hh) = host_header.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let Ok(origin_u) = url::Url::parse(site) else {
        return false;
    };
    let Ok(host_u) = url::Url::parse(&format!("{}://{}/", origin_u.scheme(), hh)) else {
        return false;
    };
    origin_u.scheme() == host_u.scheme()
        && origin_u.host() == host_u.host()
        && origin_u.port_or_known_default() == host_u.port_or_known_default()
}

fn origin_matches_issuer(site: &str, issuer: &str) -> bool {
    let Some(iss_norm) = parse_site_origin(issuer.trim()) else {
        return false;
    };
    let site = site.trim_end_matches('/');
    let iss_norm = iss_norm.trim_end_matches('/');
    site == iss_norm || origin_allowed(site, issuer.trim())
}

/// Parent allowlist **or** request from the auth service document (`Origin` matches `Host`), **or** `SERVER__ISSUER`.
fn embedded_origin_allowed(
    headers: &HeaderMap,
    reported: Option<&str>,
    parent_origins: &[String],
    relax: bool,
    issuer: &str,
) -> bool {
    if relax {
        return true;
    }
    if parent_origin_ok(reported, parent_origins, false) {
        return true;
    }
    let Some(site) = reported.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let host_hdr = headers.get(HOST).and_then(|v| v.to_str().ok());
    if origin_same_as_request_host(site, host_hdr) {
        return true;
    }
    origin_matches_issuer(site, issuer)
}

fn escape_html_text(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

fn build_frame_ancestors_csp(include_self: bool, origins: &[String]) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if include_self {
        parts.push("'self'");
    }
    for o in origins {
        let t = o.trim();
        if !t.is_empty() {
            parts.push(t);
        }
    }
    if parts.is_empty() {
        parts.push("'none'");
    }
    format!("frame-ancestors {}", parts.join(" "))
}

fn csrf_redis_key(state: &AppState, token: &str) -> String {
    state.config.redis.key(&format!("embedded_csrf:{token}"))
}

fn ip_limit_redis_key(state: &AppState, ip: &str) -> String {
    state.config.redis.key(&format!("embedded_login:ip:{ip}"))
}

fn client_ip(headers: &HeaderMap, conn: Option<SocketAddr>, trust_x_forwarded_for: bool) -> String {
    if trust_x_forwarded_for {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                let t = first.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
    }
    conn.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn resolve_embedded_client(
    pool: &sqlx::PgPool,
    public_client_id: &str,
) -> Result<EmbeddedResolve, AppError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, client_id,
                COALESCE(embedded_login_enabled, false) AS embedded_login_enabled,
                COALESCE(allow_user_registration, false) AS allow_user_registration,
                COALESCE(mfa_policy, 'off') AS mfa_policy,
                COALESCE(allow_client_totp_enrollment, true) AS allow_client_totp_enrollment,
                embedded_token_audience,
                COALESCE(embedded_parent_origins, '[]'::jsonb) AS embedded_parent_origins,
                COALESCE(embedded_protocol_v2, false) AS embedded_protocol_v2,
                embedded_ui_theme
         FROM clients WHERE client_id = $1",
    )
    .bind(public_client_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(EmbeddedResolve::UnknownClient);
    };

    let enabled: bool = row.try_get("embedded_login_enabled").unwrap_or(false);
    if !enabled {
        return Ok(EmbeddedResolve::Disabled);
    }

    let client_row_id: Uuid = row.get("id");
    let tenant_id: Uuid = row.get("tenant_id");
    let client_id: String = row.get("client_id");
    let aud_override: Option<String> = row.try_get("embedded_token_audience").ok().flatten();
    let token_audience = aud_override
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| client_id.clone());

    let origins_json: serde_json::Value = row
        .try_get("embedded_parent_origins")
        .unwrap_or_else(|_| json!([]));
    let parent_origins: Vec<String> = serde_json::from_value(origins_json).unwrap_or_default();
    let allow_user_registration: bool = row.try_get("allow_user_registration").unwrap_or(false);
    let mfa_policy: String = row
        .try_get::<String, _>("mfa_policy")
        .unwrap_or_else(|_| "off".to_string());
    let allow_client_totp_enrollment: bool =
        row.try_get("allow_client_totp_enrollment").unwrap_or(true);
    let protocol_v2: bool = row.try_get("embedded_protocol_v2").unwrap_or(false);
    let ui_theme: Option<serde_json::Value> = row
        .try_get::<serde_json::Value, _>("embedded_ui_theme")
        .ok()
        .and_then(|v| if v.is_null() { None } else { Some(v) });

    Ok(EmbeddedResolve::Ok(EmbeddedClient {
        client_row_id,
        tenant_id,
        client_id,
        token_audience,
        parent_origins,
        allow_user_registration,
        mfa_policy,
        allow_client_totp_enrollment,
        protocol_v2,
        ui_theme,
    }))
}

fn json_err(code: &str, status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message, "code": code }))).into_response()
}

fn map_app_error(e: AppError) -> Response {
    match e {
        AppError::Unauthorized => json_err(
            "INVALID_CREDENTIALS",
            StatusCode::UNAUTHORIZED,
            "invalid credentials",
        ),
        AppError::Forbidden => json_err("FORBIDDEN", StatusCode::FORBIDDEN, "forbidden"),
        AppError::ForbiddenWithReason(msg) => json_err("FORBIDDEN", StatusCode::FORBIDDEN, &msg),
        AppError::NotFound => json_err("NOT_FOUND", StatusCode::NOT_FOUND, "not found"),
        AppError::Validation(msg) => json_err("VALIDATION_ERROR", StatusCode::BAD_REQUEST, &msg),
        _ => json_err(
            "INTERNAL_ERROR",
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        ),
    }
}

#[derive(Debug)]
struct EmbeddedValidated {
    ec: EmbeddedClient,
}

async fn delete_embedded_csrf_redis(state: &Arc<AppState>, csrf_token: &str) {
    let t = csrf_token.trim();
    if t.is_empty() {
        return;
    }
    let key = csrf_redis_key(state.as_ref(), t);
    let mut r = state.auth.redis.clone();
    let _: Result<(), _> = r.del::<_, ()>(&key).await;
}

fn cookie_csrf_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            for part in raw.split(';') {
                let p = part.trim();
                if let Some(rest) = p.strip_prefix(CSRF_COOKIE) {
                    if let Some(v) = rest.strip_prefix('=') {
                        return Some(v.trim().to_string());
                    }
                }
            }
            None
        })
}

fn map_embedded_register_error(e: AppError) -> Response {
    match e {
        AppError::Validation(msg) => json_err("VALIDATION_ERROR", StatusCode::BAD_REQUEST, &msg),
        AppError::Unauthorized => json_err(
            "VERIFY_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid or expired verification token",
        ),
        AppError::Database(ref err) => {
            if let Some(db) = err.as_database_error() {
                if db.code().as_deref() == Some("23505") {
                    return json_err(
                        "EMAIL_EXISTS",
                        StatusCode::CONFLICT,
                        "email already registered",
                    );
                }
            }
            map_app_error(e)
        }
        _ => map_app_error(e),
    }
}

async fn check_ip_limit(state: &AppState, ip: &str) -> Result<(), Response> {
    let max = state.config.auth.embedded_login_ip_max_attempts;
    if max == 0 {
        return Ok(());
    }
    let win = state.config.auth.embedded_login_ip_window_seconds.max(1);
    let key = ip_limit_redis_key(state, ip);
    let mut r = state.auth.redis.clone();
    let n: i64 = r.incr(&key, 1).await.map_err(|_| {
        json_err(
            "INTERNAL_ERROR",
            StatusCode::INTERNAL_SERVER_ERROR,
            "redis error",
        )
    })?;
    if n == 1 {
        let _: Result<(), _> = r.expire(&key, win as i64).await;
    }
    if n > max as i64 {
        return Err(json_err(
            "RATE_LIMITED",
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests",
        ));
    }
    Ok(())
}

/// Shared checks for embedded JSON POSTs: IP limit, CSRF cookie+body, Redis binding, client resolve, parent origin.
/// When `consume_csrf` is `true`, the CSRF Redis key is deleted (one-shot, e.g. login or verify complete).
async fn validate_embedded_csrf_and_origin(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    conn: Option<SocketAddr>,
    client_id: &str,
    csrf_body: &str,
    consume_csrf: bool,
) -> Result<EmbeddedValidated, Response> {
    let ip = client_ip(headers, conn, state.config.auth.trust_x_forwarded_for);
    if let Err(resp) = check_ip_limit(state, &ip).await {
        return Err(resp);
    }

    let client_id = client_id.trim();
    if client_id.is_empty() || csrf_body.trim().is_empty() {
        return Err(json_err(
            "VALIDATION_ERROR",
            StatusCode::BAD_REQUEST,
            "client_id and csrf_token are required",
        ));
    }

    let Some(ct) = cookie_csrf_token(headers).filter(|t| !t.is_empty()) else {
        return Err(json_err(
            "CSRF_INVALID",
            StatusCode::FORBIDDEN,
            "missing csrf cookie",
        ));
    };

    if ct != csrf_body.trim() {
        return Err(json_err(
            "CSRF_INVALID",
            StatusCode::FORBIDDEN,
            "csrf mismatch",
        ));
    }

    let mut rconn = state.auth.redis.clone();
    let key = csrf_redis_key(state.as_ref(), &ct);
    let bound: Option<String> = rconn.get(&key).await.map_err(|_| {
        json_err(
            "INTERNAL_ERROR",
            StatusCode::INTERNAL_SERVER_ERROR,
            "redis error",
        )
    })?;

    let Some(bound_cid) = bound.filter(|s| !s.is_empty()) else {
        return Err(json_err(
            "CSRF_INVALID",
            StatusCode::FORBIDDEN,
            "invalid or expired csrf",
        ));
    };

    if bound_cid != client_id {
        return Err(json_err(
            "CSRF_INVALID",
            StatusCode::FORBIDDEN,
            "csrf client mismatch",
        ));
    }

    let ec = match resolve_embedded_client(&state.pool, client_id)
        .await
        .map_err(|_| {
            json_err(
                "INTERNAL_ERROR",
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
            )
        })? {
        EmbeddedResolve::UnknownClient => {
            return Err(json_err(
                "UNKNOWN_CLIENT",
                StatusCode::NOT_FOUND,
                "unknown OAuth client_id",
            ));
        }
        EmbeddedResolve::Disabled => {
            return Err(json_err(
                "EMBEDDED_DISABLED",
                StatusCode::FORBIDDEN,
                "embedded iframe login is disabled for this client; enable it in admin",
            ));
        }
        EmbeddedResolve::Ok(ec) => ec,
    };

    let reported = request_parent_origin(headers);
    let relax = state.config.auth.embedded_relax_parent_origin_check;
    if !embedded_origin_allowed(
        headers,
        reported.as_deref(),
        &ec.parent_origins,
        relax,
        state.config.server.issuer.as_str(),
    ) {
        return Err(json_err(
            "ORIGIN_FORBIDDEN",
            StatusCode::FORBIDDEN,
            "origin not allowed",
        ));
    }

    if consume_csrf {
        let _: Result<(), _> = rconn.del::<_, ()>(&key).await;
    }

    Ok(EmbeddedValidated { ec })
}

/// `GET /embedded-login?client_id=...`
pub async fn embedded_login_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<EmbeddedLoginQuery>,
) -> Result<Response, AppError> {
    let client_id = q.client_id.trim();
    if client_id.is_empty() {
        return Ok(json_err(
            "VALIDATION_ERROR",
            StatusCode::BAD_REQUEST,
            "client_id is required",
        ));
    }

    let ec = match resolve_embedded_client(&state.pool, client_id).await? {
        EmbeddedResolve::UnknownClient => {
            let safe = escape_html_text(client_id);
            let body = format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Embedded login</title></head><body>
<p><strong>Unknown OAuth client_id.</strong></p>
<p>Received <code>client_id</code>: <code>{safe}</code> (length {} UTF-8 bytes).</p>
<p>Typical causes: this Auth Service process uses a <strong>different Postgres</strong> than the admin UI / <code>DATABASE__URL</code> where the client was created; typo; or invisible characters when pasting the id.</p>
<p>Verify in SQL on the <strong>same</strong> database as this server: <code>SELECT client_id FROM clients WHERE client_id = '{safe}';</code></p>
</body></html>"#,
                client_id.len(),
            );
            return Ok((StatusCode::NOT_FOUND, Html(body)).into_response());
        }
        EmbeddedResolve::Disabled => {
            let body = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Embedded login</title></head><body>
<p><strong>Embedded iframe login is disabled</strong> for this OAuth client.</p>
<p>In the admin dashboard, open the client, enable <strong>Embedded iframe login</strong>, add <strong>Parent origins</strong>
(including your app’s origin and the Auth UI origin, e.g. <code>http://localhost:8080</code>), then save.</p>
</body></html>"#;
            return Ok((StatusCode::FORBIDDEN, Html(body)).into_response());
        }
        EmbeddedResolve::Ok(ec) => ec,
    };

    let reported = request_parent_origin(&headers);
    let relax = state.config.auth.embedded_relax_parent_origin_check;
    if !embedded_origin_allowed(
        &headers,
        reported.as_deref(),
        &ec.parent_origins,
        relax,
        state.config.server.issuer.as_str(),
    ) {
        let reported_dbg = reported
            .as_deref()
            .map(escape_html_text)
            .unwrap_or_else(|| {
                "(none — open the auth page only inside your app’s iframe, not in a new tab)"
                    .to_string()
            });
        let origins_list = ec
            .parent_origins
            .iter()
            .map(|s| format!("<li><code>{}</code></li>", escape_html_text(s)))
            .collect::<String>();
        let body = format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Embedded login</title></head><body>
<p><strong>Referer/Origin check failed.</strong></p>
<p>This request’s parent context was parsed as: <code>{reported_dbg}</code></p>
<p>The check uses the <strong>embedding page</strong> (e.g. <code>http://localhost:9999</code>), <em>not</em> the Auth Service URL (<code>http://localhost:8080</code>).
Add your demo app’s exact origin(s) under OAuth client <strong>Parent origins</strong> in the admin UI, for example:</p>
<ul>
<li><code>http://localhost:9999</code> and <code>http://127.0.0.1:9999</code> (both if you switch hostnames)</li>
<li><code>http://localhost:8080</code> (for CSP / framing — keep this too)</li>
</ul>
<p>Configured allowlist for this client:</p>
<ul>{origins_list}</ul>
<p>Local dev only: set <code>AUTH__EMBEDDED_RELAX_PARENT_ORIGIN_CHECK=true</code> on Auth Service to skip this check.</p>
</body></html>"#
        );
        return Ok((StatusCode::FORBIDDEN, Html(body)).into_response());
    }

    let csp = build_frame_ancestors_csp(
        state.config.auth.embedded_csp_include_self,
        &ec.parent_origins,
    );
    let csp_h =
        HeaderValue::from_str(&csp).map_err(|_| AppError::Internal("invalid CSP".to_string()))?;

    let csrf = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let mut rconn = state.auth.redis.clone();
    let key = csrf_redis_key(state.as_ref(), &csrf);
    let _: () = rconn
        .set_ex(&key, ec.client_id.as_str(), CSRF_TTL_SECS as u64)
        .await?;

    let secure = state.config.embedded_csrf_cookie_secure();
    let cookie_val = format!(
        "{CSRF_COOKIE}={csrf}; Path=/; HttpOnly; SameSite=Lax; Max-Age={CSRF_TTL_SECS}{}",
        if secure { "; Secure" } else { "" }
    );
    let cookie_h = HeaderValue::from_str(&cookie_val)
        .map_err(|_| AppError::Internal("invalid Set-Cookie".to_string()))?;

    let post_targets: Vec<String> = ec.parent_origins.clone();
    let target_origin = reported
        .clone()
        .or_else(|| ec.parent_origins.first().cloned());

    let cfg = json!({
        "client_id": ec.client_id,
        "csrf_token": csrf,
        "registration_enabled": ec.allow_user_registration,
        "client_mfa_required": ec.mfa_policy == "required",
        "allowed_parent_origins": ec.parent_origins,
        "post_message_targets": post_targets,
        "referrer_origin": reported,
        "target_origin": target_origin,
        "protocol_v2": ec.protocol_v2,
        "initial_theme": ec.ui_theme.clone().unwrap_or(serde_json::Value::Null),
    });
    let cfg_json = serde_json::to_string(&cfg).map_err(|e| AppError::Internal(e.to_string()))?;

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account</title>
  <style>
    :root {{
      --idp-color-primary: #0f3d8a;
      --idp-color-on-primary: #fff;
      --idp-color-bg: #fff;
      --idp-color-surface: #f3f3f3;
      --idp-color-error: #b00020;
      --idp-radius-md: 4px;
      --idp-space-md: 12px;
      --idp-font: system-ui, sans-serif;
    }}
    html.idp-scheme-dark {{
      --idp-color-bg: #121212;
      --idp-color-surface: #1e1e1e;
      --idp-color-on-primary: #fff;
    }}
    body {{ font-family: var(--idp-font); margin: 1rem; max-width: 22rem; background: var(--idp-color-bg); color: #111; }}
    html.idp-scheme-dark body {{ color: #eee; }}
    label {{ display: block; margin-top: 0.75rem; font-size: 0.875rem; }}
    input {{ width: 100%; box-sizing: border-box; margin-top: 0.25rem; padding: 0.5rem; border-radius: var(--idp-radius-md); }}
    button {{ margin-top: 1rem; width: 100%; padding: 0.6rem; cursor: pointer; background: var(--idp-color-primary); color: var(--idp-color-on-primary); border: none; border-radius: var(--idp-radius-md); }}
    .err {{ color: var(--idp-color-error); font-size: 0.875rem; margin-top: 0.5rem; }}
    #mfa {{ display: none; margin-top: 1rem; }}
    .tabs {{ display: flex; gap: 0.35rem; margin: 0.75rem 0 0.25rem; }}
    .tab {{ flex: 1; padding: 0.45rem 0.35rem; border: 1px solid #ccc; background: var(--idp-color-surface); cursor: pointer; font-size: 0.875rem; border-radius: var(--idp-radius-md); }}
    .tab.active {{ background: var(--idp-color-bg); border-color: #888; font-weight: 600; }}
    .panel {{ display: none; }}
    .panel.active {{ display: block; }}
    .hint {{ font-size: 0.8rem; color: #555; margin-top: 0.5rem; }}
  </style>
</head>
<body>
  <h1>Account</h1>
  <div id="tabs" class="tabs" style="display:none">
    <button type="button" class="tab active" id="tabLogin">Login</button>
    <button type="button" class="tab" id="tabRegister" style="display:none">Register</button>
  </div>
  <div id="err" class="err" role="alert"></div>

  <div id="loginPanel" class="panel active">
    <form id="f">
      <label>Email<input type="email" name="email" autocomplete="username" required></label>
      <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
      <button type="submit">Continue</button>
    </form>
    <div id="mfa">
      <label>Authenticator code<input type="text" name="totp" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code"></label>
      <button type="button" id="mfaBtn">Verify</button>
    </div>
  </div>

  <div id="registerPanel" class="panel">
    <form id="rf">
      <label>Email<input type="email" name="email" autocomplete="email" required></label>
      <label>Password<input type="password" name="password" autocomplete="new-password" required minlength="10"></label>
      <p class="hint">Minimum 10 characters. We will email a 6-digit code.</p>
      <button type="submit">Create account</button>
    </form>
  </div>

  <div id="verifyPanel" class="panel">
    <p class="hint">Enter the code sent to your email.</p>
    <form id="vf">
      <label>Code<input type="text" name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code" required></label>
      <button type="submit">Verify &amp; sign in</button>
    </form>
    <button type="button" id="resendBtn">Resend code</button>
  </div>

  <div id="loginCtePanel" class="panel">
    <p class="hint" id="loginCteTitle">2FA is required. We sent a 6-digit code to your email. Enter it to set up the Authenticator.</p>
    <form id="lcef">
      <label>Email code<input type="text" name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code" required></label>
      <button type="submit">Continue</button>
    </form>
    <button type="button" id="loginCteResendBtn">Resend code</button>
  </div>

  <div id="totpRegPanel" class="panel">
    <p class="hint" id="totpRegTitle"><strong>Authenticator</strong> is required for this client. Scan the QR or use the secret, then enter a 6-digit code.</p>
    <p id="totpRegHint" class="hint"></p>
    <img id="totpRegQr" alt="Scan this QR code with your authenticator app" width="200" height="200"
      style="display:none;max-width:100%;height:auto;image-rendering:pixelated;border:1px solid #ddd;border-radius:4px;margin:0.5rem 0;" />
    <pre id="totpRegSecret" style="font-size:0.72rem;white-space:pre-wrap;word-break:break-all;margin:0.5rem 0;"></pre>
    <form id="tf">
      <label>Authenticator code<input type="text" name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code" required></label>
      <button type="submit">Complete registration</button>
    </form>
  </div>

  <script>
(function() {{
  const CFG = {cfg_json};
  let stepUpToken = null;
  let regEvToken = null;
  let regEnrollToken = null;
  var isLoginCte = false;
  var loginCteEmailToken = null;

  function parentTarget() {{
    if (CFG.target_origin) return CFG.target_origin;
    try {{
      if (document.referrer) return new URL(document.referrer).origin;
    }} catch (e) {{}}
    return CFG.post_message_targets[0] || '*';
  }}
  function sendToParent(payload) {{
    const t = parentTarget();
    if (window.parent) window.parent.postMessage(payload, t);
  }}
  function v2Envelope(type, extra) {{
    const o = {{
      v: 1,
      type: type,
      ts: Math.floor(Date.now() / 1000),
      source: 'auth_iframe',
      nonce: (window.crypto && window.crypto.randomUUID) ? window.crypto.randomUUID() : (String(Math.random()) + String(Date.now()))
    }};
    if (extra) {{
      for (const k in extra) {{
        if (Object.prototype.hasOwnProperty.call(extra, k)) o[k] = extra[k];
      }}
    }}
    return o;
  }}
  function postOk(data) {{
    if (CFG.protocol_v2) {{
      const typ = data.type;
      const rest = {{}};
      for (const k in data) {{ if (k !== 'type') rest[k] = data[k]; }}
      sendToParent(v2Envelope(typ, rest));
    }} else {{
      sendToParent(data);
    }}
  }}
  function postErr(code, msg) {{
    if (CFG.protocol_v2) sendToParent(v2Envelope('AUTH_ERROR', {{ error: code, message: msg || '' }}));
    else sendToParent({{ type: 'AUTH_ERROR', error: code, message: msg || '' }});
  }}
  function showErr(m) {{
    document.getElementById('err').textContent = m || '';
  }}

  const tabsEl = document.getElementById('tabs');
  const tabLogin = document.getElementById('tabLogin');
  const tabRegister = document.getElementById('tabRegister');
  const loginPanel = document.getElementById('loginPanel');
  const registerPanel = document.getElementById('registerPanel');
  const verifyPanel = document.getElementById('verifyPanel');
  const loginCtePanel = document.getElementById('loginCtePanel');
  const totpRegPanel = document.getElementById('totpRegPanel');

  function showPanel(name) {{
    loginPanel.classList.toggle('active', name === 'login');
    registerPanel.classList.toggle('active', name === 'register');
    verifyPanel.classList.toggle('active', name === 'verify');
    loginCtePanel.classList.toggle('active', name === 'loginCte');
    totpRegPanel.classList.toggle('active', name === 'totpReg');
    tabLogin.classList.toggle('active', name === 'login');
    tabRegister.classList.toggle('active', name === 'register');
  }}

  async function runTotpSetup() {{
    if (!regEnrollToken) return;
    showErr('');
    document.getElementById('totpRegHint').textContent = '';
    document.getElementById('totpRegSecret').textContent = '';
    const totpRegQr = document.getElementById('totpRegQr');
    totpRegQr.removeAttribute('src');
    totpRegQr.style.display = 'none';
    const totpPath = isLoginCte ? '/api/login/client-totp-enroll/setup' : '/api/register/client-totp/setup';
    try {{
      const res = await fetch(totpPath, {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          client_id: CFG.client_id,
          csrf_token: CFG.csrf_token,
          enrollment_token: regEnrollToken
        }})
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.otpauth_url) {{
        const hint = document.getElementById('totpRegHint');
        hint.innerHTML = 'Open your authenticator app: <a href=\"' + data.otpauth_url + '\" target=\"_blank\" rel=\"noopener\">add account (opens app)</a>';
        if (data.qr_svg_base64) {{
          totpRegQr.src = 'data:image/svg+xml;base64,' + data.qr_svg_base64;
          totpRegQr.style.display = 'block';
        }}
        if (data.secret_base32) {{
          document.getElementById('totpRegSecret').textContent = 'Secret (base32): ' + data.secret_base32;
        }}
        return;
      }}
      const code = data.code || 'SETUP_FAILED';
      postErr(code, data.error || '');
      showErr(data.error || code);
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
      showErr('Network error');
    }}
  }}

  if (CFG.registration_enabled) {{
    tabsEl.style.display = 'flex';
    tabRegister.style.display = 'block';
  }}

  tabLogin.addEventListener('click', function() {{
    showErr('');
    isLoginCte = false;
    loginCteEmailToken = null;
    showPanel('login');
  }});
  tabRegister.addEventListener('click', function() {{
    if (!CFG.registration_enabled) return;
    showErr('');
    isLoginCte = false;
    loginCteEmailToken = null;
    regEvToken = null;
    regEnrollToken = null;
    showPanel('register');
  }});

  const f = document.getElementById('f');
  const mfa = document.getElementById('mfa');
  f.addEventListener('submit', async function(ev) {{
    ev.preventDefault();
    showErr('');
    const fd = new FormData(f);
    const body = {{
      email: (fd.get('email') || '').toString().trim(),
      password: (fd.get('password') || '').toString(),
      client_id: CFG.client_id,
      csrf_token: CFG.csrf_token
    }};
    try {{
      const res = await fetch('/api/login', {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.access_token) {{
        postOk({{ type: 'AUTH_SUCCESS', access_token: data.access_token, expires_in: data.expires_in }});
        showErr('Signed in. You can close this window.');
        return;
      }}
      if (data.client_totp_enroll_email_required && data.email_verification_token) {{
        isLoginCte = true;
        loginCteEmailToken = data.email_verification_token;
        f.style.display = 'none';
        mfa.style.display = 'none';
        showPanel('loginCte');
        showErr('Check your email for the 6-digit code.');
        return;
      }}
      if (data.mfa_required && data.step_up_token) {{
        stepUpToken = data.step_up_token;
        f.style.display = 'none';
        mfa.style.display = 'block';
        return;
      }}
      if (data.totp_enrollment_required) {{
        postErr('TOTP_ENROLLMENT_REQUIRED', 'Complete two-factor enrollment in the admin app.');
        showErr('Enrollment required.');
        return;
      }}
      const code = data.code || 'AUTH_ERROR';
      postErr(code, data.error || '');
      showErr(data.error || code);
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
      showErr('Network error');
    }}
  }});
  document.getElementById('mfaBtn').addEventListener('click', async function() {{
    const totp = (document.querySelector('#mfa input[name=totp]') || {{ value: '' }}).value || '';
    if (!stepUpToken) return;
    showErr('');
    try {{
      const res = await fetch('/auth/login/mfa', {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ step_up_token: stepUpToken, totp: totp.trim() }})
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.access_token) {{
        postOk({{ type: 'AUTH_SUCCESS', access_token: data.access_token, expires_in: data.expires_in }});
        showErr('Signed in.');
        return;
      }}
      postErr(data.code || 'MFA_FAILED', data.error || '');
      showErr(data.error || 'MFA failed');
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
    }}
  }});

  const lcef = document.getElementById('lcef');
  lcef.addEventListener('submit', async function(ev) {{
    ev.preventDefault();
    if (!loginCteEmailToken) {{
      showErr('Start sign-in again from Login.');
      return;
    }}
    showErr('');
    const fd = new FormData(lcef);
    const body = {{
      client_id: CFG.client_id,
      csrf_token: CFG.csrf_token,
      code: (fd.get('code') || '').toString().trim(),
      email_verification_token: loginCteEmailToken
    }};
    try {{
      const res = await fetch('/api/login/verify-client-totp-enroll-email', {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.client_totp_enroll_setup_token) {{
        regEnrollToken = data.client_totp_enroll_setup_token;
        loginCteEmailToken = null;
        document.getElementById('totpRegTitle').innerHTML = '<strong>Authenticator</strong> is required. Scan the QR, then enter a 6-digit code to sign in.';
        showPanel('totpReg');
        showErr('Add this account in your app, then enter a code below.');
        await runTotpSetup();
        return;
      }}
      const code = data.code || 'VERIFY_FAILED';
      postErr(code, data.error || '');
      showErr(data.error || code);
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
      showErr('Network error');
    }}
  }});

  document.getElementById('loginCteResendBtn').addEventListener('click', async function() {{
    if (!loginCteEmailToken) {{
      showErr('Start sign-in again from Login.');
      return;
    }}
    showErr('');
    try {{
      const res = await fetch('/api/login/resend-client-totp-enroll-email', {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          client_id: CFG.client_id,
          csrf_token: CFG.csrf_token,
          email_verification_token: loginCteEmailToken
        }})
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.email_verification_token) {{
        loginCteEmailToken = data.email_verification_token;
        showErr('New code sent.');
        return;
      }}
      const code = data.code || 'RESEND_FAILED';
      postErr(code, data.error || '');
      showErr(data.error || code);
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
      showErr('Network error');
    }}
  }});

  const rf = document.getElementById('rf');
  rf.addEventListener('submit', async function(ev) {{
    ev.preventDefault();
    if (!CFG.registration_enabled) {{
      postErr('REGISTRATION_DISABLED', 'Registration is not enabled for this client.');
      return;
    }}
    showErr('');
    const fd = new FormData(rf);
    const body = {{
      email: (fd.get('email') || '').toString().trim(),
      password: (fd.get('password') || '').toString(),
      client_id: CFG.client_id,
      csrf_token: CFG.csrf_token
    }};
    try {{
      const res = await fetch('/api/register', {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.email_verification_token) {{
        regEvToken = data.email_verification_token;
        showPanel('verify');
        showErr('Check your email for the code.');
        return;
      }}
      const code = data.code || 'REGISTRATION_FAILED';
      postErr(code, data.error || '');
      showErr(data.error || code);
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
      showErr('Network error');
    }}
  }});

  const vf = document.getElementById('vf');
  vf.addEventListener('submit', async function(ev) {{
    ev.preventDefault();
    if (!regEvToken) {{
      showErr('Start registration again.');
      return;
    }}
    showErr('');
    const fd = new FormData(vf);
    const body = {{
      client_id: CFG.client_id,
      csrf_token: CFG.csrf_token,
      code: (fd.get('code') || '').toString().trim(),
      email_verification_token: regEvToken
    }};
    try {{
      const res = await fetch('/api/register/verify-email', {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.client_totp_enrollment_required && data.enrollment_token) {{
        isLoginCte = false;
        regEnrollToken = data.enrollment_token;
        regEvToken = null;
        document.getElementById('totpRegTitle').innerHTML = '<strong>Authenticator</strong> is required for this client. Scan the QR or use the secret, then enter a 6-digit code.';
        showPanel('totpReg');
        showErr('Set up Authenticator to finish registration.');
        await runTotpSetup();
        return;
      }}
      if (res.ok && data.access_token) {{
        postOk({{ type: 'AUTH_SUCCESS', access_token: data.access_token, expires_in: data.expires_in }});
        showErr('Account verified. You are signed in.');
        return;
      }}
      const code = data.code || 'VERIFY_FAILED';
      postErr(code, data.error || '');
      showErr(data.error || code);
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
      showErr('Network error');
    }}
  }});

  document.getElementById('tf').addEventListener('submit', async function(ev) {{
    ev.preventDefault();
    if (!regEnrollToken) {{
      showErr('Start registration or sign-in again.');
      return;
    }}
    showErr('');
    const fd = new FormData(document.getElementById('tf'));
    const body = {{
      client_id: CFG.client_id,
      csrf_token: CFG.csrf_token,
      enrollment_token: regEnrollToken,
      code: (fd.get('code') || '').toString().trim()
    }};
    const totpVPath = isLoginCte ? '/api/login/client-totp-enroll/verify' : '/api/register/client-totp/verify';
    try {{
      const res = await fetch(totpVPath, {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.access_token) {{
        postOk({{ type: 'AUTH_SUCCESS', access_token: data.access_token, expires_in: data.expires_in }});
        showErr(isLoginCte ? 'Signed in.' : 'Registered and signed in.');
        regEnrollToken = null;
        isLoginCte = false;
        return;
      }}
      const code = data.code || 'CLIENT_TOTP_VERIFY_FAILED';
      postErr(code, data.error || '');
      showErr(data.error || code);
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
      showErr('Network error');
    }}
  }});

  document.getElementById('resendBtn').addEventListener('click', async function() {{
    if (!regEvToken) {{
      showErr('Start registration again.');
      return;
    }}
    showErr('');
    try {{
      const res = await fetch('/api/register/resend-code', {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          client_id: CFG.client_id,
          csrf_token: CFG.csrf_token,
          email_verification_token: regEvToken
        }})
      }});
      const data = await res.json().catch(function() {{ return {{}}; }});
      if (res.ok && data.email_verification_token) {{
        regEvToken = data.email_verification_token;
        showErr('New code sent.');
        return;
      }}
      const code = data.code || 'RESEND_FAILED';
      postErr(code, data.error || '');
      showErr(data.error || code);
    }} catch (e) {{
      postErr('NETWORK_ERROR', String(e));
      showErr('Network error');
    }}
  }});

  let mergedTheme = {{ v: 1 }};
  function allowParentOrigin(og) {{
    const a = CFG.allowed_parent_origins || [];
    for (let i = 0; i < a.length; i++) {{ if (a[i] === og) return true; }}
    return false;
  }}
  function applyTheme(t) {{
    if (!t || t.v !== 1) return;
    const h = document.documentElement;
    if (t.colorScheme === 'dark') h.classList.add('idp-scheme-dark');
    else if (t.colorScheme === 'light') h.classList.remove('idp-scheme-dark');
    if (t.colors) {{
      const c = t.colors;
      if (c.primary) h.style.setProperty('--idp-color-primary', c.primary);
      if (c.onPrimary) h.style.setProperty('--idp-color-on-primary', c.onPrimary);
      if (c.background) h.style.setProperty('--idp-color-bg', c.background);
      if (c.surface) h.style.setProperty('--idp-color-surface', c.surface);
      if (c.error) h.style.setProperty('--idp-color-error', c.error);
    }}
    if (t.radius && t.radius.md != null) h.style.setProperty('--idp-radius-md', t.radius.md + 'px');
    if (t.spacing && t.spacing.md != null) h.style.setProperty('--idp-space-md', t.spacing.md + 'px');
    if (t.font && t.font.family) {{
      const m = {{ system: 'system-ui, sans-serif', serif: 'Georgia, serif', mono: 'ui-monospace, monospace' }};
      h.style.setProperty('--idp-font', m[t.font.family] || m.system);
    }}
  }}
  function mergeTheme(base, patch) {{
    if (!patch || patch.v !== 1) return base;
    const o = (base && base.v === 1) ? JSON.parse(JSON.stringify(base)) : {{ v: 1 }};
    if (patch.colorScheme) o.colorScheme = patch.colorScheme;
    if (patch.colors) {{
      o.colors = o.colors || {{}};
      for (const k of ['primary', 'onPrimary', 'background', 'surface', 'error']) {{
        if (patch.colors[k]) o.colors[k] = patch.colors[k];
      }}
    }}
    if (patch.radius) {{
      o.radius = o.radius || {{}};
      if (patch.radius.md != null) o.radius.md = patch.radius.md;
    }}
    if (patch.spacing) {{
      o.spacing = o.spacing || {{}};
      if (patch.spacing.md != null) o.spacing.md = patch.spacing.md;
    }}
    if (patch.font) o.font = Object.assign({{}}, o.font, patch.font);
    return o;
  }}
  if (CFG.initial_theme && CFG.initial_theme.v === 1) {{
    mergedTheme = mergeTheme(mergedTheme, CFG.initial_theme);
    applyTheme(mergedTheme);
  }}
  if (CFG.protocol_v2) {{
    window.addEventListener('message', function(ev) {{
      if (ev.source !== window.parent) return;
      if (!allowParentOrigin(ev.origin)) return;
      let d = ev.data;
      if (typeof d === 'string') {{ try {{ d = JSON.parse(d); }} catch (e) {{ return; }} }}
      if (!d || d.v !== 1) return;
      if (d.source !== 'parent_sdk') return;
      if (d.type === 'INIT') {{
        const ok = allowParentOrigin(ev.origin);
        sendToParent(v2Envelope('INIT_ACK', {{ allowed: ok, client_id: CFG.client_id, protocol_version: 1 }}));
      }} else if (d.type === 'THEME_UPDATE' && d.theme && d.theme.v === 1) {{
        mergedTheme = mergeTheme(mergedTheme, d.theme);
        applyTheme(mergedTheme);
      }} else if (d.type === 'LOGOUT') {{
        showErr('');
        isLoginCte = false;
        loginCteEmailToken = null;
        showPanel('login');
        sendToParent(v2Envelope('SESSION_ENDED', {{ reason: 'logout' }}));
      }}
    }});
    sendToParent(v2Envelope('EMBED_READY', {{}}));
  }}
}})();
  </script>
</body>
</html>"#
    );

    let mut res = (StatusCode::OK, Html(html)).into_response();
    res.headers_mut().insert(
        axum::http::HeaderName::from_static("content-security-policy"),
        csp_h,
    );
    res.headers_mut().insert(
        axum::http::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    res.headers_mut().insert(
        axum::http::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        ),
    );
    res.headers_mut().insert(SET_COOKIE, cookie_h);
    Ok(res)
}

/// `POST /api/login` — iframe credential flow (JSON + CSRF cookie).
pub async fn embedded_login_api(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedLoginBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    let cmd = LoginCommand {
        tenant_id: ec.tenant_id,
        email: body.email.trim().to_string(),
        password: body.password,
        audience: ec.token_audience.clone(),
        oauth_client_id: Some(ec.client_id.clone()),
    };

    let login_result = state.auth.login(cmd).await;
    let r = match login_result {
        Ok(v) => v,
        Err(e) => return Ok(map_app_error(e)),
    };

    let resp = match r {
        LoginResult::Tokens(p) => {
            // Never return long-lived refresh tokens to the iframe document (parent uses BFF or `/oauth2/token`).
            let mut v = serde_json::to_value(&p).map_err(|e| AppError::Internal(e.to_string()))?;
            if let Some(obj) = v.as_object_mut() {
                obj.remove("refresh_token");
            }
            (Json(v).into_response(), true)
        }
        LoginResult::MfaRequired {
            mfa_required,
            step_up_token,
            token_type,
            expires_in,
        } => (
            Json(json!({
                "mfa_required": mfa_required,
                "step_up_token": step_up_token,
                "token_type": token_type,
                "expires_in": expires_in,
            }))
            .into_response(),
            false,
        ),
        LoginResult::TotpEnrollmentRequired {
            totp_enrollment_required,
            enrollment_token,
            token_type,
            expires_in,
        } => (
            Json(json!({
                "totp_enrollment_required": totp_enrollment_required,
                "enrollment_token": enrollment_token,
                "token_type": token_type,
                "expires_in": expires_in,
            }))
            .into_response(),
            false,
        ),
        LoginResult::ClientTotpEnrollEmailRequired {
            client_totp_enroll_email_required,
            email_verification_token,
            token_type,
            expires_in,
            oauth_client_id,
        } => (
            Json(json!({
                "client_totp_enroll_email_required": client_totp_enroll_email_required,
                "email_verification_token": email_verification_token,
                "token_type": token_type,
                "expires_in": expires_in,
                "oauth_client_id": oauth_client_id,
            }))
            .into_response(),
            false,
        ),
    };

    if resp.1 {
        delete_embedded_csrf_redis(&state, &body.csrf_token).await;
    }
    Ok(resp.0)
}

/// `POST /api/session-code` — mint a one-time code from a short-lived iframe `access_token` for BFF exchange (`grant_type=embedded_session` on `/oauth2/token`).
pub async fn embedded_session_code_api(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedSessionCodeBody>,
) -> Result<Response, AppError> {
    let _ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let (code, exp) = state
        .auth
        .create_embedded_exchange_code(body.access_token.trim(), body.client_id.trim())
        .await?;
    Ok(Json(json!({
        "code": code,
        "expires_in": exp,
        "token_type": "embedded_session"
    }))
    .into_response())
}

/// `POST /api/register` — embedded-only registration (returns email verification JWT; CSRF is not consumed).
pub async fn embedded_register_api(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    if !ec.allow_user_registration {
        return Ok(json_err(
            "REGISTRATION_DISABLED",
            StatusCode::FORBIDDEN,
            "user registration is disabled for this OAuth client",
        ));
    }

    let email = body.email.trim().to_string();
    if ec.mfa_policy == "required" {
        if !ec.allow_client_totp_enrollment {
            return Ok(json_err(
                "MFA_ENROLLMENT_DISABLED",
                StatusCode::FORBIDDEN,
                "client MFA is required but Authenticator enrollment is disabled for this OAuth client",
            ));
        }
        let hash = match password::hash_password(&body.password).map_err(AppError::Validation) {
            Ok(h) => h,
            Err(e) => return Ok(map_embedded_register_error(e)),
        };
        let (_pid, jwt, exp) = match state
            .ev
            .start_embedded_pending_registration(
                ec.tenant_id,
                &ec.client_id,
                &email,
                &hash,
                &ec.client_id,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return Ok(map_embedded_register_error(e)),
        };
        return Ok(Json(json!({
            "email_verification_token": jwt,
            "expires_in": exp,
            "token_type": "email_verification",
            "registration_mode": "pending_mfa_required",
        }))
        .into_response());
    }

    let out = match state
        .auth
        .register(RegisterCommand {
            tenant_id: ec.tenant_id,
            email,
            password: body.password,
            registration_source: Some(ec.client_id.clone()),
        })
        .await
    {
        Ok(v) => v,
        Err(e) => return Ok(map_embedded_register_error(e)),
    };

    Ok(Json(json!({
        "email_verification_token": out.email_verification_token,
        "expires_in": out.expires_in,
        "token_type": out.token_type,
    }))
    .into_response())
}

fn map_verify_complete_error(e: AppError) -> Response {
    match e {
        AppError::Validation(_) | AppError::Unauthorized => json_err(
            "VERIFY_CODE_INVALID",
            StatusCode::BAD_REQUEST,
            "invalid or expired verification code",
        ),
        AppError::Forbidden => json_err(
            "VERIFY_LOCKED",
            StatusCode::FORBIDDEN,
            "verification failed too many times",
        ),
        AppError::ForbiddenWithReason(msg) => json_err("FORBIDDEN", StatusCode::FORBIDDEN, &msg),
        _ => map_app_error(e),
    }
}

/// `POST /api/register/verify-email` — existing user: tokens + consume CSRF; pending required-MFA: enrollment JWT (keeps CSRF).
pub async fn embedded_register_verify_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterVerifyBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    if !ec.allow_user_registration {
        return Ok(json_err(
            "REGISTRATION_DISABLED",
            StatusCode::FORBIDDEN,
            "user registration is disabled for this OAuth client",
        ));
    }

    let tok = body.email_verification_token.trim();

    if let Ok(pclaims) = state.auth.jwt.verify_pending_email_verification(tok) {
        if ec.mfa_policy != "required" {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::BAD_REQUEST,
                "email token does not match client registration mode",
            ));
        }
        let Ok(pending_id) = Uuid::parse_str(&pclaims.sub) else {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid verification token",
            ));
        };
        let Ok(tenant_id) = Uuid::parse_str(&pclaims.tenant_id) else {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid verification token",
            ));
        };
        let Ok(verification_id) = Uuid::parse_str(&pclaims.jti) else {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid verification token",
            ));
        };

        if tenant_id != ec.tenant_id {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::FORBIDDEN,
                "verification token does not match this client",
            ));
        }

        if let Err(e) = state
            .ev
            .complete_embedded_pending_email(
                pending_id,
                tenant_id,
                verification_id,
                body.code.trim(),
            )
            .await
        {
            return Ok(map_verify_complete_error(e));
        }

        let (enroll_jwt, exp) = state
            .auth
            .jwt
            .mint_embedded_pending_client_totp_enrollment(
                pending_id,
                tenant_id,
                &ec.token_audience,
                ec.client_row_id,
                &ec.client_id,
            )?;

        return Ok(Json(json!({
            "client_totp_enrollment_required": true,
            "enrollment_token": enroll_jwt,
            "expires_in": exp,
            "token_type": "embedded_pending_client_totp",
        }))
        .into_response());
    }

    let claims = match state.auth.jwt.verify_email_verification(tok) {
        Ok(c) => c,
        Err(_) => {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid or expired email verification token",
            ));
        }
    };
    let Ok(user_id) = Uuid::parse_str(&claims.sub) else {
        return Ok(json_err(
            "VERIFY_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid verification token",
        ));
    };
    let Ok(tenant_id) = Uuid::parse_str(&claims.tenant_id) else {
        return Ok(json_err(
            "VERIFY_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid verification token",
        ));
    };
    let Ok(verification_id) = Uuid::parse_str(&claims.jti) else {
        return Ok(json_err(
            "VERIFY_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid verification token",
        ));
    };

    if tenant_id != ec.tenant_id {
        return Ok(json_err(
            "VERIFY_TOKEN_INVALID",
            StatusCode::FORBIDDEN,
            "verification token does not match this client",
        ));
    }

    let pair = match state
        .auth
        .complete_email_verification(
            user_id,
            tenant_id,
            verification_id,
            body.code.trim(),
            &ec.token_audience,
        )
        .await
    {
        Ok(p) => p,
        Err(e) => return Ok(map_verify_complete_error(e)),
    };

    delete_embedded_csrf_redis(&state, &body.csrf_token).await;

    let v = serde_json::to_value(&pair).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(v).into_response())
}

/// `POST /api/register/resend-code` — issue a new email verification JWT (CSRF not consumed).
pub async fn embedded_register_resend_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterResendBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    if !ec.allow_user_registration {
        return Ok(json_err(
            "REGISTRATION_DISABLED",
            StatusCode::FORBIDDEN,
            "user registration is disabled for this OAuth client",
        ));
    }

    let tok = body.email_verification_token.trim();

    if let Ok(pc) = state.auth.jwt.verify_pending_email_verification(tok) {
        let Ok(pending_id) = Uuid::parse_str(&pc.sub) else {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid verification token",
            ));
        };
        let Ok(tenant_id) = Uuid::parse_str(&pc.tenant_id) else {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid verification token",
            ));
        };
        if tenant_id != ec.tenant_id {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::FORBIDDEN,
                "verification token does not match this client",
            ));
        }
        let email: Option<String> = sqlx::query_scalar(
            "SELECT email FROM embedded_pending_registrations WHERE id = $1 AND tenant_id = $2 AND email_verified_at IS NULL AND expires_at > NOW()",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let Some(email) = email else {
            return Ok(json_err(
                "NOT_FOUND",
                StatusCode::NOT_FOUND,
                "pending registration not found",
            ));
        };
        let (jwt, exp) = state
            .ev
            .resend_embedded_pending_registration(pending_id, tenant_id, &email)
            .await?;
        return Ok(Json(json!({
            "email_verification_token": jwt,
            "expires_in": exp,
            "token_type": "email_verification"
        }))
        .into_response());
    }

    let claims = match state.auth.jwt.verify_email_verification(tok) {
        Ok(c) => c,
        Err(_) => {
            return Ok(json_err(
                "VERIFY_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid or expired email verification token",
            ));
        }
    };
    let Ok(user_id) = Uuid::parse_str(&claims.sub) else {
        return Ok(json_err(
            "VERIFY_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid verification token",
        ));
    };
    let Ok(tenant_id) = Uuid::parse_str(&claims.tenant_id) else {
        return Ok(json_err(
            "VERIFY_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid verification token",
        ));
    };

    if tenant_id != ec.tenant_id {
        return Ok(json_err(
            "VERIFY_TOKEN_INVALID",
            StatusCode::FORBIDDEN,
            "verification token does not match this client",
        ));
    }

    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(email) = email else {
        return Ok(json_err(
            "NOT_FOUND",
            StatusCode::NOT_FOUND,
            "user not found",
        ));
    };

    let (jwt, exp) = state
        .ev
        .resend_registration(user_id, tenant_id, &email)
        .await?;

    Ok(Json(json!({
        "email_verification_token": jwt,
        "expires_in": exp,
        "token_type": "email_verification"
    }))
    .into_response())
}

/// `POST /api/register/client-totp/setup` — pending registration only; returns otpauth URL, base32 secret, and SVG QR as base64.
pub async fn embedded_register_client_totp_setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterTotpSetupBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    if !ec.allow_user_registration || ec.mfa_policy != "required" {
        return Ok(json_err(
            "REGISTRATION_DISABLED",
            StatusCode::FORBIDDEN,
            "client TOTP setup is not available for this OAuth client",
        ));
    }

    let c = match state
        .auth
        .jwt
        .verify_embedded_pending_client_totp_enrollment(body.enrollment_token.trim())
    {
        Ok(c) => c,
        Err(_) => {
            return Ok(json_err(
                "ENROLLMENT_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid or expired enrollment token",
            ));
        }
    };

    let Ok(pending_id) = Uuid::parse_str(&c.sub) else {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid enrollment token",
        ));
    };
    let Ok(tenant_id) = Uuid::parse_str(&c.tenant_id) else {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid enrollment token",
        ));
    };
    if tenant_id != ec.tenant_id
        || c.public_oauth_client_id != ec.client_id
        || c.oauth_client_row_id != ec.client_row_id.to_string()
    {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::FORBIDDEN,
            "enrollment token does not match this client",
        ));
    }

    let (url, b32) = match state
        .totp
        .begin_pending_client_totp_setup(pending_id, tenant_id, &ec.client_id)
        .await
    {
        Ok(v) => v,
        Err(e) => return Ok(map_app_error(e)),
    };

    let qr_svg_base64 = match otpauth_url_qr_svg_base64(&url) {
        Ok(s) => s,
        Err(e) => return Ok(map_app_error(e)),
    };

    Ok(Json(json!({
        "otpauth_url": url,
        "secret_base32": b32,
        "qr_svg_base64": qr_svg_base64,
    }))
    .into_response())
}

/// `POST /api/register/client-totp/verify` — confirm Authenticator code, create user, return tokens (consumes CSRF).
pub async fn embedded_register_client_totp_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterTotpVerifyBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    if !ec.allow_user_registration || ec.mfa_policy != "required" {
        return Ok(json_err(
            "REGISTRATION_DISABLED",
            StatusCode::FORBIDDEN,
            "client TOTP verify is not available for this OAuth client",
        ));
    }

    let c = match state
        .auth
        .jwt
        .verify_embedded_pending_client_totp_enrollment(body.enrollment_token.trim())
    {
        Ok(c) => c,
        Err(_) => {
            return Ok(json_err(
                "ENROLLMENT_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid or expired enrollment token",
            ));
        }
    };

    let Ok(pending_id) = Uuid::parse_str(&c.sub) else {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid enrollment token",
        ));
    };
    let Ok(tenant_id) = Uuid::parse_str(&c.tenant_id) else {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid enrollment token",
        ));
    };
    let Ok(oauth_row) = Uuid::parse_str(&c.oauth_client_row_id) else {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid enrollment token",
        ));
    };

    if tenant_id != ec.tenant_id
        || c.public_oauth_client_id != ec.client_id
        || oauth_row != ec.client_row_id
    {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::FORBIDDEN,
            "enrollment token does not match this client",
        ));
    }

    if let Err(e) = state
        .totp
        .complete_pending_client_totp_setup(pending_id, tenant_id, &ec.client_id, body.code.trim())
        .await
    {
        return Ok(match e {
            AppError::Unauthorized => json_err(
                "CLIENT_TOTP_VERIFY_FAILED",
                StatusCode::BAD_REQUEST,
                "invalid authenticator code",
            ),
            _ => map_app_error(e),
        });
    }

    let pair = match state
        .auth
        .finalize_embedded_pending_registration(
            pending_id,
            tenant_id,
            &ec.token_audience,
            oauth_row,
        )
        .await
    {
        Ok(p) => p,
        Err(e) => return Ok(map_embedded_register_error(e)),
    };

    delete_embedded_csrf_redis(&state, &body.csrf_token).await;

    let v = serde_json::to_value(&pair).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(v).into_response())
}

// --- Login: client MFA required but not enrolled — email first, then client TOTP (no access token) ---

/// `POST /api/login/verify-client-totp-enroll-email` — after `LoginResult::ClientTotpEnrollEmailRequired`.
pub async fn embedded_login_verify_cte_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterVerifyBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    let (tok, exp) = match state
        .auth
        .verify_client_totp_enroll_email_and_mint_setup(
            &body.email_verification_token,
            body.code.trim(),
            &ec.client_id,
            &ec.token_audience,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => return Ok(map_app_error(e)),
    };

    Ok(Json(json!({
        "client_totp_enroll_setup_token": tok,
        "token_type": "client_totp_enroll_setup",
        "expires_in": exp,
    }))
    .into_response())
}

/// `POST /api/login/resend-client-totp-enroll-email` — new code + JWT (CSRF not consumed).
pub async fn embedded_login_resend_cte_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterResendBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    let c = match state
        .auth
        .jwt
        .verify_email_verification(body.email_verification_token.trim())
    {
        Ok(c) => c,
        Err(_) => {
            return Ok(json_err(
                "EMAIL_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid or expired email verification token",
            ));
        }
    };
    let user_id = match Uuid::parse_str(&c.sub) {
        Ok(v) => v,
        Err(_) => {
            return Ok(json_err(
                "EMAIL_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid email verification token",
            ));
        }
    };
    let tenant_id = match Uuid::parse_str(&c.tenant_id) {
        Ok(v) => v,
        Err(_) => {
            return Ok(json_err(
                "EMAIL_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid email verification token",
            ));
        }
    };
    if tenant_id != ec.tenant_id {
        return Ok(json_err(
            "EMAIL_TOKEN_INVALID",
            StatusCode::FORBIDDEN,
            "email token does not match this client",
        ));
    }
    let email: String =
        match sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&state.pool)
            .await?
        {
            Some(e) => e,
            None => {
                return Ok(json_err(
                    "NOT_FOUND",
                    StatusCode::NOT_FOUND,
                    "user not found",
                ));
            }
        };
    if !ec.allow_client_totp_enrollment || ec.mfa_policy != "required" {
        return Ok(json_err(
            "REGISTRATION_DISABLED",
            StatusCode::FORBIDDEN,
            "client 2FA enrollment is not available",
        ));
    }
    let (jwt, ex) = match state
        .ev
        .resend_client_totp_enroll_email(user_id, tenant_id, &email, &ec.client_id)
        .await
    {
        Ok(v) => v,
        Err(e) => return Ok(map_app_error(e)),
    };
    Ok(Json(json!({
        "email_verification_token": jwt,
        "expires_in": ex,
        "token_type": "email_verification"
    }))
    .into_response())
}

/// `POST /api/login/client-totp-enroll/setup` — setup JWT as `enrollment_token`.
pub async fn embedded_login_client_totp_enroll_setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterTotpSetupBody>,
) -> Result<Response, AppError> {
    let ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        false,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    let c = match state
        .auth
        .jwt
        .verify_client_totp_enroll_after_email(body.enrollment_token.trim())
    {
        Ok(c) => c,
        Err(_) => {
            return Ok(json_err(
                "ENROLLMENT_TOKEN_INVALID",
                StatusCode::UNAUTHORIZED,
                "invalid or expired client TOTP setup token; verify email first",
            ));
        }
    };
    let tenant_id = Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?;
    let Ok(oauth_row) = Uuid::parse_str(&c.oauth_client_row_id) else {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid enrollment token",
        ));
    };

    if tenant_id != ec.tenant_id
        || c.public_oauth_client_id != ec.client_id
        || oauth_row != ec.client_row_id
    {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::FORBIDDEN,
            "enrollment token does not match this client",
        ));
    }

    let (url, b32) = match state
        .auth
        .client_totp_enroll_setup_after_email_bearer(body.enrollment_token.trim())
        .await
    {
        Ok(v) => v,
        Err(e) => return Ok(map_app_error(e)),
    };
    let qr = match otpauth_url_qr_svg_base64(&url) {
        Ok(s) => s,
        Err(e) => return Ok(map_app_error(e)),
    };
    Ok(Json(json!({
        "otpauth_url": url,
        "secret_base32": b32,
        "qr_svg_base64": qr,
    }))
    .into_response())
}

/// `POST /api/login/client-totp-enroll/verify` — TOTP + setup JWT; access/refresh; consumes CSRF.
pub async fn embedded_login_client_totp_enroll_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    Json(body): Json<EmbeddedRegisterTotpVerifyBody>,
) -> Result<Response, AppError> {
    let _ec = match validate_embedded_csrf_and_origin(
        &state,
        &headers,
        Some(conn),
        &body.client_id,
        &body.csrf_token,
        true,
    )
    .await
    {
        Ok(v) => v.ec,
        Err(resp) => return Ok(resp),
    };

    if let Err(_) = state
        .auth
        .jwt
        .verify_client_totp_enroll_after_email(body.enrollment_token.trim())
    {
        return Ok(json_err(
            "ENROLLMENT_TOKEN_INVALID",
            StatusCode::UNAUTHORIZED,
            "invalid or expired client TOTP setup token",
        ));
    }

    let pair = match state
        .auth
        .client_totp_enroll_verify_after_email_bearer(
            body.enrollment_token.trim(),
            body.code.trim(),
        )
        .await
    {
        Ok(p) => p,
        Err(e) => {
            return Ok(match e {
                AppError::Unauthorized => json_err(
                    "CLIENT_TOTP_VERIFY_FAILED",
                    StatusCode::BAD_REQUEST,
                    "invalid authenticator code",
                ),
                _ => map_app_error(e),
            });
        }
    };

    delete_embedded_csrf_redis(&state, &body.csrf_token).await;

    let v = serde_json::to_value(&pair).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(v).into_response())
}

#[cfg(test)]
mod client_ip_unit_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::http::HeaderName;

    use super::*;

    #[test]
    fn client_ip_ignores_xff_when_untrusted() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("9.9.9.9"),
        );
        let conn = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234));
        let ip = client_ip(&h, conn, false);
        assert_eq!(ip, "1.2.3.4");
    }

    #[test]
    fn client_ip_uses_xff_when_trusted() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("9.9.9.9"),
        );
        let conn = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234));
        let ip = client_ip(&h, conn, true);
        assert_eq!(ip, "9.9.9.9");
    }
}
