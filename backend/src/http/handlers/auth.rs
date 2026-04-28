use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::header::{AUTHORIZATION, SET_COOKIE};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::{Json, extract::State};
use uuid::Uuid;

const IDP_SESSION: &str = "idp_session";
use serde::Deserialize;

use crate::{
    services::{
        app_state::AppState,
        auth_service::{LoginCommand, RegisterCommand, LoginResult},
        errors::AppError,
    },
};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub tenant_id: uuid::Uuid,
    pub email: String,
    pub password: String,
    /// Stored as `users.registration_source` (e.g. `make-auth-service`, public OAuth `client_id`).
    #[serde(default)]
    pub registration_source: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub tenant_id: uuid::Uuid,
    pub email: String,
    pub password: String,
    pub audience: String,
    /// When `true` and `AUTH__COOKIE_SECRET` is set, issues `idp_session` for `GET /authorize`.
    #[serde(default)]
    pub set_idp_session: Option<bool>,
    /// Public OAuth `client_id` when login is for a specific client (per-client MFA).
    #[serde(default)]
    pub oauth_client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginMfaRequest {
    pub step_up_token: String,
    /// 6-digit TOTP from authenticator.
    pub totp: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
    /// Ignored: resource audience is taken from the refresh token JWT `aud` claim.
    #[serde(default)]
    pub audience: String,
    /// Required when the refresh token was issued for an OAuth client (embedded login, code exchange).
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

fn bearer_admin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(auth_header) = headers.get(AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = auth_header.to_str() else {
        return false;
    };
    let Some(token) = s.strip_prefix("Bearer ").map(str::trim) else {
        return false;
    };
    if token.is_empty() {
        return false;
    }
    let expected = state.config.auth.admin_api_audience.as_str();
    let Ok(claims) = state.auth.jwt.verify(token, expected) else {
        return false;
    };
    claims.roles.iter().any(|r| r == "admin")
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // End-user self-registration uses embedded `/embedded-login` + `POST /api/register*`
    // (per OAuth client `allow_user_registration`). This endpoint is for admin API tokens only.
    if headers.get(AUTHORIZATION).is_none() {
        return Err(AppError::Unauthorized);
    }
    if !bearer_admin_allowed(&state, &headers) {
        return Err(AppError::ForbiddenWithReason(
            "POST /auth/register requires a valid admin API token (audience AUTH__ADMIN_API_AUDIENCE \
             with admin role). End-user registration: use /embedded-login and POST /api/register* \
             when the client has public registration enabled."
                .to_string(),
        ));
    }
    let out = state
        .auth
        .register(RegisterCommand {
            tenant_id: payload.tenant_id,
            email: payload.email,
            password: payload.password,
            registration_source: payload.registration_source,
        })
        .await?;
    let v = serde_json::to_value(&out).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(v))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> Result<axum::response::Response, AppError> {
    state
        .rate_limit_by_ip(
            "rl:auth:login:ip",
            &addr.ip().to_string(),
            state.config.auth.oauth_token_ip_max_attempts,
            state.config.auth.oauth_token_ip_window_seconds,
            false,
        )
        .await?;
    let r = state
        .auth
        .login(LoginCommand {
            tenant_id: payload.tenant_id,
            email: payload.email,
            password: payload.password,
            audience: payload.audience.clone(),
            oauth_client_id: payload.oauth_client_id.clone(),
        })
        .await?;
    match r {
        LoginResult::Tokens(ref p) => {
            let v = serde_json::to_value(p).map_err(|e| AppError::Internal(e.to_string()))?;
            let mut res = Json(v).into_response();
            if payload.set_idp_session == Some(true) && state.auth.jwt.idp_session_secret_configured() {
                if let Ok(c) = state
                    .auth
                    .jwt
                    .verify(&p.access_token, &payload.audience)
                {
                    if let (Ok(uid), Ok(tid)) = (
                        Uuid::parse_str(&c.sub),
                        Uuid::parse_str(&c.tenant_id),
                    ) {
                        if let Ok(sess) = state.auth.jwt.mint_idp_session(uid, tid) {
                            if let Ok(h) = http::HeaderValue::from_str(&format!(
                                "{IDP_SESSION}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600",
                                sess
                            )) {
                                res.headers_mut().insert(SET_COOKIE, h);
                            }
                        }
                    }
                }
            }
            Ok(res)
        }
        LoginResult::MfaRequired {
            mfa_required,
            step_up_token,
            token_type,
            expires_in,
        } => {
            let v = serde_json::json!({
                "mfa_required": mfa_required,
                "step_up_token": step_up_token,
                "token_type": token_type,
                "expires_in": expires_in,
            });
            Ok(Json(v).into_response())
        }
        LoginResult::TotpEnrollmentRequired {
            totp_enrollment_required,
            enrollment_token,
            token_type,
            expires_in,
        } => {
            let v = serde_json::json!({
                "totp_enrollment_required": totp_enrollment_required,
                "enrollment_token": enrollment_token,
                "token_type": token_type,
                "expires_in": expires_in,
            });
            Ok(Json(v).into_response())
        }
        LoginResult::ClientTotpEnrollEmailRequired {
            client_totp_enroll_email_required,
            email_verification_token,
            token_type,
            expires_in,
            oauth_client_id,
        } => {
            let v = serde_json::json!({
                "client_totp_enroll_email_required": client_totp_enroll_email_required,
                "email_verification_token": email_verification_token,
                "token_type": token_type,
                "expires_in": expires_in,
                "oauth_client_id": oauth_client_id,
            });
            Ok(Json(v).into_response())
        }
    }
}

/// POST /auth/login/mfa — second step when `totp` is enabled.
pub async fn login_mfa(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginMfaRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pair = state
        .auth
        .login_mfa(&payload.step_up_token, &payload.totp)
        .await?;
    Ok(Json(serde_json::to_value(&pair).map_err(|e| AppError::Internal(e.to_string()))?))
}

pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tokens = state
        .auth
        .refresh(
            &payload.refresh_token,
            payload.client_id.as_deref(),
            payload.client_secret.as_deref(),
        )
        .await?;
    Ok(Json(serde_json::to_value(&tokens).map_err(|e| AppError::Internal(e.to_string()))?))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.auth.logout(&payload.refresh_token).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

#[derive(Debug, Deserialize)]
pub struct VerifyClientTotpEnrollEmailRequest {
    pub email_verification_token: String,
    pub code: String,
    pub oauth_client_id: String,
    /// Access/refresh `aud` after TOTP (same as password login, e.g. `embedded_token_audience` or public `client_id`).
    pub audience: String,
}

/// POST /auth/verify-client-totp-enroll-email
pub async fn verify_client_totp_enroll_email(
    State(state): State<Arc<AppState>>,
    Json(b): Json<VerifyClientTotpEnrollEmailRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (tok, exp) = state
        .auth
        .verify_client_totp_enroll_email_and_mint_setup(
            b.email_verification_token.trim(),
            b.code.trim(),
            b.oauth_client_id.trim(),
            b.audience.trim(),
        )
        .await?;
    Ok(Json(serde_json::json!({
        "client_totp_enroll_setup_token": tok,
        "token_type": "client_totp_enroll_setup",
        "expires_in": exp,
    })))
}

/// POST /auth/client-totp-enroll/setup — `Authorization: Bearer <client_totp_enroll_setup token>`
pub async fn client_totp_enroll_setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(tok) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(str::trim))
    else {
        return Err(AppError::Unauthorized);
    };
    if tok.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let (url, b32) = state
        .auth
        .client_totp_enroll_setup_after_email_bearer(tok)
        .await?;
    let qr = super::qr_svg::otpauth_url_qr_svg_base64(&url)?;
    Ok(Json(serde_json::json!({
        "otpauth_url": url,
        "secret_base32": b32,
        "qr_svg_base64": qr,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ClientTotpEnrollVerifyBody {
    pub code: String,
}

/// POST /auth/client-totp-enroll/verify
pub async fn client_totp_enroll_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(b): Json<ClientTotpEnrollVerifyBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(tok) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(str::trim))
    else {
        return Err(AppError::Unauthorized);
    };
    if tok.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let pair = state
        .auth
        .client_totp_enroll_verify_after_email_bearer(tok, b.code.trim())
        .await?;
    let v = serde_json::to_value(&pair).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(v))
}
