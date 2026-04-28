//! RFC 6749–style OAuth2 endpoints (`application/x-www-form-urlencoded`) under `/oauth2/*`.
//! Per-client [`grant_types`], [`token_endpoint_auth_method`], and PKCE settings come from DB (migration 0013).

use std::sync::Arc;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json, extract::State};
use axum_extra::extract::CookieJar;
use base64::Engine;
use chrono::Duration;
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use url::Url;
use uuid::Uuid;

use crate::http::handlers::oidc::{self, AuthorizeQuery};
use crate::services::app_state::AppState;
use crate::services::auth_service::LoginCommand;
use crate::services::client_oauth::{self, ClientCredentialsSource};
use crate::services::errors::AppError;

const IDP_SESSION_COOKIE: &str = "idp_session";

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub audience: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

fn parse_basic(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ")?.trim();
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let idx = s.find(':')?;
    Some((s[..idx].to_string(), s[idx + 1..].to_string()))
}

fn merge_creds(
    headers: &axum::http::HeaderMap,
    body_cid: Option<String>,
    body_sec: Option<String>,
) -> (Option<String>, Option<String>) {
    if let Some((a, b)) = parse_basic(headers) {
        return (Some(a), Some(b));
    }
    (body_cid, body_sec)
}

pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Form(payload): Form<TokenForm>,
) -> Result<Json<serde_json::Value>, AppError> {
    let access_aud = payload
        .audience
        .as_deref()
        .unwrap_or(&state.config.auth.admin_api_audience);

    let (basic_id, basic_sec) = merge_creds(&headers, None, None);
    let client_secret_merged = payload.client_secret.clone().or(basic_sec);
    let client_id_merged = payload.client_id.clone().or(basic_id);

    let creds_src = if parse_basic(&headers).is_some() {
        ClientCredentialsSource::BasicHeader
    } else {
        ClientCredentialsSource::PostBody
    };

    match payload.grant_type.as_str() {
        "password" => {
            if !state.config.auth.allow_resource_owner_password_grant {
                return Err(AppError::Validation(
                    "resource owner password grant is disabled".to_string(),
                ));
            }
            let tenant_id = payload
                .tenant_id
                .ok_or_else(|| AppError::Validation("tenant_id is required".to_string()))?;
            let email = payload
                .email
                .ok_or_else(|| AppError::Validation("email is required".to_string()))?;
            let password = payload
                .password
                .ok_or_else(|| AppError::Validation("password is required".to_string()))?;
            let audience = payload
                .audience
                .clone()
                .unwrap_or_else(|| state.config.auth.admin_api_audience.clone());
            if let Some(ref cid) = client_id_merged {
                client_oauth::assert_grant_allowed(
                    &state.pool,
                    tenant_id,
                    cid.as_str(),
                    "password",
                )
                .await?;
            }
            let tokens = state
                .auth
                .login(LoginCommand {
                    tenant_id,
                    email,
                    password,
                    audience,
                    oauth_client_id: client_id_merged.clone(),
                })
                .await?;
            let v = match tokens {
                crate::services::auth_service::LoginResult::Tokens(p) => {
                    serde_json::to_value(p).map_err(|e| AppError::Internal(e.to_string()))?
                }
                crate::services::auth_service::LoginResult::MfaRequired {
                    mfa_required,
                    step_up_token,
                    token_type,
                    expires_in,
                } => json!({
                    "mfa_required": mfa_required,
                    "step_up_token": step_up_token,
                    "token_type": token_type,
                    "expires_in": expires_in,
                }),
                crate::services::auth_service::LoginResult::TotpEnrollmentRequired {
                    totp_enrollment_required,
                    enrollment_token,
                    token_type,
                    expires_in,
                } => json!({
                    "totp_enrollment_required": totp_enrollment_required,
                    "enrollment_token": enrollment_token,
                    "token_type": token_type,
                    "expires_in": expires_in,
                }),
                crate::services::auth_service::LoginResult::ClientTotpEnrollEmailRequired {
                    client_totp_enroll_email_required,
                    email_verification_token,
                    token_type,
                    expires_in,
                    oauth_client_id,
                } => json!({
                    "client_totp_enroll_email_required": client_totp_enroll_email_required,
                    "email_verification_token": email_verification_token,
                    "token_type": token_type,
                    "expires_in": expires_in,
                    "oauth_client_id": oauth_client_id,
                }),
            };
            Ok(Json(v))
        }
        "refresh_token" => {
            let refresh = payload
                .refresh_token
                .ok_or_else(|| AppError::Validation("refresh_token is required".to_string()))?;
            let tokens = state
                .auth
                .refresh(
                    &refresh,
                    client_id_merged.as_deref(),
                    client_secret_merged.as_deref(),
                )
                .await?;
            Ok(Json(
                serde_json::to_value(&tokens).map_err(|e| AppError::Internal(e.to_string()))?,
            ))
        }
        "embedded_session" => {
            let code = payload
                .code
                .as_deref()
                .ok_or_else(|| AppError::Validation("code is required".to_string()))?;
            let cid = client_id_merged
                .as_deref()
                .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
            let pair = state
                .auth
                .exchange_embedded_session_code(
                    code,
                    cid,
                    access_aud,
                    client_secret_merged.as_deref(),
                    creds_src,
                )
                .await?;
            let mut m =
                serde_json::to_value(&pair).map_err(|e| AppError::Internal(e.to_string()))?;
            if let Some(obj) = m.as_object_mut() {
                obj.insert("token_type".to_string(), json!("Bearer"));
            }
            Ok(Json(m))
        }
        "authorization_code" => {
            let cid = client_id_merged
                .as_deref()
                .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
            let code = payload
                .code
                .ok_or_else(|| AppError::Validation("code is required".to_string()))?;
            let ver = payload.code_verifier.as_deref().unwrap_or("");
            let ruri = payload
                .redirect_uri
                .ok_or_else(|| AppError::Validation("redirect_uri is required".to_string()))?;
            let pair = state
                .auth
                .exchange_authorization_code(
                    &code,
                    ver,
                    cid,
                    &ruri,
                    access_aud,
                    client_secret_merged.as_deref(),
                    creds_src,
                )
                .await?;
            let mut m =
                serde_json::to_value(&pair).map_err(|e| AppError::Internal(e.to_string()))?;
            if let Some(obj) = m.as_object_mut() {
                obj.insert("token_type".to_string(), json!("Bearer"));
            }
            Ok(Json(m))
        }
        _ => Err(AppError::Validation("unsupported grant_type".to_string())),
    }
}

pub async fn userinfo(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    oidc::userinfo(State(state), headers).await
}

pub async fn introspect(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Form(req): Form<IntrospectForm>,
) -> Result<Json<oidc::IntrospectResponse>, AppError> {
    let (cid, sec) = merge_creds(&headers, req.client_id.clone(), req.client_secret.clone());
    let ir = oidc::IntrospectRequest {
        token: req.token.clone(),
        token_type_hint: req.token_type_hint.clone(),
        client_id: cid,
        client_secret: sec,
    };
    oidc::introspect(State(state), headers, Json(ir)).await
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Form(mut body): Form<std::collections::HashMap<String, String>>,
) -> Result<StatusCode, AppError> {
    let (bcid, bsec) = merge_creds(&headers, None, None);
    if let Some(cid) = bcid {
        body.insert("client_id".to_string(), cid);
    }
    if let Some(sec) = bsec {
        body.insert("client_secret".to_string(), sec);
    }
    let token = body.get("token").cloned();
    let mut jb = json!({});
    if let Some(t) = token {
        jb.as_object_mut()
            .unwrap()
            .insert("token".to_string(), json!(t));
    }
    if let Some(cid) = body.get("client_id") {
        jb.as_object_mut()
            .unwrap()
            .insert("client_id".to_string(), json!(cid));
    }
    if let Some(cs) = body.get("client_secret") {
        jb.as_object_mut()
            .unwrap()
            .insert("client_secret".to_string(), json!(cs));
    }
    oidc::revoke(State(state), headers, Json(jb)).await
}

fn redirect_in_allowlist(uri: &str, allow: &serde_json::Value) -> bool {
    if let Some(a) = allow.as_array() {
        for v in a {
            if v.as_str() == Some(uri) {
                return true;
            }
        }
    }
    false
}

fn build_oauth2_authorize_url(state: &AppState, q: &AuthorizeQuery) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = write!(
        &mut s,
        "{}/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256",
        state.config.server.issuer,
        urlencoding::encode(&q.client_id),
        urlencoding::encode(&q.redirect_uri),
        urlencoding::encode(q.code_challenge.as_deref().unwrap_or(""))
    );
    if let Some(ref sc) = q.scope {
        let _ = write!(&mut s, "&scope={}", urlencoding::encode(sc));
    }
    if let Some(ref n) = q.nonce {
        let _ = write!(&mut s, "&nonce={}", urlencoding::encode(n));
    }
    s
}

/// `GET /oauth2/authorize` — same rules as `/authorize` (PKCE S256 required); `return_to` uses `/oauth2/authorize`.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuthorizeQuery>,
    jar: CookieJar,
) -> Result<Response, AppError> {
    if q.response_type != "code" {
        return Err(AppError::Validation(
            "unsupported response_type".to_string(),
        ));
    }

    if let Some(login) = &state.config.oidc.login_url
        && jar.get(IDP_SESSION_COOKIE).is_none()
    {
        let current = build_oauth2_authorize_url(&state, &q);
        let to = format!(
            "{}{}return_to={}",
            login,
            if login.contains('?') { "&" } else { "?" },
            urlencoding::encode(&current)
        );
        return Ok(Redirect::temporary(&to).into_response());
    }

    let c = jar.get(IDP_SESSION_COOKIE).ok_or(AppError::Unauthorized)?;
    let tok = c.value();
    let sess = state
        .auth
        .jwt
        .verify_idp_session(tok)
        .map_err(|_| AppError::Unauthorized)?;
    let user_sub = Uuid::parse_str(&sess.sub).map_err(|_| AppError::Unauthorized)?;
    let tenant_id_sess = Uuid::parse_str(&sess.tenant_id).map_err(|_| AppError::Unauthorized)?;

    let client_row = sqlx::query(
        "SELECT id, tenant_id, allowed_redirect_uris, scopes, COALESCE(mfa_policy, 'off') AS mfa_policy,
                client_type, COALESCE(require_pkce, true) AS require_pkce, pkce_methods
         FROM clients WHERE client_id = $1 AND tenant_id = $2",
    )
    .bind(&q.client_id)
    .bind(tenant_id_sess)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::Validation("unknown client_id".to_string()))?;

    let oauth_client_row_id: Uuid = client_row.get("id");
    let tenant_id: Uuid = client_row.get("tenant_id");
    if tenant_id != tenant_id_sess {
        return Err(AppError::Forbidden);
    }

    client_oauth::authorize_pkce_ok(
        &client_row,
        q.code_challenge.as_deref(),
        q.code_challenge_method.as_deref(),
    )?;
    let (pkce_challenge, pkce_method) =
        client_oauth::pkce_challenge_for_storage(&client_row, q.code_challenge.as_deref())?;
    if sqlx::query_scalar::<_, Uuid>("SELECT tenant_id FROM users WHERE id = $1")
        .bind(user_sub)
        .fetch_optional(&state.pool)
        .await?
        != Some(tenant_id)
    {
        return Err(AppError::Forbidden);
    }

    if state.config.oidc.client_mfa_enforce {
        let mfa_policy: String = client_row.get("mfa_policy");
        if mfa_policy == "required" {
            let ok = state
                .totp
                .is_client_totp_enabled(user_sub, tenant_id_sess, oauth_client_row_id)
                .await?;
            if !ok {
                return Err(AppError::Validation(
                    "2FA (Authenticator) is required for this client before authorization"
                        .to_string(),
                ));
            }
        }
    }

    let allow: serde_json::Value = client_row
        .try_get::<Option<serde_json::Value>, _>("allowed_redirect_uris")
        .ok()
        .flatten()
        .unwrap_or(serde_json::json!([]));
    if !redirect_in_allowlist(&q.redirect_uri, &allow) {
        return Err(AppError::Validation("invalid redirect_uri".to_string()));
    }

    let default_scope: String = client_row
        .try_get("scopes")
        .unwrap_or_else(|_| "openid profile email".to_string());
    let scope = q.scope.as_deref().unwrap_or(&default_scope);

    let ttl = Duration::seconds(state.config.oidc.auth_code_ttl_seconds as i64);
    let code = state
        .auth
        .create_authorization_code(
            user_sub,
            tenant_id,
            &q.client_id,
            pkce_challenge.as_str(),
            pkce_method.as_str(),
            &q.redirect_uri,
            q.nonce.as_deref(),
            scope,
            ttl,
        )
        .await?;

    let mut u = Url::parse(&q.redirect_uri)
        .map_err(|_| AppError::Validation("invalid redirect_uri url".to_string()))?;
    u.query_pairs_mut().append_pair("code", &code);
    if let Some(ref s) = q.state {
        u.query_pairs_mut().append_pair("state", s);
    }
    Ok(Redirect::to(u.as_str()).into_response())
}
