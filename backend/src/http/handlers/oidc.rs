use std::sync::Arc;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Json, extract::State};
use axum_extra::extract::CookieJar;
use base64::Engine;
use chrono::Duration;
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use url::Url;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::services::app_state::AppState;
use crate::services::auth_service::LoginCommand;
use crate::services::client_oauth::{self, ClientCredentialsSource};
use crate::services::errors::AppError;

fn parse_basic_client_credentials(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ")?.trim();
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let idx = s.find(':')?;
    Some((s[..idx].to_string(), s[idx + 1..].to_string()))
}

fn merge_client_credentials(
    headers: &axum::http::HeaderMap,
    body_client_id: Option<String>,
    body_client_secret: Option<String>,
) -> (Option<String>, Option<String>) {
    if let Some((cid, sec)) = parse_basic_client_credentials(headers) {
        return (Some(cid), Some(sec));
    }
    (body_client_id, body_client_secret)
}

const IDP_SESSION_COOKIE: &str = "idp_session";

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
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
pub struct IntrospectRequest {
    pub token: String,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(serde::Serialize)]
pub struct IntrospectResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

/// OIDC `GET /userinfo` — Bearer access token; `aud` must be admin API audience or a registered OAuth client.
pub async fn userinfo(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let token = auth.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)?;
    let claims = state
        .auth
        .verify_access_token_for_userinfo(token, state.config.auth.admin_api_audience.as_str())
        .await?;
    let info = state.auth.userinfo_from_access_claims(&claims).await?;
    Ok((StatusCode::OK, Json(json!(info))).into_response())
}

/// OpenID Provider metadata served by this IdP when not proxying an upstream discovery URL.
pub fn openid_configuration_document(config: &AppConfig) -> serde_json::Value {
    let issuer = config.server.issuer.as_str();
    let mut grants = vec![
        serde_json::Value::String("authorization_code".to_string()),
        serde_json::Value::String("refresh_token".to_string()),
    ];
    if config.auth.allow_resource_owner_password_grant {
        grants.push(serde_json::Value::String("password".to_string()));
    }
    grants.push(serde_json::Value::String("embedded_session".to_string()));
    let iss = issuer.trim_end_matches('/');
    json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/oauth2/authorize"),
        "token_endpoint": format!("{iss}/oauth2/token"),
        "userinfo_endpoint": format!("{iss}/oauth2/userinfo"),
        "revocation_endpoint": format!("{iss}/oauth2/revoke"),
        "introspection_endpoint": format!("{iss}/oauth2/introspect"),
        "jwks_uri": format!("{iss}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid", "profile", "email", "read", "write"],
        "grant_types_supported": grants,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "none"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "oauth2_authorization_endpoint": format!("{iss}/oauth2/authorize"),
        "oauth2_token_endpoint": format!("{iss}/oauth2/token"),
        "oauth2_userinfo_endpoint": format!("{iss}/oauth2/userinfo"),
        "legacy_authorization_endpoint": format!("{iss}/authorize"),
        "legacy_token_endpoint": format!("{iss}/token"),
        "legacy_userinfo_endpoint": format!("{iss}/userinfo"),
        "legacy_revocation_endpoint": format!("{iss}/revoke"),
        "legacy_introspection_endpoint": format!("{iss}/introspect"),
        "legacy_jwks_uri": format!("{iss}/jwks.json")
    })
}

pub async fn metadata(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let meta_url = state
        .config
        .oidc
        .server_metadata_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(url) = meta_url {
        match state.oidc_proxy.fetch_metadata(url).await {
            Ok(remote) => return Ok(Json(json!(remote))),
            Err(e) => {
                tracing::warn!(error = %e, url = %url, "oidc proxy metadata fetch failed");
                if state.config.oidc.metadata_proxy_fallback {
                    tracing::warn!(
                        "OIDC__METADATA_PROXY_FALLBACK=true: serving built-in openid-configuration"
                    );
                    return Ok(Json(openid_configuration_document(&state.config)));
                }
                return Err(AppError::OidcDiscoveryUnavailable);
            }
        }
    }

    Ok(Json(openid_configuration_document(&state.config)))
}

/// `GET /authorize` — requires `idp_session` cookie, or temporary redirect to `OIDC__LOGIN_URL?return_to=...`.
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
        let current = build_authorize_url(&state, &q);
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

fn build_authorize_url(state: &AppState, q: &AuthorizeQuery) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = write!(
        &mut s,
        "{}/authorize?client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256",
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

pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let access_aud = payload
        .audience
        .as_deref()
        .unwrap_or(&state.config.auth.admin_api_audience);

    let (basic_cid, basic_sec) = merge_client_credentials(&headers, None, None);
    let client_secret_merged = payload.client_secret.clone().or(basic_sec);
    let client_id_merged = payload.client_id.clone().or(basic_cid);

    let creds_src = if parse_basic_client_credentials(&headers).is_some() {
        ClientCredentialsSource::BasicHeader
    } else {
        ClientCredentialsSource::PostBody
    };

    match payload.grant_type.as_str() {
        "password" => {
            if !state.config.auth.allow_resource_owner_password_grant {
                return Err(AppError::Validation(
                    "resource owner password grant is disabled (set AUTH__ALLOW_RESOURCE_OWNER_PASSWORD_GRANT=true to enable)"
                        .to_string(),
                ));
            }
            tracing::warn!("deprecated OAuth2 password grant used at /token");
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
                .unwrap_or_else(|| state.config.auth.admin_api_audience.clone());

            let tokens = state
                .auth
                .login(LoginCommand {
                    tenant_id,
                    email,
                    password,
                    audience,
                    oauth_client_id: payload.client_id.clone(),
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
                } => serde_json::json!({
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
                } => serde_json::json!({
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
                } => serde_json::json!({
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
        "authorization_code" => {
            let code = payload
                .code
                .ok_or_else(|| AppError::Validation("code required".to_string()))?;
            let ver = payload.code_verifier.as_deref().unwrap_or("");
            let ruri = payload
                .redirect_uri
                .ok_or_else(|| AppError::Validation("redirect_uri required".to_string()))?;
            let cid = client_id_merged
                .as_deref()
                .ok_or_else(|| AppError::Validation("client_id required".to_string()))?;
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

pub async fn jwks(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(state.auth.jwt.jwks()))
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<StatusCode, AppError> {
    let body_cid = body
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let body_sec = body
        .get("client_secret")
        .and_then(|v| v.as_str())
        .map(String::from);
    let (cid, sec) = merge_client_credentials(&headers, body_cid, body_sec);
    let cid = cid.ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
    let creds_src = if parse_basic_client_credentials(&headers).is_some() {
        ClientCredentialsSource::BasicHeader
    } else {
        ClientCredentialsSource::PostBody
    };
    state
        .auth
        .verify_oauth_client_introspect_or_revoke(cid.as_str(), sec.as_deref(), creds_src)
        .await?;
    if let Some(t) = body.get("token").and_then(|v| v.as_str()) {
        let _ = state.auth.logout(t).await;
    }
    Ok(StatusCode::OK)
}

pub async fn introspect(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, AppError> {
    let (cid, sec) =
        merge_client_credentials(&headers, req.client_id.clone(), req.client_secret.clone());
    let cid = cid.ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
    let creds_src = if parse_basic_client_credentials(&headers).is_some() {
        ClientCredentialsSource::BasicHeader
    } else {
        ClientCredentialsSource::PostBody
    };
    state
        .auth
        .verify_oauth_client_introspect_or_revoke(cid.as_str(), sec.as_deref(), creds_src)
        .await?;

    if let Ok(c) = state
        .auth
        .verify_access_token_for_userinfo(&req.token, state.config.auth.admin_api_audience.as_str())
        .await
    {
        return Ok(Json(IntrospectResponse {
            active: true,
            sub: Some(c.sub),
            exp: Some(c.exp as i64),
            aud: Some(c.aud),
        }));
    }
    if let Ok(c) = state.auth.jwt.verify_refresh_issuer(&req.token) {
        return Ok(Json(IntrospectResponse {
            active: true,
            sub: Some(c.sub),
            exp: Some(c.exp as i64),
            aud: Some(c.aud),
        }));
    }
    Ok(Json(IntrospectResponse {
        active: false,
        sub: None,
        exp: None,
        aud: None,
    }))
}
