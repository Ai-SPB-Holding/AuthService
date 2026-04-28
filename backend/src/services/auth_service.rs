use std::sync::Arc;

use base64::Engine;
use chrono::{Duration, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row};
use uuid::Uuid;

use crate::{
    domain::auth::TokenPair,
    domain::registration_source::{self, parse_registration_source},
    repositories::user_repository::UserRepository,
    security::jwt::JwtService,
    security::password,
    services::client_oauth::{self, ClientCredentialsSource},
    services::email_verification_service::EmailVerificationService,
    services::errors::AppError,
    services::totp_service::TotpService,
};

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterCommand {
    pub tenant_id: Uuid,
    pub email: String,
    pub password: String,
    /// Label for `users.registration_source` (e.g. `make-auth-service`, OAuth `client_id`).
    #[serde(default)]
    pub registration_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPendingEmail {
    pub user_id: Uuid,
    pub email_verification_token: String,
    pub expires_in: u64,
    pub token_type: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginCommand {
    pub tenant_id: Uuid,
    pub email: String,
    pub password: String,
    pub audience: String,
    /// Public OAuth `client_id` (string) when this login is scoped to a specific client; enables per-client MFA.
    #[serde(default)]
    pub oauth_client_id: Option<String>,
}

/// Password login: tokens, MFA step-up, or forced TOTP enrollment (admin + `AUTH__REQUIRE_LOGIN_2FA` without TOTP).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum LoginResult {
    Tokens(TokenPair),
    MfaRequired {
        mfa_required: bool,
        step_up_token: String,
        token_type: &'static str,
        expires_in: u64,
    },
    TotpEnrollmentRequired {
        totp_enrollment_required: bool,
        enrollment_token: String,
        token_type: &'static str,
        expires_in: u64,
    },
    ClientTotpEnrollEmailRequired {
        client_totp_enroll_email_required: bool,
        email_verification_token: String,
        token_type: &'static str,
        expires_in: u64,
        oauth_client_id: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub sub: String,
    pub tenant_id: String,
    pub email: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub email_verified: bool,
}

#[derive(Clone)]
pub struct AuthService<R: UserRepository> {
    pub users: Arc<R>,
    pub jwt: JwtService,
    pub redis: redis::aio::ConnectionManager,
    pub _pool: PgPool,
    pub ev: Arc<EmailVerificationService>,
    pub totp: Arc<TotpService>,
    /// From `OIDC__CLIENT_MFA_ENFORCE` (default true).
    pub client_mfa_enforce: bool,
    /// From `AUTH__REQUIRE_LOGIN_2FA` (default false).
    pub require_login_2fa: bool,
}

impl<R: UserRepository> AuthService<R> {
    pub async fn register(&self, cmd: RegisterCommand) -> Result<RegisterPendingEmail, AppError> {
        if cmd.password.len() < 10 {
            return Err(AppError::Validation("password is too short".to_string()));
        }

        let email = cmd.email.trim().to_lowercase();
        let hash = password::hash_password(&cmd.password).map_err(AppError::Validation)?;
        let reg = parse_registration_source(cmd.registration_source.as_deref(), registration_source::DEFAULT_DIRECT)
            .map_err(AppError::Validation)?;
        let user = self
            .users
            .create_user(cmd.tenant_id, &email, &hash, &reg)
            .await?;
        let (_vid, ev_jwt, exp) = self
            .ev
            .start_registration(user.id, user.tenant_id, &user.email)
            .await?;
        Ok(RegisterPendingEmail {
            user_id: user.id,
            email_verification_token: ev_jwt,
            expires_in: exp,
            token_type: "email_verification",
        })
    }

    pub async fn login(&self, cmd: LoginCommand) -> Result<LoginResult, AppError> {
        let email = cmd.email.trim().to_lowercase();
        self.rate_limit_login(cmd.tenant_id, &email).await?;
        let found = self.users.find_with_credential(cmd.tenant_id, &email).await?;
        let found = match found {
            Some(v) => v,
            None => {
                let _ = self
                    .record_auth_event(cmd.tenant_id, None, false, "password_login")
                    .await;
                return Err(AppError::Unauthorized);
            }
        };

        if !password::verify_password(&cmd.password, &found.password_hash) {
            self.register_failed_login(cmd.tenant_id, &email).await?;
            let _ = self
                .record_auth_event(cmd.tenant_id, Some(found.user.id), false, "password_login")
                .await;
            return Err(AppError::Unauthorized);
        }

        if found.user.is_locked {
            return Err(AppError::Forbidden);
        }

        self.clear_failed_logins(cmd.tenant_id, &email).await?;

        if self.require_login_2fa && !found.totp_enabled {
            let roles = self.load_role_names(found.user.tenant_id, found.user.id).await?;
            if roles.iter().any(|r| r == "admin") {
                let (enrollment_token, _jti) = self
                    .jwt
                    .mint_totp_enrollment_token(
                        found.user.id,
                        found.user.tenant_id,
                        &cmd.audience,
                    )?;
                return Ok(LoginResult::TotpEnrollmentRequired {
                    totp_enrollment_required: true,
                    enrollment_token,
                    token_type: "totp_enrollment",
                    expires_in: self.jwt.mfa_stepup_ttl() as u64,
                });
            }
            return Err(AppError::Validation(
                "AUTH__REQUIRE_LOGIN_2FA is enabled: enroll user TOTP (2FA) before login"
                    .to_string(),
            ));
        }

        // Per-OAuth-client MFA (Authenticator) when `oauth_client_id` is set
        if self.client_mfa_enforce {
            if let Some(ref oc) = cmd.oauth_client_id {
                let oc = oc.trim();
                if !oc.is_empty() {
                    if let Some(row) = sqlx::query(
                        "SELECT id, mfa_policy, allow_client_totp_enrollment, client_id
                         FROM clients WHERE client_id = $1 AND tenant_id = $2",
                    )
                    .bind(oc)
                    .bind(cmd.tenant_id)
                    .fetch_optional(&self._pool)
                    .await?
                    {
                        let client_row_id: Uuid = row.get("id");
                        let mfa_policy: String = row
                            .try_get::<String, _>("mfa_policy")
                            .unwrap_or_else(|_| "off".to_string());
                        if mfa_policy != "off" {
                            let is_enrolled = self
                                .totp
                                .is_client_totp_enabled(found.user.id, found.user.tenant_id, client_row_id)
                                .await?;
                            if mfa_policy == "required" && !is_enrolled {
                                let allow_enroll: bool = row
                                    .try_get("allow_client_totp_enrollment")
                                    .unwrap_or(true);
                                if !allow_enroll {
                                    return Err(AppError::Validation(
                                        "2FA is required for this OAuth client; enable \"Allow users to enroll Authenticator for this client\" in client settings, or use another login method"
                                            .to_string(),
                                    ));
                                }
                                let (_v, email_jwt, exp) = self
                                    .ev
                                    .start_client_totp_enroll_email(
                                        found.user.id,
                                        found.user.tenant_id,
                                        &found.user.email,
                                        oc,
                                    )
                                    .await?;
                                return Ok(LoginResult::ClientTotpEnrollEmailRequired {
                                    client_totp_enroll_email_required: true,
                                    email_verification_token: email_jwt,
                                    token_type: "email_verification",
                                    expires_in: exp,
                                    oauth_client_id: oc.to_string(),
                                });
                            }
                            let use_client = (mfa_policy == "required" && is_enrolled)
                                || (mfa_policy == "optional" && is_enrolled);
                            if use_client {
                                let (step, jti) = self.jwt.mint_mfa_stepup_token_ex(
                                    found.user.id,
                                    found.user.tenant_id,
                                    &cmd.audience,
                                    "client",
                                    Some(client_row_id),
                                )?;
                                let mfa_key = format!("mfa_su:{jti}");
                                let mut r = self.redis.clone();
                                if let Err(e) = r
                                    .set_ex::<_, _, ()>(mfa_key, "1", self.jwt.mfa_stepup_ttl() as u64)
                                    .await
                                {
                                    tracing::warn!(error = %e, "mfa_su redis set");
                                }
                                return Ok(LoginResult::MfaRequired {
                                    mfa_required: true,
                                    step_up_token: step,
                                    token_type: "mfa_step_up",
                                    expires_in: self.jwt.mfa_stepup_ttl() as u64,
                                });
                            }
                        }
                    } else {
                        return Err(AppError::Validation("unknown oauth_client_id for tenant".to_string()));
                    }
                }
            }
        }

        if found.totp_enabled {
            if found.totp_secret_enc.is_none() {
                tracing::error!(user_id = %found.user.id, "totp_enabled but no secret");
                return Err(AppError::Internal("totp misconfigured".to_string()));
            }
            let (step, jti) = self
                .jwt
                .mint_mfa_stepup_token(found.user.id, found.user.tenant_id, &cmd.audience)?;
            let mfa_key = format!("mfa_su:{jti}");
            let mut r = self.redis.clone();
            if let Err(e) = r
                .set_ex::<_, _, ()>(mfa_key, "1", self.jwt.mfa_stepup_ttl() as u64)
                .await
            {
                tracing::warn!(error = %e, "mfa_su redis set");
            }
            return Ok(LoginResult::MfaRequired {
                mfa_required: true,
                step_up_token: step,
                token_type: "mfa_step_up",
                expires_in: self.jwt.mfa_stepup_ttl() as u64,
            });
        }

        let roles = self.load_role_names(found.user.tenant_id, found.user.id).await?;
        let permissions = self
            .load_permission_names(found.user.tenant_id, found.user.id)
            .await
            .unwrap_or_default();
        let oauth_binding = cmd
            .oauth_client_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let pair = self
            .issue_tokens(
                found.user.id,
                found.user.tenant_id,
                &cmd.audience,
                roles,
                permissions,
                None,
                oauth_binding,
            )
            .await?;
        self.record_auth_event(found.user.tenant_id, Some(found.user.id), true, "password_login")
            .await;
        Ok(LoginResult::Tokens(pair))
    }

    /// Complete TOTP after password step (`step_up_token` from [`LoginResult::MfaRequired`]).
    pub async fn login_mfa(&self, step_up_token: &str, code: &str) -> Result<TokenPair, AppError> {
        let c = self.jwt.verify_mfa_stepup(step_up_token)?;
        let mfa_key = format!("mfa_su:{}", c.jti);
        let mut r = self.redis.clone();
        let key_ok: bool = r
            .exists(mfa_key.clone())
            .await
            .map_err(|_| AppError::Unauthorized)?;
        if !key_ok {
            return Err(AppError::Unauthorized);
        }
        let _: () = r
            .del::<_, ()>(mfa_key)
            .await
            .map_err(|_| AppError::Unauthorized)?;
        let user_id = Uuid::parse_str(&c.sub).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?;
        let oauth_client_for_refresh = if c.mfa_ctx == "client" {
            let row_id = c
                .oauth_client_row_id
                .as_ref()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(AppError::Unauthorized)?;
            let pub_cid: String = sqlx::query_scalar("SELECT client_id::text FROM clients WHERE id = $1 AND tenant_id = $2")
                .bind(row_id)
                .bind(tenant_id)
                .fetch_optional(&self._pool)
                .await?
                .ok_or(AppError::Unauthorized)?;
            self.totp
                .verify_client_login_totp(user_id, tenant_id, row_id, &pub_cid, code)
                .await?;
            Some(pub_cid)
        } else {
            self.totp.verify_login_totp(user_id, tenant_id, code).await?;
            None
        };
        let roles = self.load_role_names(tenant_id, user_id).await?;
        let permissions = self
            .load_permission_names(tenant_id, user_id)
            .await
            .unwrap_or_default();
        let oauth_binding = oauth_client_for_refresh.as_deref();
        let pair = self
            .issue_tokens(
                user_id,
                tenant_id,
                &c.login_audience,
                roles,
                permissions,
                None,
                oauth_binding,
            )
            .await?;
        self.record_auth_event(tenant_id, Some(user_id), true, "totp_mfa")
            .await;
        Ok(pair)
    }

    /// Full session after TOTP enrollment completed via [`crate::security::jwt::AUD_TOTP_ENROLL`] token on `/2fa/verify`.
    pub async fn issue_session_after_totp_enrollment(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        login_audience: &str,
    ) -> Result<TokenPair, AppError> {
        let roles = self.load_role_names(tenant_id, user_id).await?;
        let permissions = self
            .load_permission_names(tenant_id, user_id)
            .await
            .unwrap_or_default();
        let pair = self
            .issue_tokens(user_id, tenant_id, login_audience, roles, permissions, None, None)
            .await?;
        self.record_auth_event(tenant_id, Some(user_id), true, "totp_enrollment_login")
            .await;
        Ok(pair)
    }

    /// Rotate session from a valid refresh token. The access/refresh audience is taken from the token's `aud`.
    /// When the refresh row is bound to an OAuth `client_id`, callers must pass matching `client_id`;
    /// confidential clients must also pass `client_secret`.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        client_id: Option<&str>,
        client_secret: Option<&str>,
    ) -> Result<TokenPair, AppError> {
        let claims = self.jwt.verify_refresh_issuer(refresh_token)?;
        let audience = claims.aud.clone();
        let th = refresh_token_hash(refresh_token);
        let rkey = format!("rrev:{th}");
        let mut conn = self.redis.clone();
        if conn.get::<_, Option<String>>(&rkey).await?.is_some() {
            return Err(AppError::Unauthorized);
        }

        let row_id = Uuid::parse_str(&claims.jti).map_err(|_| AppError::Unauthorized)?;
        let family_id = Uuid::parse_str(&claims.family).map_err(|_| AppError::Unauthorized)?;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Unauthorized)?;

        let row = sqlx::query(
            "SELECT rt.id, rt.revoked, rt.token_hash, rt.token_family_id, rt.oauth_client_public_id, rt.oauth_client_row_id,
                    rt.session_status, c.client_id AS bound_client_public
             FROM refresh_tokens rt
             LEFT JOIN clients c ON c.id = rt.oauth_client_row_id
             WHERE rt.id = $1 AND rt.tenant_id = $2 AND rt.user_id = $3",
        )
        .bind(row_id)
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self._pool)
        .await?;

        let Some(row) = row else {
            return Err(AppError::Unauthorized);
        };
        let revoked: bool = row.get("revoked");
        let session_status: String = row
            .try_get::<String, _>("session_status")
            .unwrap_or_else(|_| "active".to_string());
        let stored_hash: String = row.get("token_hash");
        if stored_hash != th {
            return Err(AppError::Unauthorized);
        }
        if revoked || session_status != "active" {
            self.revoke_refresh_family(tenant_id, family_id).await;
            return Err(AppError::Unauthorized);
        }

        let oauth_row_id: Option<Uuid> = row.try_get("oauth_client_row_id").ok().flatten();
        let oauth_bound_public: Option<String> = row.try_get("oauth_client_public_id").ok().flatten();
        let bound_public: Option<String> = row.try_get("bound_client_public").ok().flatten();
        let expected_public = bound_public
            .clone()
            .or(oauth_bound_public.clone())
            .filter(|s| !s.trim().is_empty());

        if oauth_row_id.is_some() || expected_public.is_some() {
            let provided = client_id
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AppError::Validation("client_id is required for this refresh token".to_string()))?;
            let exp = expected_public
                .as_deref()
                .ok_or_else(|| AppError::Internal("refresh token missing bound client".to_string()))?;
            if provided != exp {
                return Err(AppError::Unauthorized);
            }
            client_oauth::assert_grant_allowed(&self._pool, tenant_id, exp, "refresh_token").await?;
            let c_row = if let Some(cid) = oauth_row_id {
                sqlx::query(
                    "SELECT client_type, client_secret_argon2, token_endpoint_auth_method FROM clients WHERE id = $1 AND tenant_id = $2",
                )
                .bind(cid)
                .bind(tenant_id)
                .fetch_optional(&self._pool)
                .await?
                .ok_or(AppError::Unauthorized)?
            } else {
                sqlx::query(
                    "SELECT client_type, client_secret_argon2, token_endpoint_auth_method FROM clients WHERE client_id = $1 AND tenant_id = $2",
                )
                .bind(exp)
                .bind(tenant_id)
                .fetch_optional(&self._pool)
                .await?
                .ok_or(AppError::Unauthorized)?
            };
            let ctype: String = c_row
                .try_get::<String, _>("client_type")
                .unwrap_or_else(|_| "public".to_string());
            if ctype == "confidential" {
                let provided_sec = client_secret
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| AppError::Validation("client_secret is required for confidential clients".to_string()))?;
                if !client_oauth::verify_confidential_client_secret(&c_row, provided_sec) {
                    return Err(AppError::Unauthorized);
                }
            } else if client_secret.is_some_and(|s| !s.trim().is_empty()) {
                return Err(AppError::Validation(
                    "client_secret must not be sent for public OAuth clients".to_string(),
                ));
            }
        }

        // Rotate: revoke this row, issue new pair in same family
        let _ = sqlx::query(
            "UPDATE refresh_tokens SET revoked = true, session_status = 'revoked', revoked_at = NOW() WHERE id = $1",
        )
        .bind(row_id)
        .execute(&self._pool)
        .await;
        let _: () = conn
            .set_ex(rkey, "1", (self.jwt.refresh_ttl_seconds().max(1)) as u64)
            .await
            .unwrap_or(());

        let roles = self.load_role_names(tenant_id, user_id).await?;
        let permissions = self
            .load_permission_names(tenant_id, user_id)
            .await
            .unwrap_or_default();
        self.issue_tokens_with_family(
            user_id,
            tenant_id,
            &audience,
            roles,
            permissions,
            None,
            family_id,
            Some(row_id),
            oauth_bound_public
                .as_deref()
                .or(bound_public.as_deref()),
        )
        .await
    }

    /// Verify OAuth client credentials for introspection / revocation. `client_id` is required.
    pub async fn verify_oauth_client_introspect_or_revoke(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        creds_source: ClientCredentialsSource,
    ) -> Result<(), AppError> {
        client_oauth::resolve_introspect_client(&self._pool, client_id, client_secret, creds_source).await
    }

    /// Access token for OIDC userinfo: issuer/signature OK and `aud` is admin API audience or a registered OAuth client.
    pub async fn verify_access_token_for_userinfo(
        &self,
        token: &str,
        admin_api_audience: &str,
    ) -> Result<crate::security::jwt::AccessClaims, AppError> {
        let claims = self.jwt.verify_access_any_audience(token)?;
        let aud = claims.aud.trim();
        if aud.is_empty() {
            return Err(AppError::Unauthorized);
        }
        if aud == admin_api_audience.trim() {
            return Ok(claims);
        }
        let ok: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                SELECT 1 FROM clients
                WHERE client_id = $1
                   OR (embedded_token_audience IS NOT NULL AND embedded_token_audience = $1)
            )"#,
        )
        .bind(aud)
        .fetch_one(&self._pool)
        .await
        .unwrap_or(false);
        if !ok {
            return Err(AppError::Unauthorized);
        }
        Ok(claims)
    }

    /// When the access JWT carries `sid` (session / refresh row id), require that row to be active server-side.
    pub async fn ensure_access_session_active(
        &self,
        claims: &crate::security::jwt::AccessClaims,
    ) -> Result<(), AppError> {
        let Some(ref sid) = claims.sid else {
            return Ok(());
        };
        let session_id = Uuid::parse_str(sid).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Unauthorized)?;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
        let ok: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM refresh_tokens WHERE id = $1 AND tenant_id = $2 AND user_id = $3
             AND NOT revoked AND session_status = 'active' AND expires_at > NOW())",
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&self._pool)
        .await
        .unwrap_or(false);
        if !ok {
            return Err(AppError::Unauthorized);
        }
        Ok(())
    }

    async fn revoke_refresh_family(&self, tenant_id: Uuid, family_id: Uuid) {
        if let Err(e) = sqlx::query(
            "UPDATE refresh_tokens SET revoked = true, session_status = 'revoked', revoked_at = NOW()
             WHERE tenant_id = $1 AND token_family_id = $2",
        )
        .bind(tenant_id)
        .bind(family_id)
        .execute(&self._pool)
        .await
        {
            tracing::warn!(error = %e, "revoke_refresh_family");
        }
    }

    pub async fn logout(&self, refresh_token: &str) -> Result<(), AppError> {
        let th = refresh_token_hash(refresh_token);
        let mut conn = self.redis.clone();
        let rkey = format!("rrev:{th}");
        let _: () = conn
            .set_ex(rkey, "1", 60 * 60 * 24 * 14)
            .await
            .unwrap_or(());

        if let Err(e) = sqlx::query(
            "UPDATE refresh_tokens SET revoked = true, session_status = 'revoked', revoked_at = NOW() WHERE token_hash = $1",
        )
        .bind(&th)
        .execute(&self._pool)
        .await
        {
            tracing::warn!(error = %e, "refresh_tokens revoke on logout");
        }
        Ok(())
    }

    async fn load_role_names(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT r.name FROM roles r
             INNER JOIN user_roles ur ON ur.role_id = r.id AND ur.tenant_id = r.tenant_id
             WHERE ur.user_id = $1 AND ur.tenant_id = $2
             ORDER BY r.name",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self._pool)
        .await?;

        if names.is_empty() {
            Ok(vec!["user".to_string()])
        } else {
            Ok(names)
        }
    }

    async fn load_permission_names(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT p.name FROM permissions p
             INNER JOIN role_permissions rp ON rp.permission_id = p.id AND rp.tenant_id = p.tenant_id
             INNER JOIN user_roles ur ON ur.role_id = rp.role_id AND ur.tenant_id = rp.tenant_id
             WHERE ur.user_id = $1 AND ur.tenant_id = $2
             ORDER BY p.name",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self._pool)
        .await
        .unwrap_or_default();
        Ok(names)
    }

    async fn record_auth_event(&self, tenant_id: Uuid, user_id: Option<Uuid>, success: bool, event_kind: &str) {
        if let Err(e) = sqlx::query(
            "INSERT INTO auth_events (tenant_id, user_id, success, event_kind) VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(success)
        .bind(event_kind)
        .execute(&self._pool)
        .await
        {
            tracing::warn!(error = %e, "auth_events insert failed; apply migration 0002 for login metrics");
        }
    }

    async fn user_email_verified(&self, user_id: Uuid) -> bool {
        sqlx::query_scalar::<Postgres, bool>("SELECT email_verified FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self._pool)
            .await
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Standard token pair (new refresh family).
    async fn issue_tokens(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        audience: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
        scope: Option<String>,
        oauth_client_public_id: Option<&str>,
    ) -> Result<TokenPair, AppError> {
        let fam = Uuid::new_v4();
        self.issue_tokens_with_family(
            user_id,
            tenant_id,
            audience,
            roles,
            permissions,
            scope,
            fam,
            None,
            oauth_client_public_id,
        )
        .await
    }

    /// Issue access + refresh; `family_id` is stable across rotations; `rotated_from` for audit.
    async fn issue_tokens_with_family(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        audience: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
        scope: Option<String>,
        family_id: Uuid,
        rotated_from: Option<Uuid>,
        oauth_client_public_id: Option<&str>,
    ) -> Result<TokenPair, AppError> {
        let ev = self.user_email_verified(user_id).await;
        let row_id = Uuid::new_v4();
        let access = self
            .jwt
            .mint_access_token(
                user_id,
                tenant_id,
                audience,
                roles.clone(),
                permissions,
                ev,
                scope.clone(),
                Some(row_id),
            )?;
        let refresh = self
            .jwt
            .mint_refresh_token(user_id, tenant_id, audience, ev, row_id, family_id)?;
        let th = refresh_token_hash(&refresh);
        let expires_at = Utc::now() + Duration::seconds(self.jwt.refresh_ttl_seconds());

        let oauth_row: Option<Uuid> = if let Some(pid) = oauth_client_public_id.map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query_scalar("SELECT id FROM clients WHERE tenant_id = $1 AND client_id = $2")
                .bind(tenant_id)
                .bind(pid)
                .fetch_optional(&self._pool)
                .await?
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO refresh_tokens (id, tenant_id, user_id, token_hash, expires_at, revoked, token_family_id, rotated_from_id, jti_in_token, oauth_client_public_id, oauth_client_row_id)
             VALUES ($1, $2, $3, $4, $5, false, $6, $7, $8, $9, $10)",
        )
        .bind(row_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(&th)
        .bind(expires_at)
        .bind(family_id)
        .bind(rotated_from)
        .bind(row_id.to_string())
        .bind(oauth_client_public_id)
        .bind(oauth_row)
        .execute(&self._pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "refresh_tokens insert failed");
            AppError::Internal("session persistence failed".to_string())
        })?;

        Ok(TokenPair {
            access_token: access,
            refresh_token: refresh,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt.access_ttl_seconds() as u64,
            id_token: None,
        })
    }

    async fn rate_limit_login(&self, tenant_id: Uuid, email: &str) -> Result<(), AppError> {
        let key = format!("login:attempt:{tenant_id}:{email}");
        let mut conn = self.redis.clone();
        let attempts: i64 = conn.incr(&key, 1).await?;
        if attempts == 1 {
            let _: () = conn.expire(&key, 120).await?;
        }

        if attempts > 10 {
            return Err(AppError::Forbidden);
        }

        Ok(())
    }

    async fn register_failed_login(&self, tenant_id: Uuid, email: &str) -> Result<(), AppError> {
        let key = format!("login:failed:{tenant_id}:{email}");
        let mut conn = self.redis.clone();
        let failures: i64 = conn.incr(&key, 1).await?;
        if failures == 1 {
            let _: () = conn.expire(&key, 1800).await?;
        }
        Ok(())
    }

    async fn clear_failed_logins(&self, tenant_id: Uuid, email: &str) -> Result<(), AppError> {
        let key = format!("login:failed:{tenant_id}:{email}");
        let mut conn = self.redis.clone();
        let _: () = conn.del(key).await?;
        Ok(())
    }

    pub async fn userinfo_from_token(&self, token: &str, audience: &str) -> Result<UserInfo, AppError> {
        let claims = self.jwt.verify(token, audience)?;
        self.userinfo_from_access_claims(&claims).await
    }

    pub async fn userinfo_from_access_claims(
        &self,
        claims: &crate::security::jwt::AccessClaims,
    ) -> Result<UserInfo, AppError> {
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
        let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self._pool)
            .await?;
        let email = email.unwrap_or_default();

        Ok(UserInfo {
            sub: claims.sub.clone(),
            tenant_id: claims.tenant_id.clone(),
            email,
            roles: claims.roles.clone(),
            permissions: claims.permissions.clone(),
            email_verified: claims.email_verified,
        })
    }

    /// After `POST /auth/verify-client-totp-enroll-email` (or embedded equivalent): mint setup bearer for TOTP.
    pub async fn verify_client_totp_enroll_email_and_mint_setup(
        &self,
        email_jwt: &str,
        code: &str,
        oauth_client_public: &str,
        login_audience: &str,
    ) -> Result<(String, u64), AppError> {
        let c = self.jwt.verify_email_verification(email_jwt.trim())?;
        let user_id = Uuid::parse_str(&c.sub).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?;
        let ver_id = Uuid::parse_str(&c.jti).map_err(|_| AppError::Unauthorized)?;
        self.ev
            .complete_client_totp_enroll_email_code(
                user_id,
                tenant_id,
                ver_id,
                code.trim(),
                oauth_client_public.trim(),
            )
            .await?;
        let row = sqlx::query(
            "SELECT id, COALESCE(mfa_policy, 'off') AS mfa_policy, COALESCE(allow_client_totp_enrollment, true) AS allow_en
             FROM clients WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(oauth_client_public.trim())
        .bind(tenant_id)
        .fetch_optional(&self._pool)
        .await?
        .ok_or_else(|| AppError::Validation("unknown oauth client".to_string()))?;
        let client_row_id: Uuid = row.get("id");
        let mfa_policy: String = row.get("mfa_policy");
        let allow: bool = row.get("allow_en");
        if mfa_policy != "required" {
            return Err(AppError::Validation("client 2FA is not required; sign in with password".to_string()));
        }
        if !allow {
            return Err(AppError::Forbidden);
        }
        if self
            .totp
            .is_client_totp_enabled(user_id, tenant_id, client_row_id)
            .await?
        {
            return Err(AppError::Validation(
                "Authenticator is already set up for this app; use password and 2FA to sign in".to_string(),
            ));
        }
        self.jwt.mint_client_totp_enroll_after_email(
            user_id,
            tenant_id,
            login_audience,
            client_row_id,
            oauth_client_public.trim(),
        )
    }

    /// `POST /auth/client-totp-enroll/setup` with Bearer [`crate::security::jwt::AUD_CLIENT_TOTP_ENROLL_SETUP`].
    pub async fn client_totp_enroll_setup_after_email_bearer(
        &self,
        setup_bearer: &str,
    ) -> Result<(String, String), AppError> {
        let c = self.jwt.verify_client_totp_enroll_after_email(setup_bearer.trim())?;
        let user_id = Uuid::parse_str(&c.sub).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?;
        let client_row = Uuid::parse_str(&c.oauth_client_row_id).map_err(|_| AppError::Unauthorized)?;
        self.totp
            .begin_client_setup(
                user_id,
                tenant_id,
                client_row,
                c.public_oauth_client_id.as_str(),
            )
            .await
    }

    /// `POST /auth/client-totp-enroll/verify` with Bearer; issues full access/refresh after app TOTP is confirmed.
    pub async fn client_totp_enroll_verify_after_email_bearer(
        &self,
        setup_bearer: &str,
        code: &str,
    ) -> Result<TokenPair, AppError> {
        let c = self.jwt.verify_client_totp_enroll_after_email(setup_bearer.trim())?;
        let user_id = Uuid::parse_str(&c.sub).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&c.tenant_id).map_err(|_| AppError::Unauthorized)?;
        let client_row = Uuid::parse_str(&c.oauth_client_row_id).map_err(|_| AppError::Unauthorized)?;
        self.totp
            .complete_client_setup(
                user_id,
                tenant_id,
                client_row,
                c.public_oauth_client_id.as_str(),
                code.trim(),
            )
            .await?;
        let aud = c.login_audience.as_str();
        let roles = self.load_role_names(tenant_id, user_id).await?;
        let perms = self
            .load_permission_names(tenant_id, user_id)
            .await
            .unwrap_or_default();
        let pair = self
            .issue_tokens(
                user_id,
                tenant_id,
                aud,
                roles,
                perms,
                None,
                Some(c.public_oauth_client_id.as_str()),
            )
            .await?;
        self.record_auth_event(tenant_id, Some(user_id), true, "client_totp_enroll")
            .await;
        Ok(pair)
    }

    /// After successful email code verification, mint normal tokens (e.g. first login post-register).
    pub async fn complete_email_verification(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        verification_id: Uuid,
        code: &str,
        audience: &str,
    ) -> Result<TokenPair, AppError> {
        self.ev
            .complete_registration(user_id, tenant_id, verification_id, code)
            .await?;
        let roles = self.load_role_names(tenant_id, user_id).await?;
        let perms = self
            .load_permission_names(tenant_id, user_id)
            .await
            .unwrap_or_default();
        self.issue_tokens(user_id, tenant_id, audience, roles, perms, None, None)
            .await
    }

    /// Finalize embedded pending registration: insert `users`, `credentials`, `client_user_mfa`, delete pending.
    pub async fn finalize_embedded_pending_registration(
        &self,
        pending_id: Uuid,
        tenant_id: Uuid,
        audience: &str,
        oauth_client_row_id: Uuid,
    ) -> Result<TokenPair, AppError> {
        let mut tx = self._pool.begin().await?;
        let row = sqlx::query(
            "SELECT email, password_hash, registration_source, client_totp_secret_enc
             FROM embedded_pending_registrations
             WHERE id = $1 AND tenant_id = $2
               AND email_verified_at IS NOT NULL
               AND client_totp_verified_at IS NOT NULL
               AND expires_at > NOW()",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::Unauthorized)?;

        let email: String = {
            let raw: String = row.get("email");
            raw.trim().to_lowercase()
        };
        let password_hash: String = row.get("password_hash");
        let registration_source: String = row.get("registration_source");
        let totp_enc: Option<Vec<u8>> = row.get("client_totp_secret_enc");
        let totp_enc =
            totp_enc.ok_or_else(|| AppError::Internal("pending totp secret missing".to_string()))?;

        let user_id = Uuid::new_v4();
        let ins_user = sqlx::query(
            "INSERT INTO users (id, tenant_id, email, is_active, is_locked, email_verified, registration_source)
             VALUES ($1, $2, $3, true, false, true, $4)",
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&email)
        .bind(&registration_source)
        .execute(&mut *tx)
        .await;

        match ins_user {
            Ok(_) => {}
            Err(e) => {
                if let sqlx::Error::Database(ref db) = e {
                    if db.code().as_deref() == Some("23505") {
                        return Err(AppError::Validation("email already registered".to_string()));
                    }
                }
                return Err(AppError::Internal(e.to_string()));
            }
        }

        sqlx::query("INSERT INTO credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)")
            .bind(user_id)
            .bind(tenant_id)
            .bind(&password_hash)
            .execute(&mut *tx)
            .await?;

        let mfa_row_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO client_user_mfa (id, oauth_client_row_id, user_id, tenant_id, totp_secret_enc, totp_enabled, totp_enabled_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())",
        )
        .bind(mfa_row_id)
        .bind(oauth_client_row_id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(&totp_enc)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM embedded_pending_registrations WHERE id = $1")
            .bind(pending_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        let pub_cid: String = sqlx::query_scalar("SELECT client_id::text FROM clients WHERE id = $1 AND tenant_id = $2")
            .bind(oauth_client_row_id)
            .bind(tenant_id)
            .fetch_optional(&self._pool)
            .await?
            .ok_or_else(|| AppError::Internal("oauth client row missing after registration".to_string()))?;

        let roles = self.load_role_names(tenant_id, user_id).await?;
        let perms = self
            .load_permission_names(tenant_id, user_id)
            .await
            .unwrap_or_default();
        let pair = self
            .issue_tokens(
                user_id,
                tenant_id,
                audience,
                roles,
                perms,
                None,
                Some(pub_cid.as_str()),
            )
            .await?;
        let _ = self
            .record_auth_event(tenant_id, Some(user_id), true, "embedded_register")
            .await;
        Ok(pair)
    }

    /// RFC 7636: `BASE64URL(S256(code_verifier)) == code_challenge`
    pub fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
        let d = Sha256::digest(verifier.as_bytes());
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d);
        b64 == challenge
    }

    /// Insert a one-time authorization code (OIDC authorization code + PKCE).
    pub async fn create_authorization_code(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        client_id: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
        scope: &str,
        ttl: chrono::Duration,
    ) -> Result<String, AppError> {
        let client_row_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM clients WHERE tenant_id = $1 AND client_id = $2",
        )
        .bind(tenant_id)
        .bind(client_id)
        .fetch_optional(&self._pool)
        .await?
        .ok_or_else(|| AppError::Validation("unknown oauth client".to_string()))?;

        let code = Uuid::new_v4().to_string().replace('-', "")
            + &Uuid::new_v4().to_string().replace('-', "");
        let exp = Utc::now() + ttl;
        sqlx::query(
            "INSERT INTO auth_codes (code, tenant_id, user_id, client_id, client_row_id, code_challenge, code_challenge_method, redirect_uri, expires_at, nonce, scope, consumed)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false)",
        )
        .bind(&code)
        .bind(tenant_id)
        .bind(user_id)
        .bind(client_id)
        .bind(client_row_id)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(redirect_uri)
        .bind(exp)
        .bind(nonce)
        .bind(scope)
        .execute(&self._pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth_codes insert");
            AppError::Internal("auth code store failed".to_string())
        })?;
        Ok(code)
    }

    /// Exchanges an authorization code for tokens (access, refresh, optional id_token for `openid`).
    pub async fn exchange_authorization_code(
        &self,
        code: &str,
        code_verifier: &str,
        client_id: &str,
        redirect_uri: &str,
        access_audience: &str,
        client_secret: Option<&str>,
        creds_source: ClientCredentialsSource,
    ) -> Result<TokenPair, AppError> {
        let mut tx = self._pool.begin().await?;
        let row = sqlx::query(
            "SELECT code, tenant_id, user_id, client_id, code_challenge, code_challenge_method, redirect_uri, expires_at, nonce, scope, consumed
             FROM auth_codes WHERE code = $1 FOR UPDATE",
        )
        .bind(code)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            return Err(AppError::Unauthorized);
        };
        let consumed: bool = row.get("consumed");
        if consumed {
            return Err(AppError::Unauthorized);
        }
        let exp: chrono::DateTime<Utc> = row.get("expires_at");
        if Utc::now() > exp {
            return Err(AppError::Validation("code expired".to_string()));
        }
        let row_client: String = row.get("client_id");
        if row_client != client_id {
            return Err(AppError::Validation("client_id mismatch".to_string()));
        }
        let row_redirect: String = row.get("redirect_uri");
        if row_redirect != redirect_uri {
            return Err(AppError::Validation("redirect_uri mismatch".to_string()));
        }
        let challenge: String = row.get("code_challenge");
        let challenge_method: String = row
            .try_get::<String, _>("code_challenge_method")
            .unwrap_or_else(|_| "S256".to_string());
        if challenge_method == "none" {
            if !code_verifier.is_empty() {
                return Err(AppError::Validation("code_verifier must be empty for PKCE method none".to_string()));
            }
        } else if !Self::verify_pkce_s256(code_verifier, &challenge) {
            return Err(AppError::Validation("invalid code_verifier".to_string()));
        }
        let tenant_id: Uuid = row.get("tenant_id");
        let user_id: Uuid = row.get("user_id");
        let nonce: Option<String> = row.get("nonce");
        let scope_s: String = row.get("scope");

        client_oauth::assert_grant_allowed(&self._pool, tenant_id, client_id, "authorization_code").await?;

        // Verify OAuth client and optional secret
        let c_row = sqlx::query(
            "SELECT id, client_type, client_secret_argon2, scopes, token_endpoint_auth_method
             FROM clients WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::Validation("unknown client".to_string()))?;
        let ctype: String = c_row
            .try_get::<String, _>("client_type")
            .unwrap_or_else(|_| "public".to_string());
        let token_method: String = c_row
            .try_get::<String, _>("token_endpoint_auth_method")
            .unwrap_or_else(|_| "client_secret_basic".to_string());
        client_oauth::enforce_token_endpoint_auth_method(
            token_method.as_str(),
            ctype == "confidential",
            creds_source,
        )?;
        if ctype == "confidential" {
            let provided = client_secret
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AppError::Validation("client_secret required".to_string()))?;
            if !client_oauth::verify_confidential_client_secret(&c_row, provided) {
                return Err(AppError::Unauthorized);
            }
        } else if client_secret.is_some_and(|s| !s.trim().is_empty()) {
            return Err(AppError::Validation(
                "client_secret must not be sent for public OAuth clients".to_string(),
            ));
        }

        let _ = sqlx::query("UPDATE auth_codes SET consumed = true WHERE code = $1")
            .bind(code)
            .execute(&mut *tx)
            .await;
        tx.commit().await?;

        let roles = self.load_role_names(tenant_id, user_id).await?;
        let perms = self
            .load_permission_names(tenant_id, user_id)
            .await
            .unwrap_or_default();
        let scope_for_access = if scope_s.trim().is_empty() {
            None
        } else {
            Some(scope_s.clone())
        };
        let fam = Uuid::new_v4();
        let mut pair = self
            .issue_tokens_with_family(
                user_id,
                tenant_id,
                access_audience,
                roles,
                perms,
                scope_for_access.clone(),
                fam,
                None,
                Some(client_id),
            )
            .await?;
        if scope_s.split_whitespace().any(|s| s == "openid") {
            let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&self._pool)
                .await?;
            let ev = self.user_email_verified(user_id).await;
            let idt = self.jwt.mint_id_token(
                user_id,
                client_id,
                nonce,
                email.clone(),
                ev,
                &pair.access_token,
            )?;
            pair.id_token = Some(idt);
        }
        Ok(pair)
    }

    /// After embedded iframe login (`access_token` only), mint a one-time code for the BFF to exchange at `/oauth2/token`.
    pub async fn create_embedded_exchange_code(
        &self,
        access_token: &str,
        oauth_client_public_id: &str,
    ) -> Result<(String, u64), AppError> {
        let claims = self.jwt.verify_access_any_audience(access_token)?;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
        let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| AppError::Unauthorized)?;
        let oc = oauth_client_public_id.trim();
        if oc.is_empty() {
            return Err(AppError::Validation("client_id required".to_string()));
        }
        let ok: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM clients WHERE client_id = $1 AND tenant_id = $2
               AND COALESCE(embedded_flow_mode, 'code_exchange') <> 'legacy_postmessage')",
        )
        .bind(oc)
        .bind(tenant_id)
        .fetch_one(&self._pool)
        .await
        .unwrap_or(false);
        if !ok {
            return Err(AppError::Validation(
                "unknown client or session exchange not allowed for this embedded_flow_mode".to_string(),
            ));
        }
        let client_row_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM clients WHERE client_id = $1 AND tenant_id = $2
               AND COALESCE(embedded_flow_mode, 'code_exchange') <> 'legacy_postmessage'",
        )
        .bind(oc)
        .bind(tenant_id)
        .fetch_optional(&self._pool)
        .await?
        .ok_or_else(|| AppError::Validation("unknown client".to_string()))?;
        let code = Uuid::new_v4().to_string().replace('-', "")
            + &Uuid::new_v4().to_string().replace('-', "");
        let exp = Utc::now() + Duration::seconds(120);
        sqlx::query(
            "INSERT INTO embedded_exchange_codes (code, tenant_id, user_id, oauth_client_public_id, client_row_id, expires_at, consumed)
             VALUES ($1, $2, $3, $4, $5, $6, false)",
        )
        .bind(&code)
        .bind(tenant_id)
        .bind(user_id)
        .bind(oc)
        .bind(client_row_id)
        .bind(exp)
        .execute(&self._pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "embedded_exchange_codes insert");
            AppError::Internal("session code store failed".to_string())
        })?;
        Ok((code, 120))
    }

    /// `grant_type=embedded_session` on `/oauth2/token` — exchange one-time iframe code for tokens (BFF only).
    pub async fn exchange_embedded_session_code(
        &self,
        code: &str,
        oauth_client_public_id: &str,
        access_audience: &str,
        client_secret: Option<&str>,
        creds_source: ClientCredentialsSource,
    ) -> Result<TokenPair, AppError> {
        let mut tx = self._pool.begin().await?;
        let row = sqlx::query(
            "SELECT code, tenant_id, user_id, oauth_client_public_id, expires_at, consumed
             FROM embedded_exchange_codes WHERE code = $1 FOR UPDATE",
        )
        .bind(code)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Err(AppError::Unauthorized);
        };
        let consumed: bool = row.get("consumed");
        if consumed {
            return Err(AppError::Unauthorized);
        }
        let exp: chrono::DateTime<Utc> = row.get("expires_at");
        if Utc::now() > exp {
            return Err(AppError::Validation("code expired".to_string()));
        }
        let bound: String = row.get("oauth_client_public_id");
        if bound != oauth_client_public_id {
            return Err(AppError::Validation("client_id mismatch".to_string()));
        }
        let tenant_id: Uuid = row.get("tenant_id");
        let user_id: Uuid = row.get("user_id");

        client_oauth::assert_grant_allowed(&self._pool, tenant_id, oauth_client_public_id, "embedded_session").await?;

        let c_row = sqlx::query(
            "SELECT id, client_type, client_secret_argon2, token_endpoint_auth_method
             FROM clients WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(oauth_client_public_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::Validation("unknown client".to_string()))?;
        let ctype: String = c_row
            .try_get::<String, _>("client_type")
            .unwrap_or_else(|_| "public".to_string());
        let token_method: String = c_row
            .try_get::<String, _>("token_endpoint_auth_method")
            .unwrap_or_else(|_| "client_secret_basic".to_string());
        client_oauth::enforce_token_endpoint_auth_method(
            token_method.as_str(),
            ctype == "confidential",
            creds_source,
        )?;
        if ctype == "confidential" {
            let provided = client_secret
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AppError::Validation("client_secret required".to_string()))?;
            if !client_oauth::verify_confidential_client_secret(&c_row, provided) {
                return Err(AppError::Unauthorized);
            }
        } else if client_secret.is_some_and(|s| !s.trim().is_empty()) {
            return Err(AppError::Validation(
                "client_secret must not be sent for public OAuth clients".to_string(),
            ));
        }

        sqlx::query("UPDATE embedded_exchange_codes SET consumed = true WHERE code = $1")
            .bind(code)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        let roles = self.load_role_names(tenant_id, user_id).await?;
        let perms = self
            .load_permission_names(tenant_id, user_id)
            .await
            .unwrap_or_default();
        self.issue_tokens(
            user_id,
            tenant_id,
            access_audience,
            roles,
            perms,
            None,
            Some(oauth_client_public_id),
        )
        .await
    }
}

fn refresh_token_hash(token: &str) -> String {
    let d = Sha256::digest(token.as_bytes());
    d.iter().map(|b| format!("{:02x}", b)).collect()
}
