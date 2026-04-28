use base64::Engine;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::{config::AppConfig, services::errors::AppError};

pub const AUD_EMAIL_VERIFY: &str = "email-verify";
/// Email verification JWT for [`crate::services::email_verification_service::PURPOSE_EMBEDDED_PENDING_REGISTER`].
pub const AUD_EMAIL_VERIFY_PENDING: &str = "email-verify-pending";
/// Short-lived bearer to finish per-client TOTP enrollment before user row exists (embedded required-MFA registration).
pub const AUD_EMBEDDED_PENDING_CLIENT_TOTP: &str = "embedded-pending-client-totp";
/// After email code verification, allows [`crate::http::handlers::auth::client_totp_enroll_setup`]
/// without a full access session (user must not yet have per-client TOTP for this app).
pub const AUD_CLIENT_TOTP_ENROLL_SETUP: &str = "client-totp-enroll-setup";
pub const AUD_MFA_STEPUP: &str = "mfa-stepup";
/// Short-lived token for `POST /2fa/setup` + `/2fa/verify` when admin must enroll TOTP under `AUTH__REQUIRE_LOGIN_2FA`.
pub const AUD_TOTP_ENROLL: &str = "totp-enroll";
pub const AUD_IDP_SESSION: &str = "idp-session";

fn default_email_verified() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    /// Unique token id; absent in legacy access JWTs.
    #[serde(default)]
    pub jti: Option<String>,
    pub exp: usize,
    #[serde(default)]
    pub iat: Option<usize>,
    pub iss: String,
    pub aud: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub tenant_id: String,
    #[serde(default = "default_email_verified")]
    pub email_verified: bool,
    /// Server-side session id (`refresh_tokens.id`); when present, access is bound to that session row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,
    pub jti: String,
    pub family: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
    pub tenant_id: String,
    pub email_verified: bool,
    #[serde(rename = "typ")]
    pub token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub auth_time: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(rename = "at_hash", skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerifyClaims {
    pub sub: String,
    pub exp: usize,
    pub iss: String,
    pub aud: String,
    pub tenant_id: String,
    pub jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStepUpClaims {
    pub sub: String,
    pub jti: String,
    pub exp: usize,
    pub iss: String,
    pub aud: String,
    pub tenant_id: String,
    pub login_audience: String,
    /// `"user"` = verify against `users.totp_*`; `"client"` = per-OAuth-client TOTP in `client_user_mfa`.
    #[serde(default = "default_mfa_step_ctx")]
    pub mfa_ctx: String,
    /// Internal `clients.id` (UUID) when `mfa_ctx` is `client`.
    #[serde(default)]
    pub oauth_client_row_id: Option<String>,
}

fn default_mfa_step_ctx() -> String {
    "user".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEnrollmentClaims {
    pub sub: String,
    pub jti: String,
    pub exp: usize,
    pub iss: String,
    pub aud: String,
    pub tenant_id: String,
    /// Target `aud` for access/refresh after successful TOTP enrollment.
    pub login_audience: String,
}

/// `sub` = `embedded_pending_registrations.id` (pending registration, no `users` row yet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingClientTotpEnrollmentClaims {
    pub sub: String,
    pub jti: String,
    pub exp: usize,
    pub iss: String,
    pub aud: String,
    pub tenant_id: String,
    pub login_audience: String,
    pub oauth_client_row_id: String,
    pub public_oauth_client_id: String,
}

/// After email step-up, user Id in `sub`; allows client TOTP setup before full login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTotpEnrollAfterEmailClaims {
    pub sub: String,
    pub jti: String,
    pub exp: usize,
    pub iss: String,
    pub aud: String,
    pub tenant_id: String,
    pub login_audience: String,
    pub oauth_client_row_id: String,
    pub public_oauth_client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpSessionClaims {
    pub sub: String,
    pub tenant_id: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
}

#[derive(Clone)]
pub struct JwtService {
    encoding_key: EncodingKey,
    /// One or more RSA public keys (newest first); supports rotation / previous key verification.
    decoding_keys: Vec<DecodingKey>,
    issuer: String,
    access_ttl_seconds: i64,
    refresh_ttl_seconds: i64,
    email_verification_jwt_seconds: i64,
    mfa_step_up_seconds: i64,
    idp_session_ttl_seconds: i64,
    active_kid: String,
    jwks_json: serde_json::Value,
    hmac_key: Option<Vec<u8>>,
}

impl JwtService {
    fn decode_rsa<T: for<'de> serde::Deserialize<'de>>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<T, AppError> {
        for key in &self.decoding_keys {
            if let Ok(data) = decode::<T>(token, key, validation) {
                return Ok(data.claims);
            }
        }
        Err(AppError::Unauthorized)
    }

    pub fn refresh_ttl_seconds(&self) -> i64 {
        self.refresh_ttl_seconds
    }

    pub fn access_ttl_seconds(&self) -> i64 {
        self.access_ttl_seconds
    }

    pub fn mfa_stepup_ttl(&self) -> i64 {
        self.mfa_step_up_seconds
    }

    pub fn from_config(config: &AppConfig) -> Result<Self, AppError> {
        let private_pem = normalize_jwt_pem(&config.auth.jwt_private_key_pem);
        let public_pem = normalize_jwt_pem(&config.auth.jwt_public_key_pem);

        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|e| AppError::Config(format!("invalid private key: {e}")))?;
        let decoding_primary = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| AppError::Config(format!("invalid public key: {e}")))?;

        let active_kid = "rsa-key-1".to_string();
        let mut jwks_keys: Vec<serde_json::Value> = vec![rsa_jwk_entry(&public_pem, &active_kid)?];
        let mut decoding_keys = vec![decoding_primary];

        if let Some(prev_raw) = config.auth.jwt_previous_public_key_pem.as_ref() {
            let prev_pem = normalize_jwt_pem(prev_raw);
            if !prev_pem.trim().is_empty() {
                let prev_kid = config
                    .auth
                    .jwt_previous_kid
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("rsa-key-0")
                    .to_string();
                let decoding_prev = DecodingKey::from_rsa_pem(prev_pem.as_bytes())
                    .map_err(|e| AppError::Config(format!("invalid previous JWT public key: {e}")))?;
                decoding_keys.push(decoding_prev);
                jwks_keys.push(rsa_jwk_entry(&prev_pem, &prev_kid)?);
            }
        }

        let jwks_json = serde_json::json!({ "keys": jwks_keys });

        let hmac_key = config
            .auth
            .cookie_secret
            .as_ref()
            .map(|s| s.as_bytes().to_vec())
            .filter(|v| v.len() >= 32);

        Ok(Self {
            encoding_key,
            decoding_keys,
            issuer: config.server.issuer.clone(),
            access_ttl_seconds: config.auth.access_ttl_seconds as i64,
            refresh_ttl_seconds: config.auth.refresh_ttl_seconds as i64,
            email_verification_jwt_seconds: config.totp.email_verification_jwt_ttl_seconds as i64,
            mfa_step_up_seconds: config.totp.mfa_step_up_ttl_seconds as i64,
            idp_session_ttl_seconds: 3600,
            active_kid,
            jwks_json,
            hmac_key,
        })
    }

    /// Build a [`JwtService`] from PEM strings (unit tests only).
    #[cfg(test)]
    pub fn from_pems_for_test(
        issuer: &str,
        private_pem: &str,
        public_pem: &str,
        email_verification_jwt_seconds: i64,
        mfa_step_up_seconds: i64,
    ) -> Result<Self, AppError> {
        let private_pem = normalize_jwt_pem(private_pem);
        let public_pem = normalize_jwt_pem(public_pem);

        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|e| AppError::Config(format!("invalid private key: {e}")))?;

        let active_kid = "rsa-key-1".to_string();
        let jwk = rsa_jwk_entry(&public_pem, &active_kid)?;
        let jwks_json = serde_json::json!({ "keys": [jwk] });
        let decoding_keys = vec![
            DecodingKey::from_rsa_pem(public_pem.as_bytes())
                .map_err(|e| AppError::Config(format!("invalid public key: {e}")))?,
        ];

        Ok(Self {
            encoding_key,
            decoding_keys,
            issuer: issuer.to_string(),
            access_ttl_seconds: 3600,
            refresh_ttl_seconds: 7200,
            email_verification_jwt_seconds,
            mfa_step_up_seconds,
            idp_session_ttl_seconds: 3600,
            active_kid,
            jwks_json,
            hmac_key: None,
        })
    }

    pub fn idp_session_secret_configured(&self) -> bool {
        self.hmac_key.is_some()
    }

    pub fn mint_access_token(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        audience: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
        email_verified: bool,
        scope: Option<String>,
        session_id: Option<Uuid>,
    ) -> Result<String, AppError> {
        self.mint_access_token_with_jti(
            user_id,
            tenant_id,
            audience,
            roles,
            permissions,
            email_verified,
            scope,
            Uuid::new_v4().to_string(),
            session_id,
        )
    }

    fn mint_access_token_with_jti(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        audience: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
        email_verified: bool,
        scope: Option<String>,
        jti: String,
        session_id: Option<Uuid>,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let claims = AccessClaims {
            sub: user_id.to_string(),
            jti: Some(jti),
            exp: (now + Duration::seconds(self.access_ttl_seconds)).timestamp() as usize,
            iat: Some(iat),
            iss: self.issuer.clone(),
            aud: audience.to_string(),
            scope,
            roles,
            permissions,
            tenant_id: tenant_id.to_string(),
            email_verified,
            sid: session_id.map(|u| u.to_string()),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("failed to sign access token: {e}")))
    }

    pub fn mint_refresh_token(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        audience: &str,
        email_verified: bool,
        row_id: Uuid,
        family_id: Uuid,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            jti: row_id.to_string(),
            family: family_id.to_string(),
            exp: (now + Duration::seconds(self.refresh_ttl_seconds)).timestamp() as usize,
            iat,
            iss: self.issuer.clone(),
            aud: audience.to_string(),
            tenant_id: tenant_id.to_string(),
            email_verified,
            token_type: "Refresh".to_string(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("failed to sign refresh token: {e}")))
    }

    pub fn mint_id_token(
        &self,
        user_id: Uuid,
        client_id: &str,
        nonce: Option<String>,
        email: Option<String>,
        email_verified: bool,
        access_token_for_at_hash: &str,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let at_hash = at_hash_s256(access_token_for_at_hash);
        let claims = IdTokenClaims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: client_id.to_string(),
            exp: (now + Duration::seconds(self.access_ttl_seconds)).timestamp() as usize,
            iat,
            auth_time: iat,
            nonce,
            email: email.clone(),
            email_verified: if email.is_some() { Some(email_verified) } else { None },
            at_hash: Some(at_hash),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        header.typ = Some("JWT".to_string());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("failed to sign id_token: {e}")))
    }

    pub fn verify(&self, token: &str, audience: &str) -> Result<AccessClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[self.issuer.as_str()]);

        self.decode_rsa(token, &validation)
    }

    pub fn verify_access_audiences(
        &self,
        token: &str,
        audiences: &[&str],
    ) -> Result<AccessClaims, AppError> {
        if audiences.is_empty() {
            return Err(AppError::Unauthorized);
        }
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(audiences);
        validation.set_issuer(&[self.issuer.as_str()]);

        self.decode_rsa(token, &validation)
    }

    pub fn verify_refresh(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<RefreshTokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[expected_audience]);
        validation.set_issuer(&[self.issuer.as_str()]);

        self.decode_rsa(token, &validation)
    }

    /// Like [`Self::verify_refresh`], but does not enforce a specific `aud` — the audience is read from the token.
    /// Used for refresh-token rotation so clients do not need to resend the exact resource audience string.
    pub fn verify_refresh_issuer(&self, token: &str) -> Result<RefreshTokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_issuer(&[self.issuer.as_str()]);

        self.decode_rsa(token, &validation)
    }

    pub fn verify_access_any_audience(&self, token: &str) -> Result<AccessClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_issuer(&[self.issuer.as_str()]);

        self.decode_rsa(token, &validation)
    }

    pub fn jwks(&self) -> serde_json::Value {
        self.jwks_json.clone()
    }

    pub fn mint_email_verification_token(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        verification_id: Uuid,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let claims = EmailVerifyClaims {
            sub: user_id.to_string(),
            exp: (now + Duration::seconds(self.email_verification_jwt_seconds)).timestamp() as usize,
            iss: self.issuer.clone(),
            aud: AUD_EMAIL_VERIFY.to_string(),
            tenant_id: tenant_id.to_string(),
            jti: verification_id.to_string(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("sign email verify jwt: {e}")))
    }

    pub fn verify_email_verification(&self, token: &str) -> Result<EmailVerifyClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUD_EMAIL_VERIFY]);
        validation.set_issuer(&[self.issuer.as_str()]);
        self.decode_rsa(token, &validation)
    }

    pub fn mint_pending_email_verification_token(
        &self,
        pending_registration_id: Uuid,
        tenant_id: Uuid,
        verification_id: Uuid,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let claims = EmailVerifyClaims {
            sub: pending_registration_id.to_string(),
            exp: (now + Duration::seconds(self.email_verification_jwt_seconds)).timestamp() as usize,
            iss: self.issuer.clone(),
            aud: AUD_EMAIL_VERIFY_PENDING.to_string(),
            tenant_id: tenant_id.to_string(),
            jti: verification_id.to_string(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("sign pending email verify jwt: {e}")))
    }

    pub fn verify_pending_email_verification(&self, token: &str) -> Result<EmailVerifyClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUD_EMAIL_VERIFY_PENDING]);
        validation.set_issuer(&[self.issuer.as_str()]);
        self.decode_rsa(token, &validation)
    }

    pub fn mint_embedded_pending_client_totp_enrollment(
        &self,
        pending_registration_id: Uuid,
        tenant_id: Uuid,
        login_audience: &str,
        oauth_client_row_id: Uuid,
        public_oauth_client_id: &str,
    ) -> Result<(String, u64), AppError> {
        let jti = Uuid::new_v4().to_string();
        let now = Utc::now();
        let claims = PendingClientTotpEnrollmentClaims {
            sub: pending_registration_id.to_string(),
            jti: jti.clone(),
            exp: (now + Duration::seconds(self.mfa_step_up_seconds)).timestamp() as usize,
            iss: self.issuer.clone(),
            aud: AUD_EMBEDDED_PENDING_CLIENT_TOTP.to_string(),
            tenant_id: tenant_id.to_string(),
            login_audience: login_audience.to_string(),
            oauth_client_row_id: oauth_client_row_id.to_string(),
            public_oauth_client_id: public_oauth_client_id.to_string(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        let t = encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("sign embedded pending client totp jwt: {e}")))?;
        Ok((t, self.mfa_step_up_seconds as u64))
    }

    pub fn verify_embedded_pending_client_totp_enrollment(
        &self,
        token: &str,
    ) -> Result<PendingClientTotpEnrollmentClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUD_EMBEDDED_PENDING_CLIENT_TOTP]);
        validation.set_issuer(&[self.issuer.as_str()]);
        self.decode_rsa(token, &validation)
    }

    /// Short-lived bearer to run `POST /auth/client-totp-enroll/setup|verify` after email code step.
    pub fn mint_client_totp_enroll_after_email(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        login_audience: &str,
        oauth_client_row_id: Uuid,
        public_oauth_client_id: &str,
    ) -> Result<(String, u64), AppError> {
        let jti = Uuid::new_v4().to_string();
        let now = Utc::now();
        let claims = ClientTotpEnrollAfterEmailClaims {
            sub: user_id.to_string(),
            jti: jti.clone(),
            exp: (now + Duration::seconds(self.mfa_step_up_seconds)).timestamp() as usize,
            iss: self.issuer.clone(),
            aud: AUD_CLIENT_TOTP_ENROLL_SETUP.to_string(),
            tenant_id: tenant_id.to_string(),
            login_audience: login_audience.to_string(),
            oauth_client_row_id: oauth_client_row_id.to_string(),
            public_oauth_client_id: public_oauth_client_id.to_string(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        let t = encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("sign client totp enroll after email jwt: {e}")))?;
        Ok((t, self.mfa_step_up_seconds as u64))
    }

    pub fn verify_client_totp_enroll_after_email(&self, token: &str) -> Result<ClientTotpEnrollAfterEmailClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUD_CLIENT_TOTP_ENROLL_SETUP]);
        validation.set_issuer(&[self.issuer.as_str()]);
        self.decode_rsa(token, &validation)
    }

    /// Returns (jwt, jti) for one-time server-side binding (Redis).
    pub fn mint_mfa_stepup_token(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        login_audience: &str,
    ) -> Result<(String, String), AppError> {
        self.mint_mfa_stepup_token_ex(
            user_id,
            tenant_id,
            login_audience,
            "user",
            None,
        )
    }

    /// Same as [`Self::mint_mfa_stepup_token`], with optional per-OAuth-client MFA context.
    pub fn mint_mfa_stepup_token_ex(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        login_audience: &str,
        mfa_ctx: &str,
        oauth_client_row_id: Option<Uuid>,
    ) -> Result<(String, String), AppError> {
        let jti = Uuid::new_v4().to_string();
        self.mint_mfa_stepup_token_with_jti(
            user_id,
            tenant_id,
            login_audience,
            mfa_ctx,
            oauth_client_row_id,
            jti,
        )
    }

    fn mint_mfa_stepup_token_with_jti(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        login_audience: &str,
        mfa_ctx: &str,
        oauth_client_row_id: Option<Uuid>,
        jti: String,
    ) -> Result<(String, String), AppError> {
        let jti_out = jti.clone();
        let now = Utc::now();
        let claims = MfaStepUpClaims {
            sub: user_id.to_string(),
            jti,
            exp: (now + Duration::seconds(self.mfa_step_up_seconds)).timestamp() as usize,
            iss: self.issuer.clone(),
            aud: AUD_MFA_STEPUP.to_string(),
            tenant_id: tenant_id.to_string(),
            login_audience: login_audience.to_string(),
            mfa_ctx: mfa_ctx.to_string(),
            oauth_client_row_id: oauth_client_row_id.map(|u| u.to_string()),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        let t = encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("sign mfa stepup jwt: {e}")))?;
        Ok((t, jti_out))
    }

    pub fn verify_mfa_stepup(&self, token: &str) -> Result<MfaStepUpClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUD_MFA_STEPUP]);
        validation.set_issuer(&[self.issuer.as_str()]);
        self.decode_rsa(token, &validation)
    }

    /// Enrollment-only bearer for [`AUD_TOTP_ENROLL`] (same TTL as MFA step-up).
    pub fn mint_totp_enrollment_token(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        login_audience: &str,
    ) -> Result<(String, String), AppError> {
        let jti = Uuid::new_v4().to_string();
        let jti_out = jti.clone();
        let now = Utc::now();
        let claims = TotpEnrollmentClaims {
            sub: user_id.to_string(),
            jti,
            exp: (now + Duration::seconds(self.mfa_step_up_seconds)).timestamp() as usize,
            iss: self.issuer.clone(),
            aud: AUD_TOTP_ENROLL.to_string(),
            tenant_id: tenant_id.to_string(),
            login_audience: login_audience.to_string(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        let t = encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("sign totp enrollment jwt: {e}")))?;
        Ok((t, jti_out))
    }

    pub fn verify_totp_enrollment(&self, token: &str) -> Result<TotpEnrollmentClaims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[AUD_TOTP_ENROLL]);
        validation.set_issuer(&[self.issuer.as_str()]);
        self.decode_rsa(token, &validation)
    }

    pub fn mint_idp_session(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<String, AppError> {
        let key = self
            .hmac_key
            .as_ref()
            .ok_or_else(|| AppError::Config("idp session requires AUTH__COOKIE_SECRET (>= 32 bytes)".to_string()))?;
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let claims = IdpSessionClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            exp: (now + Duration::seconds(self.idp_session_ttl_seconds)).timestamp() as usize,
            iat,
            iss: self.issuer.clone(),
            aud: AUD_IDP_SESSION.to_string(),
        };
        let header = Header::new(Algorithm::HS256);
        let enc = EncodingKey::from_secret(key);
        encode(&header, &claims, &enc).map_err(|e| AppError::Internal(format!("idp session: {e}")))
    }

    pub fn verify_idp_session(&self, token: &str) -> Result<IdpSessionClaims, AppError> {
        let key = self.hmac_key.as_ref().ok_or(AppError::Unauthorized)?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[AUD_IDP_SESSION]);
        validation.set_issuer(&[self.issuer.as_str()]);
        let dec = DecodingKey::from_secret(key);
        decode::<IdpSessionClaims>(token, &dec, &validation)
            .map(|d| d.claims)
            .map_err(|_| AppError::Unauthorized)
    }
}

/// Env files and Docker often pass PEM in one line with **literal** `\n` (two chars). Without this,
/// Base64 in the body fails with `PEM Base64 error: invalid Base64 encoding`.
fn normalize_jwt_pem(s: &str) -> String {
    let t = s.trim().trim_start_matches('\u{feff}');
    t.replace("\\n", "\n")
        .replace('\r', "\n")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn at_hash_s256(access_token: &str) -> String {
    let d = sha2::Sha256::digest(access_token.as_bytes());
    let half = &d.as_slice()[..d.len() / 2];
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(half)
}

/// Load RSA public key for JWKS. Accepts the same env/.docker PEM as `jsonwebtoken` (including
/// one long base64 line); strict `RsaPublicKey::from_public_key_pem` can fail on that.
fn rsa_public_key_for_jwks(jwt_public_key_pem: &str) -> Result<RsaPublicKey, AppError> {
    let t = normalize_jwt_pem(jwt_public_key_pem);
    let lines: Vec<&str> = t.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let pkcs1_pem = lines.iter().any(|l| l.contains("BEGIN RSA PUBLIC KEY"));
    let b64: String = lines
        .iter()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|s| s.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| AppError::Config(format!("JWKS: public PEM base64: {e}")))?;
    if pkcs1_pem {
        RsaPublicKey::from_pkcs1_der(&der)
            .map_err(|e| AppError::Config(format!("JWKS: PKCS#1 public key: {e}")))
    } else {
        RsaPublicKey::from_public_key_der(&der)
            .map_err(|e| AppError::Config(format!("JWKS: SPKI public key: {e}")))
    }
}

/// One RSA JWK for JWKS document.
fn rsa_jwk_entry(jwt_public_key_pem: &str, kid: &str) -> Result<serde_json::Value, AppError> {
    let public = rsa_public_key_for_jwks(jwt_public_key_pem)?;
    let n = public.n();
    let e = public.e();
    let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e.to_bytes_be());
    let mut key = serde_json::Map::new();
    key.insert("kty".into(), serde_json::Value::String("RSA".to_string()));
    key.insert("use".into(), serde_json::Value::String("sig".to_string()));
    key.insert("alg".into(), serde_json::Value::String("RS256".to_string()));
    key.insert("kid".into(), serde_json::Value::String(kid.to_string()));
    key.insert("n".into(), serde_json::Value::String(n_b64));
    key.insert("e".into(), serde_json::Value::String(e_b64));
    Ok(serde_json::Value::Object(key))
}

#[cfg(test)]
mod parse_tests {
    use super::normalize_jwt_pem;
    use super::rsa_public_key_for_jwks;
    use jsonwebtoken::DecodingKey;

    const SAMPLE_PUB_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkj1e21KRq4jp+INs7GFDrfUf1+kvhhUlqbA6FpGreveTDlC7kK4esdgkKf8hAOERKPTcwr+hMj7JWFqlHU+et39Bmy8gMifnVlstIWQO6lm1nK9grAv4+tyiYkqoQkhnxZQMiQ2xjKCuniKjbSGDv6tYDIB9TApZQ+muLWI1Mrc8xWGcpMXSyVQTaDzp5JYsQ9Dc1JTizj+du0Akc0M8RbXj18XWYjdnBPJcn1kIb4PxKpSKMzHN+PQXCITTJ1MfhuJdDF1EDx9SEM4QUxBA0YDkvZQfUn9pqg26ehF0ejR6lZqNK7BGgNHeBZGQg/AAlcO4hvbiUR9gQHUYUW7ncQIDAQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn jwks_loader_accepts_one_long_base64_line() {
        let n = normalize_jwt_pem(SAMPLE_PUB_PEM);
        assert!(rsa_public_key_for_jwks(&n).is_ok());
        let jwt = DecodingKey::from_rsa_pem(n.as_bytes());
        assert!(jwt.is_ok());
    }

    /// Docker/.env: one physical line with literal `\n` between PEM lines.
    #[test]
    fn jwks_loader_accepts_escaped_newlines() {
        let s = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkj1e21KRq4jp+INs7GFDrfUf1+kvhhUlqbA6FpGreveTDlC7kK4esdgkKf8hAOERKPTcwr+hMj7JWFqlHU+et39Bmy8gMifnVlstIWQO6lm1nK9grAv4+tyiYkqoQkhnxZQMiQ2xjKCuniKjbSGDv6tYDIB9TApZQ+muLWI1Mrc8xWGcpMXSyVQTaDzp5JYsQ9Dc1JTizj+du0Akc0M8RbXj18XWYjdnBPJcn1kIb4PxKpSKMzHN+PQXCITTJ1MfhuJdDF1EDx9SEM4QUxBA0YDkvZQfUn9pqg26ehF0ejR6lZqNK7BGgNHeBZGQg/AAlcO4hvbiUR9gQHUYUW7ncQIDAQAB\\n-----END PUBLIC KEY-----";
        assert!(rsa_public_key_for_jwks(s).is_ok());
    }
}

/// Embedded deferred-registration bearer tokens (pending email verify + pre-user client TOTP enrollment).
#[cfg(test)]
mod embedded_flow_token_tests {
    use super::{JwtService, AUD_EMAIL_VERIFY_PENDING, AUD_EMBEDDED_PENDING_CLIENT_TOTP};
    use rand::rngs::OsRng;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;
    use uuid::Uuid;

    fn test_jwt() -> JwtService {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
        let priv_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pem")
            .to_string();
        let pub_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem")
            .to_string();
        JwtService::from_pems_for_test(
            "https://test-issuer.local",
            &priv_pem,
            &pub_pem,
            600,
            300,
        )
        .expect("jwt service")
    }

    #[test]
    fn pending_email_verify_jwt_roundtrip() {
        let jwt = test_jwt();
        let pending = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let ver = Uuid::new_v4();
        let tok = jwt
            .mint_pending_email_verification_token(pending, tenant, ver)
            .expect("mint");
        let c = jwt.verify_pending_email_verification(&tok).expect("verify");
        assert_eq!(c.sub, pending.to_string());
        assert_eq!(c.tenant_id, tenant.to_string());
        assert_eq!(c.jti, ver.to_string());
        assert_eq!(c.aud, AUD_EMAIL_VERIFY_PENDING);
    }

    #[test]
    fn pending_email_rejects_normal_email_verify_audience() {
        let jwt = test_jwt();
        let user = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let ver = Uuid::new_v4();
        let tok = jwt
            .mint_email_verification_token(user, tenant, ver)
            .expect("mint");
        assert!(jwt.verify_pending_email_verification(&tok).is_err());
    }

    #[test]
    fn embedded_pending_client_totp_enrollment_jwt_roundtrip() {
        let jwt = test_jwt();
        let pending = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let row = Uuid::new_v4();
        let (tok, exp) = jwt
            .mint_embedded_pending_client_totp_enrollment(
                pending,
                tenant,
                "my-aud",
                row,
                "pub-client-id",
            )
            .expect("mint");
        assert_eq!(exp, 300);
        let c = jwt
            .verify_embedded_pending_client_totp_enrollment(&tok)
            .expect("verify");
        assert_eq!(c.sub, pending.to_string());
        assert_eq!(c.tenant_id, tenant.to_string());
        assert_eq!(c.login_audience, "my-aud");
        assert_eq!(c.oauth_client_row_id, row.to_string());
        assert_eq!(c.public_oauth_client_id, "pub-client-id");
        assert_eq!(c.aud, AUD_EMBEDDED_PENDING_CLIENT_TOTP);
    }
}
