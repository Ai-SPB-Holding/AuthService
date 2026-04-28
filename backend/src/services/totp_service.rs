use std::sync::Arc;

use chrono::Utc;
use redis::AsyncCommands;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    repositories::user_repository::PostgresUserRepository,
    security::crypto::TotpEncryption,
    security::totp_impl::{build_totp, check_totp, generate_totp_secret},
    services::errors::AppError,
};

pub struct TotpService {
    users: Arc<PostgresUserRepository>,
    enc: Arc<TotpEncryption>,
    config: AppConfig,
    redis: redis::aio::ConnectionManager,
    pool: PgPool,
}

impl TotpService {
    pub fn new(
        users: Arc<PostgresUserRepository>,
        enc: Arc<TotpEncryption>,
        config: AppConfig,
        redis: redis::aio::ConnectionManager,
        pool: PgPool,
    ) -> Self {
        Self {
            users,
            enc,
            config,
            redis,
            pool,
        }
    }

    async fn totp_check_rate(&self, user_id: Uuid) -> Result<(), AppError> {
        let key = self.config.redis.key(&format!("totp:verify:{user_id}"));
        let mut c = self.redis.clone();
        let n: i64 = c.incr(&key, 1).await?;
        if n == 1 {
            let _: () = c.expire(&key, 300).await?;
        }
        if n > 20 {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }

    /// Generate secret, encrypt, store pending (totp_enabled stays false). Returns `otpauth://...` and base32.
    pub async fn begin_setup(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        account_email: &str,
    ) -> Result<(String, String), AppError> {
        let (raw_bytes, base32) = generate_totp_secret();
        let blob = self.enc.seal(&raw_bytes)?;
        self.users
            .set_totp_encrypted(user_id, tenant_id, Some(blob))
            .await?;
        self.users
            .set_totp_enabled(user_id, tenant_id, false)
            .await?;
        let issuer = self.config.totp.issuer_name.clone();
        let totp = build_totp(raw_bytes, Some(issuer.clone()), account_email)?;
        let url = totp.get_url();
        Ok((url, base32))
    }

    /// Confirm 6-digit code and enable 2FA.
    pub async fn complete_setup(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        code: &str,
    ) -> Result<(), AppError> {
        self.totp_check_rate(user_id).await?;
        let account_email: String =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;
        let enc_blob: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT totp_secret_enc FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let blob = enc_blob.ok_or(AppError::Validation(
            "totp not set up; call setup first".to_string(),
        ))?;
        let raw = self.enc.open(&blob)?;
        let issuer = self.config.totp.issuer_name.clone();
        let totp = build_totp(raw, Some(issuer), &account_email)?;
        let t = Utc::now().timestamp() as u64;
        if !check_totp(&totp, code, t)? {
            return Err(AppError::Unauthorized);
        }
        self.users
            .set_totp_enabled(user_id, tenant_id, true)
            .await?;
        Ok(())
    }

    /// Disable 2FA after valid current TOTP.
    pub async fn disable(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        code: &str,
    ) -> Result<(), AppError> {
        self.totp_check_rate(user_id).await?;
        let totp_en: bool =
            sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;
        if !totp_en {
            return Err(AppError::Validation("totp not enabled".to_string()));
        }
        let email: String =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;
        let enc_blob: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT totp_secret_enc FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let blob = enc_blob.ok_or(AppError::Unauthorized)?;
        let raw = self.enc.open(&blob)?;
        let issuer = self.config.totp.issuer_name.clone();
        let totp = build_totp(raw, Some(issuer), &email)?;
        let t = Utc::now().timestamp() as u64;
        if !check_totp(&totp, code, t)? {
            return Err(AppError::Unauthorized);
        }
        self.users.clear_totp(user_id, tenant_id).await?;
        Ok(())
    }

    /// Rate limit MFA login attempts (separate from enroll flow).
    async fn mfa_login_rate(&self, user_id: Uuid) -> Result<(), AppError> {
        let key = self.config.redis.key(&format!("mfa:login:totp:{user_id}"));
        let mut c = self.redis.clone();
        let n: i64 = c.incr(&key, 1).await?;
        if n == 1 {
            let _: () = c.expire(&key, 300).await?;
        }
        if n > 15 {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }

    /// After password login: check TOTP from encrypted blob in DB.
    pub async fn verify_login_totp(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        code: &str,
    ) -> Result<(), AppError> {
        self.mfa_login_rate(user_id).await?;
        let email: String =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;
        let enc_blob: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT totp_secret_enc FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let blob = enc_blob.ok_or(AppError::Unauthorized)?;
        let raw = self.enc.open(&blob)?;
        if !self.check_totp_login(&raw, &email, code)? {
            return Err(AppError::Unauthorized);
        }
        Ok(())
    }

    /// Raw secret bytes + account label (TOTP HMAC key material).
    fn check_totp_login(
        &self,
        raw_secret: &[u8],
        account_email: &str,
        code: &str,
    ) -> Result<bool, AppError> {
        let totp = build_totp(
            raw_secret.to_vec(),
            Some(self.config.totp.issuer_name.clone()),
            account_email,
        )?;
        let t = Utc::now().timestamp() as u64;
        check_totp(&totp, code, t)
    }

    // --- Per-OAuth-client TOTP (Google Authenticator) in `client_user_mfa` ---

    fn client_totp_label(email: &str, public_client_id: &str) -> String {
        format!("{email} ({public_client_id})")
    }

    /// Generate client-scoped TOTP secret; stores encrypted, `totp_enabled = false` until verify.
    pub async fn begin_client_setup(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        oauth_client_row_id: Uuid,
        public_client_id: &str,
    ) -> Result<(String, String), AppError> {
        self.totp_check_rate(user_id).await?;
        let account_email: String =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;
        let (raw_bytes, base32) = generate_totp_secret();
        let blob = self.enc.seal(&raw_bytes)?;
        let id = Uuid::new_v4();
        let label = Self::client_totp_label(&account_email, public_client_id);
        sqlx::query(
            "INSERT INTO client_user_mfa (id, oauth_client_row_id, user_id, tenant_id, totp_secret_enc, totp_enabled, updated_at)
             VALUES ($1, $2, $3, $4, $5, false, NOW())
             ON CONFLICT (oauth_client_row_id, user_id, tenant_id)
             DO UPDATE SET
               totp_secret_enc = EXCLUDED.totp_secret_enc,
               totp_enabled = false,
               totp_enabled_at = NULL,
               updated_at = NOW()",
        )
        .bind(id)
        .bind(oauth_client_row_id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(&blob)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "client_user_mfa upsert; apply migration 0006");
            AppError::Internal("client TOTP setup failed (migrations applied?)".to_string())
        })?;
        let issuer = self.config.totp.issuer_name.clone();
        let totp = build_totp(raw_bytes, Some(issuer), &label)?;
        let url = totp.get_url();
        Ok((url, base32))
    }

    pub async fn complete_client_setup(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        oauth_client_row_id: Uuid,
        public_client_id: &str,
        code: &str,
    ) -> Result<(), AppError> {
        self.totp_check_rate(user_id).await?;
        let account_email: String =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;
        let enc_blob: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT totp_secret_enc FROM client_user_mfa
             WHERE oauth_client_row_id = $1 AND user_id = $2 AND tenant_id = $3",
        )
        .bind(oauth_client_row_id)
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        let blob = enc_blob
            .ok_or_else(|| AppError::Validation("client TOTP: call setup first".to_string()))?;
        let raw = self.enc.open(&blob)?;
        let label = Self::client_totp_label(&account_email, public_client_id);
        let totp = build_totp(raw, Some(self.config.totp.issuer_name.clone()), &label)?;
        let t = Utc::now().timestamp() as u64;
        if !check_totp(&totp, code, t)? {
            return Err(AppError::Unauthorized);
        }
        sqlx::query(
            "UPDATE client_user_mfa SET totp_enabled = true, totp_enabled_at = NOW(), updated_at = NOW()
             WHERE oauth_client_row_id = $1 AND user_id = $2 AND tenant_id = $3",
        )
        .bind(oauth_client_row_id)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Disable per-client TOTP after a valid current code.
    pub async fn disable_client(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        oauth_client_row_id: Uuid,
        public_client_id: &str,
        code: &str,
    ) -> Result<(), AppError> {
        self.totp_check_rate(user_id).await?;
        let en: bool = sqlx::query_scalar(
            "SELECT totp_enabled FROM client_user_mfa
             WHERE oauth_client_row_id = $1 AND user_id = $2 AND tenant_id = $3",
        )
        .bind(oauth_client_row_id)
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(false);
        if !en {
            return Err(AppError::Validation("client TOTP not enabled".to_string()));
        }
        self.verify_client_login_totp(
            user_id,
            tenant_id,
            oauth_client_row_id,
            public_client_id,
            code,
        )
        .await?;
        sqlx::query(
            "UPDATE client_user_mfa SET
               totp_secret_enc = NULL,
               totp_enabled = false,
               totp_enabled_at = NULL,
               updated_at = NOW()
             WHERE oauth_client_row_id = $1 AND user_id = $2 AND tenant_id = $3",
        )
        .bind(oauth_client_row_id)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Used after successful password; verifies code against per-client secret.
    pub async fn verify_client_login_totp(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        oauth_client_row_id: Uuid,
        public_client_id: &str,
        code: &str,
    ) -> Result<(), AppError> {
        self.mfa_login_rate(user_id).await?;
        let email: String =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;
        let enc_blob: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT totp_secret_enc FROM client_user_mfa
             WHERE oauth_client_row_id = $1 AND user_id = $2 AND tenant_id = $3",
        )
        .bind(oauth_client_row_id)
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        let blob = enc_blob.ok_or(AppError::Unauthorized)?;
        let raw = self.enc.open(&blob)?;
        let label = Self::client_totp_label(&email, public_client_id);
        if !self.check_totp_login(&raw, &label, code)? {
            return Err(AppError::Unauthorized);
        }
        Ok(())
    }

    /// Whether user completed enrollment for this OAuth client.
    pub async fn is_client_totp_enabled(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        oauth_client_row_id: Uuid,
    ) -> Result<bool, AppError> {
        let b: Option<bool> = sqlx::query_scalar(
            "SELECT totp_enabled FROM client_user_mfa
             WHERE oauth_client_row_id = $1 AND user_id = $2 AND tenant_id = $3",
        )
        .bind(oauth_client_row_id)
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(b.unwrap_or(false))
    }

    async fn totp_check_rate_pending(&self, pending_id: Uuid) -> Result<(), AppError> {
        let key = self
            .config
            .redis
            .key(&format!("totp:verify:pending:{pending_id}"));
        let mut c = self.redis.clone();
        let n: i64 = c.incr(&key, 1).await?;
        if n == 1 {
            let _: () = c.expire(&key, 300).await?;
        }
        if n > 20 {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }

    /// Client-scoped TOTP enrollment for embedded pending registration (no `users` row yet).
    pub async fn begin_pending_client_totp_setup(
        &self,
        pending_id: Uuid,
        tenant_id: Uuid,
        public_client_id: &str,
    ) -> Result<(String, String), AppError> {
        self.totp_check_rate_pending(pending_id).await?;
        let email: String = sqlx::query_scalar(
            "SELECT email FROM embedded_pending_registrations
             WHERE id = $1 AND tenant_id = $2
               AND email_verified_at IS NOT NULL
               AND client_totp_verified_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

        let (raw_bytes, base32) = generate_totp_secret();
        let blob = self.enc.seal(&raw_bytes)?;
        let n = sqlx::query(
            "UPDATE embedded_pending_registrations
             SET client_totp_secret_enc = $1
             WHERE id = $2 AND tenant_id = $3
               AND email_verified_at IS NOT NULL
               AND client_totp_verified_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(&blob)
        .bind(pending_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if n != 1 {
            return Err(AppError::Unauthorized);
        }
        let issuer = self.config.totp.issuer_name.clone();
        let label = Self::client_totp_label(&email, public_client_id);
        let totp = build_totp(raw_bytes, Some(issuer), &label)?;
        let url = totp.get_url();
        Ok((url, base32))
    }

    pub async fn complete_pending_client_totp_setup(
        &self,
        pending_id: Uuid,
        tenant_id: Uuid,
        public_client_id: &str,
        code: &str,
    ) -> Result<(), AppError> {
        self.totp_check_rate_pending(pending_id).await?;
        let row = sqlx::query(
            "SELECT email, client_totp_secret_enc FROM embedded_pending_registrations
             WHERE id = $1 AND tenant_id = $2
               AND email_verified_at IS NOT NULL
               AND client_totp_verified_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;
        let email: String = row.get("email");
        let enc_blob: Option<Vec<u8>> = row.try_get("client_totp_secret_enc").ok().flatten();
        let blob = enc_blob
            .ok_or_else(|| AppError::Validation("client TOTP: call setup first".to_string()))?;
        let raw = self.enc.open(&blob)?;
        let label = Self::client_totp_label(&email, public_client_id);
        let totp = build_totp(raw, Some(self.config.totp.issuer_name.clone()), &label)?;
        let t = Utc::now().timestamp() as u64;
        if !check_totp(&totp, code, t)? {
            return Err(AppError::Unauthorized);
        }
        sqlx::query(
            "UPDATE embedded_pending_registrations SET client_totp_verified_at = NOW()
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
