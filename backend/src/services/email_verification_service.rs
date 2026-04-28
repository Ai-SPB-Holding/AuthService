use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::Utc;
use rand::Rng;
use redis::AsyncCommands;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    email::ExmailMailer,
    repositories::email_verification_repository::EmailVerificationRepository,
    repositories::user_repository::PostgresUserRepository,
    security::jwt::JwtService,
    services::errors::AppError,
};

pub const PURPOSE_REGISTER: &str = "register";
pub const PURPOSE_EMBEDDED_PENDING_REGISTER: &str = "embedded_pending_register";
/// Login when OAuth client has `mfa_policy=required` and user has no per-client TOTP — send code before TOTP setup.
pub const PURPOSE_CLIENT_TOTP_ENROLL_EMAIL: &str = "client_totp_enroll_email";

/// Registration / email-otp flows: Argon2-hashed code + Redis rate limits.
pub struct EmailVerificationService {
    ev: EmailVerificationRepository,
    users: Arc<PostgresUserRepository>,
    pool: PgPool,
    mail: ExmailMailer,
    config: AppConfig,
    pub jwt: JwtService,
    redis: redis::aio::ConnectionManager,
}

impl EmailVerificationService {
    pub fn new(
        ev: EmailVerificationRepository,
        users: Arc<PostgresUserRepository>,
        pool: PgPool,
        mail: ExmailMailer,
        config: AppConfig,
        jwt: JwtService,
        redis: redis::aio::ConnectionManager,
    ) -> Self {
        Self {
            ev,
            users,
            pool,
            mail,
            config,
            jwt,
            redis,
        }
    }

    fn peppered_code(&self, code: &str) -> String {
        match &self.config.email.code_pepper {
            Some(p) => format!("{code}{p}"),
            None => code.to_string(),
        }
    }

    fn hash_code(&self, code: &str) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();
        let h = argon2
            .hash_password(self.peppered_code(code).as_bytes(), &salt)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(h.to_string())
    }

    fn verify_code_argon2(&self, code: &str, stored: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(stored) else {
            return false;
        };
        Argon2::default()
            .verify_password(self.peppered_code(code).as_bytes(), &parsed)
            .is_ok()
    }

    async fn rate_limit_send(&self, user_id: Uuid) -> Result<(), AppError> {
        let key = format!("email:send:rate:{}", user_id);
        let mut c = self.redis.clone();
        let n: i64 = c.incr(&key, 1).await?;
        if n == 1 {
            let _: () = c.expire(&key, 3600).await?;
        }
        if n > self.config.email.max_sends_per_hour as i64 {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }

    async fn rate_limit_send_pending(&self, pending_id: Uuid) -> Result<(), AppError> {
        let key = format!("email:send:rate:pending:{pending_id}");
        let mut c = self.redis.clone();
        let n: i64 = c.incr(&key, 1).await?;
        if n == 1 {
            let _: () = c.expire(&key, 3600).await?;
        }
        if n > self.config.email.max_sends_per_hour as i64 {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }

    /// Create new 6-digit code, store Argon2 hash, send RU email. Returns the verification row id and JWT to present to the client.
    pub async fn start_registration(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<(Uuid, String, u64), AppError> {
        self.rate_limit_send(user_id).await?;
        let code: u32 = rand::thread_rng().gen_range(0..1_000_000);
        let code_s = format!("{code:06}");
        let hash = self.hash_code(&code_s)?;
        let id = Uuid::new_v4();
        let ttl = chrono::Duration::minutes(self.config.email.code_ttl_minutes as i64);
        let exp = Utc::now() + ttl;
        self.ev
            .replace_code(id, user_id, tenant_id, &hash, exp, PURPOSE_REGISTER)
            .await?;
        self.mail.send_email_confirmation(email, &code_s).await?;
        let jwt = self.jwt.mint_email_verification_token(user_id, tenant_id, id)?;
        let expires_in = self.config.totp.email_verification_jwt_ttl_seconds;
        Ok((id, jwt, expires_in))
    }

    /// Embedded registration when client MFA is `required`: no `users` row until email + TOTP enrollment complete.
    pub async fn start_embedded_pending_registration(
        &self,
        tenant_id: Uuid,
        oauth_client_id: &str,
        email: &str,
        password_hash: &str,
        registration_source: &str,
    ) -> Result<(Uuid, String, u64), AppError> {
        let dup_user: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2))",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_one(&self.pool)
        .await?;
        if dup_user {
            return Err(AppError::Validation("email already registered".to_string()));
        }

        let pending_id = Uuid::new_v4();
        self.rate_limit_send_pending(pending_id).await?;

        let expires_at = Utc::now() + chrono::Duration::hours(24);
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM embedded_pending_registrations WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
        )
        .bind(tenant_id)
        .bind(email)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO embedded_pending_registrations
             (id, tenant_id, oauth_client_id, email, password_hash, registration_source, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .bind(oauth_client_id)
        .bind(email)
        .bind(password_hash)
        .bind(registration_source)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let code: u32 = rand::thread_rng().gen_range(0..1_000_000);
        let code_s = format!("{code:06}");
        let hash = self.hash_code(&code_s)?;
        let ver_id = Uuid::new_v4();
        let ttl = chrono::Duration::minutes(self.config.email.code_ttl_minutes as i64);
        let exp = Utc::now() + ttl;
        self.ev
            .replace_code_pending(
                ver_id,
                pending_id,
                tenant_id,
                &hash,
                exp,
                PURPOSE_EMBEDDED_PENDING_REGISTER,
            )
            .await?;

        self.mail.send_email_confirmation(email, &code_s).await?;
        let jwt = self
            .jwt
            .mint_pending_email_verification_token(pending_id, tenant_id, ver_id)?;
        let expires_in = self.config.totp.email_verification_jwt_ttl_seconds;
        Ok((pending_id, jwt, expires_in))
    }

    /// Resend: same as start for an existing unverified user (caller must only allow `email_verified = false`).
    pub async fn resend_registration(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<(String, u64), AppError> {
        let (_id, jwt, exp) = self.start_registration(user_id, tenant_id, email).await?;
        Ok((jwt, exp))
    }

    pub async fn resend_embedded_pending_registration(
        &self,
        pending_id: Uuid,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<(String, u64), AppError> {
        self.rate_limit_send_pending(pending_id).await?;
        let row: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM embedded_pending_registrations
                WHERE id = $1 AND tenant_id = $2 AND email = $3
                  AND email_verified_at IS NULL AND expires_at > NOW()
             )",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .bind(email)
        .fetch_one(&self.pool)
        .await?;
        if !row {
            return Err(AppError::Unauthorized);
        }

        let code: u32 = rand::thread_rng().gen_range(0..1_000_000);
        let code_s = format!("{code:06}");
        let hash = self.hash_code(&code_s)?;
        let ver_id = Uuid::new_v4();
        let ttl = chrono::Duration::minutes(self.config.email.code_ttl_minutes as i64);
        let exp = Utc::now() + ttl;
        self.ev
            .replace_code_pending(
                ver_id,
                pending_id,
                tenant_id,
                &hash,
                exp,
                PURPOSE_EMBEDDED_PENDING_REGISTER,
            )
            .await?;
        self.mail.send_email_confirmation(email, &code_s).await?;
        let jwt = self
            .jwt
            .mint_pending_email_verification_token(pending_id, tenant_id, ver_id)?;
        let expires_in = self.config.totp.email_verification_jwt_ttl_seconds;
        Ok((jwt, expires_in))
    }

    /// Verify 6-digit code for embedded pending registration; marks email verified on pending row.
    pub async fn complete_embedded_pending_email(
        &self,
        pending_id: Uuid,
        tenant_id: Uuid,
        verification_id: Uuid,
        code: &str,
    ) -> Result<(), AppError> {
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err(AppError::Validation("code must be 6 digits".to_string()));
        }
        let key = format!("email:verify:rate:pending:{pending_id}");
        let mut c = self.redis.clone();
        let attempts: i64 = c.incr(&key, 1).await?;
        if attempts == 1 {
            let _: () = c.expire(&key, 600).await?;
        }
        if attempts > 30 {
            sqlx::query("DELETE FROM embedded_pending_registrations WHERE id = $1")
                .bind(pending_id)
                .execute(&self.pool)
                .await?;
            return Err(AppError::Forbidden);
        }

        let Some(row) = self.ev.get_by_id(verification_id).await? else {
            return Err(AppError::Unauthorized);
        };
        if row.pending_registration_id != Some(pending_id) || row.tenant_id != tenant_id {
            return Err(AppError::Unauthorized);
        }
        if row.user_id.is_some() {
            return Err(AppError::Unauthorized);
        }
        if Utc::now() > row.expires_at {
            return Err(AppError::Validation("code expired".to_string()));
        }

        let pending_ok: Option<bool> = sqlx::query_scalar(
            "SELECT (email_verified_at IS NULL AND expires_at > NOW()) FROM embedded_pending_registrations WHERE id = $1 AND tenant_id = $2",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(true) = pending_ok else {
            return Err(AppError::Unauthorized);
        };

        if (row.attempts as u32) >= self.config.email.max_verify_attempts {
            sqlx::query("DELETE FROM embedded_pending_registrations WHERE id = $1")
                .bind(pending_id)
                .execute(&self.pool)
                .await?;
            return Err(AppError::Forbidden);
        }

        if !self.verify_code_argon2(code, &row.code_hash) {
            self.ev.increment_attempts(verification_id).await?;
            let row2 = self
                .ev
                .get_by_id(verification_id)
                .await?
                .ok_or(AppError::Unauthorized)?;
            if (row2.attempts as u32) >= self.config.email.max_verify_attempts {
                sqlx::query("DELETE FROM embedded_pending_registrations WHERE id = $1")
                    .bind(pending_id)
                    .execute(&self.pool)
                    .await?;
            }
            return Err(AppError::Unauthorized);
        }

        self.ev.delete_by_id(verification_id).await?;
        sqlx::query(
            "UPDATE embedded_pending_registrations SET email_verified_at = NOW() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(pending_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Verify 6-digit code, mark email verified, delete row. On too many attempts, lock user.
    pub async fn complete_registration(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        verification_id: Uuid,
        code: &str,
    ) -> Result<(), AppError> {
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err(AppError::Validation("code must be 6 digits".to_string()));
        }
        let key = format!("email:verify:rate:{}", user_id);
        let mut c = self.redis.clone();
        let attempts: i64 = c.incr(&key, 1).await?;
        if attempts == 1 {
            let _: () = c.expire(&key, 600).await?;
        }
        if attempts > 30 {
            return Err(AppError::Forbidden);
        }

        let Some(row) = self.ev.get_by_id(verification_id).await? else {
            return Err(AppError::Unauthorized);
        };
        if row.user_id != Some(user_id) || row.tenant_id != tenant_id || row.pending_registration_id.is_some() {
            return Err(AppError::Unauthorized);
        }
        if Utc::now() > row.expires_at {
            return Err(AppError::Validation("code expired".to_string()));
        }
        if (row.attempts as u32) >= self.config.email.max_verify_attempts {
            self.users.lock_user(user_id, tenant_id).await?;
            return Err(AppError::Forbidden);
        }

        if !self.verify_code_argon2(code, &row.code_hash) {
            self.ev.increment_attempts(verification_id).await?;
            let row2 = self
                .ev
                .get_by_id(verification_id)
                .await?
                .ok_or(AppError::Unauthorized)?;
            if (row2.attempts as u32) >= self.config.email.max_verify_attempts {
                self.users.lock_user(user_id, tenant_id).await?;
            }
            return Err(AppError::Unauthorized);
        }

        self.ev.delete_by_id(verification_id).await?;
        self.users
            .set_email_verified(user_id, tenant_id, true)
            .await?;
        Ok(())
    }

    async fn set_cte_oauth_bind(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        oauth_client_public: &str,
    ) -> Result<(), AppError> {
        let key = format!("cte:bind:{user_id}:{tenant_id}");
        let mut c = self.redis.clone();
        c.set_ex::<_, _, ()>(&key, oauth_client_public, 7200)
            .await
            .map_err(|e| AppError::Internal(format!("redis cte:bind: {e}")))?;
        Ok(())
    }

    /// Email OTP before per-client TOTP setup for existing users. Binds `oauth_client_id` in Redis to this flow.
    pub async fn start_client_totp_enroll_email(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        email: &str,
        oauth_client_public: &str,
    ) -> Result<(Uuid, String, u64), AppError> {
        self.rate_limit_send(user_id).await?;
        self.set_cte_oauth_bind(user_id, tenant_id, oauth_client_public)
            .await?;
        let code: u32 = rand::thread_rng().gen_range(0..1_000_000);
        let code_s = format!("{code:06}");
        let hash = self.hash_code(&code_s)?;
        let ver_id = Uuid::new_v4();
        let ttl = chrono::Duration::minutes(self.config.email.code_ttl_minutes as i64);
        let exp = Utc::now() + ttl;
        self.ev
            .replace_code(
                ver_id,
                user_id,
                tenant_id,
                &hash,
                exp,
                PURPOSE_CLIENT_TOTP_ENROLL_EMAIL,
            )
            .await?;
        self.mail.send_email_confirmation(email, &code_s).await?;
        let jwt = self
            .jwt
            .mint_email_verification_token(user_id, tenant_id, ver_id)?;
        let expires_in = self.config.totp.email_verification_jwt_ttl_seconds;
        Ok((ver_id, jwt, expires_in as u64))
    }

    pub async fn resend_client_totp_enroll_email(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        email: &str,
        oauth_client_public: &str,
    ) -> Result<(String, u64), AppError> {
        self.rate_limit_send(user_id).await?;
        self.set_cte_oauth_bind(user_id, tenant_id, oauth_client_public)
            .await?;
        let code: u32 = rand::thread_rng().gen_range(0..1_000_000);
        let code_s = format!("{code:06}");
        let hash = self.hash_code(&code_s)?;
        let ver_id = Uuid::new_v4();
        let ttl = chrono::Duration::minutes(self.config.email.code_ttl_minutes as i64);
        let exp = Utc::now() + ttl;
        self.ev
            .replace_code(
                ver_id,
                user_id,
                tenant_id,
                &hash,
                exp,
                PURPOSE_CLIENT_TOTP_ENROLL_EMAIL,
            )
            .await?;
        self.mail.send_email_confirmation(email, &code_s).await?;
        let jwt = self
            .jwt
            .mint_email_verification_token(user_id, tenant_id, ver_id)?;
        let expires_in = self.config.totp.email_verification_jwt_ttl_seconds;
        Ok((jwt, expires_in as u64))
    }

    /// Verify 6-digit code; does not set `email_verified` (user is already an account). Clears `cte:bind` Redis key.
    pub async fn complete_client_totp_enroll_email_code(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        verification_id: Uuid,
        code: &str,
        oauth_client_public: &str,
    ) -> Result<(), AppError> {
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err(AppError::Validation("code must be 6 digits".to_string()));
        }
        let key = format!("email:verify:rate:{}", user_id);
        let mut c = self.redis.clone();
        let attempts: i64 = c.incr(&key, 1).await?;
        if attempts == 1 {
            let _: () = c.expire(&key, 600).await?;
        }
        if attempts > 30 {
            return Err(AppError::Forbidden);
        }
        let bind_key = format!("cte:bind:{user_id}:{tenant_id}");
        let mut c2 = self.redis.clone();
        let expected_oauth: Option<String> = c2.get(&bind_key).await.map_err(|e| {
            AppError::Internal(format!("redis cte:bind get: {e}"))
        })?;
        let Some(expected) = expected_oauth else {
            return Err(AppError::Unauthorized);
        };
        if expected != oauth_client_public {
            return Err(AppError::Validation(
                "oauth client does not match the login you started; sign in again".to_string(),
            ));
        }
        let Some(row) = self.ev.get_by_id(verification_id).await? else {
            return Err(AppError::Unauthorized);
        };
        if row.user_id != Some(user_id) || row.tenant_id != tenant_id || row.pending_registration_id.is_some() {
            return Err(AppError::Unauthorized);
        }
        if row.purpose != PURPOSE_CLIENT_TOTP_ENROLL_EMAIL {
            return Err(AppError::Unauthorized);
        }
        if Utc::now() > row.expires_at {
            return Err(AppError::Validation("code expired".to_string()));
        }
        if (row.attempts as u32) >= self.config.email.max_verify_attempts {
            self.users.lock_user(user_id, tenant_id).await?;
            return Err(AppError::Forbidden);
        }
        if !self.verify_code_argon2(code, &row.code_hash) {
            self.ev.increment_attempts(verification_id).await?;
            let row2 = self
                .ev
                .get_by_id(verification_id)
                .await?
                .ok_or(AppError::Unauthorized)?;
            if (row2.attempts as u32) >= self.config.email.max_verify_attempts {
                self.users.lock_user(user_id, tenant_id).await?;
            }
            return Err(AppError::Unauthorized);
        }
        self.ev.delete_by_id(verification_id).await?;
        let mut c3 = self.redis.clone();
        let _: () = c3.del::<_, ()>(bind_key).await.map_err(|e| {
            AppError::Internal(format!("redis cte:bind del: {e}"))
        })?;
        Ok(())
    }
}
