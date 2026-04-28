use std::sync::Arc;

use base64::Engine;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::{
    config::AppConfig, email::ExmailMailer, oidc::proxy::OidcProxy,
    repositories::email_verification_repository::EmailVerificationRepository,
    repositories::user_repository::PostgresUserRepository, security::crypto::TotpEncryption,
    security::jwt::JwtService, services::auth_service::AuthService,
    services::email_verification_service::EmailVerificationService, services::errors::AppError,
    services::totp_service::TotpService,
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub pool: PgPool,
    pub user_repo: Arc<PostgresUserRepository>,
    pub auth: Arc<AuthService<PostgresUserRepository>>,
    pub oidc_proxy: OidcProxy,
    pub totp: Arc<TotpService>,
    pub ev: Arc<EmailVerificationService>,
    pub totp_enc: Arc<TotpEncryption>,
}

impl AppState {
    pub async fn build(config: AppConfig) -> Result<Self, AppError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.database.pool_size)
            .connect(&config.database.url)
            .await?;

        let redis_client = redis::Client::open(config.redis.url.clone())?;
        let redis = ConnectionManager::new(redis_client).await?;

        let user_repo = Arc::new(PostgresUserRepository::new(pool.clone()));
        let jwt = JwtService::from_config(&config)?;

        let key_bytes = totp_key_bytes(&config)?;
        let prev_key = totp_previous_key_bytes(&config)?;
        let totp_enc = Arc::new(TotpEncryption::from_key(&key_bytes, prev_key.as_ref()));

        let ev_repo = EmailVerificationRepository::new(pool.clone());
        let mail = ExmailMailer::from_config(&config)?;
        let ev = Arc::new(EmailVerificationService::new(
            ev_repo,
            user_repo.clone(),
            pool.clone(),
            mail,
            config.clone(),
            jwt.clone(),
            redis.clone(),
        ));
        let totp = Arc::new(TotpService::new(
            user_repo.clone(),
            totp_enc.clone(),
            config.clone(),
            redis.clone(),
            pool.clone(),
        ));

        let client_mfa_enforce = config.oidc.client_mfa_enforce;
        let require_login_2fa = config.auth.require_login_2fa;
        let max_client_access_ttl_seconds = config.auth.max_client_access_ttl_seconds;
        let max_client_refresh_ttl_seconds = config.auth.max_client_refresh_ttl_seconds;
        let redis_prefix = config.redis.prefix.clone();
        let auth = Arc::new(AuthService {
            users: user_repo.clone(),
            jwt,
            redis,
            redis_prefix,
            _pool: pool.clone(),
            ev: ev.clone(),
            totp: totp.clone(),
            client_mfa_enforce,
            require_login_2fa,
            max_client_access_ttl_seconds,
            max_client_refresh_ttl_seconds,
        });

        Ok(Self {
            config,
            pool,
            user_repo,
            auth,
            oidc_proxy: OidcProxy::new(),
            totp,
            ev,
            totp_enc,
        })
    }

    /// Increment a Redis counter keyed by `redis_key` + IP. When `fail_closed`, Redis errors become
    /// [`crate::services::errors::AppError::Internal`] (used for `/token`).
    pub async fn rate_limit_by_ip(
        &self,
        redis_key: &str,
        ip: &str,
        max_attempts: u32,
        window_secs: u64,
        fail_closed: bool,
    ) -> Result<(), crate::services::errors::AppError> {
        if max_attempts == 0 {
            return Ok(());
        }
        let key = self.config.redis.key(&format!("{redis_key}:{ip}"));
        let mut r = self.auth.redis.clone();
        let n: i64 = match r.incr(&key, 1).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "rate_limit redis incr");
                if fail_closed {
                    return Err(crate::services::errors::AppError::Internal(
                        "oauth rate limit store unavailable".to_string(),
                    ));
                }
                return Ok(());
            }
        };
        if n == 1 {
            if let Err(e) = r.expire::<_, ()>(&key, window_secs.max(1) as i64).await {
                tracing::warn!(error = %e, "rate_limit redis expire");
                if fail_closed {
                    return Err(crate::services::errors::AppError::Internal(
                        "oauth rate limit store unavailable".to_string(),
                    ));
                }
            }
        }
        if n > i64::from(max_attempts) {
            return Err(crate::services::errors::AppError::TooManyRequests);
        }
        Ok(())
    }
}

fn totp_key_bytes(config: &AppConfig) -> Result<[u8; 32], AppError> {
    if config.totp.encryption_key_b64.is_empty() {
        return Err(AppError::Config(
            "TOTP__ENCRYPTION_KEY_B64 is required (32 bytes, base64).".to_string(),
        ));
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(config.totp.encryption_key_b64.trim().as_bytes())
        .map_err(|e| AppError::Config(format!("TOTP__ENCRYPTION_KEY_B64: {e}")))?;
    raw.try_into().map_err(|_| {
        AppError::Config("TOTP__ENCRYPTION_KEY_B64 must decode to exactly 32 bytes".to_string())
    })
}

fn totp_previous_key_bytes(config: &AppConfig) -> Result<Option<[u8; 32]>, AppError> {
    let Some(raw_b64) = config.totp.encryption_key_previous_b64.as_ref() else {
        return Ok(None);
    };
    let t = raw_b64.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(t.as_bytes())
        .map_err(|e| AppError::Config(format!("TOTP__ENCRYPTION_KEY_PREVIOUS_B64: {e}")))?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| {
        AppError::Config(
            "TOTP__ENCRYPTION_KEY_PREVIOUS_B64 must decode to exactly 32 bytes".to_string(),
        )
    })?;
    Ok(Some(arr))
}
