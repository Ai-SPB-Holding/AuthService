use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{domain::user::User, services::errors::AppError};

#[derive(Debug, Clone)]
pub struct UserWithCredential {
    pub user: User,
    pub password_hash: String,
    pub totp_enabled: bool,
    pub totp_secret_enc: Option<Vec<u8>>,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(
        &self,
        tenant_id: Uuid,
        email: &str,
        password_hash: &str,
        registration_source: &str,
    ) -> Result<User, AppError>;
    async fn find_with_credential(&self, tenant_id: Uuid, email: &str) -> Result<Option<UserWithCredential>, AppError>;
}

#[derive(Clone)]
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn set_email_verified(&self, user_id: Uuid, tenant_id: Uuid, v: bool) -> Result<(), AppError> {
        sqlx::query("UPDATE users SET email_verified = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(v)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn lock_user(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE users SET is_locked = true WHERE id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn unlock_user(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE users SET is_locked = false WHERE id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_email_verified(&self, user_id: Uuid) -> Result<bool, AppError> {
        let b: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(b)
    }

    /// Encrypted TOTP secret blob; `totp_enabled` may still be false until user confirms the code.
    pub async fn set_totp_encrypted(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        enc: Option<Vec<u8>>,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE users SET totp_secret_enc = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(enc)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_totp_enabled(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        enabled: bool,
    ) -> Result<(), AppError> {
        if enabled {
            sqlx::query(
                "UPDATE users SET totp_enabled = true, totp_enabled_at = NOW() WHERE id = $1 AND tenant_id = $2",
            )
            .bind(user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query("UPDATE users SET totp_enabled = false, totp_enabled_at = NULL WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Clear TOTP for disable flow.
    pub async fn clear_totp(&self, user_id: Uuid, tenant_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE users SET totp_secret_enc = NULL, totp_enabled = false, totp_enabled_at = NULL
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create_user(
        &self,
        tenant_id: Uuid,
        email: &str,
        password_hash: &str,
        registration_source: &str,
    ) -> Result<User, AppError> {
        let mut tx = self.pool.begin().await?;
        let user_id = Uuid::new_v4();

        let email_norm = email.trim().to_lowercase();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, is_active, is_locked, email_verified, registration_source)
            VALUES ($1, $2, $3, true, false, false, $4)",
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&email_norm)
        .bind(registration_source)
        .execute(&mut *tx)
        .await?;

        sqlx::query("INSERT INTO credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)")
            .bind(user_id)
            .bind(tenant_id)
            .bind(password_hash)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(User {
            id: user_id,
            tenant_id,
            email: email_norm,
            is_active: true,
            is_locked: false,
            email_verified: false,
            totp_enabled: false,
            registration_source: registration_source.to_string(),
        })
    }

    async fn find_with_credential(&self, tenant_id: Uuid, email: &str) -> Result<Option<UserWithCredential>, AppError> {
        let row = sqlx::query(
            "SELECT u.id, u.tenant_id, u.email, u.is_active, u.is_locked, u.email_verified, u.totp_enabled,
                    u.registration_source, u.totp_secret_enc, c.password_hash
            FROM users u
            JOIN credentials c ON c.user_id = u.id AND c.tenant_id = u.tenant_id
            WHERE u.tenant_id = $1 AND u.email_norm = lower(trim(both from $2::text))",
        )
        .bind(tenant_id)
        .bind(email.trim())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| UserWithCredential {
            user: User {
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
            },
            password_hash: row.get("password_hash"),
            totp_enabled: row.get("totp_enabled"),
            totp_secret_enc: row.get("totp_secret_enc"),
        }))
    }
}
