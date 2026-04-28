use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::services::errors::AppError;

#[derive(Debug, Clone)]
pub struct EmailVerificationRow {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub pending_registration_id: Option<Uuid>,
    pub tenant_id: Uuid,
    pub code_hash: String,
    pub expires_at: DateTime<Utc>,
    pub attempts: i32,
    pub purpose: String,
}

pub struct EmailVerificationRepository {
    pool: PgPool,
}

impl EmailVerificationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Replace any pending row for the same (user, purpose) with a new code.
    pub async fn replace_code(
        &self,
        id: Uuid,
        user_id: Uuid,
        tenant_id: Uuid,
        code_hash: &str,
        expires_at: DateTime<Utc>,
        purpose: &str,
    ) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM email_verifications WHERE user_id = $1 AND purpose = $2")
            .bind(user_id)
            .bind(purpose)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO email_verifications (id, user_id, code_hash, expires_at, attempts, created_at, purpose, tenant_id, pending_registration_id)
             VALUES ($1, $2, $3, $4, 0, NOW(), $5, $6, NULL)",
        )
        .bind(id)
        .bind(user_id)
        .bind(code_hash)
        .bind(expires_at)
        .bind(purpose)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Replace pending embedded-registration verification for (`pending_registration_id`, `purpose`).
    pub async fn replace_code_pending(
        &self,
        id: Uuid,
        pending_registration_id: Uuid,
        tenant_id: Uuid,
        code_hash: &str,
        expires_at: DateTime<Utc>,
        purpose: &str,
    ) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM email_verifications WHERE pending_registration_id = $1 AND purpose = $2",
        )
        .bind(pending_registration_id)
        .bind(purpose)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO email_verifications (id, user_id, code_hash, expires_at, attempts, created_at, purpose, tenant_id, pending_registration_id)
             VALUES ($1, NULL, $2, $3, 0, NOW(), $4, $5, $6)",
        )
        .bind(id)
        .bind(code_hash)
        .bind(expires_at)
        .bind(purpose)
        .bind(tenant_id)
        .bind(pending_registration_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<EmailVerificationRow>, AppError> {
        let row = sqlx::query(
            "SELECT id, user_id, pending_registration_id, tenant_id, code_hash, expires_at, attempts, purpose
             FROM email_verifications WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| EmailVerificationRow {
            id: r.get("id"),
            user_id: r.get::<Option<Uuid>, _>("user_id"),
            pending_registration_id: r.get::<Option<Uuid>, _>("pending_registration_id"),
            tenant_id: r.get("tenant_id"),
            code_hash: r.get("code_hash"),
            expires_at: r.get("expires_at"),
            attempts: r.get("attempts"),
            purpose: r.get("purpose"),
        }))
    }

    pub async fn increment_attempts(&self, id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE email_verifications SET attempts = attempts + 1 WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_by_id(&self, id: Uuid) -> Result<(), AppError> {
        sqlx::query("DELETE FROM email_verifications WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
