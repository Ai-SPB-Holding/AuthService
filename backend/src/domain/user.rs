use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub is_active: bool,
    pub is_locked: bool,
    pub email_verified: bool,
    pub totp_enabled: bool,
    /// Set at account creation; same column as `registration_source` in DB.
    pub registration_source: String,
}
