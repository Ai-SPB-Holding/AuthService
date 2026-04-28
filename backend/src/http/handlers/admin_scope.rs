//! Who may see **all-tenant** data in the admin API (metrics, user lists, etc.).

use crate::config::AppConfig;
use crate::security::jwt::AccessClaims;

/// `true` only if JWT `sub` is in `AUTH__GLOBAL_ADMIN_USER_IDS` or `AUTH__AUTH_SERVICE_DEPLOYMENT_ADMINS`.
/// Otherwise the admin API is **scoped to `tenant_id` from the access token** (one organization / «клиент-организация»).
#[inline]
pub fn is_deployment_global_admin(config: &AppConfig, claims: &AccessClaims) -> bool {
    config.is_global_service_admin(claims.sub.as_str())
}
