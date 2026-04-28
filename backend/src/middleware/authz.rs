//! Authorization helpers for RBAC-style checks on [`crate::security::jwt::AccessClaims`].
//!
//! Route-level middleware cannot know per-handler permission needs without extra state; handlers
//! should call [`access_has_permission`] / [`access_has_any_role`] after bearer authentication.

use axum::{extract::Request, middleware::Next, response::Response};

use crate::security::jwt::AccessClaims;

/// Returns true if the token includes `permission` or the user has the `admin` role.
pub fn access_has_permission(claims: &AccessClaims, permission: &str) -> bool {
    claims.roles.iter().any(|r| r == "admin")
        || claims.permissions.iter().any(|p| p == permission)
}

pub fn access_has_any_role(claims: &AccessClaims, roles: &[&str]) -> bool {
    claims.roles.iter().any(|r| roles.iter().any(|x| x == r))
}

pub fn require_permission(claims: &AccessClaims, permission: &str) -> Result<(), crate::services::errors::AppError> {
    if access_has_permission(claims, permission) {
        Ok(())
    } else {
        Err(crate::services::errors::AppError::Forbidden)
    }
}

/// No-op middleware placeholder (keeps stack compatibility). Prefer [`require_permission`] in handlers.
pub async fn authz_layer(req: Request, next: Next) -> Response {
    next.run(req).await
}
