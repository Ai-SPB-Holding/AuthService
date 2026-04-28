//! Admin role **or** `client_user_membership` row (tenant + user).

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::middleware::admin_audience;
use crate::services::app_state::AppState;
use crate::services::errors::AppError;

const ADMIN_ROLE: &str = "admin";

pub async fn require_settings_access(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let claims = admin_audience::parse_bearer_admin_audience(&state, &request)?;
    if claims.roles.iter().any(|r| r == ADMIN_ROLE) {
        request.extensions_mut().insert(claims);
        return Ok(next.run(request).await);
    }

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("invalid sub in token".to_string()))?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::Validation("invalid tenant in token".to_string()))?;

    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM client_user_membership
            WHERE tenant_id = $1 AND user_id = $2
        )",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if !allowed {
        return Err(AppError::Forbidden);
    }

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
