use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

use crate::middleware::admin_audience;
use crate::services::app_state::AppState;
use crate::services::errors::AppError;

const ADMIN_ROLE: &str = "admin";

/// Requires `Authorization: Bearer <access_jwt>` with `admin` in token roles. Inserts `AccessClaims` for downstream handlers.
pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let claims = admin_audience::parse_bearer_admin_audience(&state, &request)?;
    if !claims.roles.iter().any(|r| r == ADMIN_ROLE) {
        return Err(AppError::Forbidden);
    }

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
