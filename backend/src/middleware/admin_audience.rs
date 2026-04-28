//! Verifies `Authorization: Bearer` access JWT with audience == `AUTH__ADMIN_API_AUDIENCE`.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};

use crate::security::jwt::AccessClaims;
use crate::services::app_state::AppState;
use crate::services::errors::AppError;

/// Parse Bearer token and validate audience is the admin API audience (no role check).
pub fn parse_bearer_admin_audience(
    state: &AppState,
    request: &Request,
) -> Result<AccessClaims, AppError> {
    let Some(auth_header) = request.headers().get(header::AUTHORIZATION) else {
        return Err(AppError::Unauthorized);
    };
    let Ok(s) = auth_header.to_str() else {
        return Err(AppError::Unauthorized);
    };
    let Some(token) = s.strip_prefix("Bearer ").map(str::trim) else {
        return Err(AppError::Unauthorized);
    };
    if token.is_empty() {
        return Err(AppError::Unauthorized);
    }

    let expected = state.config.auth.admin_api_audience.as_str();
    state.auth.jwt.verify(token, expected)
}

/// Middleware: valid admin-audience JWT; inserts [`AccessClaims`] for handlers.
pub async fn require_admin_audience(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let claims = parse_bearer_admin_audience(&state, &request)?;
    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
