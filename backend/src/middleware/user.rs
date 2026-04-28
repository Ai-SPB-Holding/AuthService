use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};

use crate::security::jwt::{AccessClaims, TotpEnrollmentClaims};
use crate::services::app_state::AppState;
use crate::services::errors::AppError;

/// `Authorization: Bearer` — either a normal access JWT or a TOTP enrollment token (`totp-enroll` aud).
#[derive(Debug, Clone)]
pub enum BearerPrincipal {
    Access(AccessClaims),
    TotpEnroll(TotpEnrollmentClaims),
}

/// Like [`require_bearer_user`], but also accepts `AUD_TOTP_ENROLL` for forced admin TOTP setup.
pub async fn require_bearer_user_or_totp_enroll(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
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

    if let Ok(c) = state.auth.jwt.verify_totp_enrollment(token) {
        request
            .extensions_mut()
            .insert(BearerPrincipal::TotpEnroll(c));
        return Ok(next.run(request).await);
    }
    let claims = state.auth.jwt.verify_access_any_audience(token)?;
    state.auth.ensure_access_session_active(&claims).await?;
    request
        .extensions_mut()
        .insert(BearerPrincipal::Access(claims));
    Ok(next.run(request).await)
}

/// `Authorization: Bearer` access JWT (any audience). Inserts `AccessClaims` in extensions.
pub async fn require_bearer_user(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
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

    let claims = state.auth.jwt.verify_access_any_audience(token)?;
    state.auth.ensure_access_session_active(&claims).await?;
    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
