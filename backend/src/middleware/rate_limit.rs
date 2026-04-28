use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::services::app_state::AppState;
use crate::services::errors::AppError;

/// Redis-backed IP rate limits for OAuth and embedded auth endpoints.
pub async fn oauth_and_embedded_rate_limit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let ip = addr.ip().to_string();
    let path = req.uri().path();
    match path {
        "/token" | "/oauth2/token" => {
            state
                .rate_limit_by_ip(
                    "rl:oauth:token",
                    &ip,
                    state.config.auth.oauth_token_ip_max_attempts,
                    state.config.auth.oauth_token_ip_window_seconds,
                    true,
                )
                .await?;
        }
        "/authorize" | "/oauth2/authorize" => {
            state
                .rate_limit_by_ip(
                    "rl:oauth:authorize",
                    &ip,
                    state.config.auth.oauth_authorize_ip_max_attempts,
                    state.config.auth.oauth_authorize_ip_window_seconds,
                    false,
                )
                .await?;
        }
        "/api/login" => {
            state
                .rate_limit_by_ip(
                    "rl:embedded:login:ip",
                    &ip,
                    state.config.auth.embedded_login_ip_max_attempts,
                    state.config.auth.embedded_login_ip_window_seconds,
                    false,
                )
                .await?;
        }
        _ => {}
    }
    Ok(next.run(req).await)
}
