//! Global security response headers and `Cache-Control` for sensitive paths.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Request, Response, header},
    middleware::Next,
};

use crate::services::app_state::AppState;

fn path_needs_no_store(path: &str) -> bool {
    path.starts_with("/auth/")
        || path.starts_with("/oauth2/")
        || path.starts_with("/.well-known/")
        || path.starts_with("/api/")
        || path.starts_with("/2fa/")
        || path.starts_with("/email/")
        || path.starts_with("/admin/")
        || path == "/authorize"
        || path == "/token"
        || path == "/userinfo"
        || path == "/revoke"
        || path == "/introspect"
        || path == "/jwks.json"
        || path == "/embedded-login"
}

pub async fn security_response_headers(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    let _ = headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    if state.config.server.x_frame_options_deny {
        let _ = headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }

    let corp = state.config.server.cross_origin_resource_policy.trim();
    if !corp.is_empty()
        && let Ok(val) = HeaderValue::from_str(corp)
    {
        let _ = headers.insert(
            header::HeaderName::from_static("cross-origin-resource-policy"),
            val,
        );
    }

    if path_needs_no_store(&path) {
        let _ = headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
        );
        let _ = headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }

    response
}

#[cfg(test)]
mod tests {
    use super::path_needs_no_store;

    #[test]
    fn no_store_paths() {
        assert!(path_needs_no_store("/auth/login"));
        assert!(path_needs_no_store("/.well-known/openid-configuration"));
        assert!(path_needs_no_store("/oauth2/token"));
        assert!(path_needs_no_store("/token"));
        assert!(!path_needs_no_store("/health"));
        assert!(!path_needs_no_store("/metrics"));
    }
}
