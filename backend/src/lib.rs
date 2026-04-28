pub mod config;
pub mod domain;
pub mod email;
pub mod http;
pub mod middleware;
pub mod oidc;
pub mod repositories;
pub mod security;
pub mod services;

use std::sync::Arc;

use axum::http::Method;
use axum::middleware::from_fn_with_state;
use axum::{Router, routing::{get, post}};
use config::AppConfig;
use http::handlers::{
    auth, email_verification_http, embedded_login, health, metrics, oauth2, oidc as oidc_handlers, two_factor,
};
use services::app_state::AppState;
use tower_http::cors::{Any, CorsLayer};

pub async fn build_router(config: AppConfig) -> Result<Router, crate::services::errors::AppError> {
    let state = Arc::new(AppState::build(config).await?);

    let auth_routes = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/login/mfa", post(auth::login_mfa))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route(
            "/auth/verify-client-totp-enroll-email",
            post(auth::verify_client_totp_enroll_email),
        )
        .route(
            "/auth/client-totp-enroll/setup",
            post(auth::client_totp_enroll_setup),
        )
        .route(
            "/auth/client-totp-enroll/verify",
            post(auth::client_totp_enroll_verify),
        );

    let mfa_setup_verify = Router::new()
        .route("/2fa/setup", post(two_factor::setup_2fa))
        .route("/2fa/verify", post(two_factor::verify_2fa))
        .route_layer(from_fn_with_state(
            state.clone(),
            crate::middleware::user::require_bearer_user_or_totp_enroll,
        ));

    let mfa_user_only = Router::new()
        .route("/2fa/disable", post(two_factor::disable_2fa))
        .route("/2fa/client/setup", post(two_factor::client_setup_2fa))
        .route("/2fa/client/verify", post(two_factor::client_verify_2fa))
        .route("/2fa/client/disable", post(two_factor::client_disable_2fa))
        .route_layer(from_fn_with_state(
            state.clone(),
            crate::middleware::user::require_bearer_user,
        ));

    let mfa_enroll = mfa_setup_verify.merge(mfa_user_only);

    let email_routes = Router::new()
        .route("/email/send-code", post(email_verification_http::send_code))
        .route("/email/verify-code", post(email_verification_http::verify_code));

    let oauth_rate_limit = axum::middleware::from_fn_with_state(
        state.clone(),
        crate::middleware::rate_limit::oauth_and_embedded_rate_limit,
    );

    let oidc_routes = Router::new()
        .route("/.well-known/openid-configuration", get(oidc_handlers::metadata))
        .route("/authorize", get(oidc_handlers::authorize))
        .route("/token", post(oidc_handlers::token))
        .route("/userinfo", get(oidc_handlers::userinfo))
        .route("/jwks.json", get(oidc_handlers::jwks))
        .route("/revoke", post(oidc_handlers::revoke))
        .route("/introspect", post(oidc_handlers::introspect))
        .layer(oauth_rate_limit.clone());

    let oauth2_routes = Router::new()
        .route("/oauth2/authorize", get(oauth2::authorize))
        .route("/oauth2/token", post(oauth2::token))
        .route("/oauth2/userinfo", get(oauth2::userinfo))
        .route("/oauth2/introspect", post(oauth2::introspect))
        .route("/oauth2/revoke", post(oauth2::revoke))
        .layer(oauth_rate_limit.clone());

    let embedded_api_routes = Router::new()
        .route("/api/login", post(embedded_login::embedded_login_api))
        .route(
            "/api/session-code",
            post(embedded_login::embedded_session_code_api),
        )
        .route("/api/register", post(embedded_login::embedded_register_api))
        .route(
            "/api/register/verify-email",
            post(embedded_login::embedded_register_verify_email),
        )
        .route(
            "/api/register/resend-code",
            post(embedded_login::embedded_register_resend_code),
        )
        .route(
            "/api/register/client-totp/setup",
            post(embedded_login::embedded_register_client_totp_setup),
        )
        .route(
            "/api/register/client-totp/verify",
            post(embedded_login::embedded_register_client_totp_verify),
        )
        .route(
            "/api/login/verify-client-totp-enroll-email",
            post(embedded_login::embedded_login_verify_cte_email),
        )
        .route(
            "/api/login/resend-client-totp-enroll-email",
            post(embedded_login::embedded_login_resend_cte_email),
        )
        .route(
            "/api/login/client-totp-enroll/setup",
            post(embedded_login::embedded_login_client_totp_enroll_setup),
        )
        .route(
            "/api/login/client-totp-enroll/verify",
            post(embedded_login::embedded_login_client_totp_enroll_verify),
        )
        .layer(oauth_rate_limit);

    let admin_routes = Router::new()
        .route(
            "/admin/dashboard/stats",
            get(crate::http::handlers::admin::get_dashboard_stats),
        )
        .route("/admin/rbac", get(crate::http::handlers::admin::get_rbac))
        .route(
            "/admin/clients",
            get(crate::http::handlers::admin_portal::list_clients).post(crate::http::handlers::admin::create_client),
        )
        .route(
            "/admin/clients/generate-id",
            post(crate::http::handlers::admin::generate_client_id),
        )
        .route(
            "/admin/clients/:client_row_id/users/:user_id/2fa",
            get(crate::http::handlers::admin::admin_client_user_2fa_status),
        )
        .route(
            "/admin/clients/:client_row_id/users/:user_id/2fa/setup",
            post(crate::http::handlers::admin::admin_client_user_2fa_setup),
        )
        .route(
            "/admin/clients/:client_row_id/users/:user_id/2fa/verify",
            post(crate::http::handlers::admin::admin_client_user_2fa_verify),
        )
        .route(
            "/admin/clients/:client_row_id/users/:user_id/2fa/disable",
            post(crate::http::handlers::admin::admin_client_user_2fa_disable),
        )
        .route(
            "/admin/clients/:id",
            get(crate::http::handlers::admin_portal::get_client)
                .put(crate::http::handlers::admin::update_client)
                .delete(crate::http::handlers::admin::delete_client),
        )
        .route(
            "/admin/clients/:id/rotate-secret",
            post(crate::http::handlers::admin::rotate_client_secret),
        )
        .route(
            "/oauth/clients",
            get(crate::http::handlers::admin_portal::list_clients).post(crate::http::handlers::admin::create_client),
        )
        .route(
            "/oauth/clients/:id",
            get(crate::http::handlers::admin_portal::get_client).put(crate::http::handlers::admin::update_client),
        )
        .route(
            "/admin/audit-logs",
            get(crate::http::handlers::admin_portal::list_audit_logs),
        )
        .route(
            "/admin/sessions/:id/revoke",
            post(crate::http::handlers::admin_portal::revoke_session),
        )
        .route(
            "/admin/sessions",
            get(crate::http::handlers::admin_portal::list_sessions),
        )
        .route(
            "/admin/tenant-ids/generate",
            get(crate::http::handlers::admin::generate_tenant_id),
        )
        .route(
            "/admin/users",
            get(crate::http::handlers::admin::list_users).post(crate::http::handlers::admin::create_user),
        )
        .route(
            "/admin/users/:id/send-verification-email",
            post(crate::http::handlers::admin::admin_send_verification_email),
        )
        .route(
            "/admin/users/:id/verify-email",
            post(crate::http::handlers::admin::admin_verify_email),
        )
        .route(
            "/admin/users/:id/reset-email-verification",
            post(crate::http::handlers::admin::admin_reset_email_verification),
        )
        .route(
            "/admin/users/:id",
            get(crate::http::handlers::admin::get_user)
                .patch(crate::http::handlers::admin::patch_user)
                .put(crate::http::handlers::admin::update_user)
                .delete(crate::http::handlers::admin::delete_user),
        )
        .route("/admin/roles", post(crate::http::handlers::admin::create_role))
        .route(
            "/admin/roles/:id",
            get(crate::http::handlers::admin::get_role)
                .put(crate::http::handlers::admin::update_role)
                .delete(crate::http::handlers::admin::delete_role),
        )
        .route(
            "/admin/permissions",
            post(crate::http::handlers::admin::create_permission),
        )
        .route(
            "/admin/permissions/:id",
            get(crate::http::handlers::admin::get_permission)
                .put(crate::http::handlers::admin::update_permission)
                .delete(crate::http::handlers::admin::delete_permission),
        )
        .route_layer(from_fn_with_state(
            state.clone(),
            crate::middleware::admin::require_admin,
        ));

    let admin_session_route = Router::new()
        .route(
            "/admin/session",
            get(crate::http::handlers::admin_settings::get_admin_session),
        )
        .route_layer(from_fn_with_state(
            state.clone(),
            crate::middleware::admin_audience::require_admin_audience,
        ));

    let admin_settings_route = Router::new()
        .route(
            "/admin/settings",
            get(crate::http::handlers::admin_settings::get_settings).put(
                crate::http::handlers::admin_settings::put_settings,
            ),
        )
        .route_layer(from_fn_with_state(
            state.clone(),
            crate::middleware::settings_access::require_settings_access,
        ));

    let origins: Vec<axum::http::HeaderValue> = state
        .config
        .cors_origin_list()
        .into_iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let cors = if origins.is_empty() {
        CorsLayer::new()
    } else {
        use tower_http::cors::AllowOrigin;
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
    };

    Ok(Router::new()
        .route("/health", get(health::healthcheck))
        .route("/metrics", get(metrics::metrics))
        .route("/embedded-login", get(embedded_login::embedded_login_page))
        .merge(embedded_api_routes)
        .merge(oauth2_routes)
        .merge(auth_routes)
        .merge(mfa_enroll)
        .merge(email_routes)
        .merge(oidc_routes)
        .merge(admin_session_route)
        .merge(admin_settings_route)
        .merge(admin_routes)
        .with_state(state)
        .layer(cors))
}
