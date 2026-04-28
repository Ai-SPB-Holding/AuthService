//! Iframe embedded-login demo — parity with `examples/python` (Flask).

mod error;
mod handlers;
pub mod settings;
mod store;

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

pub use error::DemoError;
pub use settings::DemoSettings;

use authservice_sdk::{ClientConfig, OAuth2Client};
use store::SqliteTokenStore;

pub struct AppState {
    pub settings: DemoSettings,
    pub client_config: ClientConfig,
    pub store: SqliteTokenStore,
    pub oauth: OAuth2Client,
    pub http: reqwest::Client,
}

pub async fn run(settings: DemoSettings) -> Result<(), DemoError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let listen_port = settings.listen_port;
    let http = reqwest::Client::builder()
        .build()
        .map_err(|e| DemoError::msg(e.to_string()))?;
    let sdk_cfg = settings.sdk_config()?;
    let client_config = sdk_cfg.client.clone();
    let oauth = OAuth2Client::from_config(http.clone(), &sdk_cfg);
    let store = SqliteTokenStore::open(&settings.sqlite_path)?;

    let state = Arc::new(AppState {
        settings,
        client_config,
        store,
        oauth,
        http,
    });

    let static_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static");

    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/register", get(handlers::register_page))
        .route("/auth/callback", post(handlers::auth_callback))
        .route("/profile", get(handlers::profile))
        .route("/demo/oidc-refresh", get(handlers::oidc_refresh))
        .route("/logout", post(handlers::logout))
        .route("/admin/tokens", get(handlers::admin_tokens))
        .nest_service("/static", ServeDir::new(static_dir))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!(
        "{}:{}",
        std::env::var("DEMO_BIND").unwrap_or_else(|_| "127.0.0.1".to_string()),
        listen_port
    );

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| DemoError::msg(format!("bind {addr}: {e}")))?;

    tracing::info!("iframe demo listening on http://{addr}");
    axum::serve(listener, app)
        .await
        .map_err(|e| DemoError::msg(e.to_string()))?;

    Ok(())
}
