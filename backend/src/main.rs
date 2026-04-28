use std::net::SocketAddr;

use auth_service::config::AppConfig;
use auth_service::services::observability;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    observability::init_tracing();

    let config = AppConfig::from_env()?;
    let app = auth_service::build_router(config.clone()).await?;
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;

    let listener = TcpListener::bind(addr).await?;
    info!("auth-service listening on {}", addr);
    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app).await?;

    Ok(())
}
