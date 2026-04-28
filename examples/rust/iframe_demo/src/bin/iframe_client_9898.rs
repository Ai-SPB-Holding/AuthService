//! Public iframe demo — port `DEMO_PORT_9898` (default 9898).

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = iframe_demo::DemoSettings::load_public_9898()?;
    iframe_demo::run(settings).await?;
    Ok(())
}
