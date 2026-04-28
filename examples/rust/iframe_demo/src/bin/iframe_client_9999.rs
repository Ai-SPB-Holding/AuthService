//! Confidential iframe demo — port `DEMO_PORT_9999` (default 9999).

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = iframe_demo::DemoSettings::load_confidential_9999()?;
    iframe_demo::run(settings).await?;
    Ok(())
}
