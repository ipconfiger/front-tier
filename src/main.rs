use anyhow::Result;
use tracing::info;

mod backend_pool;
mod config;
mod observability;
mod state;

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = observability::logging::init_logging(&config::LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        output: "console".to_string(),
        file_path: None,
    });

    info!("Pingora Virtual Host Proxy starting...");

    Ok(())
}
