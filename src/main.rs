use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing::{info, error};

mod api;
mod backend_pool;
mod config;
mod health_check;
mod observability;
mod proxy;
mod state;

#[derive(Parser)]
#[command(name = "pingora-vhost")]
#[command(about = "Pingora-based virtual host proxy", long_about = None)]
struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy server
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = config::load_config(&cli.config)?;
    let _guard = observability::logging::init_logging(&config.logging);

    info!("Starting Pingora Virtual Host Proxy...");

    // Initialize state from config
    let state = Arc::new(state::AppState::from_config(
        config.virtual_hosts.clone(),
        config.backends.clone(),
    ).await);

    // Start management API
    let api_addr = config.proxy.management_api_addr.clone();
    let api_state = (*state).clone();
    tokio::spawn(async move {
        let (addr, app) = api::server::create_api_server(&api_addr, api_state).unwrap();
        info!("Management API listening on http://{}", addr);
        if let Err(e) = api::server::run_api_server(addr, app).await {
            error!("API server error: {}", e);
        }
    });

    // Start proxy
    info!("Proxy server starting on {}", config.proxy.listen_addr);

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
