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
mod tls;

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
    config::validate_config(&config)
        .map_err(|e| anyhow::anyhow!("Invalid config: {}", e))?;
    config::validate_tls_config(&config)
        .map_err(|e| anyhow::anyhow!("Invalid TLS config: {}", e))?;
    let _guard = observability::logging::init_logging(&config.logging);

    info!("Starting Pingora Virtual Host Proxy...");

    // Initialize state from config
    let state = Arc::new(state::AppState::from_config(
        config.virtual_hosts.clone(),
        config.backends.clone(),
    ).await);

    // Initialize certificate manager
    let cert_manager = Arc::new(tls::certificate_manager::CertificateManager::new(
        config.lets_encrypt.clone(),
    ));

    // Start management API
    let api_addr = config.proxy.management_api_addr.clone();
    let api_state = (*state).clone();
    let api_cert_manager = Arc::clone(&cert_manager);
    tokio::spawn(async move {
        let (addr, app) = api::server::create_api_server(&api_addr, api_state, api_cert_manager).unwrap();
        info!("Management API listening on http://{}", addr);
        if let Err(e) = api::server::run_api_server(addr, app).await {
            error!("API server error: {}", e);
        }
    });

    // Start certificate watcher for file-based certificates
    let has_file_certs = config.virtual_hosts.iter().any(|vh| {
        matches!(&vh.certificate_source, Some(config::CertificateSource::File { .. }))
    });

    if has_file_certs {
        let watcher = Arc::new(tls::CertificateWatcher::new(cert_manager.clone(), 1));
        for vhost in &config.virtual_hosts {
            if let Some(config::CertificateSource::File { cert_path, key_path }) = &vhost.certificate_source {
                watcher.add_watch_paths(&vhost.domain, Some(cert_path), Some(key_path)).await;
            }
        }
        match watcher.start() {
            Ok(handle) => {
                info!("Certificate watcher started successfully");
                // Watcher runs in background, handle is kept to prevent dropping
                tokio::spawn(async move {
                    let _ = handle.await;
                });
            }
            Err(e) => {
                error!("Failed to start certificate watcher: {}", e);
            }
        }
    }

    // Start proxy
    info!("Proxy server starting on {}", config.proxy.listen_addr);
    let mut proxy_service = proxy::MyProxy::new(config.clone(), state.clone(), cert_manager.clone());

    // Wait for shutdown signal or proxy service completion
    tokio::select! {
        result = proxy_service.run() => {
            match result {
                Ok(_) => info!("Proxy service completed successfully"),
                Err(e) => error!("Proxy service error: {}", e),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received");
        }
    }

    info!("Shutting down...");

    Ok(())
}
