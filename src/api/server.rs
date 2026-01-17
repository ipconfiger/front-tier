use anyhow::Result;
use axum::{routing::{get, post}, Router};
use std::net::SocketAddr;
use tracing::info;
use crate::state::AppState;
use crate::api::domains;
use crate::api::backends;

/// Create the API server router with all routes
pub fn create_api_server(bind_addr: &str) -> Result<(SocketAddr, Router)> {
    // Parse the bind address
    let addr: SocketAddr = bind_addr.parse()?;

    // Create application state
    let state = AppState::new();

    // Build the router with CORS support
    let app = Router::new()
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/domains", get(domains::list_domains).post(domains::add_domain))
        .route("/api/v1/domains/:domain",
               get(domains::get_domain)
                   .put(domains::update_domain)
                   .delete(domains::delete_domain))
        .route("/api/v1/domains/:domain/switch", post(domains::switch_domain_tag))
        .route("/api/v1/backends", get(backends::list_backends).post(backends::add_backend))
        .route("/api/v1/backends/:id",
               get(backends::get_backend)
                   .put(backends::update_backend)
                   .delete(backends::delete_backend))
        .with_state(state)
        .layer(tower_http::cors::CorsLayer::permissive());

    info!("API server configured to bind on {}", addr);

    Ok((addr, app))
}

/// Run the API server
pub async fn run_api_server(addr: SocketAddr, app: Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("API server listening on {}", addr);
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

/// Basic health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_api_server_valid_addr() {
        let result = create_api_server("127.0.0.1:0");
        assert!(result.is_ok());
        let (addr, _app) = result.unwrap();
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn test_create_api_server_invalid_addr() {
        let result = create_api_server("invalid");
        assert!(result.is_err());
    }
}
