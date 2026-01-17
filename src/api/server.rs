use anyhow::Result;
use axum::{routing::get, Router};
use std::net::SocketAddr;
use tracing::info;

/// Create the API server router with all routes
pub fn create_api_server(bind_addr: &str) -> Result<(SocketAddr, Router)> {
    // Parse the bind address
    let addr: SocketAddr = bind_addr.parse()?;

    // Build the router with CORS support
    let app = Router::new()
        .route("/api/v1/health", get(health_check))
        .layer(tower_http::cors::CorsLayer::permissive());

    info!("API server configured to bind on {}", addr);

    Ok((addr, app))
}

/// Run the API server
pub async fn run_api_server(addr: SocketAddr, app: Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("API server listening on {}", addr);
    axum::serve(listener, app).await?;
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
