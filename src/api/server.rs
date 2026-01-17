use anyhow::Result;
use axum::{routing::{get, post}, Router, response::Response, extract::State};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use crate::state::AppState;
use crate::api::domains;
use crate::api::backends;
use crate::api::certificates;
use crate::observability::metrics::MetricsCollector;
use crate::tls::{handle_acme_challenge, certificate_manager::CertificateManager};

/// Create the API server router with all routes
pub fn create_api_server(
    bind_addr: &str,
    state: AppState,
    cert_manager: Arc<CertificateManager>,
) -> Result<(SocketAddr, Router)> {
    // Parse the bind address
    let addr: SocketAddr = bind_addr.parse()?;
    let metrics = Arc::new(MetricsCollector::new());

    // Clone challenges for ACME handler
    let challenges = Arc::clone(&state.acme_challenges);

    // Build the API router with CORS support
    let api_routes = Router::new()
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
        .route("/api/v1/certificates", get(certificates::list_certificates))
        .route("/api/v1/certificates/:domain/reload", post(certificates::reload_certificate))
        .route("/api/v1/certificates/obtain", post(certificates::obtain_certificate))
        .route("/api/v1/metrics", get(metrics_handler))
        .with_state((state, metrics, cert_manager));

    // Build ACME challenge router with separate state
    let acme_routes = Router::new()
        .route("/.well-known/acme-challenge/:token", get(handle_acme_challenge))
        .with_state(challenges);

    // Combine both routers
    let app = Router::new()
        .merge(api_routes)
        .merge(acme_routes)
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

/// Prometheus metrics endpoint
async fn metrics_handler(
    State((_, metrics, _)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>
) -> Response {
    Response::new(axum::body::Body::from(metrics.export_metrics()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_api_server_valid_addr() {
        let state = AppState::new();
        let cert_manager = Arc::new(CertificateManager::new(None));
        let result = create_api_server("127.0.0.1:0", state, cert_manager);
        assert!(result.is_ok());
        let (addr, _app) = result.unwrap();
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn test_create_api_server_invalid_addr() {
        let state = AppState::new();
        let cert_manager = Arc::new(CertificateManager::new(None));
        let result = create_api_server("invalid", state, cert_manager);
        assert!(result.is_err());
    }
}
