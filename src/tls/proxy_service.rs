//! Pingora proxy service with SNI-based TLS and tag-based backend routing

use crate::config::VirtualHost;
use crate::state::AppState;
use crate::tls::CertificateManager;
use async_trait::async_trait;
use pingora::prelude::*;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// TLS proxy service that routes requests based on Host header and tag-based backend selection
pub struct MyProxyService {
    /// Application state with virtual hosts, backends, and health status
    pub state: Arc<AppState>,
    /// Certificate manager for TLS certificate lookups
    pub cert_manager: Arc<CertificateManager>,
    /// HTTPS port for redirect construction
    pub https_port: u16,
}

impl MyProxyService {
    /// Create a new proxy service
    pub fn new(
        state: Arc<AppState>,
        cert_manager: Arc<CertificateManager>,
        https_port: u16,
    ) -> Self {
        Self {
            state,
            cert_manager,
            https_port,
        }
    }

    /// Select a healthy backend for the given virtual host
    async fn select_backend(
        &self,
        virtual_host: &VirtualHost,
    ) -> Result<Option<String>> {
        let backends = self.state.backends.read().await;
        let backend_health = self.state.backend_health.read().await;

        // Find all backends with the enabled tag
        let candidate_backends: Vec<&String> = backends
            .values()
            .filter(|b| b.tags.contains(&virtual_host.enabled_backends_tag))
            .map(|b| &b.id)
            .collect();

        if candidate_backends.is_empty() {
            warn!(
                "No backends found with tag '{}' for domain '{}'",
                virtual_host.enabled_backends_tag, virtual_host.domain
            );
            return Ok(None);
        }

        // Filter by health status
        let healthy_backends: Vec<&String> = candidate_backends
            .iter()
            .filter(|backend_id| {
                backend_health
                    .get(**backend_id)
                    .map(|h| h.healthy)
                    .unwrap_or(false)
            })
            .copied()
            .collect();

        if healthy_backends.is_empty() {
            // All backends are unhealthy, log warning but still return a backend
            warn!(
                "All backends with tag '{}' for domain '{}' are unhealthy, using first candidate",
                virtual_host.enabled_backends_tag, virtual_host.domain
            );
            Ok(Some(candidate_backends[0].clone()))
        } else {
            // Select first healthy backend (simple round-robin)
            // TODO: Implement proper round-robin or weighted selection
            let selected = healthy_backends[0];
            debug!(
                "Selected backend '{}' for domain '{}'",
                selected, virtual_host.domain
            );
            Ok(Some(selected.clone()))
        }
    }

    /// Get backend address by ID
    async fn get_backend_address(&self, backend_id: &str) -> Option<String> {
        let backends = self.state.backends.read().await;
        backends.get(backend_id).map(|b| b.address.clone())
    }
}

#[async_trait]
impl ProxyHttp for MyProxyService {
    /// Context type - we don't need per-request context
    type CTX = ();

    /// Create new context (unit type)
    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    /// Select upstream peer based on Host header and virtual host configuration
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Extract host from Host header (HTTP/1.1) or URI authority (HTTP/2)
        let host_header = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                // HTTP/2 uses :authority pseudo-header, which may be normalized to Host
                // Try getting from URI if Host header is missing
                session.req_header().uri.authority().map(|a| a.as_str())
            })
            .ok_or_else(|| Error::new(ErrorType::HTTPStatus(400)))?;

        // Parse host (remove port if present)
        let host = host_header
            .split(':')
            .next()
            .unwrap_or(host_header);

        debug!("Processing request for host: {}", host);

        // Look up virtual host
        let virtual_hosts = self.state.virtual_hosts.read().await;
        let virtual_host = virtual_hosts
            .get(host)
            .ok_or_else(|| {
                Error::new(ErrorType::HTTPStatus(404))
            })?;

        // Select backend based on tag and health
        let backend_id = self
            .select_backend(virtual_host)
            .await?
            .ok_or_else(|| {
                Error::new(ErrorType::HTTPStatus(503))
            })?;

        // Get backend address
        let backend_address = self
            .get_backend_address(&backend_id)
            .await
            .ok_or_else(|| {
                Error::new(ErrorType::InternalError)
            })?;

        info!(
            "Routing request for '{}' to backend '{}' at {}",
            host, backend_id, backend_address
        );

        // Create HTTP peer - backends use plain HTTP (TLS terminates at proxy)
        let peer = Box::new(HttpPeer::new(
            backend_address,
            false, // No TLS for backend connection (backends are plain HTTP)
            "".to_string(), // No SNI needed for plain HTTP
        ));

        Ok(peer)
    }

    /// Modify upstream request before sending to backend
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Set Host header to match the virtual host
        let host_header = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok());

        if let Some(host) = host_header {
            let _ = upstream_request.insert_header("Host", host);

            // Add X-Forwarded-For header
            if let Some(client_addr) = session.client_addr() {
                let _ = upstream_request.insert_header("X-Forwarded-For", client_addr.to_string());
            }

            // Add X-Forwarded-Proto header
            let _ = upstream_request.insert_header("X-Forwarded-Proto", "https");
        }

        Ok(())
    }
}

/// HTTP redirect service for port 80 -> 443
///
/// Bypasses redirect for ACME challenge requests and proxies them to management API.
pub struct HttpRedirectService {
    /// HTTPS port for redirect construction
    pub https_port: u16,
    /// Management API port for ACME challenge handling
    pub management_api_port: u16,
}

impl HttpRedirectService {
    /// Create a new HTTP redirect service
    ///
    /// # Arguments
    /// * `https_port` - HTTPS port for redirect construction
    /// * `management_api_port` - Management API port for ACME challenge proxying
    pub fn new(https_port: u16, management_api_port: u16) -> Self {
        Self {
            https_port,
            management_api_port,
        }
    }
}

#[async_trait]
impl ProxyHttp for HttpRedirectService {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    /// Return error to skip proxying
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Check if this is an ACME challenge request
        let path = session.req_header().uri.path();

        if path.starts_with("/.well-known/acme-challenge/") {
            // Proxy to management API server for challenge handling
            let peer = HttpPeer::new(
                (std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), self.management_api_port),
                false, // No TLS for local communication
                "".to_string(),
            );
            return Ok(Box::new(peer));
        }

        // Return error to prevent normal proxy flow
        // The redirect will be handled by request_filter
        Err(Error::new(ErrorType::HTTPStatus(301)))
    }

    /// Handle request before proxying - return redirect response
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // Check if this is an ACME challenge request
        let path = session.req_header().uri.path();

        if path.starts_with("/.well-known/acme-challenge/") {
            // Bypass redirect and let request proxy to management API
            // Return false to continue normal proxy flow (upstream_peer will handle it)
            info!(
                "Bypassing redirect for ACME challenge request: {}",
                path
            );
            return Ok(false);
        }

        // Normal redirect logic for non-ACME requests
        // Extract Host header
        let host_header = session
            .req_header()
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        // Parse host (remove port if present)
        let host = host_header.split(':').next().unwrap_or(host_header);

        // Construct HTTPS URL
        let query = session
            .req_header()
            .uri
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default();

        let redirect_url = format!("https://{}:{}{}{}", host, self.https_port, path, query);

        info!("Redirecting HTTP request to: {}", redirect_url);

        // Build 301 redirect response with Location header
        let mut response_header = ResponseHeader::build(301, None).unwrap();
        response_header
            .insert_header("Location", redirect_url.as_str())
            .map_err(|_| Error::new(ErrorType::InternalError))?;

        // Write response to session
        session
            .write_response_header(Box::new(response_header), true)
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;

        // Return true to indicate response was sent and proxy should exit
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Backend;
    use crate::state::BackendHealth;

    #[tokio::test]
    async fn test_select_backend_healthy() {
        let state = Arc::new(AppState::new());
        let cert_manager = Arc::new(CertificateManager::new(None));
        let service = MyProxyService::new(state.clone(), cert_manager, 443);

        // Add test backends
        let mut backends = state.backends.write().await;
        backends.insert(
            "backend1".to_string(),
            Backend {
                id: "backend1".to_string(),
                address: "127.0.0.1:8080".to_string(),
                tags: vec!["tag-a".to_string()],
            },
        );
        backends.insert(
            "backend2".to_string(),
            Backend {
                id: "backend2".to_string(),
                address: "127.0.0.1:8081".to_string(),
                tags: vec!["tag-a".to_string()],
            },
        );

        // Set health status
        let mut health = state.backend_health.write().await;
        health.insert(
            "backend1".to_string(),
            BackendHealth {
                healthy: true,
                consecutive_failures: 0,
                consecutive_successes: 5,
                last_check: None,
            },
        );
        health.insert(
            "backend2".to_string(),
            BackendHealth {
                healthy: true,
                consecutive_failures: 0,
                consecutive_successes: 3,
                last_check: None,
            },
        );

        // Test selection
        let vhost = VirtualHost {
            domain: "example.com".to_string(),
            enabled_backends_tag: "tag-a".to_string(),
            http_to_https: true,
            tls_enabled: false,
            certificate_source: None,
        };

        let selected = service.select_backend(&vhost).await.unwrap();
        assert!(selected.is_some());
        assert!(["backend1", "backend2"].contains(&selected.unwrap().as_str()));
    }

    #[tokio::test]
    async fn test_select_backend_unhealthy() {
        let state = Arc::new(AppState::new());
        let cert_manager = Arc::new(CertificateManager::new(None));
        let service = MyProxyService::new(state.clone(), cert_manager, 443);

        // Add test backend
        let mut backends = state.backends.write().await;
        backends.insert(
            "backend1".to_string(),
            Backend {
                id: "backend1".to_string(),
                address: "127.0.0.1:8080".to_string(),
                tags: vec!["tag-a".to_string()],
            },
        );

        // Set unhealthy status
        let mut health = state.backend_health.write().await;
        health.insert(
            "backend1".to_string(),
            BackendHealth {
                healthy: false,
                consecutive_failures: 5,
                consecutive_successes: 0,
                last_check: None,
            },
        );

        // Test selection - should still return backend even if unhealthy
        let vhost = VirtualHost {
            domain: "example.com".to_string(),
            enabled_backends_tag: "tag-a".to_string(),
            http_to_https: true,
            tls_enabled: false,
            certificate_source: None,
        };

        let selected = service.select_backend(&vhost).await.unwrap();
        assert!(selected.is_some());
        assert_eq!(selected.unwrap(), "backend1");
    }

    #[tokio::test]
    async fn test_select_backend_no_backends() {
        let state = Arc::new(AppState::new());
        let cert_manager = Arc::new(CertificateManager::new(None));
        let service = MyProxyService::new(state.clone(), cert_manager, 443);

        // No backends added

        let vhost = VirtualHost {
            domain: "example.com".to_string(),
            enabled_backends_tag: "tag-a".to_string(),
            http_to_https: true,
            tls_enabled: false,
            certificate_source: None,
        };

        let selected = service.select_backend(&vhost).await.unwrap();
        assert!(selected.is_none());
    }

    #[tokio::test]
    async fn test_get_backend_address() {
        let state = Arc::new(AppState::new());
        let cert_manager = Arc::new(CertificateManager::new(None));
        let service = MyProxyService::new(state.clone(), cert_manager, 443);

        // Add test backend
        let mut backends = state.backends.write().await;
        backends.insert(
            "backend1".to_string(),
            Backend {
                id: "backend1".to_string(),
                address: "192.168.1.100:9000".to_string(),
                tags: vec!["tag-a".to_string()],
            },
        );

        let address = service.get_backend_address("backend1").await;
        assert_eq!(address, Some("192.168.1.100:9000".to_string()));

        let address = service.get_backend_address("nonexistent").await;
        assert!(address.is_none());
    }
}
