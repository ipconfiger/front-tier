//! Pingora TLS proxy with SNI-based certificate selection and tag-based backend routing

use crate::config::Config;
use crate::state::AppState;
use crate::tls::{CertificateManager, MyProxyService, HttpRedirectService};
use anyhow::{Context, Result};
use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::listeners::TlsAcceptCallbacks;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::protocols::tls::TlsRef;
use pingora::services::Service;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use pingora_proxy::http_proxy_service;
use std::sync::Arc;
use tracing::{info, warn, error, debug};

/// Main TLS proxy server
pub struct MyProxy {
    server: Option<Server>,
    config: Config,
    state: Arc<AppState>,
    cert_manager: Arc<CertificateManager>,
}

impl MyProxy {
    /// Create a new TLS proxy instance
    pub fn new(
        config: Config,
        state: Arc<AppState>,
        cert_manager: Arc<CertificateManager>,
    ) -> Self {
        Self {
            server: None,
            config,
            state,
            cert_manager,
        }
    }

    /// Run the proxy server
    pub async fn run(&mut self) -> Result<()> {
        let mut my_server = Server::new(None)?;
        my_server.bootstrap();

        info!("Proxy server bootstrapped");

        // Load all certificates for virtual hosts
        self.load_certificates().await?;

        // Create TLS listener with SNI callback and add to server
        self.create_tls_listener(&mut my_server)?;

        // Create HTTP redirect listener (if configured) and add to server
        if self.config.proxy.listen_addr_http.is_some() {
            self.create_http_listener(&mut my_server)?;
        }

        info!(
            "Proxy server initialized: HTTPS on {}, HTTP redirect on {}",
            self.config.proxy.listen_addr,
            self.config.proxy.listen_addr_http.as_ref().map(|s| s.as_str()).unwrap_or("disabled")
        );

        // Run the server in a blocking task to avoid runtime conflicts
        // This blocks forever
        info!("Proxy server running...");
        tokio::task::spawn_blocking(move || {
            my_server.run_forever();
        }).await.unwrap();

        Ok(())
    }

    /// Load all certificates for configured virtual hosts
    async fn load_certificates(&self) -> Result<()> {
        let virtual_hosts = self.state.virtual_hosts.read().await;
        let vhosts_vec: Vec<_> = virtual_hosts.values().cloned().collect();

        drop(virtual_hosts); // Release lock before loading certs

        self.cert_manager
            .load_virtual_host_certificates(&vhosts_vec)
            .await
            .context("Failed to load virtual host certificates")?;

        info!("All virtual host certificates loaded successfully");
        Ok(())
    }

    /// Create TLS listener with SNI callback for certificate selection
    fn create_tls_listener(&self, my_server: &mut Server) -> Result<()> {
        // Create SNI callback handler
        let sni_callback = SniCallback {
            cert_manager: self.cert_manager.clone(),
        };

        // Wrap in Box for trait object
        let callbacks: TlsAcceptCallbacks = Box::new(sni_callback);

        // Create TLS settings with callbacks
        let mut tls_settings = TlsSettings::with_callbacks(callbacks)
            .context("Failed to create TLS settings with callbacks")?;

        // Enable HTTP/2 support
        tls_settings.enable_h2();

        // TLS version configuration
        // mozilla_intermediate_v5 (used by with_callbacks) already configures:
        // - Minimum TLS version: 1.2
        // - Maximum TLS version: 1.3
        // - Secure cipher suites
        // This meets the requirement of TLS 1.2 and 1.3 only

        // Create proxy service with state and cert manager
        let proxy_service = MyProxyService::new(
            self.state.clone(),
            self.cert_manager.clone(),
            self.extract_https_port(),
        );

        // Create Pingora proxy service
        let mut service =
            http_proxy_service(&my_server.configuration, proxy_service);

        // Add TLS listener
        service.add_tls_with_settings(
            &self.config.proxy.listen_addr,
            None, // SOCKS addr (not used)
            tls_settings,
        );

        info!(
            "TLS listener created on {} with SNI callback",
            self.config.proxy.listen_addr
        );

        // Add service to server
        my_server.add_service(service);

        Ok(())
    }

    /// Create HTTP redirect listener for port 80
    fn create_http_listener(&self, my_server: &mut Server) -> Result<()> {
        let http_addr = self.config.proxy.listen_addr_http.as_ref().unwrap();

        // Extract management API port for ACME challenge proxying
        let management_api_port = self.extract_management_api_port();

        // Create HTTP redirect service with management API port
        let redirect_service = HttpRedirectService::new(
            self.extract_https_port(),
            management_api_port,
        );

        // Create Pingora proxy service
        let mut service =
            http_proxy_service(&my_server.configuration, redirect_service);

        // Add TCP listener (HTTP, no TLS)
        service.add_tcp(http_addr);

        info!(
            "HTTP redirect listener created on {} with ACME challenge proxy to port {}",
            http_addr, management_api_port
        );

        // Add service to server
        my_server.add_service(service);

        Ok(())
    }

    /// Extract HTTPS port from listen_addr
    fn extract_https_port(&self) -> u16 {
        self.config
            .proxy
            .listen_addr
            .split(':')
            .last()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443)
    }

    /// Extract management API port from management_api_addr
    fn extract_management_api_port(&self) -> u16 {
        self.config
            .proxy
            .management_api_addr
            .split(':')
            .last()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080)
    }
}

/// SNI callback handler for dynamic certificate selection
struct SniCallback {
    cert_manager: Arc<CertificateManager>,
}

#[async_trait]
impl TlsAccept for SniCallback {
    /// Certificate callback - called during TLS handshake when SNI is received
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        // Get SNI hostname from TLS handshake
        let servername = match ssl.servername(pingora::tls::ssl::NameType::HOST_NAME) {
            Some(name) => name.to_string(),
            None => {
                warn!("No SNI hostname provided in TLS handshake");
                return;
            }
        };

        debug!("SNI callback received for domain: {}", servername);

        // Look up certificate for this domain
        let loaded_cert = match self.cert_manager.get_certificate(&servername).await {
            Some(cert) => cert,
            None => {
                // Try wildcard certificate lookup
                let wildcard_domain = format!("*.{}", servername.split('.').skip(1).collect::<Vec<_>>().join("."));
                if let Some(cert) = self.cert_manager.get_certificate(&wildcard_domain).await {
                    debug!("Using wildcard certificate for domain: {}", wildcard_domain);
                    cert
                } else {
                    error!("No certificate found for domain: {}", servername);
                    return;
                }
            }
        };

        // Load certificate and key from PEM
        let cert_pem = match std::fs::read_to_string(
            loaded_cert.cert_path.as_ref().expect("Certificate path should be set")
        ) {
            Ok(pem) => pem,
            Err(e) => {
                error!("Failed to read certificate file: {}", e);
                return;
            }
        };

        let key_pem = match std::fs::read_to_string(
            loaded_cert.key_path.as_ref().expect("Key path should be set")
        ) {
            Ok(pem) => pem,
            Err(e) => {
                error!("Failed to read key file: {}", e);
                return;
            }
        };

        // Parse certificate and key
        let key_bytes = key_pem.as_bytes();
        let pkey = match PKey::private_key_from_pem(key_bytes) {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to parse private key: {}", e);
                return;
            }
        };

        // Parse the first certificate (end-entity) from PEM
        let x509_cert = match X509::from_pem(cert_pem.as_bytes()) {
            Ok(cert) => cert,
            Err(e) => {
                error!("Failed to parse certificate from PEM: {}", e);
                return;
            }
        };

        debug!("Parsed end-entity certificate");

        // Set the end-entity certificate
        if let Err(e) = ext::ssl_use_certificate(ssl, &x509_cert) {
            error!("Failed to use certificate: {}", e);
            return;
        }

        // Set private key
        if let Err(e) = ext::ssl_use_private_key(ssl, &pkey) {
            error!("Failed to use private key: {}", e);
            return;
        }

        // Try to parse and add additional certificates from the PEM as chain
        // Find all certificates between BEGIN/END markers
        let cert_count = cert_pem.matches("-----BEGIN CERTIFICATE-----").count();
        debug!("Found {} certificates in PEM file", cert_count);

        if cert_count > 1 {
            // Skip the first certificate (already loaded as end-entity)
            // Find the position after the first END CERTIFICATE marker
            let first_end_pos = match cert_pem.find("-----END CERTIFICATE-----") {
                Some(pos) => pos + "-----END CERTIFICATE-----".len(),
                None => {
                    error!("Could not find END CERTIFICATE marker");
                    return;
                }
            };

            let mut search_start = first_end_pos;

            // Parse remaining certificates as intermediates
            let mut chain_index = 0;
            while search_start < cert_pem.len() {
                // Find the next certificate block
                let begin_pos = match cert_pem[search_start..].find("-----BEGIN CERTIFICATE-----") {
                    Some(pos) => search_start + pos,
                    None => break, // No more certificates
                };

                let end_pos = match cert_pem[begin_pos..].find("-----END CERTIFICATE-----") {
                    Some(pos) => begin_pos + pos + "-----END CERTIFICATE-----".len(),
                    None => {
                        error!("Found BEGIN CERTIFICATE but no END CERTIFICATE for chain cert {}", chain_index);
                        break;
                    }
                };

                let cert_pem_block = &cert_pem[begin_pos..end_pos];
                debug!("Parsing chain certificate {}: {} bytes", chain_index + 1, cert_pem_block.len());

                match X509::from_pem(cert_pem_block.as_bytes()) {
                    Ok(chain_cert) => {
                        debug!("Successfully parsed chain certificate {}", chain_index + 1);
                        if let Err(e) = ext::ssl_add_chain_cert(ssl, &chain_cert) {
                            error!("Failed to add chain certificate {}: {}", chain_index, e);
                            search_start = end_pos;
                            chain_index += 1;
                            continue;
                        }
                        info!("Added intermediate certificate {} to chain", chain_index + 1);
                    }
                    Err(e) => {
                        error!("Failed to parse chain certificate {}: {}", chain_index, e);
                    }
                }

                search_start = end_pos;
                chain_index += 1;
            }
        }

        info!("Successfully loaded certificate for domain: {}", servername);
    }

    /// Optional callback after handshake completes
    async fn handshake_complete_callback(&self, ssl: &TlsRef) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        // Optionally log handshake completion
        if let Some(servername) = ssl.servername(pingora::tls::ssl::NameType::HOST_NAME) {
            debug!("TLS handshake completed for domain: {}", servername);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VirtualHost;
    use std::collections::HashMap;

    #[test]
    fn test_extract_https_port_default() {
        let config = Config {
            proxy: crate::config::ProxyConfig {
                listen_addr: "0.0.0.0:443".to_string(),
                listen_addr_http: Some("0.0.0.0:80".to_string()),
                management_api_addr: "127.0.0.1:8080".to_string(),
            },
            lets_encrypt: None,
            logging: crate::config::LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                output: "console".to_string(),
                file_path: None,
            },
            metrics: crate::config::MetricsConfig {
                enabled: false,
                listen_addr: "0.0.0.0:9090".to_string(),
            },
            health_check: crate::config::HealthCheckConfig {
                interval_secs: 10,
                timeout_secs: 5,
                unhealthy_threshold: 3,
                healthy_threshold: 2,
            },
            virtual_hosts: vec![],
            backends: vec![],
        };

        let state = Arc::new(AppState::new());
        let cert_manager = Arc::new(CertificateManager::new(None));
        let proxy = MyProxy::new(config, state, cert_manager);

        assert_eq!(proxy.extract_https_port(), 443);
    }

    #[test]
    fn test_extract_https_port_custom() {
        let config = Config {
            proxy: crate::config::ProxyConfig {
                listen_addr: "0.0.0.0:8443".to_string(),
                listen_addr_http: Some("0.0.0.0:8080".to_string()),
                management_api_addr: "127.0.0.1:8080".to_string(),
            },
            lets_encrypt: None,
            logging: crate::config::LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                output: "console".to_string(),
                file_path: None,
            },
            metrics: crate::config::MetricsConfig {
                enabled: false,
                listen_addr: "0.0.0.0:9090".to_string(),
            },
            health_check: crate::config::HealthCheckConfig {
                interval_secs: 10,
                timeout_secs: 5,
                unhealthy_threshold: 3,
                healthy_threshold: 2,
            },
            virtual_hosts: vec![],
            backends: vec![],
        };

        let state = Arc::new(AppState::new());
        let cert_manager = Arc::new(CertificateManager::new(None));
        let proxy = MyProxy::new(config, state, cert_manager);

        assert_eq!(proxy.extract_https_port(), 8443);
    }
}
