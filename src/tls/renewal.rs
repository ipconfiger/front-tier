//! Automatic certificate renewal module

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::acme_manager::AcmeManager;
use super::certificate_manager::CertificateManager;

/// Configuration for certificate renewal
#[derive(Debug, Clone)]
pub struct RenewalConfig {
    /// How often to check for certificates needing renewal (in seconds)
    pub check_interval_secs: u64,

    /// How many days before expiration to renew certificates
    pub renewal_days_before_expiry: u64,
}

impl Default for RenewalConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 24 * 60 * 60, // Check daily
            renewal_days_before_expiry: 30,    // Renew 30 days before expiration
        }
    }
}

/// Certificate renewal manager
pub struct RenewalManager {
    /// Certificate manager for reloading certificates
    cert_manager: Arc<CertificateManager>,
    /// ACME manager for obtaining new certificates (optional)
    acme_manager: Option<Arc<AcmeManager>>,
    /// Renewal configuration
    config: RenewalConfig,
}

impl RenewalManager {
    /// Create a new renewal manager
    pub fn new(
        cert_manager: Arc<CertificateManager>,
        acme_manager: Option<Arc<AcmeManager>>,
        config: RenewalConfig,
    ) -> Self {
        Self {
            cert_manager,
            acme_manager,
            config,
        }
    }

    /// Start the renewal background task
    ///
    /// This runs in a loop, checking periodically for certificates that need renewal
    pub async fn start(&self) -> Result<()> {
        info!(
            "Starting certificate renewal manager (check interval: {}s, renewal window: {} days before expiry)",
            self.config.check_interval_secs,
            self.config.renewal_days_before_expiry
        );

        let mut timer = interval(StdDuration::from_secs(self.config.check_interval_secs));
        timer.tick().await; // Skip first immediate tick

        loop {
            timer.tick().await;

            debug!("Running certificate renewal check");

            if let Err(e) = self.check_and_renew_certificates().await {
                error!("Certificate renewal check failed: {}", e);
            }
        }
    }

    /// Check all certificates and renew those that need it
    async fn check_and_renew_certificates(&self) -> Result<()> {
        // Get all loaded certificates from certificate manager
        let certificates = self.cert_manager.get_all_certificates().await;

        let renewal_threshold = Utc::now() + Duration::days(self.config.renewal_days_before_expiry as i64);

        let mut renewed_count = 0;
        let mut failed_count = 0;

        for (domain, loaded_cert) in certificates {
            debug!(
                "Checking certificate for domain: {} (expires: {})",
                domain, loaded_cert.expires_at
            );

            // Check if certificate needs renewal
            if loaded_cert.expires_at < renewal_threshold {
                info!(
                    "Certificate for {} needs renewal (expires: {}, threshold: {})",
                    domain, loaded_cert.expires_at, renewal_threshold
                );

                match self.renew_certificate(&domain, &loaded_cert).await {
                    Ok(_) => {
                        renewed_count += 1;
                    }
                    Err(e) => {
                        error!("Failed to renew certificate for {}: {}", domain, e);
                        failed_count += 1;
                    }
                }
            } else {
                let days_until_expiry = (loaded_cert.expires_at - Utc::now()).num_days();
                debug!(
                    "Certificate for {} is valid for {} more days",
                    domain, days_until_expiry
                );
            }
        }

        if renewed_count > 0 || failed_count > 0 {
            info!(
                "Certificate renewal check complete: {} renewed, {} failed",
                renewed_count, failed_count
            );
        } else {
            debug!("Certificate renewal check complete: no certificates needed renewal");
        }

        Ok(())
    }

    /// Renew a certificate for a specific domain
    async fn renew_certificate(&self, domain: &str, current_cert: &crate::tls::certificate_manager::LoadedCertificate) -> Result<()> {
        // Check if this is a Let's Encrypt certificate
        if let Some(acme_manager) = &self.acme_manager {
            // Let's Encrypt certificates are stored in the cache directory
            // Check if the certificate path is within the cache directory
            let is_lets_encrypt_cert = current_cert.cert_path.as_ref()
                .map_or(false, |p| {
                    // Check if any parent directory name matches cache_dir
                    // This works because acme_lib stores certs in the cache_dir
                    p.contains(&acme_manager.config.cache_dir)
                });

            if is_lets_encrypt_cert {
                info!(
                    "Renewing Let's Encrypt certificate for domain: {}",
                    domain
                );

                // Obtain new certificate from Let's Encrypt
                let domains = vec![domain.to_string()];
                let (_cert_path, _key_path) = acme_manager
                    .obtain_certificate(domains)
                    .await
                    .context("Failed to obtain new certificate from Let's Encrypt")?;

                // Reload the certificate in the certificate manager
                self.cert_manager
                    .reload_certificate(domain)
                    .await
                    .context("Failed to reload renewed certificate")?;

                info!("Successfully renewed Let's Encrypt certificate for domain: {}", domain);
                return Ok(());
            }
        }

        // For file-based certificates, we can't auto-renew
        // Just warn the user to update the certificate file
        warn!(
            "Certificate for {} (file-based) needs renewal but cannot be auto-renewed. \
             Please update the certificate file manually.",
            domain
        );

        Err(anyhow::anyhow!(
            "Cannot auto-renew file-based certificate for domain: {}",
            domain
        ))
    }

    /// Calculate days until certificate expires
    pub fn days_until_expiry(&self, expires_at: DateTime<Utc>) -> i64 {
        (expires_at - Utc::now()).num_days()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renewal_config_default() {
        let config = RenewalConfig::default();
        assert_eq!(config.check_interval_secs, 24 * 60 * 60);
        assert_eq!(config.renewal_days_before_expiry, 30);
    }

    #[test]
    fn test_days_until_expiry() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let renewal_config = RenewalConfig::default();
        let renewal_manager = RenewalManager::new(cert_manager, None, renewal_config);

        let now = Utc::now();
        let future = now + Duration::days(10);

        let days = renewal_manager.days_until_expiry(future);
        // Should be approximately 10 days (may be off by 1 due to timing)
        assert!(days >= 9 && days <= 10);
    }

    #[test]
    fn test_days_until_expiry_past() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let renewal_config = RenewalConfig::default();
        let renewal_manager = RenewalManager::new(cert_manager, None, renewal_config);

        let past = Utc::now() - Duration::days(10);

        let days = renewal_manager.days_until_expiry(past);
        assert!(days < 0);
    }
}
