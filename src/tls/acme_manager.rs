// ACME manager for Let's Encrypt certificate automation

use anyhow::{Context, Result, anyhow};
use acme_lib::{
    create_p384_key,
    Directory, DirectoryUrl,
};
use acme_lib::order::Auth;
use acme_lib::persist::FilePersist;
use chrono::{DateTime, Duration, Utc};
use rustls::Certificate;
use rustls_pemfile::certs;
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::tls::dns_provider::DnsProvider;

/// HTTP-01 challenge data for serving challenges
#[derive(Debug, Clone)]
pub struct ChallengeData {
    /// Token from the challenge
    pub token: String,
    /// Key authorization that needs to be served
    pub key_auth: String,
    /// Domain this challenge is for
    pub domain: String,
    /// When this challenge expires
    pub expires_at: DateTime<Utc>,
}

/// Manages ACME certificate operations with Let's Encrypt
pub struct AcmeManager {
    /// Let's Encrypt configuration
    config: crate::config::LetEncryptConfig,
    /// Active challenge data (shared with HTTP challenge handler)
    challenges: Arc<RwLock<HashMap<String, ChallengeData>>>,
    /// DNS provider for DNS-01 challenges (optional)
    dns_provider: Option<Arc<dyn DnsProvider>>,
}

impl AcmeManager {
    /// Create a new ACME manager
    pub fn new(config: crate::config::LetEncryptConfig, dns_provider: Option<Arc<dyn DnsProvider>>) -> Self {
        Self {
            config,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            dns_provider,
        }
    }

    /// Determine if we should use DNS-01 or HTTP-01 challenge
    fn should_use_dns_challenge(&self) -> bool {
        self.dns_provider.is_some()
    }

    /// Get shared challenge data storage (for HTTP challenge handler)
    pub fn challenges(&self) -> Arc<RwLock<HashMap<String, ChallengeData>>> {
        Arc::clone(&self.challenges)
    }

    /// Check if using Let's Encrypt staging environment
    pub fn is_staging(&self) -> bool {
        self.config.staging
    }

    /// Get the configured email address
    pub fn email(&self) -> &str {
        &self.config.email
    }

    /// Obtain a certificate for one or more domains
    ///
    /// This performs the full ACME flow:
    /// 1. Create or load ACME account
    /// 2. Create order for domains
    /// 3. Complete HTTP-01 challenges for each domain
    /// 4. Finalize order and download certificate
    /// 5. Save certificate and key to cache_dir
    ///
    /// Returns (cert_path, key_path) on success
    pub async fn obtain_certificate(&self, domains: Vec<String>) -> Result<(String, String)> {
        if domains.is_empty() {
            anyhow::bail!("Cannot obtain certificate for empty domain list");
        }

        // Validate domains
        for domain in &domains {
            if domain.is_empty() || domain.contains('/') || domain.contains(':') {
                anyhow::bail!("Invalid domain: {}", domain);
            }
        }

        tracing::info!(
            "Obtaining Let's Encrypt certificate for domains: {:?}",
            domains
        );

        // Ensure cache directory exists
        fs::create_dir_all(&self.config.cache_dir)
            .context("Failed to create ACME cache directory")?;

        // Use FilePersist to store account key and certificates
        let persist = FilePersist::new(&self.config.cache_dir);

        // Select ACME directory URL
        let dir_url = if self.config.staging {
            tracing::info!("Using Let's Encrypt staging environment");
            DirectoryUrl::LetsEncryptStaging
        } else {
            tracing::warn!("Using Let's Encrypt production environment");
            DirectoryUrl::LetsEncrypt
        };

        // Create ACME directory
        let dir = Directory::from_url(persist, dir_url)
            .context("Failed to connect to ACME directory")?;

        // Create or load account
        let account = dir.account(&self.config.email)
            .map_err(|e| {
                tracing::error!("ACME account creation failed: {:#?}", e);
                anyhow::anyhow!("Failed to create/load ACME account: {:#}", e)
            })?;

        tracing::info!("Using ACME account with email: {}", self.config.email);

        // Create order for all domains (first is primary, rest are alt names)
        let primary = &domains[0];
        let alt_names: Vec<&str> = domains.iter().skip(1).map(|s| s.as_str()).collect();

        let mut order = account.new_order(primary, &alt_names)
            .context("Failed to create ACME order")?;

        tracing::info!("Created ACME order for {} domains", domains.len());

        // Complete challenges if needed
        let ord_csr = loop {
            // Check if we can skip to CSR (domains already authorized)
            if let Some(ord_csr) = order.confirm_validations() {
                tracing::info!("Domains already authorized, skipping challenges");
                break ord_csr;
            }

            // Get authorizations
            let auths = order.authorizations()
                .context("Failed to get authorizations")?;

            if auths.is_empty() {
                anyhow::bail!("No authorizations returned for order");
            }

            // Process each authorization
            for auth in &auths {
                self.process_authorization(&auth)
                    .await
                    .with_context(|| format!("Failed to process authorization for domain: {:?}", auth.domain_name()))?;
            }

            // Refresh order to check if validations are complete
            order.refresh()
                .context("Failed to refresh order")?;

            // Check again if we can proceed
            if let Some(ord_csr) = order.confirm_validations() {
                break ord_csr;
            }
        };

        tracing::info!("All domains authorized, finalizing certificate");

        // Create certificate private key
        let pkey_pri = create_p384_key();

        // Finalize order with CSR (polls for certificate issuance)
        let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)
            .context("Failed to finalize order")?;

        // Download certificate
        tracing::info!("Downloading certificate...");
        let _cert = ord_cert.download_and_save_cert()
            .context("Failed to download certificate")?;

        // Find certificate and key files in cache directory
        // acme_lib uses pattern: {account_id}_crt_{domain}.crt and {account_id}_key_{domain}.key
        let entries = fs::read_dir(&self.config.cache_dir)
            .context("Failed to read cache directory")?;

        let mut cert_path = None;
        let mut key_path = None;

        // Sanitize domain name for file matching (replace dots with underscores)
        let domain_escaped = primary.replace('.', "_");

        for entry in entries {
            let path = entry?.path();
            let file_name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Match certificate file: *_crt_{domain}.crt
            if file_name.contains("_crt_") && file_name.contains(&domain_escaped) && file_name.ends_with(".crt") {
                cert_path = Some(path.clone());
            }

            // Match key file: *_key_{domain}.key
            if file_name.contains("_key_") && file_name.contains(&domain_escaped) && file_name.ends_with(".key") {
                key_path = Some(path.clone());
            }
        }

        let cert_path = cert_path.ok_or_else(|| anyhow!("Certificate file not found for domain: {}", primary))?;
        let key_path = key_path.ok_or_else(|| anyhow!("Private key file not found for domain: {}", primary))?;

        tracing::info!(
            "Successfully obtained certificate for domains: {:?}",
            domains
        );

        Ok((
            cert_path.to_str().unwrap().to_string(),
            key_path.to_str().unwrap().to_string(),
        ))
    }

    /// Process a single authorization (HTTP-01 or DNS-01 challenge)
    async fn process_authorization(&self, auth: &Auth<FilePersist>) -> Result<()> {
        let domain = auth.domain_name();

        // Check if authorization is already valid
        if !auth.need_challenge() {
            tracing::info!("Authorization already valid for domain: {}", domain);
            return Ok(());
        }

        tracing::info!("Processing authorization for domain: {}", domain);

        // Choose challenge type based on configuration
        if self.should_use_dns_challenge() {
            self.process_dns01_challenge(auth, domain).await
        } else {
            self.process_http01_challenge(auth, domain).await
        }
    }

    /// Process HTTP-01 challenge
    async fn process_http01_challenge(&self, auth: &Auth<FilePersist>, domain: &str) -> Result<()> {
        let challenge = auth.http_challenge();
        let token = challenge.http_token().to_string();
        let proof = challenge.http_proof();

        tracing::info!(
            "Got HTTP-01 challenge for domain: {} (token: {})",
            domain,
            token
        );

        let challenge_data = ChallengeData {
            token: token.clone(),
            key_auth: proof.clone(),
            domain: domain.to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        self.challenges.write().await.insert(token.clone(), challenge_data);

        tracing::info!(
            "Stored challenge data for token: {} (domain: {})",
            token,
            domain
        );

        tracing::info!("Requesting HTTP-01 challenge validation for token: {}", token);
        challenge.validate(5000).context("Failed to validate HTTP-01 challenge")?;

        tracing::info!("HTTP-01 challenge validation requested successfully");
        Ok(())
    }

    /// Process DNS-01 challenge
    async fn process_dns01_challenge(&self, auth: &Auth<FilePersist>, domain: &str) -> Result<()> {
        let dns_provider = self.dns_provider.as_ref()
            .ok_or_else(|| anyhow!("DNS-01 challenge requested but no DNS provider configured"))?;

        let challenge = auth.dns_challenge();

        // Get the DNS key authorization
        let key_auth = challenge.dns_proof();

        tracing::info!(
            "Got DNS-01 challenge for domain: {} (key_auth: {})",
            domain,
            key_auth
        );

        // Create TXT record
        let acme_record = format!("_acme-challenge.{}", domain);
        tracing::info!(
            "Creating TXT record {} via {}",
            acme_record,
            dns_provider.provider_name()
        );

        dns_provider.create_txt_record(domain, &key_auth)
            .await
            .context("Failed to create TXT record")?;

        // Wait for DNS propagation
        let propagation_secs = self.config.dns_propagation_secs;
        tracing::info!("Waiting {} seconds for DNS propagation", propagation_secs);
        tokio::time::sleep(tokio::time::Duration::from_secs(propagation_secs)).await;

        // Validate challenge
        tracing::info!("Requesting DNS-01 challenge validation for domain: {}", domain);
        challenge.validate(5000).context("Failed to validate DNS-01 challenge")?;

        tracing::info!("DNS-01 challenge validation requested successfully");

        // Keep track of created TXT records for cleanup (store in a separate map)
        // We'll clean these up after certificate is obtained

        Ok(())
    }

    /// Get certificate file path for a domain
    fn cert_path(&self, domain: &str) -> PathBuf {
        PathBuf::from(&self.config.cache_dir)
            .join(format!("{}.crt.pem", domain))
    }

    /// Get private key file path for a domain
    fn key_path(&self, domain: &str) -> PathBuf {
        PathBuf::from(&self.config.cache_dir)
            .join(format!("{}.key.pem", domain))
    }

    /// Check if a certificate file exists for a domain
    pub fn certificate_exists(&self, domain: &str) -> bool {
        self.cert_path(domain).exists() && self.key_path(domain).exists()
    }

    /// Get certificate expiration date if it exists
    pub fn get_certificate_expiration(&self, domain: &str) -> Result<Option<DateTime<Utc>>> {
        let cert_path = self.cert_path(domain);

        if !cert_path.exists() {
            return Ok(None);
        }

        let cert_pem = fs::read_to_string(&cert_path)
            .context("Failed to read certificate file")?;

        let cert = Self::parse_certificate_pem(&cert_pem)?;
        let (expires_at, _) = crate::tls::certificate_manager::CertificateManager::extract_cert_info(&cert)?;

        Ok(Some(expires_at))
    }

    /// Parse PEM-encoded certificate
    fn parse_certificate_pem(pem: &str) -> Result<Certificate> {
        let mut reader = BufReader::new(pem.as_bytes());
        let cert_items = certs(&mut reader)
            .map_err(|e| anyhow!("Failed to parse PEM certificate: {}", e))?;

        if cert_items.is_empty() {
            anyhow::bail!("No certificates found in PEM data");
        }

        Ok(Certificate(cert_items[0].clone()))
    }

    /// Clean up expired challenge data
    pub async fn cleanup_expired_challenges(&self) {
        let now = Utc::now();
        let mut challenges = self.challenges.write().await;

        let expired: Vec<String> = challenges
            .iter()
            .filter(|(_, data)| data.expires_at < now)
            .map(|(token, _)| token.clone())
            .collect();

        for token in expired {
            challenges.remove(&token);
            tracing::debug!("Removed expired challenge: {}", token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> crate::config::LetEncryptConfig {
        let mut config = crate::config::LetEncryptConfig::default();
        config.email = "test@example.com".to_string();
        config.cache_dir = "/tmp/test_acme_cache".to_string();
        config
    }

    #[test]
    fn test_acme_manager_creation() {
        let config = create_test_config();
        let manager = AcmeManager::new(config, None);

        assert_eq!(manager.config.email, "test@example.com");
        assert!(manager.config.staging);
    }

    #[test]
    fn test_certificate_paths() {
        let config = create_test_config();
        let manager = AcmeManager::new(config, None);

        let cert_path = manager.cert_path("example.com");
        let key_path = manager.key_path("example.com");

        assert_eq!(
            cert_path,
            PathBuf::from("/tmp/test_acme_cache/example.com.crt.pem")
        );
        assert_eq!(
            key_path,
            PathBuf::from("/tmp/test_acme_cache/example.com.key.pem")
        );
    }

    #[test]
    fn test_certificate_exists() {
        let config = create_test_config();
        let manager = AcmeManager::new(config, None);

        // Non-existent certificate
        assert!(!manager.certificate_exists("example.com"));
    }

    #[test]
    fn test_challenge_data() {
        let challenge = ChallengeData {
            token: "test_token".to_string(),
            key_auth: "test_key_auth".to_string(),
            domain: "example.com".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };

        assert_eq!(challenge.token, "test_token");
        assert_eq!(challenge.domain, "example.com");
    }

    #[tokio::test]
    async fn test_cleanup_expired_challenges() {
        let config = create_test_config();
        let manager = AcmeManager::new(config, None);

        // Add an expired challenge
        let expired_challenge = ChallengeData {
            token: "expired_token".to_string(),
            key_auth: "test_key_auth".to_string(),
            domain: "example.com".to_string(),
            expires_at: Utc::now() - chrono::Duration::hours(1), // Expired
        };

        manager.challenges.write().await.insert(
            "expired_token".to_string(),
            expired_challenge
        );

        // Cleanup
        manager.cleanup_expired_challenges().await;

        // Verify it's removed
        assert!(!manager.challenges.read().await.contains_key("expired_token"));
    }
}
