use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use rustls::{Certificate, PrivateKey};
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A loaded TLS certificate with its metadata
#[derive(Debug, Clone)]
pub struct LoadedCertificate {
    /// The parsed certificate in rustls format
    pub cert: Certificate,
    /// The parsed private key in rustls format
    pub key: PrivateKey,
    /// When this certificate expires
    pub expires_at: DateTime<Utc>,
    /// Domain names this certificate is valid for
    pub domains: Vec<String>,
    /// Path to certificate file (for hot reload)
    pub cert_path: Option<String>,
    /// Path to key file (for hot reload)
    pub key_path: Option<String>,
}

/// Manages loading and caching of TLS certificates
#[derive(Debug, Clone)]
pub struct CertificateManager {
    /// Map of domain -> loaded certificate
    certificates: Arc<RwLock<HashMap<String, LoadedCertificate>>>,
    /// Let's Encrypt configuration (for future ACME support)
    _lets_encrypt_config: Option<crate::config::LetEncryptConfig>,
}

impl CertificateManager {
    /// Create a new certificate manager
    pub fn new(lets_encrypt_config: Option<crate::config::LetEncryptConfig>) -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
            _lets_encrypt_config: lets_encrypt_config,
        }
    }

    /// Load a certificate from PEM files
    pub async fn load_certificate_from_files(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<LoadedCertificate> {
        // Read certificate file
        let cert_pem = fs::read_to_string(cert_path)
            .with_context(|| format!("Failed to read certificate file: {}", cert_path))?;

        // Read key file
        let key_pem = fs::read_to_string(key_path)
            .with_context(|| format!("Failed to read key file: {}", key_path))?;

        // Parse certificate and key
        let cert = Self::parse_certificate(&cert_pem)
            .context("Failed to parse certificate")?;

        let key = Self::parse_private_key(&key_pem)
            .context("Failed to parse private key")?;

        // Extract certificate metadata
        let (expires_at, domains) = Self::extract_cert_info(&cert)
            .context("Failed to extract certificate info")?;

        Ok(LoadedCertificate {
            cert,
            key,
            expires_at,
            domains,
            cert_path: Some(cert_path.to_string()),
            key_path: Some(key_path.to_string()),
        })
    }

    /// Parse a PEM-encoded certificate
    pub fn parse_certificate(pem: &str) -> Result<Certificate> {
        use rustls_pemfile::certs;

        let mut cert_reader = BufReader::new(pem.as_bytes());
        let cert_items = certs(&mut cert_reader)
            .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificate: {}", e))?;

        if cert_items.is_empty() {
            anyhow::bail!("No certificates found in PEM data");
        }

        // We only use the first certificate (the end-entity cert)
        Ok(Certificate(cert_items[0].clone()))
    }

    /// Parse a PEM-encoded private key (supports RSA and ECDSA)
    pub fn parse_private_key(pem: &str) -> Result<PrivateKey> {
        use rustls_pemfile::{ec_private_keys, pkcs8_private_keys, rsa_private_keys};

        // Try RSA key first
        let mut key_reader = BufReader::new(pem.as_bytes());
        let rsa_keys = rsa_private_keys(&mut key_reader)
            .map_err(|e| anyhow::anyhow!("Failed to parse RSA key: {}", e))?;

        if !rsa_keys.is_empty() {
            return Ok(PrivateKey(rsa_keys[0].clone()));
        }

        // Reset reader and try PKCS8
        let mut key_reader = BufReader::new(pem.as_bytes());
        let pkcs8_keys = pkcs8_private_keys(&mut key_reader)
            .map_err(|e| anyhow::anyhow!("Failed to parse PKCS8 key: {}", e))?;

        if !pkcs8_keys.is_empty() {
            return Ok(PrivateKey(pkcs8_keys[0].clone()));
        }

        // Reset reader and try ECDSA
        let mut key_reader = BufReader::new(pem.as_bytes());
        let ec_keys = ec_private_keys(&mut key_reader)
            .map_err(|e| anyhow::anyhow!("Failed to parse ECDSA key: {}", e))?;

        if !ec_keys.is_empty() {
            return Ok(PrivateKey(ec_keys[0].clone()));
        }

        anyhow::bail!("Failed to parse private key (tried RSA, PKCS8, ECDSA)");
    }

    /// Extract expiration date and domains from a certificate
    pub fn extract_cert_info(cert: &Certificate) -> Result<(DateTime<Utc>, Vec<String>)> {
        use x509_parser::parse_x509_certificate;

        // Parse DER-encoded certificate
        let (_, x509) = parse_x509_certificate(&cert.0)
            .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {}", e))?;

        // Extract expiration date
        let not_after = x509.validity().not_after;
        let expires_at = Self::parse_asn1_time(&not_after)?;

        // Extract domains from Common Name and Subject Alternative Names
        let mut domains = Vec::new();

        // Try to get CN (Common Name) from subject
        if let Some(cn) = x509.subject().iter_common_name().next() {
            if let Ok(cn_str) = cn.as_str() {
                domains.push(cn_str.to_string());
            }
        }

        // Extract DNS names from Subject Alternative Names extension
        let san_ext = x509
            .extensions()
            .iter()
            .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME);

        if let Some(san) = san_ext {
            let parsed = san.parsed_extension();
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san_names) =
                parsed
            {
                for name in &san_names.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                        domains.push(dns.to_string());
                    }
                }
            }
        }

        // Remove duplicates while preserving order
        domains.sort();
        domains.dedup();

        Ok((expires_at, domains))
    }

    /// Parse ASN.1 time to DateTime<Utc>
    fn parse_asn1_time(time: &x509_parser::time::ASN1Time) -> Result<DateTime<Utc>> {
        // Try Unix timestamp (x509-parser 0.15 returns i64 directly)
        let timestamp = time.timestamp();
        Utc.timestamp_opt(timestamp, 0)
            .single()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert ASN.1 time to DateTime"))
    }

    /// Load certificates for all virtual hosts
    pub async fn load_virtual_host_certificates(
        &self,
        vhosts: &[crate::config::VirtualHost],
    ) -> Result<()> {
        for vhost in vhosts {
            if !vhost.tls_enabled {
                continue;
            }

            let cert_source = vhost
                .certificate_source
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Virtual host {} has TLS enabled but no certificate source",
                        vhost.domain
                    )
                })?;

            match cert_source {
                crate::config::CertificateSource::File { cert_path, key_path } => {
                    let loaded_cert = self
                        .load_certificate_from_files(cert_path, key_path)
                        .await
                        .with_context(|| {
                            format!(
                                "Failed to load certificate for virtual host: {}",
                                vhost.domain
                            )
                        })?;

                    // Store certificate for each domain it covers
                    let mut certs = self.certificates.write().await;
                    for domain in &loaded_cert.domains {
                        certs.insert(domain.clone(), loaded_cert.clone());
                    }

                    tracing::info!(
                        "Loaded certificate for {} from {} (domains: {:?}, expires: {})",
                        vhost.domain,
                        cert_path,
                        loaded_cert.domains,
                        loaded_cert.expires_at
                    );
                }
                crate::config::CertificateSource::LetsEncrypt => {
                    tracing::warn!(
                        "Let's Encrypt certificates not yet implemented for domain: {}",
                        vhost.domain
                    );
                }
            }
        }

        Ok(())
    }

    /// Get a certificate by domain name
    pub async fn get_certificate(&self, domain: &str) -> Option<LoadedCertificate> {
        let certs = self.certificates.read().await;
        certs.get(domain).cloned()
    }

    /// Reload a certificate from disk
    pub async fn reload_certificate(&self, domain: &str) -> Result<()> {
        let (cert_path, key_path) = {
            let certs = self.certificates.read().await;
            let loaded = certs.get(domain).ok_or_else(|| {
                anyhow::anyhow!("No certificate found for domain: {}", domain)
            })?;

            (
                loaded.cert_path.clone().ok_or_else(|| {
                    anyhow::anyhow!("Certificate for {} has no file path", domain)
                })?,
                loaded.key_path.clone().ok_or_else(|| {
                    anyhow::anyhow!("Certificate for {} has no key file path", domain)
                })?,
            )
        };

        let loaded_cert = self
            .load_certificate_from_files(&cert_path, &key_path)
            .await
            .with_context(|| format!("Failed to reload certificate for domain: {}", domain))?;

        let mut certs = self.certificates.write().await;
        for d in &loaded_cert.domains {
            certs.insert(d.clone(), loaded_cert.clone());
        }

        tracing::info!(
            "Reloaded certificate for {} from {} (domains: {:?})",
            domain,
            cert_path,
            loaded_cert.domains
        );

        Ok(())
    }

    /// Get all expiration dates for monitoring
    pub async fn get_expiration_dates(&self) -> HashMap<String, DateTime<Utc>> {
        let certs = self.certificates.read().await;
        certs
            .iter()
            .map(|(domain, cert)| (domain.clone(), cert.expires_at))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_certificate() -> String {
        r#"-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUXyYHjT1vPJEbHY9V2WPxOF3IX5QwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjQwMTAxMDAwMDAwWhcNMjUw
MTAxMDAwMDAwWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B
AQEAAOIBjQAwggE8AoGBAOWnKymK3ZPJrDYdYhYxYmYgXyQY5xLwZJZ5xJxLwZJZ
5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5x
JxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
ZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJ
Z5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5
xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJx
LwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLwZJZ5xJxLw
-----END CERTIFICATE-----"#.to_string()
    }

    #[test]
    fn test_parse_invalid_certificate() {
        let invalid_pem = "NOT A PEM FILE";
        let result = CertificateManager::parse_certificate(invalid_pem);
        assert!(result.is_err(), "Should fail to parse invalid PEM");
    }

    #[test]
    fn test_parse_empty_certificate() {
        let empty_pem = "";
        let result = CertificateManager::parse_certificate(empty_pem);
        assert!(result.is_err(), "Should fail to parse empty PEM");
    }

    #[test]
    fn test_parse_invalid_private_key() {
        let invalid_key = "NOT A KEY";
        let result = CertificateManager::parse_private_key(invalid_key);
        assert!(result.is_err(), "Should fail to parse invalid key");
    }

    #[tokio::test]
    async fn test_certificate_manager_creation() {
        let manager = CertificateManager::new(None);
        // Verify manager is created successfully
        let certs = manager.certificates.read().await;
        assert_eq!(certs.len(), 0, "New manager should have no certificates");
    }

    #[tokio::test]
    async fn test_get_nonexistent_certificate() {
        let manager = CertificateManager::new(None);
        let cert = manager.get_certificate("example.com").await;
        assert!(cert.is_none(), "Should return None for non-existent domain");
    }
}
