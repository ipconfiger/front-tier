use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::state::AppState;
use crate::observability::metrics::MetricsCollector;
use crate::tls::{certificate_manager::CertificateManager, AcmeManager};
use tracing::{info, error};

/// Certificate status information for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateStatus {
    pub domain: String,
    pub expires_at: DateTime<Utc>,
    pub days_until_expiration: i64,
    pub source: String,  // "file" or "lets_encrypt"
}

/// Response message for certificate operations
#[derive(Debug, Serialize)]
pub struct CertificateReloadResponse {
    pub message: String,
    pub domain: String,
}

/// Request to obtain a new certificate
#[derive(Debug, Serialize, Deserialize)]
pub struct ObtainCertificateRequest {
    /// Primary domain for the certificate
    pub domain: String,
    /// Optional additional domains (SANs)
    #[serde(default)]
    pub alt_names: Vec<String>,
}

/// Response after obtaining certificate
#[derive(Debug, Serialize)]
pub struct ObtainCertificateResponse {
    pub message: String,
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
    pub staging: bool,
}

/// GET /api/v1/certificates - List all certificates with their status
pub async fn list_certificates(
    State((state, _, cert_manager)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>,
) -> Result<Json<Vec<CertificateStatus>>, StatusCode> {
    // Get all loaded certificates with their expiration dates
    let expiration_dates = cert_manager.get_expiration_dates().await;

    // Get virtual hosts to determine certificate source
    let vhosts = state.virtual_hosts.read().await;

    // Build certificate status list
    let mut cert_statuses = Vec::new();

    for (domain, expires_at) in expiration_dates {
        // Calculate days until expiration
        let now = Utc::now();
        let duration = expires_at.signed_duration_since(now);
        let days_until_expiration = duration.num_days();

        // Determine certificate source from virtual host config
        let source = vhosts
            .get(&domain)
            .and_then(|vh| vh.certificate_source.as_ref())
            .map(|cert_source| match cert_source {
                crate::config::CertificateSource::File { .. } => "file".to_string(),
                crate::config::CertificateSource::LetsEncrypt => "lets_encrypt".to_string(),
            })
            .unwrap_or_else(|| "unknown".to_string());

        cert_statuses.push(CertificateStatus {
            domain,
            expires_at,
            days_until_expiration,
            source,
        });
    }

    // Sort by domain name for consistent output
    cert_statuses.sort_by(|a, b| a.domain.cmp(&b.domain));

    info!("Listed {} certificates", cert_statuses.len());
    Ok(Json(cert_statuses))
}

/// POST /api/v1/certificates/:domain/reload - Manually reload a certificate
pub async fn reload_certificate(
    State((_, _, cert_manager)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if certificate exists for this domain
    let cert_exists = cert_manager.get_certificate(&domain).await.is_some();

    if !cert_exists {
        info!("Certificate not found for domain: {}", domain);
        return Err(StatusCode::NOT_FOUND);
    }

    // Attempt to reload the certificate
    match cert_manager.reload_certificate(&domain).await {
        Ok(()) => {
            info!("Successfully reloaded certificate for domain: {}", domain);
            Ok((
                StatusCode::OK,
                Json(CertificateReloadResponse {
                    message: format!("Certificate reloaded successfully for domain: {}", domain),
                    domain,
                }),
            ))
        }
        Err(e) => {
            tracing::error!("Failed to reload certificate for domain {}: {}", domain, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /api/v1/certificates/obtain - Obtain a new certificate from Let's Encrypt
pub async fn obtain_certificate(
    State((state, _, cert_manager)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>,
    Json(req): Json<ObtainCertificateRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    info!("Certificate obtain request received for domain: {}", req.domain);

    // Check if ACME manager is available
    let acme_manager = state.acme_manager.as_ref().ok_or_else(|| {
        error!("ACME manager not configured - Let's Encrypt is not enabled");
        StatusCode::SERVICE_UNAVAILABLE
    })?;

    // Build domain list (primary + alt names)
    let mut domains = vec![req.domain.clone()];
    domains.extend(req.alt_names.clone());

    // Validate domains
    for domain in &domains {
        if domain.is_empty() || domain.contains('/') || domain.contains(':') {
            error!("Invalid domain: {}", domain);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    info!("Requesting certificate for {} domains from Let's Encrypt", domains.len());

    // Obtain certificate from Let's Encrypt
    let (cert_path, key_path) = acme_manager
        .obtain_certificate(domains.clone())
        .await
        .map_err(|e| {
            error!("Failed to obtain certificate for domains {:?}: {}", domains, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(
        "Certificate obtained successfully for {}, loading into certificate manager",
        req.domain
    );

    // Load the obtained certificate into the certificate manager
    cert_manager
        .load_certificate_from_files(&cert_path, &key_path)
        .await
        .map_err(|e| {
            error!("Failed to load obtained certificate: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!("Certificate loaded successfully for domain: {}", req.domain);

    // Check if using staging
    let staging = acme_manager.is_staging();

    Ok((
        StatusCode::OK,
        Json(ObtainCertificateResponse {
            message: format!(
                "Certificate obtained successfully for domain: {} ({} alt names)",
                req.domain,
                req.alt_names.len()
            ),
            domain: req.domain,
            cert_path,
            key_path,
            staging,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_status_serialization() {
        let status = CertificateStatus {
            domain: "example.com".to_string(),
            expires_at: Utc::now(),
            days_until_expiration: 90,
            source: "file".to_string(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&status);
        assert!(json.is_ok());
    }

    #[test]
    fn test_certificate_status_deserialization() {
        let json = r#"{
            "domain": "example.com",
            "expires_at": "2024-12-31T23:59:59Z",
            "days_until_expiration": 90,
            "source": "file"
        }"#;

        let status_result: Result<CertificateStatus, _> = serde_json::from_str(json);
        assert!(status_result.is_ok());
        let status = status_result.unwrap();
        assert_eq!(status.domain, "example.com");
        assert_eq!(status.days_until_expiration, 90);
        assert_eq!(status.source, "file");
    }

    #[test]
    fn test_obtain_certificate_request_serialization() {
        let req = ObtainCertificateRequest {
            domain: "example.com".to_string(),
            alt_names: vec!["www.example.com".to_string(), "api.example.com".to_string()],
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("www.example.com"));
        assert!(json.contains("api.example.com"));
    }

    #[test]
    fn test_obtain_certificate_request_empty_alt_names() {
        let json = r#"{"domain":"example.com","alt_names":[]}"#;

        let req: Result<ObtainCertificateRequest, _> = serde_json::from_str(json);
        assert!(req.is_ok());
        let parsed = req.unwrap();
        assert_eq!(parsed.domain, "example.com");
        assert!(parsed.alt_names.is_empty());
    }

    #[test]
    fn test_obtain_certificate_response_serialization() {
        let response = ObtainCertificateResponse {
            message: "Certificate obtained successfully".to_string(),
            domain: "example.com".to_string(),
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
            staging: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Certificate obtained successfully"));
        assert!(json.contains("true")); // staging: true
    }

    #[test]
    fn test_obtain_certificate_request_deserialization() {
        let json = r#"{
            "domain": "test.example.com",
            "alt_names": ["www.test.example.com"]
        }"#;

        let req: Result<ObtainCertificateRequest, _> = serde_json::from_str(json);
        assert!(req.is_ok());
        let parsed = req.unwrap();
        assert_eq!(parsed.domain, "test.example.com");
        assert_eq!(parsed.alt_names.len(), 1);
        assert_eq!(parsed.alt_names[0], "www.test.example.com");
    }
}
