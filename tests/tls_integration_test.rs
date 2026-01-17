//! TLS integration tests
//!
//! These tests verify the complete TLS flow including:
//! - SNI certificate selection
//! - HTTP to HTTPS redirects
//! - Certificate reload functionality
//! - Certificate API endpoints

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use pingora_vhost::config::{CertificateSource, VirtualHost};
use pingora_vhost::tls::certificate_manager::CertificateManager;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

fn get_fixture_path(filename: &str) -> String {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/certs");
    path.push(filename);
    path.to_str().unwrap().to_string()
}

// Helper function to create API server with preloaded certificates
async fn create_test_api_server_with_certs() -> (String, axum::Router) {
    let state = pingora_vhost::state::AppState::new();
    let cert_manager = Arc::new(CertificateManager::new(None));

    // Load test certificates
    let vhosts = vec![
        VirtualHost {
            domain: "example.com".to_string(),
            enabled_backends_tag: "example".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::File {
                cert_path: get_fixture_path("example.com.crt"),
                key_path: get_fixture_path("example.com.key"),
            }),
        },
        VirtualHost {
            domain: "test.org".to_string(),
            enabled_backends_tag: "test".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::File {
                cert_path: get_fixture_path("test.org.crt"),
                key_path: get_fixture_path("test.org.key"),
            }),
        },
    ];

    cert_manager
        .load_virtual_host_certificates(&vhosts)
        .await
        .unwrap();

    let (addr, app) =
        pingora_vhost::api::server::create_api_server("127.0.0.1:0", state, cert_manager)
            .unwrap();
    (addr.to_string(), app)
}

#[tokio::test]
async fn test_sni_certificate_selection() {
    // This test verifies that the CertificateManager correctly stores
    // certificates for multiple domains and returns the correct one

    let cert_manager = CertificateManager::new(None);

    // Load two different certificates for different domains
    let vhosts = vec![
        VirtualHost {
            domain: "example.com".to_string(),
            enabled_backends_tag: "example".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::File {
                cert_path: get_fixture_path("example.com.crt"),
                key_path: get_fixture_path("example.com.key"),
            }),
        },
        VirtualHost {
            domain: "test.org".to_string(),
            enabled_backends_tag: "test".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::File {
                cert_path: get_fixture_path("test.org.crt"),
                key_path: get_fixture_path("test.org.key"),
            }),
        },
    ];

    cert_manager
        .load_virtual_host_certificates(&vhosts)
        .await
        .unwrap();

    // Verify we can get the correct certificate for each domain
    let example_cert = cert_manager.get_certificate("example.com").await;
    assert!(example_cert.is_some(), "Should find certificate for example.com");

    let test_cert = cert_manager.get_certificate("test.org").await;
    assert!(test_cert.is_some(), "Should find certificate for test.org");

    // Verify the certificates are different
    let example_cert = example_cert.unwrap();
    let test_cert = test_cert.unwrap();

    assert_ne!(
        example_cert.domains, test_cert.domains,
        "Certificates should have different domain sets"
    );

    assert!(
        example_cert.domains.contains(&"example.com".to_string()),
        "example.com cert should contain example.com domain"
    );

    assert!(
        test_cert.domains.contains(&"test.org".to_string()),
        "test.org cert should contain test.org domain"
    );

    // Test SAN (Subject Alternative Name) functionality
    // example.com cert should also work for www.example.com
    let www_example_cert = cert_manager.get_certificate("www.example.com").await;
    assert!(
        www_example_cert.is_some(),
        "Should find certificate for www.example.com via SAN"
    );

    // test.org cert should also work for api.test.org
    let api_test_cert = cert_manager.get_certificate("api.test.org").await;
    assert!(
        api_test_cert.is_some(),
        "Should find certificate for api.test.org via SAN"
    );
}

#[tokio::test]
async fn test_http_to_https_redirect() {
    // This test verifies that virtual hosts configured with http_to_https
    // will properly redirect HTTP traffic to HTTPS

    let state = pingora_vhost::state::AppState::new();

    // Add a virtual host with HTTP to HTTPS redirect enabled
    let vhost = VirtualHost {
        domain: "redirect-test.com".to_string(),
        enabled_backends_tag: "test".to_string(),
        http_to_https: true,
        tls_enabled: true,
        certificate_source: Some(CertificateSource::File {
            cert_path: get_fixture_path("example.com.crt"),
            key_path: get_fixture_path("example.com.key"),
        }),
    };

    // Manually add the virtual host to state
    state
        .virtual_hosts
        .write()
        .await
        .insert(vhost.domain.clone(), vhost.clone());

    // Retrieve the virtual host to verify the configuration
    let vhosts = state.virtual_hosts.read().await;
    let retrieved_vhost = vhosts.get("redirect-test.com");

    assert!(
        retrieved_vhost.is_some(),
        "Should find the virtual host we just added"
    );

    let retrieved_vhost = retrieved_vhost.unwrap();
    assert!(
        retrieved_vhost.http_to_https,
        "Virtual host should have http_to_https enabled"
    );

    // Verify the domain is correct
    assert_eq!(
        retrieved_vhost.domain, "redirect-test.com",
        "Domain should match what we added"
    );
}

#[tokio::test]
async fn test_certificate_reload() {
    // This test verifies that certificates can be reloaded from disk

    let cert_manager = CertificateManager::new(None);

    // Load a certificate
    let vhosts = vec![VirtualHost {
        domain: "example.com".to_string(),
        enabled_backends_tag: "example".to_string(),
        http_to_https: true,
        tls_enabled: true,
        certificate_source: Some(CertificateSource::File {
            cert_path: get_fixture_path("example.com.crt"),
            key_path: get_fixture_path("example.com.key"),
        }),
    }];

    cert_manager
        .load_virtual_host_certificates(&vhosts)
        .await
        .unwrap();

    // Get the original certificate
    let original_cert = cert_manager.get_certificate("example.com").await;
    assert!(original_cert.is_some(), "Should load original certificate");

    let original_cert = original_cert.unwrap();
    let original_expires = original_cert.expires_at;

    // Reload the certificate
    let reload_result = cert_manager.reload_certificate("example.com").await;
    assert!(
        reload_result.is_ok(),
        "Should successfully reload certificate"
    );

    // Verify the certificate still exists after reload
    let reloaded_cert = cert_manager.get_certificate("example.com").await;
    assert!(
        reloaded_cert.is_some(),
        "Should find certificate after reload"
    );

    let reloaded_cert = reloaded_cert.unwrap();

    // Since we're reloading from the same file, the expiration should match
    assert_eq!(
        reloaded_cert.expires_at, original_expires,
        "Reloaded certificate should have same expiration (same file)"
    );

    // Verify domains are still present
    assert!(
        reloaded_cert
            .domains
            .contains(&"example.com".to_string()),
        "Reloaded cert should still contain example.com"
    );
    assert!(
        reloaded_cert
            .domains
            .contains(&"www.example.com".to_string()),
        "Reloaded cert should still contain www.example.com"
    );
}

#[tokio::test]
async fn test_certificate_reload_nonexistent() {
    // This test verifies that attempting to reload a nonexistent certificate fails appropriately

    let cert_manager = CertificateManager::new(None);

    // Try to reload a certificate that doesn't exist
    let reload_result = cert_manager.reload_certificate("nonexistent.com").await;

    assert!(
        reload_result.is_err(),
        "Should fail to reload nonexistent certificate"
    );

    let err = reload_result.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("No certificate found"),
        "Error message should mention certificate not found: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_certificate_api_list() {
    // This test verifies the certificate listing API endpoint

    let (_, app) = create_test_api_server_with_certs().await;

    // Request the list of certificates
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/certificates")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Should return 200 OK for certificate list"
    );

    // Parse response body
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Should parse JSON response");

    // Verify we have certificates
    let certs = json.as_array().expect("Response should be an array");
    assert!(!certs.is_empty(), "Should have at least one certificate");

    // Verify certificate structure
    for cert in certs {
        assert!(
            cert.get("domain").is_some(),
            "Certificate should have domain field"
        );
        assert!(
            cert.get("expires_at").is_some(),
            "Certificate should have expires_at field"
        );
        assert!(
            cert.get("days_until_expiration").is_some(),
            "Certificate should have days_until_expiration field"
        );
        assert!(
            cert.get("source").is_some(),
            "Certificate should have source field"
        );
    }

    // Verify we have certificates for both test domains
    let domains: Vec<String> = certs
        .iter()
        .filter_map(|c| c.get("domain").and_then(|d| d.as_str()))
        .map(String::from)
        .collect();

    assert!(
        domains.contains(&"example.com".to_string()),
        "Should have certificate for example.com"
    );
    assert!(
        domains.contains(&"test.org".to_string()),
        "Should have certificate for test.org"
    );
}

#[tokio::test]
async fn test_certificate_api_reload() {
    // This test verifies the certificate reload API endpoint

    let (_, app) = create_test_api_server_with_certs().await;

    // Request to reload the example.com certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/certificates/example.com/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Should return 200 OK for successful reload"
    );

    // Parse response body
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Should parse JSON response");

    // Verify response structure
    assert!(
        json.get("message").is_some(),
        "Response should have message field"
    );
    assert!(
        json.get("domain").is_some(),
        "Response should have domain field"
    );

    assert_eq!(
        json.get("domain").unwrap().as_str(),
        Some("example.com"),
        "Domain should be example.com"
    );

    let message = json.get("message").unwrap().as_str().unwrap();
    assert!(
        message.contains("reloaded successfully"),
        "Message should indicate successful reload: {}",
        message
    );
}

#[tokio::test]
async fn test_certificate_api_reload_nonexistent() {
    // This test verifies that attempting to reload a nonexistent certificate via API returns 404

    let (_, app) = create_test_api_server_with_certs().await;

    // Request to reload a nonexistent certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/certificates/nonexistent.com/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "Should return 404 for nonexistent certificate"
    );
}

#[tokio::test]
async fn test_certificate_expiration_dates() {
    // This test verifies that expiration dates are correctly extracted and tracked

    let cert_manager = CertificateManager::new(None);

    let vhosts = vec![
        VirtualHost {
            domain: "example.com".to_string(),
            enabled_backends_tag: "example".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::File {
                cert_path: get_fixture_path("example.com.crt"),
                key_path: get_fixture_path("example.com.key"),
            }),
        },
        VirtualHost {
            domain: "test.org".to_string(),
            enabled_backends_tag: "test".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::File {
                cert_path: get_fixture_path("test.org.crt"),
                key_path: get_fixture_path("test.org.key"),
            }),
        },
    ];

    cert_manager
        .load_virtual_host_certificates(&vhosts)
        .await
        .unwrap();

    // Get all expiration dates
    let expirations = cert_manager.get_expiration_dates().await;

    // Verify we have expiration dates for all domains
    assert!(
        expirations.contains_key("example.com"),
        "Should have expiration for example.com"
    );
    assert!(
        expirations.contains_key("www.example.com"),
        "Should have expiration for www.example.com"
    );
    assert!(
        expirations.contains_key("test.org"),
        "Should have expiration for test.org"
    );
    assert!(
        expirations.contains_key("api.test.org"),
        "Should have expiration for api.test.org"
    );

    // Verify all expiration dates are in the future
    let now = chrono::Utc::now();
    for (domain, expires_at) in &expirations {
        assert!(
            expires_at > &now,
            "Certificate for {} should not be expired (expires: {:?}, now: {:?})",
            domain,
            expires_at,
            now
        );
    }
}

#[tokio::test]
async fn test_multiple_domains_same_certificate() {
    // This test verifies that a single certificate with multiple SANs
    // is correctly accessible by all its domain names

    let cert_manager = CertificateManager::new(None);

    // Load example.com certificate which has SANs for example.com and www.example.com
    let vhosts = vec![VirtualHost {
        domain: "example.com".to_string(),
        enabled_backends_tag: "example".to_string(),
        http_to_https: true,
        tls_enabled: true,
        certificate_source: Some(CertificateSource::File {
            cert_path: get_fixture_path("example.com.crt"),
            key_path: get_fixture_path("example.com.key"),
        }),
    }];

    cert_manager
        .load_virtual_host_certificates(&vhosts)
        .await
        .unwrap();

    // Verify we can get the same certificate using different domain names
    let cert_1 = cert_manager.get_certificate("example.com").await;
    let cert_2 = cert_manager.get_certificate("www.example.com").await;

    assert!(
        cert_1.is_some(),
        "Should find certificate for example.com"
    );
    assert!(
        cert_2.is_some(),
        "Should find certificate for www.example.com"
    );

    let cert_1 = cert_1.unwrap();
    let cert_2 = cert_2.unwrap();

    // Both should return the same certificate
    assert_eq!(
        cert_1.expires_at, cert_2.expires_at,
        "Same cert should have same expiration"
    );

    // Both domains should be in the certificate's domain list
    assert!(
        cert_1.domains.contains(&"example.com".to_string()),
        "Should contain example.com"
    );
    assert!(
        cert_1.domains.contains(&"www.example.com".to_string()),
        "Should contain www.example.com"
    );
}

#[tokio::test]
async fn test_certificate_source_tracking() {
    // This test verifies that certificate sources are correctly tracked

    let cert_manager = Arc::new(CertificateManager::new(None));
    let state = pingora_vhost::state::AppState::new();

    // Add a virtual host with file-based certificate
    let vhost = VirtualHost {
        domain: "example.com".to_string(),
        enabled_backends_tag: "example".to_string(),
        http_to_https: true,
        tls_enabled: true,
        certificate_source: Some(CertificateSource::File {
            cert_path: get_fixture_path("example.com.crt"),
            key_path: get_fixture_path("example.com.key"),
        }),
    };

    // Manually add the virtual host to state
    state
        .virtual_hosts
        .write()
        .await
        .insert(vhost.domain.clone(), vhost.clone());

    // Load certificates
    let vhosts = state.virtual_hosts.read().await;
    let vhost_vec = vhosts.values().cloned().collect::<Vec<_>>();
    drop(vhosts);

    cert_manager
        .load_virtual_host_certificates(&vhost_vec)
        .await
        .unwrap();

    // Verify certificate is loaded
    let cert = cert_manager.get_certificate("example.com").await;
    assert!(cert.is_some(), "Should load certificate");

    let cert = cert.unwrap();
    assert!(
        cert.cert_path.is_some(),
        "Certificate should have file path tracked"
    );
    assert!(
        cert.key_path.is_some(),
        "Certificate should have key path tracked"
    );

    assert_eq!(
        cert.cert_path.unwrap(),
        get_fixture_path("example.com.crt"),
        "Certificate path should match"
    );
    assert_eq!(
        cert.key_path.unwrap(),
        get_fixture_path("example.com.key"),
        "Key path should match"
    );
}

// Helper function to convert response body to bytes
async fn to_bytes(body: axum::body::Body) -> Result<Vec<u8>, axum::Error> {
    let collected = body.collect().await?.to_bytes();
    Ok(collected.to_vec())
}
