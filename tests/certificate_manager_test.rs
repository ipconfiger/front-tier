// Integration tests for CertificateManager

use pingora_vhost::tls::CertificateManager;
use std::path::PathBuf;

fn get_fixture_path(filename: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/certs");
    path.push(filename);
    path.to_str().unwrap().to_string()
}

#[tokio::test]
async fn test_load_certificate_from_files() {
    let manager = CertificateManager::new(None);

    let cert_path = get_fixture_path("example.com.crt");
    let key_path = get_fixture_path("example.com.key");

    let result = manager.load_certificate_from_files(&cert_path, &key_path).await;

    assert!(result.is_ok(), "Should successfully load certificate");
    let loaded = result.unwrap();

    // Verify certificate has content
    assert!(!loaded.cert.0.is_empty(), "Certificate should not be empty");

    // Verify key has content
    assert!(!loaded.key.0.is_empty(), "Private key should not be empty");

    // Verify domains were extracted
    assert!(!loaded.domains.is_empty(), "Should have extracted domains");
    assert!(
        loaded.domains.contains(&"example.com".to_string()),
        "Should contain example.com domain"
    );
    assert!(
        loaded.domains.contains(&"www.example.com".to_string()),
        "Should contain www.example.com domain"
    );

    // Verify expiration date is in the future
    let now = chrono::Utc::now();
    assert!(
        loaded.expires_at > now,
        "Certificate should not be expired (expires: {:?}, now: {:?})",
        loaded.expires_at,
        now
    );

    // Verify file paths are stored
    assert_eq!(
        loaded.cert_path, Some(cert_path),
        "Certificate path should be stored"
    );
    assert_eq!(
        loaded.key_path, Some(key_path),
        "Key path should be stored"
    );
}

#[tokio::test]
async fn test_load_certificate_from_files_ecdsa() {
    let manager = CertificateManager::new(None);

    let cert_path = get_fixture_path("test.org.crt");
    let key_path = get_fixture_path("test.org.key");

    let result = manager.load_certificate_from_files(&cert_path, &key_path).await;

    assert!(result.is_ok(), "Should successfully load ECDSA certificate");
    let loaded = result.unwrap();

    // Verify certificate has content
    assert!(!loaded.cert.0.is_empty(), "Certificate should not be empty");

    // Verify key has content
    assert!(!loaded.key.0.is_empty(), "Private key should not be empty");

    // Verify domains were extracted
    assert!(!loaded.domains.is_empty(), "Should have extracted domains");
    assert!(
        loaded.domains.contains(&"test.org".to_string()),
        "Should contain test.org domain"
    );
    assert!(
        loaded.domains.contains(&"api.test.org".to_string()),
        "Should contain api.test.org domain"
    );
}

#[tokio::test]
async fn test_load_certificate_nonexistent_file() {
    let manager = CertificateManager::new(None);

    let result = manager
        .load_certificate_from_files("/nonexistent/cert.crt", "/nonexistent/cert.key")
        .await;

    assert!(result.is_err(), "Should fail to load nonexistent file");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Failed to read"),
        "Error should mention file reading failure"
    );
}

#[tokio::test]
async fn test_parse_certificate_rsa() {
    let cert_path = get_fixture_path("example.com.crt");
    let cert_pem = std::fs::read_to_string(cert_path).unwrap();

    let result = CertificateManager::parse_certificate(&cert_pem);

    assert!(result.is_ok(), "Should parse RSA certificate");
    let cert = result.unwrap();
    assert!(!cert.0.is_empty(), "Certificate should not be empty");
}

#[tokio::test]
async fn test_parse_certificate_ecdsa() {
    let cert_path = get_fixture_path("test.org.crt");
    let cert_pem = std::fs::read_to_string(cert_path).unwrap();

    let result = CertificateManager::parse_certificate(&cert_pem);

    assert!(result.is_ok(), "Should parse ECDSA certificate");
    let cert = result.unwrap();
    assert!(!cert.0.is_empty(), "Certificate should not be empty");
}

#[tokio::test]
async fn test_parse_private_key_rsa() {
    let key_path = get_fixture_path("example.com.key");
    let key_pem = std::fs::read_to_string(key_path).unwrap();

    let result = CertificateManager::parse_private_key(&key_pem);

    assert!(result.is_ok(), "Should parse RSA private key");
    let key = result.unwrap();
    assert!(!key.0.is_empty(), "Key should not be empty");
}

#[tokio::test]
async fn test_parse_private_key_ecdsa() {
    let key_path = get_fixture_path("test.org.key");
    let key_pem = std::fs::read_to_string(key_path).unwrap();

    let result = CertificateManager::parse_private_key(&key_pem);

    assert!(result.is_ok(), "Should parse ECDSA private key");
    let key = result.unwrap();
    assert!(!key.0.is_empty(), "Key should not be empty");
}

#[tokio::test]
async fn test_extract_cert_info_rsa() {
    let cert_path = get_fixture_path("example.com.crt");
    let cert_pem = std::fs::read_to_string(cert_path).unwrap();
    let cert = CertificateManager::parse_certificate(&cert_pem).unwrap();

    let result = CertificateManager::extract_cert_info(&cert);

    assert!(result.is_ok(), "Should extract certificate info");
    let (expires_at, domains) = result.unwrap();

    // Verify expiration date
    let now = chrono::Utc::now();
    assert!(
        expires_at > now,
        "Certificate should not be expired (expires: {:?}, now: {:?})",
        expires_at,
        now
    );

    // Verify domains
    assert!(!domains.is_empty(), "Should have at least one domain");
    assert!(
        domains.contains(&"example.com".to_string()),
        "Should contain example.com"
    );
    assert!(
        domains.contains(&"www.example.com".to_string()),
        "Should contain www.example.com"
    );
}

#[tokio::test]
async fn test_extract_cert_info_ecdsa() {
    let cert_path = get_fixture_path("test.org.crt");
    let cert_pem = std::fs::read_to_string(cert_path).unwrap();
    let cert = CertificateManager::parse_certificate(&cert_pem).unwrap();

    let result = CertificateManager::extract_cert_info(&cert);

    assert!(result.is_ok(), "Should extract certificate info");
    let (expires_at, domains) = result.unwrap();

    // Verify expiration date
    let now = chrono::Utc::now();
    assert!(
        expires_at > now,
        "Certificate should not be expired (expires: {:?}, now: {:?})",
        expires_at,
        now
    );

    // Verify domains
    assert!(!domains.is_empty(), "Should have at least one domain");
    assert!(
        domains.contains(&"test.org".to_string()),
        "Should contain test.org"
    );
    assert!(
        domains.contains(&"api.test.org".to_string()),
        "Should contain api.test.org"
    );
}

#[tokio::test]
async fn test_load_virtual_host_certificates() {
    use pingora_vhost::config::{CertificateSource, VirtualHost};

    let manager = CertificateManager::new(None);

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

    let result = manager.load_virtual_host_certificates(&vhosts).await;

    assert!(result.is_ok(), "Should load virtual host certificates");

    // Verify we can retrieve the certificate
    let cert = manager.get_certificate("example.com").await;
    assert!(cert.is_some(), "Should find certificate for example.com");

    let cert = cert.unwrap();
    assert!(
        cert.domains.contains(&"example.com".to_string()),
        "Should contain example.com domain"
    );
}

#[tokio::test]
async fn test_get_certificate() {
    use pingora_vhost::config::{CertificateSource, VirtualHost};

    let manager = CertificateManager::new(None);

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

    manager
        .load_virtual_host_certificates(&vhosts)
        .await
        .unwrap();

    // Test getting existing certificate
    let cert = manager.get_certificate("example.com").await;
    assert!(cert.is_some(), "Should find certificate for example.com");

    // Test getting non-existent certificate
    let cert = manager.get_certificate("nonexistent.com").await;
    assert!(cert.is_none(), "Should not find certificate for nonexistent.com");

    // Test getting SAN certificate
    let cert = manager.get_certificate("www.example.com").await;
    assert!(cert.is_some(), "Should find certificate for www.example.com (SAN)");
}

#[tokio::test]
async fn test_get_expiration_dates() {
    use pingora_vhost::config::{CertificateSource, VirtualHost};

    let manager = CertificateManager::new(None);

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

    manager
        .load_virtual_host_certificates(&vhosts)
        .await
        .unwrap();

    let expirations = manager.get_expiration_dates().await;

    assert!(!expirations.is_empty(), "Should have expiration dates");
    assert!(
        expirations.contains_key("example.com"),
        "Should have example.com expiration"
    );
    assert!(
        expirations.contains_key("www.example.com"),
        "Should have www.example.com expiration"
    );
    assert!(
        expirations.contains_key("test.org"),
        "Should have test.org expiration"
    );
    assert!(
        expirations.contains_key("api.test.org"),
        "Should have api.test.org expiration"
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
async fn test_reload_certificate() {
    use pingora_vhost::config::{CertificateSource, VirtualHost};

    let manager = CertificateManager::new(None);

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

    manager
        .load_virtual_host_certificates(&vhosts)
        .await
        .unwrap();

    // Get original expiration
    let original_cert = manager.get_certificate("example.com").await.unwrap();
    let original_expires = original_cert.expires_at;

    // Reload certificate
    let result = manager.reload_certificate("example.com").await;
    assert!(result.is_ok(), "Should successfully reload certificate");

    // Verify certificate still exists and is valid
    let reloaded_cert = manager.get_certificate("example.com").await;
    assert!(reloaded_cert.is_some(), "Should find certificate after reload");

    let reloaded_cert = reloaded_cert.unwrap();
    assert_eq!(
        reloaded_cert.expires_at, original_expires,
        "Expiration should match (same file)"
    );
}

#[tokio::test]
async fn test_reload_nonexistent_certificate() {
    let manager = CertificateManager::new(None);

    let result = manager.reload_certificate("nonexistent.com").await;

    assert!(result.is_err(), "Should fail to reload nonexistent certificate");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("No certificate found"),
        "Error should mention certificate not found"
    );
}
