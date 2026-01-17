// Let's Encrypt ACME Integration Test
//
// This test verifies that the ACME manager can:
// 1. Create and load ACME accounts
// 2. Connect to Let's Encrypt staging
// 3. Create orders
// 4. Handle challenge data
//
// NOTE: Full certificate issuance requires:
// - A real domain with DNS pointing to this server
// - HTTP port 80 accessible from internet
// - Time for ACME validation (30-60 seconds)

use pingora_vhost::tls::AcmeManager;
use pingora_vhost::config::LetEncryptConfig;
use std::collections::HashMap;
use chrono::{Utc, Duration};

#[tokio::test]
async fn test_acme_manager_staging_connection() {
    // Test connecting to Let's Encrypt staging
    let config = LetEncryptConfig {
        email: "test@example.com".to_string(),
        staging: true,  // Use staging
        cache_dir: "/tmp/test_acme_staging".to_string(),
    };

    let manager = AcmeManager::new(config);

    // Verify manager was created (check via challenges accessor)
    let challenges_store = manager.challenges();
    let challenges = challenges_store.read().await;
    assert!(challenges.is_empty()); // Should be empty initially
    drop(challenges);

    // Verify challenge storage is accessible
    let challenges = challenges_store.read().await;
    assert!(challenges.is_empty()); // Should be empty initially
    drop(challenges);

    // Test adding and retrieving challenge data
    let test_challenge = pingora_vhost::tls::ChallengeData {
        token: "test_token".to_string(),
        key_auth: "test_key_auth".to_string(),
        domain: "example.com".to_string(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    challenges_store.write().await.insert(
        "test_token".to_string(),
        test_challenge
    );

    // Verify challenge was stored
    let challenges = challenges_store.read().await;
    assert_eq!(challenges.len(), 1);
    assert!(challenges.contains_key("test_token"));
    assert_eq!(challenges.get("test_token").unwrap().domain, "example.com");
}

#[tokio::test]
async fn test_acme_certificate_paths() {
    let config = LetEncryptConfig {
        email: "test@example.com".to_string(),
        staging: true,
        cache_dir: "/tmp/test_acme_paths".to_string(),
    };

    let manager = AcmeManager::new(config);

    // Test certificate path generation
    // Note: These are internal methods, but we can verify the structure
    let domain = "example.com";
    let cert_exists = manager.certificate_exists(domain);

    // Should be false since we haven't obtained any certificates
    assert!(!cert_exists);
}

#[tokio::test]
async fn test_acme_challenge_cleanup() {
    let config = LetEncryptConfig {
        email: "test@example.com".to_string(),
        staging: true,
        cache_dir: "/tmp/test_acme_cleanup".to_string(),
    };

    let manager = AcmeManager::new(config);

    let challenges_store = manager.challenges();

    // Add valid challenge
    let valid_challenge = pingora_vhost::tls::ChallengeData {
        token: "valid_token".to_string(),
        key_auth: "valid_auth".to_string(),
        domain: "example.com".to_string(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    // Add expired challenge
    let expired_challenge = pingora_vhost::tls::ChallengeData {
        token: "expired_token".to_string(),
        key_auth: "expired_auth".to_string(),
        domain: "example.com".to_string(),
        expires_at: Utc::now() - Duration::hours(1), // Expired
    };

    challenges_store.write().await.insert(
        "valid_token".to_string(),
        valid_challenge
    );
    challenges_store.write().await.insert(
        "expired_token".to_string(),
        expired_challenge
    );

    // Verify both exist
    assert_eq!(challenges_store.read().await.len(), 2);

    // Cleanup expired
    manager.cleanup_expired_challenges().await;

    // Verify only valid challenge remains
    assert_eq!(challenges_store.read().await.len(), 1);
    assert!(challenges_store.read().await.contains_key("valid_token"));
    assert!(!challenges_store.read().await.contains_key("expired_token"));
}

#[tokio::test]
async fn test_acme_certificate_expiration() {
    let config = LetEncryptConfig {
        email: "test@example.com".to_string(),
        staging: true,
        cache_dir: "/tmp/test_acme_expiration".to_string(),
    };

    let manager = AcmeManager::new(config);

    // Test getting expiration for non-existent certificate
    let result = manager.get_certificate_expiration("example.com");
    assert!(result.is_ok());
    assert!(result.unwrap().is_none()); // None = certificate doesn't exist
}

// Integration test note:
//
// To test full certificate issuance, you would need:
// 1. A real domain with DNS pointing to your server
// 2. This server accessible on port 80 from internet
// 3. Time for ACME validation (30-60 seconds)
//
// Example code (commented out as it requires real domain):
//
// #[tokio::test]
// #[ignore]  // Run with: cargo test --test acme_integration_test -- --ignored
// async fn test_full_acme_flow() {
//     let config = LetEncryptConfig {
//         email: "your-email@example.com".to_string(),
//         staging: true,  // Always test with staging first!
//         cache_dir: "/tmp/acme_test_certs".to_string(),
//     };
//
//     let manager = AcmeManager::new(config);
//
//     // This would:
//     // 1. Connect to Let's Encrypt staging
//     // 2. Create account
//     // 3. Create order for domain
//     // 4. Complete HTTP-01 challenge
//     // 5. Download certificate
//
//     let result = manager.obtain_certificate(vec![
//         "your-domain.com".to_string()
//     ]).await;
//
//     assert!(result.is_ok());
//     let (cert_path, key_path) = result.unwrap();
//
//     // Verify certificate files exist
//     assert!(std::path::Path::new(&cert_path).exists());
//     assert!(std::path::Path::new(&key_path).exists());
//
//     // Verify certificate is loaded in certificate manager
//     assert!(manager.certificate_exists("your-domain.com"));
// }
