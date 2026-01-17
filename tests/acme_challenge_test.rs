// Integration test for ACME HTTP-01 challenge handler

use pingora_vhost::api::server;
use pingora_vhost::state::AppState;
use pingora_vhost::tls::ChallengeData;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn test_acme_challenge_endpoint_integration() {
    // Create test state with ACME challenges
    let mut state = AppState::new();

    // Add a test challenge
    let challenge = ChallengeData {
        token: "test_token_123".to_string(),
        key_auth: "test_key_authorization_value".to_string(),
        domain: "example.com".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };

    state
        .acme_challenges
        .write()
        .await
        .insert(challenge.token.clone(), challenge);

    // Create API server with test state
    let cert_manager = Arc::new(
        pingora_vhost::tls::certificate_manager::CertificateManager::new(None)
    );
    let (_addr, app) = server::create_api_server("127.0.0.1:0", state, cert_manager).unwrap();

    // Test valid challenge request
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/acme-challenge/test_token_123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify response body contains key authorization
    let body = response.into_body();
    let body_bytes = body.collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert_eq!(body_str, "test_key_authorization_value");
}

#[tokio::test]
async fn test_acme_challenge_endpoint_not_found() {
    let state = AppState::new();
    let cert_manager = Arc::new(
        pingora_vhost::tls::certificate_manager::CertificateManager::new(None)
    );
    let (_addr, app) = server::create_api_server("127.0.0.1:0", state, cert_manager).unwrap();

    // Test request for non-existent token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/acme-challenge/nonexistent_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_acme_challenge_endpoint_expired() {
    let mut state = AppState::new();

    // Add an expired challenge
    let expired_challenge = ChallengeData {
        token: "expired_token".to_string(),
        key_auth: "expired_key_auth".to_string(),
        domain: "example.com".to_string(),
        expires_at: chrono::Utc::now() - chrono::Duration::hours(1), // Expired
    };

    state
        .acme_challenges
        .write()
        .await
        .insert(expired_challenge.token.clone(), expired_challenge);

    let cert_manager = Arc::new(
        pingora_vhost::tls::certificate_manager::CertificateManager::new(None)
    );
    let (_addr, app) = server::create_api_server("127.0.0.1:0", state, cert_manager).unwrap();

    // Test request for expired token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/acme-challenge/expired_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn test_acme_challenge_content_type() {
    let mut state = AppState::new();

    let challenge = ChallengeData {
        token: "content_type_test".to_string(),
        key_auth: "test_key_auth".to_string(),
        domain: "example.com".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };

    state
        .acme_challenges
        .write()
        .await
        .insert(challenge.token.clone(), challenge);

    let cert_manager = Arc::new(
        pingora_vhost::tls::certificate_manager::CertificateManager::new(None)
    );
    let (_addr, app) = server::create_api_server("127.0.0.1:0", state, cert_manager).unwrap();

    // Test request and check Content-Type header
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/acme-challenge/content_type_test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check Content-Type header is text/plain
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    assert_eq!(content_type, Some("text/plain"));
}

#[tokio::test]
async fn test_acme_challenge_multiple_domains() {
    let mut state = AppState::new();

    // Add challenges for multiple domains
    let challenge1 = ChallengeData {
        token: "token_domain1".to_string(),
        key_auth: "key_auth_domain1".to_string(),
        domain: "domain1.example.com".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };

    let challenge2 = ChallengeData {
        token: "token_domain2".to_string(),
        key_auth: "key_auth_domain2".to_string(),
        domain: "domain2.example.com".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(2),
    };

    state
        .acme_challenges
        .write()
        .await
        .insert(challenge1.token.clone(), challenge1);
    state
        .acme_challenges
        .write()
        .await
        .insert(challenge2.token.clone(), challenge2);

    let cert_manager = Arc::new(
        pingora_vhost::tls::certificate_manager::CertificateManager::new(None)
    );
    let (_addr, app) = server::create_api_server("127.0.0.1:0", state, cert_manager).unwrap();

    // Test first challenge
    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/acme-challenge/token_domain1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::OK);
    let body1 = response1.into_body();
    let body1_bytes = body1.collect().await.unwrap().to_bytes();
    assert_eq!(
        String::from_utf8(body1_bytes.to_vec()).unwrap(),
        "key_auth_domain1"
    );

    // Test second challenge
    let response2 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/acme-challenge/token_domain2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::OK);
    let body2 = response2.into_body();
    let body2_bytes = body2.collect().await.unwrap().to_bytes();
    assert_eq!(
        String::from_utf8(body2_bytes.to_vec()).unwrap(),
        "key_auth_domain2"
    );
}
