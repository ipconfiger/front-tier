use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

// Helper function to create API server with fresh state
fn create_test_api_server() -> (String, axum::Router) {
    let state = pingora_vhost::state::AppState::new();
    let cert_manager = std::sync::Arc::new(
        pingora_vhost::tls::certificate_manager::CertificateManager::new(None)
    );
    let (addr, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0", state, cert_manager).unwrap();
    (addr.to_string(), app)
}

#[tokio::test]
async fn test_full_ab_switch_flow() {
    let (_, app) = create_test_api_server();

    // Step 1: Add a domain with tag "a"
    let domain_body = r#"{"domain":"test.com","enabled_backends_tag":"a","http_to_https":true}"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(domain_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify domain was created with tag "a"
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["domain"], "test.com");
    assert_eq!(json["enabled_backends_tag"], "a");

    // Step 2: Add backend with tag "a"
    let backend_a = r#"{"id":"backend-a1","address":"192.168.1.10:8080","tags":["a"]}"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(backend_a))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify backend was created
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], "backend-a1");
    assert_eq!(json["tags"], serde_json::json!(["a"]));

    // Step 3: Add backend with tag "b"
    let backend_b = r#"{"id":"backend-b1","address":"192.168.1.11:8080","tags":["b"]}"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(backend_b))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify backend was created
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], "backend-b1");
    assert_eq!(json["tags"], serde_json::json!(["b"]));

    // Step 4: Switch domain to tag "b"
    let switch_body = r#"{"new_tag":"b"}"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains/test.com/switch")
                .header("content-type", "application/json")
                .body(Body::from(switch_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify switch response
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["domain"], "test.com");
    assert_eq!(json["enabled_backends_tag"], "b");

    // Step 5: Verify domain now points to tag "b"
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/domains/test.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify the domain is now using tag "b"
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["domain"], "test.com");
    assert_eq!(json["enabled_backends_tag"], "b");
    assert_eq!(json["http_to_https"], true);
}

#[tokio::test]
async fn test_health_endpoint() {
    let (_, app) = create_test_api_server();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify response body is "OK"
    let body = to_bytes(response.into_body()).await.unwrap();
    assert_eq!(body, b"OK");
}

#[tokio::test]
async fn test_ab_switch_with_multiple_backends() {
    let (_, app) = create_test_api_server();

    // Add a domain
    let domain_body = r#"{"domain":"example.com","enabled_backends_tag":"group-a"}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(domain_body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Add multiple backends with tag "group-a"
    for i in 1..=3 {
        let backend = format!(r#"{{"id":"backend-a{}","address":"192.168.1.{}:8080","tags":["group-a"]}}"#, i, 10 + i);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/backends")
                    .header("content-type", "application/json")
                    .body(Body::from(backend))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    // Add multiple backends with tag "group-b"
    for i in 1..=2 {
        let backend = format!(r#"{{"id":"backend-b{}","address":"192.168.2.{}:8080","tags":["group-b"]}}"#, i, 20 + i);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/backends")
                    .header("content-type", "application/json")
                    .body(Body::from(backend))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    // Switch domain to tag "group-b"
    let switch_body = r#"{"new_tag":"group-b"}"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains/example.com/switch")
                .header("content-type", "application/json")
                .body(Body::from(switch_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify switch
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["enabled_backends_tag"], "group-b");

    // List all backends to verify both groups exist
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/backends")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn test_ab_switch_round_trip() {
    let (_, app) = create_test_api_server();

    // Add a domain with tag "a"
    let domain_body = r#"{"domain":"roundtrip.com","enabled_backends_tag":"a"}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(domain_body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Add backends for both tags
    let backend_a = r#"{"id":"backend-a","address":"192.168.1.10:8080","tags":["a"]}"#;
    let backend_b = r#"{"id":"backend-b","address":"192.168.1.11:8080","tags":["b"]}"#;

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(backend_a))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(backend_b))
                .unwrap(),
        )
        .await
        .unwrap();

    // Switch a -> b
    let switch_body = r#"{"new_tag":"b"}"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains/roundtrip.com/switch")
                .header("content-type", "application/json")
                .body(Body::from(switch_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["enabled_backends_tag"], "b");

    // Switch b -> a (round trip)
    let switch_body = r#"{"new_tag":"a"}"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains/roundtrip.com/switch")
                .header("content-type", "application/json")
                .body(Body::from(switch_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["enabled_backends_tag"], "a");

    // Verify final state
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/domains/roundtrip.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["enabled_backends_tag"], "a");
}

async fn to_bytes(body: axum::body::Body) -> Result<Vec<u8>, axum::Error> {
    let collected = body.collect().await?.to_bytes();
    Ok(collected.to_vec())
}
