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
    let (addr, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0", state).unwrap();
    (addr.to_string(), app)
}

#[tokio::test]
async fn test_list_domains_empty() {
    let (_, app) = create_test_api_server();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/domains")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify response body is empty array
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, serde_json::json!([]));
}

#[tokio::test]
async fn test_add_domain() {
    let (_, app) = create_test_api_server();

    let body = r#"{"domain":"test.com","enabled_backends_tag":"a"}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify response body
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["domain"], "test.com");
    assert_eq!(json["enabled_backends_tag"], "a");
    assert_eq!(json["http_to_https"], true);
}

#[tokio::test]
async fn test_add_domain_duplicate() {
    let (_, app) = create_test_api_server();

    let body = r#"{"domain":"test.com","enabled_backends_tag":"a"}"#;

    // Add first domain
    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response1.status(), StatusCode::CREATED);

    // Try to add duplicate domain
    let response2 = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_domain() {
    let (_, app) = create_test_api_server();

    // First add a domain
    let body = r#"{"domain":"test.com","enabled_backends_tag":"a"}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get the domain
    let response = app
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

    // Verify response body
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["domain"], "test.com");
    assert_eq!(json["enabled_backends_tag"], "a");
}

#[tokio::test]
async fn test_get_domain_not_found() {
    let (_, app) = create_test_api_server();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/domains/nonexistent.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_domain_partial() {
    let (_, app) = create_test_api_server();

    // First add a domain
    let body = r#"{"domain":"test.com","enabled_backends_tag":"a","http_to_https":true}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Update only the tag
    let update_body = r#"{"enabled_backends_tag":"b"}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/domains/test.com")
                .header("content-type", "application/json")
                .body(Body::from(update_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify response body
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["domain"], "test.com");
    assert_eq!(json["enabled_backends_tag"], "b");
    assert_eq!(json["http_to_https"], true); // Should remain true
}

#[tokio::test]
async fn test_update_domain_not_found() {
    let (_, app) = create_test_api_server();

    let body = r#"{"enabled_backends_tag":"b"}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/domains/nonexistent.com")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_domain() {
    let (_, app) = create_test_api_server();

    // First add a domain
    let body = r#"{"domain":"test.com","enabled_backends_tag":"a"}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Delete the domain
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/domains/test.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_domain_not_found() {
    let (_, app) = create_test_api_server();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/domains/nonexistent.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_switch_domain_tag() {
    let (_, app) = create_test_api_server();

    // First add a domain
    let body = r#"{"domain":"test.com","enabled_backends_tag":"a"}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Switch the tag
    let switch_body = r#"{"new_tag":"b"}"#;
    let response = app
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

    // Verify response body
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["domain"], "test.com");
    assert_eq!(json["enabled_backends_tag"], "b");
}

#[tokio::test]
async fn test_switch_domain_tag_not_found() {
    let (_, app) = create_test_api_server();

    let body = r#"{"new_tag":"b"}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/domains/nonexistent.com/switch")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

async fn to_bytes(body: axum::body::Body) -> Result<Vec<u8>, axum::Error> {
    use http_body_util::BodyExt;
    let collected = body.collect().await?.to_bytes();
    Ok(collected.to_vec())
}
