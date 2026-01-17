use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

// Helper function to create API server with fresh state
fn create_test_api_server() -> (String, axum::Router) {
    let state = pingora_vhost::state::AppState::new();
    let (addr, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0", state).unwrap();
    (addr.to_string(), app)
}

#[tokio::test]
async fn test_list_backends_empty() {
    let (_, app) = create_test_api_server();

    let response = app
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

    // Verify response body is empty array
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, serde_json::json!([]));
}

#[tokio::test]
async fn test_add_backend() {
    let (_, app) = create_test_api_server();

    let body = r#"{"id":"backend1","address":"192.168.1.10:8080","tags":["a"]}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
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
    assert_eq!(json["id"], "backend1");
    assert_eq!(json["address"], "192.168.1.10:8080");
    assert_eq!(json["tags"], serde_json::json!(["a"]));
}

#[tokio::test]
async fn test_add_backend_duplicate() {
    let (_, app) = create_test_api_server();

    let body = r#"{"id":"backend1","address":"192.168.1.10:8080","tags":["a"]}"#;

    // Add first backend
    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response1.status(), StatusCode::CREATED);

    // Try to add duplicate backend
    let response2 = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_backend() {
    let (_, app) = create_test_api_server();

    // First add a backend
    let body = r#"{"id":"backend1","address":"192.168.1.10:8080","tags":["a"]}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get the backend
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/backends/backend1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify response body
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], "backend1");
    assert_eq!(json["address"], "192.168.1.10:8080");
    assert_eq!(json["tags"], serde_json::json!(["a"]));
}

#[tokio::test]
async fn test_get_backend_not_found() {
    let (_, app) = create_test_api_server();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/backends/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_backend_partial() {
    let (_, app) = create_test_api_server();

    // First add a backend
    let body = r#"{"id":"backend1","address":"192.168.1.10:8080","tags":["a","b"]}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Update only the address
    let update_body = r#"{"address":"192.168.1.11:9090"}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/backends/backend1")
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
    assert_eq!(json["id"], "backend1");
    assert_eq!(json["address"], "192.168.1.11:9090");
    assert_eq!(json["tags"], serde_json::json!(["a", "b"])); // Should remain unchanged
}

#[tokio::test]
async fn test_update_backend_not_found() {
    let (_, app) = create_test_api_server();

    let body = r#"{"address":"192.168.1.11:9090"}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/backends/nonexistent")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_backend() {
    let (_, app) = create_test_api_server();

    // First add a backend
    let body = r#"{"id":"backend1","address":"192.168.1.10:8080","tags":["a"]}"#;
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Delete the backend
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/backends/backend1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_backend_not_found() {
    let (_, app) = create_test_api_server();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/backends/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_backends_multiple() {
    let (_, app) = create_test_api_server();

    // Add multiple backends
    let body1 = r#"{"id":"backend1","address":"192.168.1.10:8080","tags":["a"]}"#;
    let body2 = r#"{"id":"backend2","address":"192.168.1.11:8080","tags":["b"]}"#;
    let body3 = r#"{"id":"backend3","address":"192.168.1.12:8080","tags":["a","b"]}"#;

    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/backends")
                .header("content-type", "application/json")
                .body(Body::from(body1))
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
                .body(Body::from(body2))
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
                .body(Body::from(body3))
                .unwrap(),
        )
        .await
        .unwrap();

    // List all backends
    let response = app
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

    // Verify response body
    let body = to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 3);
}

async fn to_bytes(body: axum::body::Body) -> Result<Vec<u8>, axum::Error> {
    use http_body_util::BodyExt;
    let collected = body.collect().await?.to_bytes();
    Ok(collected.to_vec())
}
