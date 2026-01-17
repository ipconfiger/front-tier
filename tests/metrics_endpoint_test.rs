use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Method, Request};
use pingora_vhost::api::server;
use pingora_vhost::state::AppState;
use tower::ServiceExt;

#[tokio::test]
async fn test_metrics_endpoint() {
    let state = AppState::new();
    let (_addr, app) = server::create_api_server("127.0.0.1:0", state).unwrap();

    // Build a request to hit the metrics endpoint
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/metrics")
        .body(Body::empty())
        .unwrap();

    // Call the API
    let response = app.oneshot(request).await.unwrap();

    // Check that the response is OK
    assert_eq!(response.status(), 200);

    // Collect the response body
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let metrics_text = String::from_utf8(body.to_vec()).unwrap();

    // Verify the metrics contain expected content
    assert!(metrics_text.contains("proxy_requests_total"));
    assert!(metrics_text.contains("proxy_request_duration_ms"));
    assert!(metrics_text.contains("proxy_active_connections"));
}
