use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn test_list_domains_empty() {
    let (_, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0").unwrap();

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
}

#[tokio::test]
async fn test_add_domain() {
    let (_, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0").unwrap();

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
}
