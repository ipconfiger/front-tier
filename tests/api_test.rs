#[tokio::test]
async fn test_api_server_starts() {
    // We'll test that the API server can be created
    // Actual HTTP testing will come later
    let result = pingora_vhost::api::server::create_api_server("127.0.0.1:0");
    assert!(result.is_ok());
}
