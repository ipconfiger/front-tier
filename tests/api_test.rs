#[tokio::test]
async fn test_api_server_starts() {
    // We'll test that the API server can be created
    // Actual HTTP testing will come later
    let state = pingora_vhost::state::AppState::new();
    let cert_manager = std::sync::Arc::new(
        pingora_vhost::tls::certificate_manager::CertificateManager::new(None)
    );
    let result = pingora_vhost::api::server::create_api_server("127.0.0.1:0", state, cert_manager);
    assert!(result.is_ok());
    let (addr, _app) = result.unwrap();
    assert_eq!(addr.port(), 0);
}
