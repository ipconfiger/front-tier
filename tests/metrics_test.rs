use pingora_vhost::observability::metrics::MetricsCollector;

#[tokio::test]
async fn test_metrics_increment() {
    let collector = MetricsCollector::new();
    collector.record_request("test.com", 200, 100.0).await;
    collector.record_request("test.com", 200, 150.0).await;

    let stats = collector.get_stats("test.com").await;
    assert_eq!(stats.total_requests, 2);
}

#[tokio::test]
async fn test_metrics_success_error_counting() {
    let collector = MetricsCollector::new();
    collector.record_request("test.com", 200, 100.0).await;
    collector.record_request("test.com", 304, 50.0).await;
    collector.record_request("test.com", 500, 200.0).await;
    collector.record_request("test.com", 404, 100.0).await;

    let stats = collector.get_stats("test.com").await;
    assert_eq!(stats.total_requests, 4);
    assert_eq!(stats.success_requests, 2); // 200 and 304
    assert_eq!(stats.error_requests, 2); // 500 and 404
}

#[tokio::test]
async fn test_metrics_average_latency() {
    let collector = MetricsCollector::new();
    collector.record_request("test.com", 200, 100.0).await;
    collector.record_request("test.com", 200, 200.0).await;
    collector.record_request("test.com", 200, 300.0).await;

    let stats = collector.get_stats("test.com").await;
    assert_eq!(stats.total_requests, 3);
    assert!((stats.avg_latency_ms - 200.0).abs() < 0.01, "Expected avg latency 200.0, got {}", stats.avg_latency_ms);
}

#[tokio::test]
async fn test_metrics_export() {
    let collector = MetricsCollector::new();
    collector.record_request("test.com", 200, 100.0).await;

    let metrics = collector.export_metrics();
    assert!(metrics.contains("proxy_requests_total"));
    assert!(metrics.contains("proxy_request_duration_ms"));
    assert!(metrics.contains("proxy_active_connections"));
}

#[tokio::test]
async fn test_metrics_empty_domain() {
    let collector = MetricsCollector::new();
    let stats = collector.get_stats("nonexistent.com").await;

    assert_eq!(stats.total_requests, 0);
    assert_eq!(stats.success_requests, 0);
    assert_eq!(stats.error_requests, 0);
    assert_eq!(stats.avg_latency_ms, 0.0);
}
