use pingora_vhost::health_check::{HealthChecker, HealthStatus};
use std::time::Duration;

#[tokio::test]
async fn test_health_check_success_threshold() {
    let checker = HealthChecker::new(2, 3, Duration::from_secs(1));

    // Simulate 2 successful checks
    for _ in 0..2 {
        checker.record_success("test-backend").await;
    }

    let status = checker.get_status("test-backend").await;
    assert_eq!(status, HealthStatus::Healthy);
}

#[tokio::test]
async fn test_health_check_failure_threshold() {
    let checker = HealthChecker::new(2, 3, Duration::from_secs(1));

    // Simulate 3 failed checks
    for _ in 0..3 {
        checker.record_failure("test-backend").await;
    }

    let status = checker.get_status("test-backend").await;
    assert_eq!(status, HealthStatus::Unhealthy);
}

#[tokio::test]
async fn test_health_check_recovery() {
    let checker = HealthChecker::new(2, 3, Duration::from_secs(1));

    // Fail 3 times -> unhealthy
    for _ in 0..3 {
        checker.record_failure("test-backend").await;
    }
    assert_eq!(checker.get_status("test-backend").await, HealthStatus::Unhealthy);

    // Succeed 2 times -> healthy
    for _ in 0..2 {
        checker.record_success("test-backend").await;
    }
    assert_eq!(checker.get_status("test-backend").await, HealthStatus::Healthy);
}
