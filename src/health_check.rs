use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// Health status of a backend
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum HealthStatus {
    /// Backend is healthy and can receive traffic
    Healthy,
    /// Backend is unhealthy and should be excluded from routing
    Unhealthy,
    /// Backend health is unknown (initial state)
    Unknown,
}

/// Health check state for a single backend
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BackendHealthState {
    /// Current consecutive successful checks
    consecutive_successes: u32,
    /// Current consecutive failed checks
    consecutive_failures: u32,
    /// Current health status
    status: HealthStatus,
    /// Timestamp of the last health check
    last_check: DateTime<Utc>,
}

#[allow(dead_code)]
impl BackendHealthState {
    fn new() -> Self {
        Self {
            consecutive_successes: 0,
            consecutive_failures: 0,
            status: HealthStatus::Unknown,
            last_check: Utc::now(),
        }
    }

    /// Record a successful health check
    fn record_success(&mut self, healthy_threshold: u32) {
        self.consecutive_successes += 1;
        self.consecutive_failures = 0;
        self.last_check = Utc::now();

        if self.consecutive_successes >= healthy_threshold {
            self.status = HealthStatus::Healthy;
        }
    }

    /// Record a failed health check
    fn record_failure(&mut self, unhealthy_threshold: u32) {
        self.consecutive_failures += 1;
        self.consecutive_successes = 0;
        self.last_check = Utc::now();

        if self.consecutive_failures >= unhealthy_threshold {
            self.status = HealthStatus::Unhealthy;
        }
    }
}

/// Health checker for monitoring backend health
///
/// Tracks consecutive successes/failures and determines health status
/// based on configurable thresholds.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HealthChecker {
    /// Number of consecutive successes required to mark backend as healthy
    healthy_threshold: u32,
    /// Number of consecutive failures required to mark backend as unhealthy
    unhealthy_threshold: u32,
    /// Time window for health checks (not currently used, reserved for future)
    #[allow(dead_code)]
    check_interval: std::time::Duration,
    /// Health state for all tracked backends
    backends: Arc<RwLock<HashMap<String, BackendHealthState>>>,
}

#[allow(dead_code)]
impl HealthChecker {
    /// Create a new health checker
    ///
    /// # Arguments
    /// * `healthy_threshold` - Consecutive successes needed to mark healthy
    /// * `unhealthy_threshold` - Consecutive failures needed to mark unhealthy
    /// * `check_interval` - Time between health checks
    ///
    /// # Example
    /// ```no_run
    /// use pingora_vhost::health_check::HealthChecker;
    /// use std::time::Duration;
    ///
    /// let checker = HealthChecker::new(2, 3, Duration::from_secs(10));
    /// ```
    pub fn new(healthy_threshold: u32, unhealthy_threshold: u32, check_interval: std::time::Duration) -> Self {
        Self {
            healthy_threshold,
            unhealthy_threshold,
            check_interval,
            backends: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a successful health check for a backend
    ///
    /// Increments the consecutive success counter and resets the failure counter.
    /// If the success threshold is reached, the backend is marked as healthy.
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    pub async fn record_success(&self, backend_id: &str) {
        let mut backends = self.backends.write().await;
        let state = backends
            .entry(backend_id.to_string())
            .or_insert_with(BackendHealthState::new);

        state.record_success(self.healthy_threshold);
    }

    /// Record a failed health check for a backend
    ///
    /// Increments the consecutive failure counter and resets the success counter.
    /// If the failure threshold is reached, the backend is marked as unhealthy.
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    pub async fn record_failure(&self, backend_id: &str) {
        let mut backends = self.backends.write().await;
        let state = backends
            .entry(backend_id.to_string())
            .or_insert_with(BackendHealthState::new);

        state.record_failure(self.unhealthy_threshold);
    }

    /// Get the current health status of a backend
    ///
    /// Returns `Unknown` if the backend has not been tracked yet.
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    ///
    /// # Returns
    /// The current health status of the backend
    pub async fn get_status(&self, backend_id: &str) -> HealthStatus {
        let backends = self.backends.read().await;
        backends
            .get(backend_id)
            .map(|state| state.status)
            .unwrap_or(HealthStatus::Unknown)
    }

    /// Check if a backend is healthy
    ///
    /// A backend is considered healthy if it has reached the success threshold
    /// and has not reached the failure threshold.
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    ///
    /// # Returns
    /// `true` if the backend is healthy, `false` otherwise
    pub async fn is_healthy(&self, backend_id: &str) -> bool {
        self.get_status(backend_id).await == HealthStatus::Healthy
    }

    /// Get the timestamp of the last health check for a backend
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    ///
    /// # Returns
    /// The timestamp of the last check, or None if the backend has not been checked yet
    pub async fn get_last_check(&self, backend_id: &str) -> Option<DateTime<Utc>> {
        let backends = self.backends.read().await;
        backends.get(backend_id).map(|state| state.last_check)
    }

    /// Get the count of consecutive successes for a backend
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    ///
    /// # Returns
    /// The number of consecutive successes, or None if the backend has not been tracked yet
    pub async fn get_consecutive_successes(&self, backend_id: &str) -> Option<u32> {
        let backends = self.backends.read().await;
        backends.get(backend_id).map(|state| state.consecutive_successes)
    }

    /// Get the count of consecutive failures for a backend
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    ///
    /// # Returns
    /// The number of consecutive failures, or None if the backend has not been tracked yet
    pub async fn get_consecutive_failures(&self, backend_id: &str) -> Option<u32> {
        let backends = self.backends.read().await;
        backends.get(backend_id).map(|state| state.consecutive_failures)
    }

    /// Remove a backend from health tracking
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    pub async fn remove_backend(&self, backend_id: &str) {
        let mut backends = self.backends.write().await;
        backends.remove(backend_id);
    }

    /// Get all tracked backends and their health statuses
    ///
    /// # Returns
    /// A map of backend IDs to their current health status
    pub async fn get_all_statuses(&self) -> HashMap<String, HealthStatus> {
        let backends = self.backends.read().await;
        backends
            .iter()
            .map(|(id, state)| (id.clone(), state.status))
            .collect()
    }

    /// Perform an HTTP health check against a backend
    ///
    /// Makes an HTTP GET request to the backend's health endpoint and records
    /// the result as a success or failure based on the response status.
    ///
    /// # Arguments
    /// * `backend_id` - Unique identifier for the backend
    /// * `address` - Backend address (e.g., "192.168.1.100:8080")
    /// * `health_path` - Health check endpoint path (e.g., "/health")
    ///
    /// # Example
    /// ```no_run
    /// # use pingora_vhost::health_check::HealthChecker;
    /// # use std::time::Duration;
    /// # async fn example() {
    /// let checker = HealthChecker::new(2, 3, Duration::from_secs(10));
    /// checker.check_backend_http("backend-1", "192.168.1.100:8080", "/health").await;
    /// # }
    /// ```
    pub async fn check_backend_http(&self, backend_id: &str, address: &str, health_path: &str) {
        let url = format!("http://{}{}", address, health_path);

        match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(client) => {
                match client.get(&url).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            self.record_success(backend_id).await;
                        } else {
                            debug!("Backend {} returned status {}", backend_id, response.status());
                            self.record_failure(backend_id).await;
                        }
                    }
                    Err(e) => {
                        debug!("Failed to check backend {}: {}", backend_id, e);
                        self.record_failure(backend_id).await;
                    }
                }
            }
            Err(e) => {
                debug!("Failed to build HTTP client: {}", e);
                self.record_failure(backend_id).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backend_state_record_success() {
        let mut state = BackendHealthState::new();
        assert_eq!(state.status, HealthStatus::Unknown);

        // First success - still unknown (threshold is 2)
        state.record_success(2);
        assert_eq!(state.status, HealthStatus::Unknown);
        assert_eq!(state.consecutive_successes, 1);

        // Second success - becomes healthy
        state.record_success(2);
        assert_eq!(state.status, HealthStatus::Healthy);
        assert_eq!(state.consecutive_successes, 2);
    }

    #[tokio::test]
    async fn test_backend_state_record_failure() {
        let mut state = BackendHealthState::new();
        assert_eq!(state.status, HealthStatus::Unknown);

        // First failure - still unknown (threshold is 3)
        state.record_failure(3);
        assert_eq!(state.status, HealthStatus::Unknown);
        assert_eq!(state.consecutive_failures, 1);

        // Second failure - still unknown
        state.record_failure(3);
        assert_eq!(state.status, HealthStatus::Unknown);
        assert_eq!(state.consecutive_failures, 2);

        // Third failure - becomes unhealthy
        state.record_failure(3);
        assert_eq!(state.status, HealthStatus::Unhealthy);
        assert_eq!(state.consecutive_failures, 3);
    }

    #[tokio::test]
    async fn test_backend_state_reverts_on_change() {
        let mut state = BackendHealthState::new();

        // Get healthy
        state.record_success(2);
        state.record_success(2);
        assert_eq!(state.status, HealthStatus::Healthy);
        assert_eq!(state.consecutive_successes, 2);
        assert_eq!(state.consecutive_failures, 0);

        // Failure resets success counter but keeps status Healthy (not yet unhealthy)
        state.record_failure(3);
        assert_eq!(state.status, HealthStatus::Healthy); // Still healthy (threshold not reached)
        assert_eq!(state.consecutive_successes, 0); // Reset
        assert_eq!(state.consecutive_failures, 1);

        // More failures until unhealthy threshold reached
        state.record_failure(3);
        state.record_failure(3);
        assert_eq!(state.status, HealthStatus::Unhealthy); // Now unhealthy
        assert_eq!(state.consecutive_failures, 3);

        // Success resets failure counter but keeps status Unhealthy (not yet healthy)
        state.record_success(2);
        assert_eq!(state.status, HealthStatus::Unhealthy); // Still unhealthy (threshold not reached)
        assert_eq!(state.consecutive_successes, 1);
        assert_eq!(state.consecutive_failures, 0); // Reset

        // Another success makes it healthy
        state.record_success(2);
        assert_eq!(state.status, HealthStatus::Healthy);
        assert_eq!(state.consecutive_successes, 2);
    }
}
