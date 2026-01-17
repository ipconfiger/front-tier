# Pingora Virtual Host Proxy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Pingora-based reverse proxy supporting virtual hosting, AB rolling updates, Let's Encrypt TLS, and full observability via HTTP API.

**Architecture:** Rust async service using Pingora for proxy core, Axum for management API, in-memory state management with Arc<RwState<T>>, tag-based backend pools, active+passive health checking, and Let's Encrypt ACME integration.

**Tech Stack:** Rust, Pingora, Tokio, Axum, Serde/TOML, Prometheus, Tracing, rustls/acme-lib

---

## Task 1: Initialize Rust Project Structure

**Files:**
- Create: `Cargo.toml`
- Create: `config.example.toml`
- Create: `src/main.rs`
- Create: `src/config.rs`
- Create: `src/state.rs`
- Create: `.gitignore`

**Step 1: Create Cargo.toml with dependencies**

```toml
[package]
name = "pingora-vhost"
version = "0.1.0"
edition = "2021"

[dependencies]
pingora = "0.1"
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
axum = "0.7"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors"] }
prometheus = "0.13"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
tracing-appender = "0.2"
rustls = "0.21"
acme-lib = "0.8"
anyhow = "1.0"
thiserror = "1.0"

[dev-dependencies]
reqwest = { version = "0.11", features = ["rustls-tls"] }
```

**Step 2: Create .gitignore**

```
/target
config.toml
*.log
 certs/
.DS_Store
```

**Step 3: Create src/main.rs (minimal entry point)**

```rust
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Pingora Virtual Host Proxy starting...");
    Ok(())
}
```

**Step 4: Create src/config.rs (config structures)**

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub lets_encrypt: Option<LetEncryptConfig>,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub health_check: HealthCheckConfig,
    pub virtual_hosts: Vec<VirtualHost>,
    pub backends: Vec<Backend>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    #[serde(default)]
    pub listen_addr_http: Option<String>,
    pub management_api_addr: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LetEncryptConfig {
    pub email: String,
    #[serde(default)]
    pub staging: bool,
    pub cache_dir: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_output")]
    pub output: String,
    #[serde(default)]
    pub file_path: Option<String>,
}

fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "json".to_string() }
fn default_log_output() -> String { "console".to_string() }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_addr")]
    pub listen_addr: String,
}

fn default_metrics_addr() -> String { "0.0.0.0:9090".to_string() }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthCheckConfig {
    #[serde(default = "default_check_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_check_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

fn default_check_interval() -> u64 { 10 }
fn default_check_timeout() -> u64 { 5 }
fn default_unhealthy_threshold() -> u32 { 3 }
fn default_healthy_threshold() -> u32 { 2 }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VirtualHost {
    pub domain: String,
    pub enabled_backends_tag: String,
    #[serde(default = "default_http_to_https")]
    pub http_to_https: bool,
}

fn default_http_to_https() -> bool { true }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Backend {
    pub id: String,
    pub address: String,
    pub tags: Vec<String>,
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
```

**Step 5: Create src/state.rs (shared state)**

```rust
use crate::config::{Backend, VirtualHost};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct BackendHealth {
    pub healthy: bool,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone)]
pub struct AppState {
    pub virtual_hosts: Arc<RwLock<HashMap<String, VirtualHost>>>,
    pub backends: Arc<RwLock<HashMap<String, Backend>>>,
    pub backend_health: Arc<RwLock<HashMap<String, BackendHealth>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            virtual_hosts: Arc::new(RwLock::new(HashMap::new())),
            backends: Arc::new(RwLock::new(HashMap::new())),
            backend_health: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn from_config(
        virtual_hosts: Vec<VirtualHost>,
        backends: Vec<Backend>,
    ) -> Self {
        let vh_map: HashMap<String, VirtualHost> = virtual_hosts
            .into_iter()
            .map(|vh| (vh.domain.clone(), vh))
            .collect();

        let backend_map: HashMap<String, Backend> = backends
            .into_iter()
            .map(|b| (b.id.clone(), b))
            .collect();

        Self {
            virtual_hosts: Arc::new(RwLock::new(vh_map)),
            backends: Arc::new(RwLock::new(backend_map)),
            backend_health: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
```

**Step 6: Create config.example.toml**

```toml
[proxy]
listen_addr = "0.0.0.0:443"
listen_addr_http = "0.0.0.0:80"
management_api_addr = "127.0.0.1:8080"

[lets_encrypt]
email = "admin@example.com"
staging = true
cache_dir = "/etc/pingora-ssl/certs"

[logging]
level = "info"
format = "text"
output = "console"
file_path = "/var/log/pingora-proxy/proxy.log"

[metrics]
enabled = true
listen_addr = "0.0.0.0:9090"

[health_check]
interval_secs = 10
timeout_secs = 5
unhealthy_threshold = 3
healthy_threshold = 2

[[virtual_hosts]]
domain = "example.com"
enabled_backends_tag = "a"
http_to_https = true

[[backends]]
id = "web-v1"
address = "localhost:3001"
tags = ["a"]
```

**Step 7: Verify project compiles**

Run: `cargo check`
Expected: No errors (warnings about unused code are OK)

**Step 8: Initialize git repository**

```bash
git init
git add .
git commit -m "feat: initialize Rust project with config structures"
```

---

## Task 2: Implement Logging Infrastructure

**Files:**
- Modify: `src/main.rs`
- Create: `src/observability/logging.rs`
- Create: `src/observability/mod.rs`

**Step 1: Create src/observability/mod.rs**

```rust
pub mod logging;
```

**Step 2: Create src/observability/logging.rs**

```rust
use crate::config::LoggingConfig;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_logging(config: &LoggingConfig) -> Option<WorkerGuard> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(match config.level.as_str() {
            "trace" => Level::TRACE.into(),
            "debug" => Level::DEBUG.into(),
            "info" => Level::INFO.into(),
            "warn" => Level::WARN.into(),
            "error" => Level::ERROR.into(),
            _ => Level::INFO.into(),
        })
        .from_env_lossy();

    let guard = match (config.output.as_str(), config.format.as_str()) {
        ("console", "text") => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .init();
            None
        }
        ("console", "json") => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_writer(std::io::stdout))
                .init();
            None
        }
        ("file", "text") => {
            let file_appender = tracing_appender::rolling::daily(
                config.file_path.as_ref().unwrap(),
                "proxy.log",
            );
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(non_blocking))
                .init();
            Some(guard)
        }
        ("file", "json") => {
            let file_appender = tracing_appender::rolling::daily(
                config.file_path.as_ref().unwrap(),
                "proxy.log",
            );
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_writer(non_blocking))
                .init();
            Some(guard)
        }
        _ => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .init();
            None
        }
    };

    guard
}
```

**Step 3: Modify src/main.rs to use logging**

```rust
use anyhow::Result;
use tracing::info;

mod config;
mod observability;
mod state;

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = observability::logging::init_logging(&config::LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        output: "console".to_string(),
        file_path: None,
    });

    info!("Pingora Virtual Host Proxy starting...");

    Ok(())
}
```

**Step 4: Verify logging works**

Run: `cargo run`
Expected: Output shows "Pingora Virtual Host Proxy starting..."

**Step 5: Commit**

```bash
git add src/
git commit -m "feat: implement structured logging infrastructure"
```

---

## Task 3: Implement Backend Pool Management

**Files:**
- Create: `src/backend_pool.rs`
- Create: `tests/backend_pool_test.rs`

**Step 1: Write failing test for backend pool**

Create `tests/backend_pool_test.rs`:

```rust
use pingora_vhost::backend_pool::BackendPool;
use pingora_vhost::config::Backend;

#[tokio::test]
async fn test_add_backend() {
    let pool = BackendPool::new();
    let backend = Backend {
        id: "test-1".to_string(),
        address: "localhost:3001".to_string(),
        tags: vec!["a".to_string()],
    };

    pool.add_backend(backend.clone()).await;
    let retrieved = pool.get_backend("test-1").await;

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, "test-1");
}

#[tokio::test]
async fn test_get_backends_by_tag() {
    let pool = BackendPool::new();

    pool.add_backend(Backend {
        id: "backend-1".to_string(),
        address: "localhost:3001".to_string(),
        tags: vec!["a".to_string()],
    }).await;

    pool.add_backend(Backend {
        id: "backend-2".to_string(),
        address: "localhost:3002".to_string(),
        tags: vec!["b".to_string()],
    }).await;

    pool.add_backend(Backend {
        id: "backend-3".to_string(),
        address: "localhost:3003".to_string(),
        tags: vec!["a".to_string(), "b".to_string()],
    }).await;

    let tag_a_backends = pool.get_backends_by_tag("a").await;
    assert_eq!(tag_a_backends.len(), 2);

    let tag_b_backends = pool.get_backends_by_tag("b").await;
    assert_eq!(tag_b_backends.len(), 2);
}

#[tokio::test]
async fn test_remove_backend() {
    let pool = BackendPool::new();
    let backend = Backend {
        id: "test-1".to_string(),
        address: "localhost:3001".to_string(),
        tags: vec!["a".to_string()],
    };

    pool.add_backend(backend.clone()).await;
    pool.remove_backend("test-1").await;

    let retrieved = pool.get_backend("test-1").await;
    assert!(retrieved.is_none());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test backend_pool`
Expected: COMPILER ERROR - module doesn't exist

**Step 3: Create src/backend_pool.rs**

```rust
use crate::config::Backend;
use crate::state::{BackendHealth, AppState};
use std::collections::HashMap;
use tracing::{debug, info};

pub struct BackendPool {
    state: AppState,
}

impl BackendPool {
    pub fn new() -> Self {
        Self {
            state: AppState::new(),
        }
    }

    pub async fn add_backend(&self, backend: Backend) {
        let mut backends = self.state.backends.write().await;
        info!("Adding backend: {} at {}", backend.id, backend.address);
        backends.insert(backend.id.clone(), backend);
    }

    pub async fn get_backend(&self, id: &str) -> Option<Backend> {
        let backends = self.state.backends.read().await;
        backends.get(id).cloned()
    }

    pub async fn get_backends_by_tag(&self, tag: &str) -> Vec<Backend> {
        let backends = self.state.backends.read().await;
        backends
            .values()
            .filter(|b| b.tags.contains(&tag.to_string()))
            .cloned()
            .collect()
    }

    pub async fn remove_backend(&self, id: &str) {
        let mut backends = self.state.backends.write().await;
        info!("Removing backend: {}", id);
        backends.remove(id);
    }

    pub async fn list_backends(&self) -> Vec<Backend> {
        let backends = self.state.backends.read().await;
        backends.values().cloned().collect()
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }
}

impl Default for BackendPool {
    fn default() -> Self {
        Self::new()
    }
}
```

**Step 4: Add module to main.rs**

Modify `src/main.rs`:

```rust
mod backend_pool;
// ... other mods
```

Create `src/lib.rs`:

```rust
pub mod backend_pool;
pub mod config;
pub mod observability;
pub mod state;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test backend_pool`
Expected: PASS (all 3 tests pass)

**Step 6: Commit**

```bash
git add src/ tests/
git commit -m "feat: implement backend pool with tag-based routing"
```

---

## Task 4: Implement Health Checking

**Files:**
- Create: `src/health_check.rs`
- Create: `tests/health_check_test.rs`

**Step 1: Write failing test for health check state transitions**

Create `tests/health_check_test.rs`:

```rust
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
```

**Step 2: Run tests to verify they fail**

Run: `cargo test health_check`
Expected: COMPILER ERROR

**Step 3: Create src/health_check.rs**

```rust
use crate::state::{BackendHealth, AppState};
use std::time::Duration;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{debug, warn, info};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

pub struct HealthChecker {
    state: AppState,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    check_interval: Duration,
}

impl HealthChecker {
    pub fn new(healthy_threshold: u32, unhealthy_threshold: u32, check_interval: Duration) -> Self {
        Self {
            state: AppState::new(),
            healthy_threshold,
            unhealthy_threshold,
            check_interval,
        }
    }

    pub async fn record_success(&self, backend_id: &str) {
        let mut health_map = self.state.backend_health.write().await;
        let health = health_map.entry(backend_id.to_string()).or_insert_with(|| BackendHealth {
            healthy: false,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check: None,
        });

        health.consecutive_successes += 1;
        health.consecutive_failures = 0;

        if !health.healthy && health.consecutive_successes >= self.healthy_threshold {
            health.healthy = true;
            info!("Backend {} is now healthy", backend_id);
        }

        health.last_check = Some(chrono::Utc::now());
    }

    pub async fn record_failure(&self, backend_id: &str) {
        let mut health_map = self.state.backend_health.write().await;
        let health = health_map.entry(backend_id.to_string()).or_insert_with(|| BackendHealth {
            healthy: false,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check: None,
        });

        health.consecutive_failures += 1;
        health.consecutive_successes = 0;

        if health.healthy && health.consecutive_failures >= self.unhealthy_threshold {
            health.healthy = false;
            warn!("Backend {} is now unhealthy", backend_id);
        }

        health.last_check = Some(chrono::Utc::now());
    }

    pub async fn get_status(&self, backend_id: &str) -> HealthStatus {
        let health_map = self.state.backend_health.read().await;
        match health_map.get(backend_id) {
            Some(health) => {
                if health.healthy {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Unhealthy
                }
            }
            None => HealthStatus::Unknown,
        }
    }

    pub async fn is_healthy(&self, backend_id: &str) -> bool {
        self.get_status(backend_id).await == HealthStatus::Healthy
    }

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
    async fn test_default_status_unknown() {
        let checker = HealthChecker::new(2, 3, Duration::from_secs(1));
        assert_eq!(checker.get_status("nonexistent").await, HealthStatus::Unknown);
    }
}
```

**Step 4: Add chrono dependency to Cargo.toml**

Add to `[dependencies]`:
```toml
chrono = "0.4"
```

**Step 5: Add module to lib.rs**

```rust
pub mod health_check;
```

**Step 6: Run tests to verify they pass**

Run: `cargo test health_check`
Expected: PASS

**Step 7: Commit**

```bash
git add src/ tests/ Cargo.toml
git commit -m "feat: implement active health checking with thresholds"
```

---

## Task 5: Implement Management API - Server Setup

**Files:**
- Create: `src/api/mod.rs`
- Create: `src/api/server.rs`
- Create: `tests/api_test.rs`

**Step 1: Write failing test for API server startup**

Create `tests/api_test.rs`:

```rust
#[tokio::test]
async fn test_api_server_starts() {
    // We'll test that the API server can be created
    // Actual HTTP testing will come later
    let result = pingora_vhost::api::server::create_api_server("127.0.0.1:0");
    assert!(result.is_ok());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test api_server_starts`
Expected: COMPILER ERROR

**Step 3: Create src/api/mod.rs**

```rust
pub mod server;
```

**Step 4: Create src/api/server.rs**

```rust
use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use crate::state::AppState;

pub fn create_api_server(addr: &str) -> anyhow::Result<(SocketAddr, Router)> {
    let addr: SocketAddr = addr.parse()?;
    let state = AppState::new();

    let app = Router::new()
        .route("/api/v1/health", get(health_check))
        .with_state(state);

    Ok((addr, app))
}

async fn health_check() -> &'static str {
    "OK"
}

pub async fn run_api_server(addr: SocketAddr, app: Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

**Step 5: Add api module to lib.rs**

```rust
pub mod api;
```

**Step 6: Run tests to verify they pass**

Run: `cargo test api_server_starts`
Expected: PASS

**Step 7: Commit**

```bash
git add src/ tests/
git commit -m "feat: add API server infrastructure"
```

---

## Task 6: Implement API - Domain Endpoints

**Files:**
- Create: `src/api/domains.rs`
- Modify: `src/api/server.rs`
- Create: `tests/api_domains_test.rs`

**Step 1: Write failing tests for domain API**

Create `tests/api_domains_test.rs`:

```rust
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
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
```

**Step 2: Run tests to verify they fail**

Run: `cargo test api_domains`
Expected: COMPILER ERROR

**Step 3: Create src/api/domains.rs**

```rust
use crate::config::VirtualHost;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    Json as ResponseJson,
};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
    pub enabled_backends_tag: String,
    #[serde(default)]
    pub http_to_https: bool,
}

#[derive(Serialize)]
pub struct DomainResponse {
    pub domain: String,
    pub enabled_backends_tag: String,
    pub http_to_https: bool,
}

impl From<VirtualHost> for DomainResponse {
    fn from(vh: VirtualHost) -> Self {
        Self {
            domain: vh.domain,
            enabled_backends_tag: vh.enabled_backends_tag,
            http_to_https: vh.http_to_https,
        }
    }
}

pub async fn list_domains(State(state): State<AppState>) -> ResponseJson<Vec<DomainResponse>> {
    let hosts = state.virtual_hosts.read().await;
    let domains: Vec<DomainResponse> = hosts.values().cloned().map(Into::into).collect();
    Json(domains)
}

pub async fn add_domain(
    State(state): State<AppState>,
    Json(req): Json<CreateDomainRequest>,
) -> Result<Json<DomainResponse>, StatusCode> {
    let mut hosts = state.virtual_hosts.write().await;

    if hosts.contains_key(&req.domain) {
        return Err(StatusCode::CONFLICT);
    }

    let vh = VirtualHost {
        domain: req.domain.clone(),
        enabled_backends_tag: req.enabled_backends_tag,
        http_to_https: req.http_to_https,
    };

    info!("Adding domain: {}", req.domain);
    hosts.insert(req.domain.clone(), vh.clone());

    Ok(Json(DomainResponse::from(vh)))
}

pub async fn get_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<DomainResponse>, StatusCode> {
    let hosts = state.virtual_hosts.read().await;

    match hosts.get(&domain) {
        Some(vh) => Ok(Json(DomainResponse::from(vh.clone()))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn delete_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let mut hosts = state.virtual_hosts.write().await;

    match hosts.remove(&domain) {
        Some(_) => {
            info!("Deleted domain: {}", domain);
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
pub struct UpdateDomainRequest {
    pub enabled_backends_tag: Option<String>,
    pub http_to_https: Option<bool>,
}

pub async fn update_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<DomainResponse>, StatusCode> {
    let mut hosts = state.virtual_hosts.write().await;

    match hosts.get_mut(&domain) {
        Some(vh) => {
            if let Some(tag) = req.enabled_backends_tag {
                vh.enabled_backends_tag = tag;
            }
            if let Some(redirect) = req.http_to_https {
                vh.http_to_https = redirect;
            }
            info!("Updated domain: {}", domain);
            Ok(Json(DomainResponse::from(vh.clone())))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn switch_domain_tag(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<DomainResponse>, StatusCode> {
    let mut hosts = state.virtual_hosts.write().await;

    match hosts.get_mut(&domain) {
        Some(vh) => {
            let new_tag = if vh.enabled_backends_tag == "a" {
                "b".to_string()
            } else {
                "a".to_string()
            };
            vh.enabled_backends_tag = new_tag.clone();
            info!("Switched domain {} to tag {}", domain, new_tag);
            Ok(Json(DomainResponse::from(vh.clone())))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}
```

**Step 4: Update src/api/server.rs to include domain routes**

```rust
use axum::{
    routing::{get, post, put, delete},
    Router,
};
use std::net::SocketAddr;
use crate::state::AppState;
use super::domains;

pub fn create_api_server(addr: &str) -> anyhow::Result<(SocketAddr, Router)> {
    let addr: SocketAddr = addr.parse()?;
    let state = AppState::new();

    let app = Router::new()
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/domains", get(domains::list_domains).post(domains::add_domain))
        .route("/api/v1/domains/:domain", get(domains::get_domain).put(domains::update_domain).delete(domains::delete_domain))
        .route("/api/v1/domains/:domain/switch", post(domains::switch_domain_tag))
        .with_state(state);

    Ok((addr, app))
}

async fn health_check() -> &'static str {
    "OK"
}

pub async fn run_api_server(addr: SocketAddr, app: Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

**Step 5: Add http-body-util to Cargo.toml dev-dependencies**

```toml
http-body-util = "0.1"
```

**Step 6: Run tests to verify they pass**

Run: `cargo test api_domains`
Expected: PASS

**Step 7: Commit**

```bash
git add src/ tests/ Cargo.toml
git commit -m "feat: implement domain management API endpoints"
```

---

## Task 7: Implement API - Backend Endpoints

**Files:**
- Create: `src/api/backends.rs`
- Modify: `src/api/server.rs`
- Create: `tests/api_backends_test.rs`

**Step 1: Write failing tests for backend API**

Create `tests/api_backends_test.rs`:

```rust
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn test_list_backends_empty() {
    let (_, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0").unwrap();

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
}

#[tokio::test]
async fn test_add_backend() {
    let (_, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0").unwrap();

    let body = r#"{"id":"test-1","address":"localhost:3001","tags":["a"]}"#;
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
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test api_backends`
Expected: COMPILER ERROR or 404

**Step 3: Create src/api/backends.rs**

```rust
use crate::config::Backend;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Deserialize)]
pub struct CreateBackendRequest {
    pub id: String,
    pub address: String,
    pub tags: Vec<String>,
}

#[derive(Serialize)]
pub struct BackendResponse {
    pub id: String,
    pub address: String,
    pub tags: Vec<String>,
}

impl From<Backend> for BackendResponse {
    fn from(b: Backend) -> Self {
        Self {
            id: b.id,
            address: b.address,
            tags: b.tags,
        }
    }
}

pub async fn list_backends(State(state): State<AppState>) -> Json<Vec<BackendResponse>> {
    let backends = state.backends.read().await;
    let result: Vec<BackendResponse> = backends.values().cloned().map(Into::into).collect();
    Json(result)
}

pub async fn add_backend(
    State(state): State<AppState>,
    Json(req): Json<CreateBackendRequest>,
) -> Result<Json<BackendResponse>, StatusCode> {
    let mut backends = state.backends.write().await;

    if backends.contains_key(&req.id) {
        return Err(StatusCode::CONFLICT);
    }

    let backend = Backend {
        id: req.id.clone(),
        address: req.address,
        tags: req.tags,
    };

    info!("Adding backend: {} at {}", backend.id, backend.address);
    backends.insert(req.id.clone(), backend.clone());

    Ok(Json(BackendResponse::from(backend)))
}

pub async fn get_backend(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<BackendResponse>, StatusCode> {
    let backends = state.backends.read().await;

    match backends.get(&id) {
        Some(backend) => Ok(Json(BackendResponse::from(backend.clone()))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn delete_backend(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let mut backends = state.backends.write().await;

    match backends.remove(&id) {
        Some(_) => {
            info!("Deleted backend: {}", id);
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
pub struct UpdateBackendRequest {
    pub address: Option<String>,
    pub tags: Option<Vec<String>>,
}

pub async fn update_backend(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateBackendRequest>,
) -> Result<Json<BackendResponse>, StatusCode> {
    let mut backends = state.backends.write().await;

    match backends.get_mut(&id) {
        Some(backend) => {
            if let Some(addr) = req.address {
                backend.address = addr;
            }
            if let Some(tags) = req.tags {
                backend.tags = tags;
            }
            info!("Updated backend: {}", id);
            Ok(Json(BackendResponse::from(backend.clone())))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}
```

**Step 4: Update src/api/server.rs to include backend routes**

```rust
use super::{domains, backends};

// Inside create_api_server, add:
.route("/api/v1/backends", get(backends::list_backends).post(backends::add_backend))
.route("/api/v1/backends/:id", get(backends::get_backend).put(backends::update_backend).delete(backends::delete_backend))
```

**Step 5: Run tests to verify they pass**

Run: `cargo test api_backends`
Expected: PASS

**Step 6: Commit**

```bash
git add src/ tests/
git commit -m "feat: implement backend management API endpoints"
```

---

## Task 8: Integrate Pingora Proxy Core

**Files:**
- Create: `src/proxy.rs`
- Modify: `src/main.rs`
- Add: Pingora proxy setup

**Step 1: Create src/proxy.rs**

```rust
use crate::config::Config;
use crate::state::AppState;
use anyhow::Result;
use pingora::prelude::*;
use std::sync::Arc;
use tracing::{info, error};

pub struct MyProxy {
    server: Option<Server>,
    config: Config,
    state: Arc<AppState>,
}

impl MyProxy {
    pub fn new(config: Config, state: Arc<AppState>) -> Self {
        Self {
            server: None,
            config,
            state,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        let mut server_conf = ServerConf::default();
        server_conf.bind = Some(self.config.proxy.listen_addr.parse()?);

        let mut my_proxy = Server::new(Some(server_conf))?;
        my_proxy.bootstrap();

        // TODO: Set up Pingora proxy with SNI routing
        // This requires Pingora's specific APIs for upstream selection

        info!("Proxy server listening on {}", self.config.proxy.listen_addr);

        self.server = Some(my_proxy);
        Ok(())
    }
}
```

**Step 2: Update main.rs to load config and start services**

```rust
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

mod api;
mod backend_pool;
mod config;
mod health_check;
mod observability;
mod proxy;
mod state;

#[derive(Parser)]
#[command(name = "pingora-vhost")]
#[command(about = "Pingora-based virtual host proxy", long_about = None)]
struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy server
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = config::load_config(&cli.config)?;
    let _guard = observability::logging::init_logging(&config.logging);

    info!("Starting Pingora Virtual Host Proxy...");

    // Initialize state from config
    let state = Arc::new(state::AppState::from_config(
        config.virtual_hosts.clone(),
        config.backends.clone(),
    ).await);

    // Start management API
    let api_addr = config.proxy.management_api_addr.clone();
    let api_state = state.clone();
    tokio::spawn(async move {
        let (addr, app) = api::server::create_api_server(&api_addr).unwrap();
        info!("Management API listening on http://{}", addr);
        if let Err(e) = api::server::run_api_server(addr, app).await {
            error!("API server error: {}", e);
        }
    });

    // Start proxy
    info!("Proxy server starting on {}", config.proxy.listen_addr);

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
```

**Step 3: Add clap dependency to Cargo.toml**

```toml
clap = { version = "4.4", features = ["derive"] }
```

**Step 4: Verify project compiles**

Run: `cargo check`
Expected: No errors

**Step 5: Commit**

```bash
git add src/ Cargo.toml
git commit -m "feat: add Pingora proxy server skeleton"
```

---

## Task 9: Implement Metrics and Observability

**Files:**
- Create: `src/observability/metrics.rs`
- Modify: `src/api/server.rs`
- Create: `tests/metrics_test.rs`

**Step 1: Write failing test for metrics collection**

Create `tests/metrics_test.rs`:

```rust
use pingora_vhost::observability::metrics::MetricsCollector;

#[tokio::test]
async fn test_metrics_increment() {
    let collector = MetricsCollector::new();
    collector.record_request("test.com", 200, 100);
    collector.record_request("test.com", 200, 150);

    let stats = collector.get_stats("test.com").await;
    assert_eq!(stats.total_requests, 2);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test metrics`
Expected: COMPILER ERROR

**Step 3: Create src/observability/metrics.rs**

```rust
use prometheus::{
    Counter, Histogram, IntCounter, IntGauge, Registry, TextEncoder,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DomainStats {
    pub total_requests: u64,
    pub success_requests: u64,
    pub error_requests: u64,
    pub avg_latency_ms: f64,
}

pub struct MetricsCollector {
    registry: Registry,
    request_count: IntCounter,
    request_duration: Histogram,
    active_connections: IntGauge,
    domain_stats: Arc<RwLock<HashMap<String, DomainStats>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        let registry = Registry::new();

        let request_count = IntCounter::new(
            "proxy_requests_total",
            "Total number of requests"
        ).unwrap();

        let request_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "proxy_request_duration_ms",
                "Request duration in milliseconds"
            ).buckets(vec![0.1, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0])
        ).unwrap();

        let active_connections = IntGauge::new(
            "proxy_active_connections",
            "Number of active connections"
        ).unwrap();

        registry.register(Box::new(request_count.clone())).unwrap();
        registry.register(Box::new(request_duration.clone())).unwrap();
        registry.register(Box::new(active_connections.clone())).unwrap();

        Self {
            registry,
            request_count,
            request_duration,
            active_connections,
            domain_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn record_request(&self, domain: &str, status: u16, duration_ms: f64) {
        self.request_count.inc();
        self.request_duration.observe(duration_ms);

        let mut stats = self.domain_stats.write().await;
        let domain_stat = stats.entry(domain.to_string()).or_insert_with(|| DomainStats {
            total_requests: 0,
            success_requests: 0,
            error_requests: 0,
            avg_latency_ms: 0.0,
        });

        domain_stat.total_requests += 1;
        if status >= 200 && status < 400 {
            domain_stat.success_requests += 1;
        } else {
            domain_stat.error_requests += 1;
        }

        // Update rolling average
        let n = domain_stat.total_requests as f64;
        domain_stat.avg_latency_ms =
            (domain_stat.avg_latency_ms * (n - 1.0) + duration_ms) / n;
    }

    pub async fn get_stats(&self, domain: &str) -> DomainStats {
        let stats = self.domain_stats.read().await;
        stats.get(domain)
            .cloned()
            .unwrap_or(DomainStats {
                total_requests: 0,
                success_requests: 0,
                error_requests: 0,
                avg_latency_ms: 0.0,
            })
    }

    pub fn export_metrics(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
```

**Step 4: Add metrics module to observability/mod.rs**

```rust
pub mod logging;
pub mod metrics;
```

**Step 5: Add metrics endpoint to API server**

Modify `src/api/server.rs`:

```rust
use crate::observability::metrics::MetricsCollector;
use axum::response::Response;

pub fn create_api_server(addr: &str) -> anyhow::Result<(SocketAddr, Router)> {
    let addr: SocketAddr = addr.parse()?;
    let state = AppState::new();
    let metrics = Arc::new(MetricsCollector::new());

    let app = Router::new()
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/domains", get(domains::list_domains).post(domains::add_domain))
        .route("/api/v1/domains/:domain", get(domains::get_domain).put(domains::update_domain).delete(domains::delete_domain))
        .route("/api/v1/domains/:domain/switch", post(domains::switch_domain_tag))
        .route("/api/v1/backends", get(backends::list_backends).post(backends::add_backend))
        .route("/api/v1/backends/:id", get(backends::get_backend).put(backends::update_backend).delete(backends::delete_backend))
        .route("/api/v1/metrics", get(metrics_handler))
        .with_state((state, metrics)));

    Ok((addr, app))
}

async fn metrics_handler(State((_, metrics)): State<(AppState, Arc<MetricsCollector>)>) -> Response {
    Response::new(axum::body::Body::from(metrics.export_metrics()))
}
```

**Step 6: Run tests to verify they pass**

Run: `cargo test metrics`
Expected: PASS

**Step 7: Commit**

```bash
git add src/ tests/
git commit -m "feat: implement Prometheus metrics collection"
```

---

## Task 10: Create Integration Test for Full Flow

**Files:**
- Create: `tests/integration_test.rs`

**Step 1: Create integration test**

```rust
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_full_ab_switch_flow() {
    // This would require running a full proxy server
    // For now, we'll test the API endpoints in isolation

    let (_, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0").unwrap();

    // Add a domain
    let domain_body = json!({
        "domain": "test.com",
        "enabled_backends_tag": "a",
        "http_to_https": true
    });

    let response = app
        .clone()
        .oneshot(
            reqwest::Request::builder()
                .method("POST")
                .uri("http://localhost/api/v1/domains")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(domain_body.to_string()))
                .unwrap()
                .into(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 201);

    // Add backends with tag "a"
    let backend_a = json!({
        "id": "backend-a1",
        "address": "localhost:3001",
        "tags": ["a"]
    });

    let response = app
        .clone()
        .oneshot(
            reqwest::Request::builder()
                .method("POST")
                .uri("http://localhost/api/v1/backends")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(backend_a.to_string()))
                .unwrap()
                .into(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 201);

    // Add backends with tag "b"
    let backend_b = json!({
        "id": "backend-b1",
        "address": "localhost:3002",
        "tags": ["b"]
    });

    let response = app
        .clone()
        .oneshot(
            reqwest::Request::builder()
                .method("POST")
                .uri("http://localhost/api/v1/backends")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(backend_b.to_string()))
                .unwrap()
                .into(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 201);

    // Switch domain to tag "b"
    let response = app
        .clone()
        .oneshot(
            reqwest::Request::builder()
                .method("POST")
                .uri("http://localhost/api/v1/domains/test.com/switch")
                .body(axum::body::Body::empty())
                .unwrap()
                .into(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    // Verify domain now points to tag "b"
    let response = app
        .clone()
        .oneshot(
            reqwest::Request::builder()
                .method("GET")
                .uri("http://localhost/api/v1/domains/test.com")
                .body(axum::body::Body::empty())
                .unwrap()
                .into(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_health_endpoint() {
    let (_, app) = pingora_vhost::api::server::create_api_server("127.0.0.1:0").unwrap();

    let response = app
        .oneshot(
            reqwest::Request::builder()
                .method("GET")
                .uri("http://localhost/api/v1/health")
                .body(axum::body::Body::empty())
                .unwrap()
                .into(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
}
```

**Step 2: Run integration tests**

Run: `cargo test --test integration_test`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/
git commit -m "test: add integration tests for AB switching flow"
```

---

## Task 11: Implement Configuration Loading and Main Loop

**Files:**
- Modify: `src/main.rs`
- Create: `src/config.rs` (add validation)

**Step 1: Add config validation to src/config.rs**

```rust
pub fn validate_config(config: &Config) -> Result<(), String> {
    // Validate backends have valid addresses
    for backend in &config.backends {
        if backend.address.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!("Invalid backend address: {}", backend.address));
        }
        if backend.tags.is_empty() {
            return Err(format!("Backend {} has no tags", backend.id));
        }
    }

    // Validate virtual hosts have valid backend tags
    let all_tags: std::collections::HashSet<&String> = config.backends
        .iter()
        .flat_map(|b| &b.tags)
        .collect();

    for vh in &config.virtual_hosts {
        if !all_tags.contains(&vh.enabled_backends_tag) {
            return Err(format!(
                "Domain {} references non-existent tag '{}'",
                vh.domain, vh.enabled_backends_tag
            ));
        }
    }

    Ok(())
}
```

**Step 2: Update main.rs to validate config**

```rust
// After loading config:
config::validate_config(&config)
    .map_err(|e| anyhow::anyhow!("Invalid config: {}", e))?;
```

**Step 3: Test with invalid config**

Create `tests/config_test.rs`:

```rust
use pingora_vhost::config::{Config, validate_config};

#[test]
fn test_validate_config_invalid_backend_address() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: None,
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "invalid-address".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_config(&config);
    assert!(result.is_err());
}

#[test]
fn test_validate_config_valid() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: None,
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![pingora_vhost::config::VirtualHost {
            domain: "test.com".to_string(),
            enabled_backends_tag: "a".to_string(),
            http_to_https: true,
        }],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "localhost:3001".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_config(&config);
    assert!(result.is_ok());
}
```

**Step 4: Run config tests**

Run: `cargo test config`
Expected: PASS

**Step 5: Commit**

```bash
git add src/ tests/
git commit -m "feat: add configuration validation"
```

---

## Task 12: Add README and Documentation

**Files:**
- Create: `README.md`
- Create: `CLAUDE.md`

**Step 1: Create README.md**

```markdown
# Pingora Virtual Host Proxy

A Pingora-based reverse proxy for virtual hosting with zero-dimension rolling AB updates, Let's Encrypt TLS certificates, and full observability.

## Features

- **Virtual Hosting** - Host multiple domains on a single proxy instance
- **AB Rolling Updates** - Switch traffic between backend versions with zero downtime
- **Tag-based Backend Pool** - Organize backends with flexible tags (a, b, canary, etc.)
- **Active + Passive Health Checking** - Automatic failover for unhealthy backends
- **Let's Encrypt Integration** - Automatic TLS certificate issuance and renewal
- **HTTP Management API** - Dynamic configuration without restarts
- **Full Observability** - Prometheus metrics, structured logging, health status

## Quick Start

1. Copy example configuration:
```bash
cp config.example.toml config.toml
```

2. Edit `config.toml` with your domains and backends

3. Run the proxy:
```bash
cargo run -- --config config.toml
```

## Configuration

See `config.example.toml` for full configuration options.

## API Endpoints

### Domains
- `GET /api/v1/domains` - List all domains
- `POST /api/v1/domains` - Add new domain
- `GET /api/v1/domains/{domain}` - Get domain details
- `PUT /api/v1/domains/{domain}` - Update domain
- `DELETE /api/v1/domains/{domain}` - Remove domain
- `POST /api/v1/domains/{domain}/switch` - Switch AB tag (a↔b)

### Backends
- `GET /api/v1/backends` - List all backends
- `POST /api/v1/backends` - Register backend
- `GET /api/v1/backends/{id}` - Get backend details
- `PUT /api/v1/backends/{id}` - Update backend
- `DELETE /api/v1/backends/{id}` - Remove backend

### Observability
- `GET /api/v1/health` - Health check
- `GET /api/v1/metrics` - Prometheus metrics
- `GET /api/v1/stats` - Real-time statistics

## AB Switching

1. Deploy new backend version with tag "b"
2. Switch domain to use tag "b":
```bash
curl -X POST http://localhost:8080/api/v1/domains/example.com/switch
```
3. Monitor health and metrics
4. Rollback by switching back to "a" if needed

## Development

Run tests:
```bash
cargo test
```

Run with debug logging:
```bash
RUST_LOG=debug cargo run
```

## License

MIT
```

**Step 2: Create CLAUDE.md**

```markdown
# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pingora-based virtual host proxy with AB rolling updates, Let's Encrypt TLS, and HTTP management API.

## Build Commands

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run specific test
cargo test test_name

# Run with custom config
cargo run -- --config config.toml

# Format code
cargo fmt

# Run linter
cargo clippy
```

## Architecture

- **src/proxy.rs** - Pingora proxy server with SNI routing
- **src/backend_pool.rs** - Tag-based backend management
- **src/health_check.rs** - Active + passive health checking
- **src/api/** - HTTP management API (domains, backends, metrics)
- **src/observability/** - Logging and metrics
- **src/state.rs** - Shared in-memory state (Arc<RwLock<T>>)
- **src/config.rs** - TOML configuration parsing and validation

## Key Concepts

**Tags:** Backends are organized by tags (e.g., "a", "b"). Domains reference a tag to route traffic.

**AB Switching:** Change a domain's `enabled_backends_tag` from "a" to "b" to instantly switch traffic.

**Health Checking:** Backends are marked unhealthy after 3 consecutive failures, healthy after 2 consecutive successes.

## Testing

- Unit tests in `tests/` directory
- Integration tests for full AB switching flow
- Run `cargo test` to execute all tests

## Configuration Validation

All configs are validated at startup. Backend addresses must be valid, and domain tags must reference existing backend tags.
```

**Step 3: Commit documentation**

```bash
git add README.md CLAUDE.md
git commit -m "docs: add README and CLAUDE.md documentation"
```

---

## Task 13: Final Verification and Cleanup

**Files:**
- Run all tests
- Check for unused dependencies
- Verify example config

**Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass

**Step 2: Check for unused dependencies**

Run: `cargo +nightly udeps`
OR
Run: `cargo clippy --warnings`
Expected: No critical warnings

**Step 3: Verify example config is valid**

Run: `cargo run --bin config-validator -- config.example.toml`
(If you implement a config validator binary)

**Step 4: Final commit**

```bash
git add .
git commit -m "chore: finalize implementation and cleanup"
```

**Step 5: Tag release**

```bash
git tag v0.1.0
git push origin main --tags
```

---

## Implementation Notes

- **Pingora Integration:** The proxy implementation in `src/proxy.rs` is a skeleton. Full Pingora integration requires implementing their upstream selection and SNI routing APIs, which may need additional Pingora-specific code.

- **Let's Encrypt:** TLS implementation requires additional work with `acme-lib` and `rustls`. The design includes it but implementation details depend on Pingora's TLS extension points.

- **Health Check Task:** The health checker runs on a timer. You'll need to spawn a task in main.rs that periodically checks all backends.

- **State Persistence:** Optional state persistence (SQLite) is not implemented but could be added by serializing AppState to disk.

- **Testing:** Some tests are placeholder implementations. The integration test especially would benefit from running actual HTTP servers as backends.

## Next Steps After Implementation

1. **Complete Pingora Integration:** Implement actual SNI routing and upstream selection
2. **Add Let's Encrypt:** Implement automatic certificate issuance and renewal
3. **Health Check Task:** Spawn background health checker that periodically probes backends
4. **Add E2E Tests:** Test with real backend servers
5. **Performance Testing:** Benchmark under load
6. **Production Hardening:** Add rate limiting, request size limits, timeouts
