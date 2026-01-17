# Pingora Virtual Host Proxy - AI Collaboration Guide

## Project Overview

**Pingora Virtual Host Proxy** is a high-performance reverse proxy built on Cloudflare's Pingora framework. It provides dynamic virtual host routing, health checking, A/B testing capabilities, and observability features through a RESTful management API.

**Key Characteristics:**
- Written in Rust for performance and safety
- Built on Pingora (Cloudflare's successor to NGINX)
- Designed for production use with proper error handling and observability
- Zero-downtime reconfiguration via management API
- Tag-based backend pool management for canary deployments

**Current Status:**
- Core infrastructure: Complete (config, state, API, health checks, metrics)
- Pingora proxy integration: Scaffolding only (proxy.rs has TODO markers)
- Let's Encrypt: Configuration present, implementation not yet integrated

## Build Commands

### Development

```bash
# Build (debug)
cargo build

# Build (release, optimized)
cargo build --release

# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test --test api_test

# Format code
cargo fmt

# Check for issues
cargo clippy

# Run the proxy
cargo run
```

### Running the Proxy

```bash
# Using default config.toml
./target/release/pingora-vhost

# Using custom config
./target/release/pingora-vhost --config /path/to/config.toml

# Explicit run command (same as default)
./target/release/pingora-vhost run
```

### Development Workflow

1. **Make changes**: Edit source files
2. **Run tests**: `cargo test`
3. **Check formatting**: `cargo fmt --check`
4. **Run clippy**: `cargo clippy -- -D warnings`
5. **Build**: `cargo build --release`
6. **Test manually**: Run the binary and verify behavior

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Requests                          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Pingora Proxy Server (TODO)                    │
│  - SNI-based routing                                        │
│  - TLS termination                                          │
│  - HTTP/HTTPS handling                                      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Backend Pool Selection                         │
│  - Tag-based filtering                                      │
│  - Load distribution                                        │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Backend Servers                                │
│  - v1 backends (tag "a")                                    │
│  - v2 backends (tag "b")                                    │
└─────────────────────────────────────────────────────────────┘

                     ┌─────────────────┐
                     │ Management API  │
                     │   (Axum/Tokio)  │
                     └─────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │  AppState (In-Memory) │
          │  - Virtual Hosts     │
          │  - Backends          │
          │  - Health Status     │
          └──────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │  Background Tasks    │
          │  - Health Checker    │
          │  - Metrics Collector │
          └──────────────────────┘
```

### Module Structure

#### Core Modules

**`config.rs`**
- Defines `Config`, `ProxySettings`, `VirtualHost`, `Backend` structs
- Loads and validates TOML configuration
- Validates backend tags referenced by virtual hosts exist
- **Key function**: `load_config()`, `validate_config()`

**`state.rs`**
- Defines `AppState` struct holding in-memory state
- Thread-safe access using `tokio::sync::RwLock`
- Stores: `virtual_hosts` (HashMap), `backends` (HashMap), `health_status` (HashMap)
- **Key methods**: `new()`, `from_config()` (initializes from config file)

**`proxy.rs`**
- **Currently scaffolding only**
- Intended to wrap Pingora's Server
- Will implement SNI-based routing to backend pools
- **Status**: Contains TODO markers for Pingora integration

#### Health Checking

**`health_check.rs`**
- Periodic health checks of all backends
- HTTP GET requests to backend `/health` endpoint
- Configurable intervals, timeouts, thresholds
- Updates health status in `AppState`
- **Key struct**: `HealthChecker`
- **Key method**: `run()` - spawns background task

**`backend_pool.rs`**
- Filters backends by tag
- Selects healthy backends from pool
- **Key functions**: `filter_backends_by_tag()`, `get_healthy_backends()`

#### Management API

**`api/server.rs`**
- Axum-based HTTP server
- CORS enabled for cross-origin requests
- Routes: health, domains, backends, metrics
- **Key function**: `create_api_server()`, `run_api_server()`

**`api/domains.rs`**
- CRUD operations for virtual hosts
- List, add, get, update, delete domains
- **Special endpoint**: `POST /api/v1/domains/:domain/switch` - for A/B testing tag switching

**`api/backends.rs`**
- CRUD operations for backends
- List, add, get, update, delete backends
- Partial updates supported (only update provided fields)

#### Observability

**`observability/logging.rs`**
- Initializes tracing subscriber
- Supports text or JSON format
- Console or file output
- **Key function**: `init_logging()`

**`observability/metrics.rs`**
- Prometheus-compatible metrics
- Request counting, latency histograms
- Health check status metrics
- **Key struct**: `MetricsCollector`
- **Key method**: `export_metrics()` - returns Prometheus text format

### Data Flow

1. **Startup**:
   - Load `config.toml`
   - Validate configuration (check tag references)
   - Initialize `AppState` from config
   - Start background health checker
   - Start API server
   - Start Pingora proxy (TODO)

2. **Runtime Reconfiguration**:
   - Client calls API endpoint
   - API handler updates `AppState` (RwLock-protected)
   - Changes immediately reflected in routing decisions
   - No restart required

3. **Health Checking Loop**:
   - Every `interval_secs`, check all backends
   - For each backend: send HTTP GET to `/health`
   - Update health status in `AppState`
   - Backends below `unhealthy_threshold` marked unhealthy
   - Backends reaching `healthy_threshold` marked healthy

4. **Request Routing** (TODO - in proxy.rs):
   - Accept connection on :443 or :80
   - Parse SNI from TLS handshake
   - Lookup domain in `virtual_hosts`
   - Get `enabled_backends_tag` for domain
   - Filter backends by tag
   - Filter to healthy backends only
   - Distribute traffic among healthy backends
   - Return response to client

## Key Concepts

### Virtual Hosts and Backends

**Virtual Host**: A domain name that routes to a pool of backends
- Has an `enabled_backends_tag` to select which backend pool to use
- Can optionally redirect HTTP to HTTPS
- Example: `example.com` → backends tagged "a"

**Backend**: An origin server that receives proxied traffic
- Has a unique `id` and `address` (host:port)
- Has one or more `tags` for grouping
- Example: `web-v1` at `localhost:3001` with tags ["a", "stable"]

### Tag-Based Routing

Tags are the key to A/B testing and canary deployments:

1. **Tag System**:
   - Each backend can have multiple tags
   - Each domain selects ONE tag at a time
   - Switching tags changes traffic routing instantly

2. **Use Cases**:
   - **A/B Testing**: Tag "a" = version A, Tag "b" = version B
   - **Canary Deployment**: Tag "stable" = production, Tag "canary" = new version
   - **Blue-Green**: Tag "blue" = old version, Tag "green" = new version
   - **Gradual Rollout**: Multiple domains with different tags

3. **Switching Flow**:
   ```
   Initial: example.com → tag "a" → backends [v1-1, v1-2]
   Switch API call: POST /domains/example.com/switch {"new_tag": "b"}
   Result: example.com → tag "b" → backends [v2-1, v2-2]
   ```

### Health Checking

- **Active Health Checks**: Proxy sends requests to backends
- **Configurable**: Interval, timeout, thresholds
- **State Tracking**: Each backend has health status in `AppState`
- **Traffic Filtering**: Only healthy backends receive traffic
- **Auto-Recovery**: Unhealthy backends can become healthy again

### Management API Design

**RESTful Principles**:
- Standard HTTP verbs: GET (read), POST (create), PUT (update), DELETE (remove)
- JSON request/response bodies
- Appropriate HTTP status codes: 200 OK, 201 Created, 404 Not Found, 409 Conflict
- Resource URLs: `/api/v1/domains/:domain`, `/api/v1/backends/:id`

**Idempotency**:
- PUT and DELETE are idempotent (safe to retry)
- POST is not idempotent (creates new resources)
- GET is idempotent and safe

**Partial Updates**:
- PUT endpoints support partial updates
- Only include fields you want to change
- Omitted fields keep their existing values

### Observability

**Logging**:
- Structured logging with `tracing` crate
- Text format for development (human-readable)
- JSON format for production (log aggregation)
- Log levels: trace, debug, info, warn, error

**Metrics**:
- Prometheus format (widely adopted)
- Exposed on separate port (9090 by default)
- Counters for request totals
- Histograms for request latency
- Gauges for health status

## Development Guidelines

### Code Organization

1. **Module Boundaries**:
   - Each `.rs` file should have a single responsibility
   - Use `mod` declarations in `lib.rs` to expose public modules
   - Keep related functionality together

2. **Error Handling**:
   - Use `anyhow::Result` for application errors
   - Use `thiserror` for custom error types (if needed)
   - Propagate errors with `?` operator
   - Add context with `.context()` or `.map_err()`

3. **Async/Await**:
   - Most I/O operations should be async
   - Use `tokio::spawn` for background tasks
   - Use `tokio::sync::RwLock` for shared state
   - Avoid blocking operations in async context

4. **Testing**:
   - Unit tests in same file as code (module `tests`)
   - Integration tests in `tests/` directory
   - Test file naming: `<module>_test.rs`
   - Mock external dependencies (backends, APIs)

### Common Patterns

**Adding a New API Endpoint**:

1. Define request/response structs in appropriate module:
```rust
#[derive(Deserialize)]
pub struct MyRequest {
    pub field: String,
}

#[derive(Serialize)]
pub struct MyResponse {
    pub field: String,
}
```

2. Implement handler function:
```rust
pub async fn my_handler(
    State((state, _)): State<(AppState, Arc<MetricsCollector>)>,
    Json(req): Json<MyRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Your logic here
    Ok(Json(response))
}
```

3. Add route in `api/server.rs`:
```rust
.route("/api/v1/myresource", get(my_handler))
```

4. Write tests in `tests/api_test.rs` or new file

**Adding a New Configuration Field**:

1. Add field to struct in `config.rs`:
```rust
pub struct MySettings {
    pub my_field: String,
}
```

2. Add to `Config` struct if needed

3. Add section to `config.example.toml`

4. Update documentation

5. Write tests in `tests/config_test.rs`

### Performance Considerations

1. **Lock Contention**:
   - Keep RwLock lock duration short
   - Clone data before releasing lock if needed
   - Use read locks when possible (multiple readers allowed)

2. **Async Tasks**:
   - Don't block the async runtime
   - Use `tokio::time::timeout` for timeouts
   - Use `tokio::select!` for waiting on multiple futures

3. **Memory**:
   - Be mindful of cloning large data structures
   - Use `Arc` for shared read-only data
   - Consider streaming for large payloads

### Testing Strategy

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test API endpoints and component interaction
3. **Configuration Tests**: Validate config loading and validation
4. **Health Check Tests**: Verify health checking logic
5. **Metrics Tests**: Ensure metrics are collected correctly

## Current Limitations and TODOs

1. **Pingora Integration**:
   - `proxy.rs` is currently scaffolding
   - Actual request routing not implemented
   - Need to integrate Pingora's SNI routing APIs

2. **Let's Encrypt**:
   - Configuration exists but not used
   - Certificate automation not implemented
   - Manual TLS cert management required for now

3. **Advanced Load Balancing**:
   - No weighted round-robin
   - No least-connections algorithm
   - No session affinity

4. **Security Features**:
   - No rate limiting
   - No authentication on API endpoints
   - No IP whitelisting/blacklisting

## Common Tasks

### Adding a New Domain

```bash
curl -X POST http://127.0.0.1:8080/api/v1/domains \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "new.example.com",
    "enabled_backends_tag": "a",
    "http_to_https": true
  }'
```

### Switching to Canary Backend

```bash
curl -X POST http://127.0.0.1:8080/api/v1/domains/example.com/switch \
  -H "Content-Type: application/json" \
  -d '{"new_tag": "canary"}'
```

### Checking Backend Health

```bash
# View all backends
curl http://127.0.0.1:8080/api/v1/backends

# View health status in metrics
curl http://127.0.0.1:9090/api/v1/metrics | grep health_check
```

### Viewing Logs

```bash
# If using file output
tail -f /var/log/pingora-proxy/proxy.log

# If using console output (development)
# Logs are printed to stdout
```

## Debugging Tips

1. **Enable Debug Logging**:
   Set `level = "debug"` in `[logging]` section of config.toml

2. **Check Health Status**:
   Query `/api/v1/backends` and verify backends are marked healthy

3. **Verify Tag References**:
   Ensure `enabled_backends_tag` in virtual hosts matches backend tags

4. **API Errors**:
   API returns appropriate HTTP status codes:
   - 404: Resource not found
   - 409: Resource already exists (conflict)
   - 400: Invalid request body

5. **Metrics Endpoint**:
   Always returns 200 OK, even if no metrics collected yet

## Resources

- **Pingora Documentation**: https://github.com/cloudflare/pingora
- **Axum Framework**: https://github.com/tokio-rs/axum
- **Tokio Async Runtime**: https://tokio.rs/
- **Prometheus Metrics**: https://prometheus.io/docs/concepts/data_model/
- **Project Repository**: [Your repo URL]

## Notes for AI Assistants

When working on this codebase:

1. **Read existing code patterns** before writing new code
2. **Match the existing style** (formatting, naming conventions, error handling)
3. **Add tests** for new functionality
4. **Update documentation** (this file, README.md, config.example.toml)
5. **Run `cargo test` and `cargo clippy`** before committing
6. **Consider thread safety** - all state is shared via Arc<RwLock<>>
7. **Use async/await** consistently - no blocking operations in async context
8. **Propagate errors properly** - don't silently ignore errors
9. **Log important operations** - use tracing::info, warn, error
10. **Think about observability** - add metrics for new features
