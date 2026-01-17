# Pingora Virtual Host Proxy

A high-performance, configurable virtual host proxy built on Cloudflare's Pingora proxy framework. Features dynamic backend management, health checking, metrics, and support for A/B testing through tag-based backend switching.

## Features

- **Virtual Host Routing**: Route multiple domains to different backend pools based on SNI
- **Dynamic Configuration**: Runtime configuration via RESTful API - no restarts required
- **Health Checking**: Automatic backend health monitoring with configurable thresholds
- **A/B Testing**: Switch between backend pools on-the-fly for canary deployments
- **Metrics & Observability**: Prometheus-compatible metrics endpoint
- **TLS Termination**: HTTPS support with automatic certificate management (Let's Encrypt planned)
- **HTTP to HTTPS Redirect**: Optional automatic redirect for enhanced security

## Quick Start

### Prerequisites

- Rust 1.70+ (for building from source)
- Linux/BSD/macOS (Pingora currently doesn't support Windows)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd front_tier
```

2. Build the project:
```bash
cargo build --release
```

3. Create a configuration file:
```bash
cp config.example.toml config.toml
# Edit config.toml with your settings
```

4. Run the proxy:
```bash
./target/release/pingora-vhost
```

The proxy will start on port 443 (HTTPS) and 80 (HTTP), with the management API on port 8080.

## Configuration

The proxy uses a TOML configuration file. Here's a minimal example:

```toml
[proxy]
listen_addr = "0.0.0.0:443"              # HTTPS port
listen_addr_http = "0.0.0.0:80"          # HTTP port
management_api_addr = "127.0.0.1:8080"   # API port

[logging]
level = "info"
format = "text"

[metrics]
enabled = true
listen_addr = "0.0.0.0:9090"             # Prometheus metrics

[health_check]
interval_secs = 10
timeout_secs = 5
unhealthy_threshold = 3
healthy_threshold = 2

# Define your virtual hosts (domains)
[[virtual_hosts]]
domain = "example.com"
enabled_backends_tag = "a"               # Use backends tagged "a"
http_to_https = true

# Define backend servers
[[backends]]
id = "web-v1"
address = "localhost:3001"
tags = ["a"]

[[backends]]
id = "web-v2"
address = "localhost:3002"
tags = ["b"]
```

### Configuration Options

#### `[proxy]`
- `listen_addr`: Address/port for HTTPS connections
- `listen_addr_http`: Address/port for HTTP connections
- `management_api_addr`: Address/port for the management API

#### `[lets_encrypt]` (Planned)
- `email`: Email for Let's Encrypt account
- `staging`: Use Let's Encrypt staging environment (recommended for testing)
- `cache_dir`: Directory to cache certificates

#### `[logging]`
- `level`: Log level (trace, debug, info, warn, error)
- `format`: Log format (text or json)
- `output`: Output destination (console or file)
- `file_path`: Path to log file (when output=file)

#### `[metrics]`
- `enabled`: Enable/disable metrics collection
- `listen_addr`: Address for Prometheus metrics endpoint

#### `[health_check]`
- `interval_secs`: Health check interval in seconds
- `timeout_secs`: Health check timeout in seconds
- `unhealthy_threshold`: Number of failed checks before marking unhealthy
- `healthy_threshold`: Number of successful checks before marking healthy

#### `[[virtual_hosts]]`
- `domain`: Domain name to route
- `enabled_backends_tag`: Tag of backends to route traffic to
- `http_to_https`: Redirect HTTP to HTTPS

#### `[[backends]]`
- `id`: Unique backend identifier
- `address`: Backend address (host:port)
- `tags`: List of tags for grouping backends

## API Endpoints

The management API runs on the configured `management_api_addr` (default: http://127.0.0.1:8080).

### Health Check
```bash
GET /api/v1/health
```

Returns "OK" if the service is healthy.

### Domains Management

#### List All Domains
```bash
GET /api/v1/domains
```

Response:
```json
[
  {
    "domain": "example.com",
    "enabled_backends_tag": "a",
    "http_to_https": true
  }
]
```

#### Get Specific Domain
```bash
GET /api/v1/domains/:domain
```

#### Add Domain
```bash
POST /api/v1/domains
Content-Type: application/json

{
  "domain": "example.com",
  "enabled_backends_tag": "a",
  "http_to_https": true
}
```

#### Update Domain
```bash
PUT /api/v1/domains/:domain
Content-Type: application/json

{
  "enabled_backends_tag": "b",
  "http_to_https": false
}
```

#### Delete Domain
```bash
DELETE /api/v1/domains/:domain
```

### Backends Management

#### List All Backends
```bash
GET /api/v1/backends
```

Response:
```json
[
  {
    "id": "web-v1",
    "address": "localhost:3001",
    "tags": ["a"]
  }
]
```

#### Get Specific Backend
```bash
GET /api/v1/backends/:id
```

#### Add Backend
```bash
POST /api/v1/backends
Content-Type: application/json

{
  "id": "web-v2",
  "address": "localhost:3002",
  "tags": ["b"]
}
```

#### Update Backend
```bash
PUT /api/v1/backends/:id
Content-Type: application/json

{
  "address": "localhost:3003",
  "tags": ["a", "b"]
}
```

#### Delete Backend
```bash
DELETE /api/v1/backends/:id
```

### Metrics

```bash
GET /api/v1/metrics
```

Returns Prometheus-formatted metrics.

## A/B Testing with Backend Switching

The proxy supports A/B testing and canary deployments through tag-based backend switching. Here's how it works:

### Concept

1. **Backend Tags**: Each backend can have multiple tags (e.g., "a", "b", "stable", "canary")
2. **Domain Configuration**: Each domain is configured to use one tag at a time
3. **Runtime Switching**: Switch the active tag for a domain without restarting the proxy

### Example Setup

```toml
# Production backends (tagged "a")
[[backends]]
id = "app-v1-stable"
address = "backend-prod-1:8080"
tags = ["a", "stable"]

[[backends]]
id = "app-v1-stable-2"
address = "backend-prod-2:8080"
tags = ["a", "stable"]

# Canary backends (tagged "b")
[[backends]]
id = "app-v2-canary"
address = "backend-canary:8080"
tags = ["b", "canary"]

# Domain configured to use stable backends
[[virtual_hosts]]
domain = "app.example.com"
enabled_backends_tag = "a"
http_to_https = true
```

### Performing a Switch

1. **Start with all traffic on stable (tag "a")**
2. **Switch to canary (tag "b")**:
```bash
curl -X POST http://127.0.0.1:8080/api/v1/domains/app.example.com/switch \
  -H "Content-Type: application/json" \
  -d '{"new_tag": "b"}'
```

3. **Monitor metrics** at `http://127.0.0.1:9090/metrics`
4. **Rollback if needed** by switching back to tag "a":
```bash
curl -X POST http://127.0.0.1:8080/api/v1/domains/app.example.com/switch \
  -H "Content-Type: application/json" \
  -d '{"new_tag": "a"}'
```

### Gradual Rollout Strategy

For gradual rollout, you can configure multiple domains with different backend weights:

```toml
# 10% of users to canary
[[virtual_hosts]]
domain = "canary.app.example.com"
enabled_backends_tag = "b"

# 90% of users to stable
[[virtual_hosts]]
domain = "app.example.com"
enabled_backends_tag = "a"
```

Then use your DNS or load balancer to route 10% of traffic to the canary subdomain.

## Metrics

The proxy exposes Prometheus-compatible metrics on the configured metrics port (default: 9090). Available metrics include:

- `proxy_requests_total`: Total number of proxied requests
- `proxy_latency_seconds`: Request latency histogram
- `health_check_status`: Backend health check status
- `api_requests_total`: API request count by endpoint
- `api_latency_seconds`: API request latency

### Viewing Metrics

```bash
curl http://127.0.0.1:9090/api/v1/metrics
```

### Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'pingora-proxy'
    static_configs:
      - targets: ['proxy-server:9090']
```

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_health_check
```

### Code Structure

```
src/
├── main.rs              # Entry point
├── config.rs            # Configuration loading and validation
├── state.rs             # Application state management
├── proxy.rs             # Pingora proxy integration (TODO)
├── backend_pool.rs      # Backend selection logic
├── health_check.rs      # Health checking implementation
├── api/                 # Management API
│   ├── server.rs        # API server setup
│   ├── domains.rs       # Domain endpoints
│   └── backends.rs      # Backend endpoints
└── observability/       # Logging and metrics
    ├── logging.rs
    └── metrics.rs
```

## Roadmap

- [ ] Full Pingora proxy integration (currently scaffolding)
- [ ] Let's Encrypt automatic certificate management
- [ ] WebSocket support
- [ ] gRPC proxy support
- [ ] Rate limiting
- [ ] Circuit breaking
- [ ] Request/response transformation
- [ ] Admin web UI

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `cargo test`
2. Code is formatted: `cargo fmt`
3. No linter warnings: `cargo clippy`

## License

This project is built on Cloudflare's Pingora framework. Please review the Pingora license when using in production.

## Acknowledgments

- Built with [Cloudflare Pingora](https://github.com/cloudflare/pingora)
- Inspired by modern proxy solutions like NGINX, Envoy, and HAProxy
