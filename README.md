# Pingora Virtual Host Proxy

A high-performance, configurable virtual host proxy built on Cloudflare's Pingora proxy framework. Features dynamic backend management, health checking, metrics, and support for A/B testing through tag-based backend switching.

## Features

- **Virtual Host Routing**: Route multiple domains to different backend pools based on SNI
- **Dynamic Configuration**: Runtime configuration via RESTful API - no restarts required
- **Health Checking**: Automatic backend health monitoring with configurable thresholds
- **A/B Testing**: Switch between backend pools on-the-fly for canary deployments
- **Metrics & Observability**: Prometheus-compatible metrics endpoint
- **TLS Termination**: Full HTTPS support with SNI-based certificate selection
- **Dual Certificate Sources**: File-based certificates (nginx-style) and Let's Encrypt automatic certificates
- **HTTP to HTTPS Redirect**: Optional automatic redirect for enhanced security
- **Hot Certificate Reload**: Update certificates without downtime
- **Certificate Management API**: Monitor and reload certificates via RESTful API

## Quick Start

### Prerequisites

- Rust 1.70+ (for building from source)
- Linux/BSD/macOS (Pingora currently doesn't support Windows)

### Installation

1. Clone the repository:
```bash
git clone [Replace with your repository URL]
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

#### `[lets_encrypt]`
- `email`: Email for Let's Encrypt account (required for automatic certificates)
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
- `tls_enabled`: Enable TLS for this domain (default: true)
- `certificate_source`: Certificate configuration (optional)
  - `type`: Either "file" or "lets_encrypt"
  - For "file" type:
    - `cert_path`: Path to certificate file (.crt or .pem)
    - `key_path`: Path to private key file (.key)
  - For "lets_encrypt" type: No additional fields needed

#### `[[backends]]`
- `id`: Unique backend identifier
- `address`: Backend address (host:port)
- `tags`: List of tags for grouping backends

## TLS/SSL Configuration

The proxy supports two certificate sources:

### 1. File-Based Certificates (nginx-style)

Use existing certificates in standard formats:

```toml
[[virtual_hosts]]
domain = "secure.example.com"
enabled_backends_tag = "a"
http_to_https = true
tls_enabled = true
[virtual_hosts.certificate_source]
type = "file"
cert_path = "/etc/ssl/certs/secure.example.com.crt"
key_path = "/etc/ssl/private/secure.example.com.key"
```

Supported formats:
- Certificates: `.crt`, `.pem`, `.cer`
- Private keys: `.key`, `.pem` (unencrypted or PKCS#8)

### 2. Let's Encrypt Automatic Certificates

Automatic certificate issuance and renewal:

```toml
[[virtual_hosts]]
domain = "auto-secure.example.com"
enabled_backends_tag = "a"
http_to_https = true
tls_enabled = true
[virtual_hosts.certificate_source]
type = "lets_encrypt"
```

**Requirements:**
- Domain DNS must point to the proxy server
- Port 80 must be accessible for HTTP-01 challenge
- Configure `[lets_encrypt]` section with your email

**Let's Encrypt Configuration:**
```toml
[lets_encrypt]
email = "admin@example.com"
staging = true  # Use staging for testing, set false for production
cache_dir = "/etc/pingora-ssl/certs"
```

### DNS-01 Challenge (Recommended for China)

If your server is in China or port 80 is blocked by ICP/ISP firewalls, use DNS-01 challenge validation:

```toml
[lets_encrypt]
email = "admin@example.com"
staging = true
cache_dir = "./acme-certs"

[lets_encrypt.dns_provider]
provider = "aliyun"
access_key_id = "your-access-key-id"
access_key_secret = "your-access-key-secret"

dns_propagation_secs = 30
```

**Supported DNS providers:**
- Aliyun (Alibaba Cloud) DNS
- Cloudflare DNS (coming soon)
- DNSPod (Tencent Cloud) DNS (coming soon)

**DNS-01 vs HTTP-01:**
- DNS-01 works when port 80 is blocked
- DNS-01 supports wildcard certificates
- HTTP-01 is simpler but requires public HTTP access

### HTTP to HTTPS Redirect

Automatically redirect HTTP traffic to HTTPS:

```toml
[[virtual_hosts]]
domain = "example.com"
http_to_https = true  # Redirects all HTTP traffic to HTTPS
```

When enabled:
1. HTTP requests to port 80 receive 301 Permanent Redirect
2. Clients are redirected to the same URL with https://
3. SNI routing works seamlessly after redirect

### SNI-Based Certificate Selection

The proxy automatically selects the correct certificate based on the TLS Server Name Indication (SNI) extension:

```toml
# Multiple domains with different certificates
[[virtual_hosts]]
domain = "example.com"
enabled_backends_tag = "a"
[virtual_hosts.certificate_source]
type = "file"
cert_path = "/etc/ssl/certs/example.com.crt"
key_path = "/etc/ssl/private/example.com.key"

[[virtual_hosts]]
domain = "api.example.com"
enabled_backends_tag = "api"
[virtual_hosts.certificate_source]
type = "lets_encrypt"

[[virtual_hosts]]
domain = "blog.example.com"
enabled_backends_tag = "blog"
[virtual_hosts.certificate_source]
type = "file"
cert_path = "/etc/ssl/certs/blog.com.crt"
key_path = "/etc/ssl/private/blog.com.key"
```

Each domain presents its own certificate during TLS handshake.

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

### Certificate Management

#### List All Certificates
```bash
GET /api/v1/certificates
```

Response:
```json
[
  {
    "domain": "example.com",
    "expires_at": "2025-04-15T12:00:00Z",
    "days_until_expiration": 89,
    "source": "file"
  },
  {
    "domain": "api.example.com",
    "expires_at": "2025-03-20T08:30:00Z",
    "days_until_expiration": 63,
    "source": "lets_encrypt"
  }
]
```

#### Reload Certificate
```bash
POST /api/v1/certificates/:domain/reload
```

Manually reload a certificate from disk (useful after updating certificate files):

Response:
```json
{
  "message": "Certificate reloaded successfully for domain: example.com",
  "domain": "example.com"
}
```

**Note:** Certificates are automatically reloaded when files change. This endpoint is for manual reloads if needed.

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

3. **Monitor metrics** at `http://127.0.0.1:8080/api/v1/metrics`
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

The proxy exposes Prometheus-compatible metrics at `/api/v1/metrics` on the management API server (default port: 8080). Available metrics include:

- `proxy_requests_total`: Total number of proxied requests
- `proxy_latency_seconds`: Request latency histogram
- `health_check_status`: Backend health check status
- `api_requests_total`: API request count by endpoint
- `api_latency_seconds`: API request latency

### Viewing Metrics

```bash
curl http://127.0.0.1:8080/api/v1/metrics
```

### Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'pingora-proxy'
    static_configs:
      - targets: ['proxy-server:8080']
    metrics_path: '/api/v1/metrics'
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

## Troubleshooting

### Certificate Issues

#### Certificate Loading Failures

**Problem:** Proxy fails to start with "certificate not found" error

**Solutions:**
1. Verify certificate file paths are correct
2. Check file permissions (proxy needs read access)
3. Ensure certificate and key match:
   ```bash
   # Compare certificate modulus
   openssl x509 -noout -modulus -in /path/to/cert.crt | openssl md5
   openssl rsa -noout -modulus -in /path/to/key.key | openssl md5
   # Both should output the same hash
   ```

#### SNI Routing Issues

**Problem:** Wrong certificate presented for a domain

**Solutions:**
1. Verify domain configuration matches the requested hostname
2. Check DNS resolves to correct IP
3. Test SNI manually:
   ```bash
   openssl s_client -connect example.com:443 -servername example.com
   # Verify the certificate presented
   ```

#### Let's Encrypt Certificate Issues

**Problem:** Automatic certificate issuance fails

**Solutions:**
1. Verify DNS points to proxy server
2. Check port 80 is accessible from internet:
   ```bash
   # From external machine
   curl http://your-domain.com/.well-known/acme-challenge/test
   ```
3. Check Let's Encrypt rate limits:
   - Staging: No strict limits
   - Production: 50 certificates per domain per week
4. Review proxy logs for ACME challenge errors
5. Test with staging first (staging = true)

#### Certificate Expiration Monitoring

Monitor certificates via API:

```bash
# Check all certificates
curl http://127.0.0.1:8080/api/v1/certificates

# Set up automated monitoring
watch -n 3600 'curl -s http://127.0.0.1:8080/api/v1/certificates | jq ".[] | select(.days_until_expiration < 30)"'
```

#### Hot Reload Not Working

**Problem:** Certificate changes not taking effect

**Solutions:**
1. Verify file watcher is running (check logs)
2. Manually reload via API:
   ```bash
   curl -X POST http://127.0.0.1:8080/api/v1/certificates/example.com/reload
   ```
3. Check file system events:
   ```bash
   # Linux: install inotify-tools
   inotifywait -m /etc/ssl/certs/
   ```

### Health Check Failures

**Problem:** Backends marked as unhealthy

**Solutions:**
1. Test health endpoint manually:
   ```bash
   curl http://backend-ip:port/health
   ```
2. Adjust health check thresholds in config
3. Check network connectivity
4. Review backend logs

### Performance Issues

**Problem:** High latency or slow responses

**Solutions:**
1. Check metrics endpoint for bottlenecks
2. Verify backend performance
3. Increase health check timeout
4. Review system resources (CPU, memory, network)

For more troubleshooting tips, see the [Chinese User Manual](docs/用户手册.md).

## Roadmap

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
