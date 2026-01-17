# Pingora Virtual Host Proxy Design

**Date:** 2026-01-17
**Author:** Claude Code
**Status:** Approved

## Overview

A Pingora-based reverse proxy for virtual hosting with zero-dimension rolling AB updates, Let's Encrypt TLS certificates, and full observability. Similar to nginx virtual hosts but with dynamic API-based configuration and blue-green deployment support.

## Architecture

### Core Components

1. **Proxy Core** - Pingora HTTP listener handling incoming requests, SNI routing based on hostname, and forwarding to backend pools
2. **Management API** - HTTP REST API for dynamic configuration (add/remove domains, backends, switch AB tags)
3. **Backend Pool Manager** - Tag-based backend registration (tags "a", "b", etc.) with active + passive health checking
4. **TLS Manager** - Let's Encrypt integration with automatic certificate issuance and renewal, plus fallback for manual nginx-style certs
5. **Observability Layer** - Structured logging (JSON for production, text for dev), Prometheus metrics endpoint, health status dashboard

### Data Flow

```
Request → SNI Routing → Backend Selection (by active tag) → Health Filter → Backend
                                                    ↑
Health Checker → Periodic Probes → Update Health Status → Router routes around unhealthy backends
```

## Configuration

### Initial Configuration (config.toml)

```toml
[proxy]
listen_addr = "0.0.0.0:443"
listen_addr_http = "0.0.0.0:80"
management_api_addr = "127.0.0.1:8080"

[lets_encrypt]
email = "admin@example.com"
staging = false
cache_dir = "/etc/pingora-ssl/certs"

[logging]
level = "info"
format = "json"  # or "text" for dev
output = "file"  # or "console"
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
enabled_backends_tag = "a"  # or "b" for AB switching
http_to_https = true

[[virtual_hosts]]
domain = "api.example.com"
enabled_backends_tag = "b"
http_to_https = true

[[backends]]
id = "web-v1"
address = "localhost:3001"
tags = ["a"]

[[backends]]
id = "web-v2"
address = "localhost:3002"
tags = ["b"]

[[backends]]
id = "api-server"
address = "192.168.1.100:8080"
tags = ["a", "b"]
```

## Management API

### REST Endpoints

**Domain Management:**
- `GET /api/v1/domains` - List all virtual hosts
- `POST /api/v1/domains` - Add new domain
- `GET /api/v1/domains/{domain}` - Get domain config
- `PUT /api/v1/domains/{domain}` - Update domain (switch tag, etc.)
- `DELETE /api/v1/domains/{domain}` - Remove domain

**Backend Management:**
- `GET /api/v1/backends` - List all backends
- `POST /api/v1/backends` - Register new backend
- `GET /api/v1/backends/{id}` - Get backend details
- `PUT /api/v1/backends/{id}` - Update backend (tags, address)
- `DELETE /api/v1/backends/{id}` - Remove backend
- `POST /api/v1/backends/{id}/drain` - Graceful drain backend
- `POST /api/v1/backends/{id}/health` - Trigger immediate health check

**AB Switching:**
- `POST /api/v1/domains/{domain}/switch` - Switch enabled_backends_tag (a↔b)

**Observability:**
- `GET /api/v1/health` - Overall proxy health
- `GET /api/v1/metrics` - Prometheus metrics
- `GET /api/v1/domains/{domain}/backends` - Backend status for domain
- `GET /api/v1/logs/stream` - SSE stream of recent logs
- `GET /api/v1/stats` - Real-time stats (req/s, errors, etc.)

**TLS Management:**
- `GET /api/v1/certs` - List all certificates
- `POST /api/v1/certs/{domain}/renew` - Manual certificate renewal
- `GET /api/v1/certs/{domain}` - Certificate details (expiry, etc.)

### AB Switching Flow

1. Deploy new backend version with tag "b"
2. POST to `/api/v1/domains/example.com/switch` - changes `enabled_backends_tag` from "a" to "b"
3. Health checker validates "b" backends before routing traffic
4. Zero downtime - existing connections drain gracefully

## Health Checking

### Active Health Checks
- Periodic HTTP GET to `/health` (or configurable path) every 10 seconds
- TCP connect check if HTTP health endpoint not configured
- 3 consecutive failures → mark backend as **unhealthy**
- 2 consecutive successes → mark backend as **healthy**
- Unhealthy backends excluded from routing but still probed for recovery

### Passive Health Detection
- Track success/failure of actual proxy requests
- 5xx responses or connection failures count toward unhealthy threshold
- Circuit breaker pattern: temporarily back off from failing backends
- Automatic retry with exponential backoff for transient failures

## Error Handling

- **Backend unreachable:** Try next available backend in pool, return 502 only if all down
- **TLS handshake failure:** Log error, return 503, trigger health check
- **No healthy backends:** Return 503 with clear error message
- **Certificate expiry warning:** Alert 30 days before expiry via log and API endpoint
- **Let's Encrypt failures:** Log error, continue with existing cert if valid, alert admin

### Graceful Shutdown
1. Receive SIGTERM → stop accepting new connections
2. Drain existing connections (configurable timeout, default 30s)
3. Force close after timeout
4. Save current state to optional persistence file

## Project Structure

```
pingora-vhost/
├── Cargo.toml
├── config.example.toml
├── src/
│   ├── main.rs              # Entry point, signal handling
│   ├── config.rs            # Config file parsing
│   ├── proxy.rs             # Pingora proxy setup
│   ├── router.rs            # SNI routing, backend selection
│   ├── backend_pool.rs      # Tag-based backend management
│   ├── health_check.rs      # Active + passive health checking
│   ├── tls.rs               # Let's Encrypt + cert management
│   ├── api/
│   │   ├── mod.rs           # API module
│   │   ├── server.rs        # HTTP API server
│   │   ├── domains.rs       # Domain endpoints
│   │   ├── backends.rs      # Backend endpoints
│   │   └── observability.rs # Health, metrics, logs
│   ├── observability/
│   │   ├── mod.rs
│   │   ├── metrics.rs       # Prometheus metrics
│   │   ├── logging.rs       # Structured logging
│   │   └── stats.rs         # Real-time statistics
│   └── state.rs             # Shared in-memory state
└── tests/
    └── integration.rs       # Integration tests
```

## Dependencies

- `pingora` - Core proxy functionality
- `tokio` - Async runtime
- `serde` + `toml` - Config serialization
- `axum` - HTTP API server
- `prometheus` - Metrics export
- `rustls` + `acme-lib` - Let's Encrypt TLS
- `tracing` + `tracing-subscriber` - Structured logging

## State Management

- `Arc<RwState<T>>` for thread-safe shared state
- In-memory backend registry with tag indexing
- Channel-based communication between health checker and router
- Optional persistence via periodic state snapshots

## Testing Strategy

### Unit Tests
- Tag-based backend pool selection logic
- Health check state transitions (healthy ↔ unhealthy)
- Configuration parsing and validation
- API request/response handling
- Certificate expiry calculations

### Integration Tests
- Full proxy flow: client → TLS → routing → backend
- AB switching scenario: register "b" backends, switch tag, verify traffic routing
- Health check failover: kill backend, verify traffic reroutes
- Let's Encrypt certificate issuance (use staging environment)
- Configuration hot-reload via API

### Manual Testing Scenarios

1. Deploy two backend versions (ports 3001, 3002), register with tags "a" and "b"
2. Add domain `test.local` pointing to tag "a", verify traffic goes to port 3001
3. Switch domain to tag "b" via API, verify traffic now goes to port 3002
4. Stop port 3002 backend, verify health checker marks it unhealthy
5. Restart port 3002, verify it recovers and traffic resumes
6. Test Let's Encrypt staging cert issuance for real domain

### Load Testing
- Use `wrk` or `hey` to verify performance under load
- Test connection pooling and keep-alive reuse
- Verify graceful shutdown doesn't drop connections

## Implementation Notes

- Load initial config from file, then all changes via API
- Supports both local and remote backends
- Tag-based backend registration allows flexible version management
- Full observability with structured logs and Prometheus metrics
- Let's Encrypt automation for zero-maintenance TLS
