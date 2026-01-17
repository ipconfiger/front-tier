# ACME Certificate Issuance API Documentation

## Overview

The ACME (Automatic Certificate Management Environment) API allows you to automatically obtain SSL/TLS certificates from Let's Encrypt via the management API.

## Prerequisites

Before using the ACME API, ensure:

1. **Let's Encrypt is configured** in your `config.toml`:
   ```toml
   [lets_encrypt]
   email = "your-email@example.com"
   staging = true  # Set to false for production
   cache_dir = "/etc/pingora-ssl/certs"
   ```

2. **Domain DNS is configured** - The domain you're requesting a certificate for must have DNS pointing to your server

3. **Port 80 is accessible** - Let's Encrypt uses HTTP-01 challenges, so port 80 must be accessible from the internet

4. **Proxy is running** - The proxy must be running to serve challenges and handle certificate issuance

## API Endpoint

### Obtain Certificate

**POST** `/api/v1/certificates/obtain`

Obtains a new SSL/TLS certificate from Let's Encrypt for one or more domains.

#### Request Body

```json
{
  "domain": "example.com",
  "alt_names": ["www.example.com", "api.example.com"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | Yes | Primary domain for the certificate |
| `alt_names` | array | No | Additional domains (Subject Alternative Names) |

#### Response (Success - 200)

```json
{
  "message": "Certificate obtained successfully for domain: example.com (2 alt names)",
  "domain": "example.com",
  "cert_path": "/etc/pingora-ssl/certs/example.com.crt.pem",
  "key_path": "/etc/pingora-ssl/certs/example.com.key.pem",
  "staging": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `message` | string | Success message |
| `domain` | string | Primary domain |
| `cert_path` | string | Path to certificate file |
| `key_path` | string | Path to private key file |
| `staging` | boolean | Whether certificate is from staging environment |

#### Error Responses

**503 Service Unavailable** - Let's Encrypt not configured
```json
{
  "error": "ACME manager not configured - Let's Encrypt is not enabled"
}
```

**400 Bad Request** - Invalid domain
```json
{
  "error": "Invalid domain: example..com"
}
```

**500 Internal Server Error** - ACME protocol error
```json
{
  "error": "Failed to obtain certificate for domains [...]"
}
```

## Usage Examples

### Example 1: Single Domain Certificate

```bash
curl -X POST http://localhost:8080/api/v1/certificates/obtain \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### Example 2: Multi-Domain Certificate (SAN)

```bash
curl -X POST http://localhost:8080/api/v1/certificates/obtain \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "alt_names": ["www.example.com", "api.example.com", "mail.example.com"]
  }'
```

### Example 3: With jq to Pretty-Print

```bash
curl -X POST http://localhost:8080/api/v1/certificates/obtain \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' \
  | jq '.'
```

## What Happens During Certificate Issuance

1. **ACME Account Creation** - Creates or loads ACME account with Let's Encrypt
2. **Order Creation** - Creates an order for the requested domains
3. **HTTP-01 Challenge** - Let's Encrypt asks us to prove we own the domain:
   - Challenge token is stored in memory
   - Let's Encrypt requests `http://<domain>/.well-known/acme-challenge/<token>`
   - Our proxy serves the challenge response
   - Let's Encrypt validates the challenge
4. **Certificate Download** - Once validated, certificate is downloaded
5. **Certificate Loading** - Certificate is loaded into the certificate manager
6. **TLS Ready** - Certificate is now available for TLS connections

## Staging vs Production

**Staging (Recommended for Testing)**
```toml
[lets_encrypt]
staging = true  # Uses Let's Encrypt staging environment
```
- No rate limits
- Certificates are NOT trusted by browsers
- Use for initial testing and development

**Production**
```toml
[lets_encrypt]
staging = false  # Uses Let's Encrypt production environment
```
- **Strict rate limits** (50 certificates per domain per week)
- Certificates ARE trusted by browsers
- Only use after successful testing in staging

## Rate Limits

Let's Encrypt has strict rate limits:

- **50 certificates per domain per week** (production)
- **Failed validations count against rate limit**
- **Duplicate certificates** within 7 days are rate-limited

**Tips to avoid rate limits:**
1. Always test with `staging = true` first
2. Use staging until your configuration is correct
3. Only switch to production when ready
4. Don't repeatedly request certificates for the same domain

## Certificate Lifecycle

- **Validity:** 90 days
- **Auto-renewal:** Not yet implemented (manual renewal required)
- **Storage:** Certificates are cached in `cache_dir`

To check certificate expiration:
```bash
curl http://localhost:8080/api/v1/certificates | jq '.'
```

## Troubleshooting

### Certificate Issuance Fails

**Problem:** Returns 500 error

**Common causes:**
1. **DNS not configured** - Domain doesn't point to your server
2. **Port 80 blocked** - Let's Encrypt can't reach your server on port 80
3. **Firewall rules** - Blocking incoming HTTP requests
4. **Invalid domain** - Domain contains invalid characters

**Debug steps:**
1. Check DNS: `dig +short example.com`
2. Check port 80: `curl http://example.com/.well-known/acme-challenge/test`
3. Check proxy logs: Look for ACME-related messages
4. Verify domain is accessible from internet

### "ACME manager not configured" Error

**Problem:** Returns 503 Service Unavailable

**Solution:** Add Let's Encrypt configuration to `config.toml`:
```toml
[lets_encrypt]
email = "your-email@example.com"
staging = true
cache_dir = "/etc/pingora-ssl/certs"
```

Then restart the proxy.

### Challenge Validation Timeout

**Problem:** Let's Encrypt can't validate the challenge

**Solution:**
1. Ensure proxy is running on port 80
2. Check firewall allows port 80 from internet
3. Verify DNS A record points to correct IP
4. Test challenge endpoint: `curl http://your-domain.com/.well-known/acme-challenge/test`

## Integration with Virtual Hosts

After obtaining a certificate, add it to your virtual host configuration:

```toml
[[virtual_hosts]]
domain = "example.com"
enabled_backends_tag = "production"
http_to_https = true
tls_enabled = true
[virtual_hosts.certificate_source]
type = "lets_encrypt"
```

The certificate will be automatically used for TLS connections to that domain.

## See Also

- [ACME Integration Test Documentation](./ACME_INTEGRATION_TEST.md)
- [Certificate Management API](./API.md)
- [Configuration Guide](./configuration.md)
