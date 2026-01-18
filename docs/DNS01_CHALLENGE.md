# DNS-01 Challenge Validation

## Overview

DNS-01 challenge validation allows obtaining Let's Encrypt certificates without requiring HTTP server access on port 80. This is especially useful for:
- Servers behind ICP/ISP firewalls (common in China)
- Networks with port 80 restrictions
- Obtaining wildcard certificates (*.example.com)

## How It Works

1. Let's Encrypt provides a challenge token
2. Application creates a TXT record at `_acme-challenge.yourdomain.com`
3. Wait for DNS propagation (default: 30 seconds)
4. Let's Encrypt validates by querying DNS
5. Certificate issued, TXT record deleted

## Configuration

### Aliyun DNS (Alibaba Cloud)

1. Get AccessKey from [Aliyun Console](https://ram.console.aliyun.com/manage/ak)
2. Add to configuration:

```toml
[lets_encrypt.dns_provider]
provider = "aliyun"
access_key_id = "LTAI5t..."
access_key_secret = "xxxxxx"
```

3. Set propagation time (optional):

```toml
dns_propagation_secs = 30  # Adjust for your DNS
```

## API Usage

Request certificate with DNS-01 challenge:

```bash
curl -X POST http://localhost:8080/api/v1/certificates/obtain \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "challenge_type": "dns-01"
  }'
```

Or use "auto" to automatically select DNS-01 if configured:

```bash
curl -X POST http://localhost:8080/api/v1/certificates/obtain \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "challenge_type": "auto"
  }'
```

## Troubleshooting

### Certificate issuance fails

1. **Check DNS credentials:**
   ```bash
   curl -X POST http://localhost:8080/api/v1/certificates/obtain \
     -H "Content-Type: application/json" \
     -d '{"domain": "test.com"}'
   ```

2. **Verify TXT record created:**
   ```bash
   dig TXT _acme-challenge.test.com
   ```

3. **Increase propagation time if DNS is slow:**
   ```toml
   dns_propagation_secs = 60  # Wait 60 seconds
   ```

### TXT record not cleaned up

Check logs for errors during cleanup. Manual cleanup:

```bash
# Aliyun: Delete via console or API
# Record name: _acme-challenge.<domain>
# Type: TXT
```

## Security Notes

- **Access Keys:** Store securely, use environment variables
- **Permissions:** Only grant DNS read/write access
- **Rotation:** Rotate access keys regularly
- **Monitoring:** Monitor DNS changes for security

## Comparison: HTTP-01 vs DNS-01

| Feature | HTTP-01 | DNS-01 |
|---------|---------|--------|
| Port Requirements | 80 (HTTP) | 53 (DNS) |
| Firewall Sensitivity | High (ICP/ISP blocks) | Low (rarely blocked) |
| Wildcard Support | No | Yes |
| Setup Complexity | Simple | Moderate (DNS API) |
| Validation Speed | Fast (~5s) | Slower (~30s) |
| Server Location | Any | Any (including China) |

## Future Enhancements

- [ ] Cloudflare DNS provider
- [ ] DNSPod (Tencent) DNS provider
- [ ] AWS Route53 provider
- [ ] Google Cloud DNS provider
- [ ] Automatic retry with exponential backoff
- [ ] DNS validation via multiple resolvers
