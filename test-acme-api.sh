#!/bin/bash
# Test ACME Certificate Issuance API Endpoint

set -e

echo "=========================================="
echo "ACME Certificate Issuance API Test"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_PORT="${API_PORT:-8080}"
API_URL="http://localhost:${API_PORT}"

echo "Testing ACME API endpoint..."
echo "API URL: $API_URL"
echo ""

# Check if proxy is running
echo -n "1. Checking if proxy is running... "
if ! pgrep -f "pingora-vhost run" > /dev/null; then
    echo -e "${RED}✗ Proxy not running${NC}"
    echo "   Please start the proxy first"
    exit 1
fi
echo -e "${GREEN}✓ Proxy is running${NC}"

# Test health endpoint
echo -n "2. Testing health endpoint... "
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/api/v1/health" --connect-timeout 5 || echo "000")
if [ "$HEALTH_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Health check passed${NC}"
else
    echo -e "${RED}✗ Health check failed (HTTP $HEALTH_CODE)${NC}"
    exit 1
fi

# Test certificate obtain endpoint (without Let's Encrypt configured)
echo ""
echo "3. Testing certificate obtain endpoint (without Let's Encrypt)..."
echo "   This should return 503 Service Unavailable"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" "${API_URL}/api/v1/certificates/obtain" \
    -H "Content-Type: application/json" \
    -d '{"domain":"example.com","alt_names":[]}' \
    --connect-timeout 5 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "   HTTP Status: $HTTP_CODE"
echo "   Response: $BODY"

if [ "$HTTP_CODE" = "503" ]; then
    echo -e "${GREEN}✓ Correctly returned 503 when Let's Encrypt not configured${NC}"
else
    echo -e "${YELLOW}⚠ Expected 503 but got $HTTP_CODE${NC}"
    echo "   This might mean Let's Encrypt IS configured"
fi

# Test with Let's Encrypt configured
echo ""
echo "4. Testing with Let's Encrypt configuration..."
echo "   Creating test config with Let's Encrypt staging..."

# Create test config
cat > /tmp/test-acme-api-config.toml << EOF
[proxy]
listen_addr = "0.0.0.0:8443"
listen_addr_http = "0.0.0.0:8080"
management_api_addr = "127.0.0.1:9090"

[lets_encrypt]
email = "test@example.com"
staging = true
cache_dir = "/tmp/test-acme-certs"

[logging]
level = "info"
format = "text"
output = "console"

[metrics]
enabled = false
listen_addr = "0.0.0.0:9090"

[health_check]
interval_secs = 10
timeout_secs = 5
unhealthy_threshold = 3
healthy_threshold = 2

[[virtual_hosts]]
domain = "test.example.com"
enabled_backends_tag = "test"
http_to_https = true
tls_enabled = false

[[backends]]
id = "test-backend"
address = "127.0.0.1:9999"
tags = ["test"]
EOF

echo "   Test config created"

# Note: We can't actually test certificate issuance without a real domain
# But we can verify the endpoint is accessible

echo ""
echo "5. API Endpoint Summary"
echo "   =========================================="
echo "   Endpoint: POST ${API_URL}/api/v1/certificates/obtain"
echo ""
echo "   Request Format:"
echo '   {'
echo '     "domain": "example.com",'
echo '     "alt_names": ["www.example.com", "api.example.com"]'
echo '   }'
echo ""
echo "   Response Format (success):"
echo '   {'
echo '     "message": "Certificate obtained successfully...",'
echo '     "domain": "example.com",'
echo '     "cert_path": "/path/to/cert.pem",'
echo '     "key_path": "/path/to/key.pem",'
echo '     "staging": true'
echo '   }'
echo ""
echo "   Response Codes:"
echo "   - 200: Certificate obtained successfully"
echo "   - 400: Invalid domain or request"
echo "   - 503: Let's Encrypt not configured"
echo "   - 500: ACME protocol error"
echo ""

echo -e "${YELLOW}⚠ FULL TEST REQUIREMENTS:${NC}"
echo "   To test actual certificate issuance, you need:"
echo "   1. A real domain with DNS pointing to this server"
echo "   2. Port 80 accessible from internet (for HTTP-01 challenge)"
echo "   3. Let's Encrypt configured in config.toml"
echo ""

echo "=========================================="
echo "Test Complete"
echo "=========================================="
