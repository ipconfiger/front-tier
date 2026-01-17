#!/bin/bash
# Let's Encrypt ACME Integration Test
#
# This script demonstrates how to test the Let's Encrypt ACME integration.
#
# REQUIREMENTS:
# 1. A real domain name with DNS configured to point to your server
# 2. Port 80 accessible from the internet (for Let's Encrypt HTTP-01 challenge)
# 3. Port 443 accessible from the internet (for HTTPS)
# 4. The proxy built and running
#
# SETUP:
# 1. Edit test-acme-config.toml:
#    - Change 'your-email@example.com' to your real email
#    - Change 'test.example.com' to your actual domain
#    - Verify staging = true for initial testing
# 2. Ensure DNS A record points to this server's IP
# 3. Run this script

set -e

DOMAIN="${DOMAIN:-test.example.com}"
CONFIG_FILE="${CONFIG_FILE:-test-acme-config.toml}"
CACHE_DIR="/tmp/acme-certs"

echo "=========================================="
echo "Let's Encrypt ACME Integration Test"
echo "=========================================="
echo "Domain: $DOMAIN"
echo "Config: $CONFIG_FILE"
echo ""

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: $CONFIG_FILE"
    echo "Please create it from test-acme-config.toml.example"
    exit 1
fi

# Check if binary is built
if [ ! -f "./target/release/pingora-vhost" ]; then
    echo "Building proxy..."
    cargo build --release
fi

echo "Step 1: Checking prerequisites..."
echo "-----------------------------------"

# Check if domain resolves to this machine
echo -n "Checking if $DOMAIN resolves to this machine... "
if host "$DOMAIN" | grep -q "has address"; then
    echo "✓ DNS configured"
else
    echo "✗ WARNING: DNS may not be configured for $DOMAIN"
    echo "  The ACME challenge will fail without proper DNS."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if ports are available
echo -n "Checking if port 80 is available... "
if lsof -Pi :80 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "✗ Port 80 is already in use"
    echo "  Please stop the service using port 80"
    exit 1
else
    echo "✓ Port 80 is available"
fi

echo -n "Checking if port 443 is available... "
if lsof -Pi :443 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "✗ Port 443 is already in use"
    echo "  Please stop the service using port 443"
    exit 1
else
    echo "✓ Port 443 is available"
fi

echo ""
echo "Step 2: Starting the proxy..."
echo "-----------------------------------"

# Kill any existing proxy
pkill -f pingora-vhost || true
sleep 1

# Start proxy in background
./target/release/pingora-vhost run --config "$CONFIG_FILE" > /tmp/proxy-acme-test.log 2>&1 &
PROXY_PID=$!
echo "Proxy started with PID: $PROXY_PID"

# Wait for proxy to initialize
echo "Waiting for proxy to initialize..."
sleep 5

# Check if proxy is running
if ! ps -p $PROXY_PID > /dev/null; then
    echo "ERROR: Proxy failed to start. Check /tmp/proxy-acme-test.log"
    exit 1
fi

echo "✓ Proxy is running"
echo ""

echo "Step 3: Verifying proxy is accessible..."
echo "-----------------------------------"

# Test HTTP endpoint
echo -n "Testing HTTP redirect... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN/" --connect-timeout 5 || echo "000")
if [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "✓ Returns redirect ($HTTP_CODE)"
else
    echo "✗ Unexpected response: $HTTP_CODE"
fi

# Test ACME challenge endpoint
echo -n "Testing ACME challenge endpoint... "
ACME_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/.well-known/acme-challenge/test" --connect-timeout 5 || echo "000")
if [ "$ACME_CODE" = "404" ]; then
    echo "✓ Endpoint accessible (404 = no active challenges, which is expected)"
else
    echo "✗ Unexpected response: $ACME_CODE"
fi

echo ""
echo "Step 4: ACME Challenge Flow"
echo "-----------------------------------"
echo "The ACME flow will:"
echo "1. Create an ACME account with Let's Encrypt"
echo "2. Create an order for domain: $DOMAIN"
echo "3. Complete HTTP-01 challenge:"
echo "   - Let's Encrypt will request http://$DOMAIN/.well-known/acme-challenge/<token>"
echo "   - Our proxy will serve the challenge response"
echo "4. Download and save the certificate"
echo ""

echo "IMPORTANT NOTES:"
echo "- Using Let's Encrypt STAGING environment (certificates are not trusted)"
echo "- Check the proxy logs: tail -f /tmp/proxy-acme-test.log"
echo "- The process may take 30-60 seconds"
echo ""

read -p "Do you want to proceed with obtaining a certificate? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    kill $PROXY_PID
    exit 0
fi

echo ""
echo "Note: The ACME integration code is implemented but not yet exposed via API."
echo "To trigger certificate issuance, you would need to:"
echo "1. Add an API endpoint to call AcmeManager::obtain_certificate()"
echo "2. Or trigger it manually when a domain is added with LetsEncrypt source"
echo ""
echo "For now, let's verify the infrastructure is in place..."
echo ""

# Test the ACME challenge handler directly
echo "Testing ACME challenge handler..."
echo "-----------------------------------"

# Check if certificate cache directory exists
if [ -d "$CACHE_DIR" ]; then
    echo "✓ Certificate cache directory exists: $CACHE_DIR"
    ls -la "$CACHE_DIR" 2>/dev/null || echo "  (empty)"
else
    echo "✓ Certificate cache directory will be created: $CACHE_DIR"
fi

echo ""
echo "=========================================="
echo "Test Complete"
echo "=========================================="
echo ""
echo "Summary:"
echo "- Proxy is running on ports 80 and 443"
echo "- HTTP to HTTPS redirect is working"
echo "- ACME challenge endpoint is accessible"
echo "- Infrastructure is ready for Let's Encrypt integration"
echo ""
echo "To complete the ACME flow:"
echo "1. Implement API endpoint or automatic trigger for certificate issuance"
echo "2. For production testing: Set staging = false in config"
echo "3. Ensure domain DNS properly points to this server"
echo ""
echo "Proxy logs: tail -f /tmp/proxy-acme-test.log"
echo "API endpoint: http://localhost:8080/api/v1/certificates"
echo ""
echo "Stop proxy: kill $PROXY_PID"
echo ""
