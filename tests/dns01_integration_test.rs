//! DNS-01 challenge integration tests

#[cfg(test)]
mod tests {
    use pingora_vhost::tls::dns_provider::{DnsProvider, extract_base_domain};
    use pingora_vhost::tls::dns_provider::AliyunDnsProvider;

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("example.com"), "example.com");
        assert_eq!(extract_base_domain("www.example.com"), "example.com");
        assert_eq!(extract_base_domain("api.sub.example.com"), "example.com");
        assert_eq!(extract_base_domain("single"), "single");
    }

    #[test]
    fn test_aliyun_provider_creation() {
        let provider = AliyunDnsProvider::new(
            "test_key_id".to_string(),
            "test_key_secret".to_string(),
        );

        assert_eq!(provider.provider_name(), "Aliyun DNS");
    }

    // TODO: Add integration test with mock Aliyun API
    // Requires setting up a test server or using recorded responses

    // TODO: Add end-to-end test with Let's Encrypt staging
    // Requires:
    // - Test domain with DNS access
    // - Valid Aliyun credentials
    // - Long-running test (5+ minutes)
}
