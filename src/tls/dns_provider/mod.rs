//! DNS provider abstraction for ACME DNS-01 challenge validation

pub mod aliyun;

pub use aliyun::AliyunDnsProvider;

use anyhow::Result;
use async_trait::async_trait;

/// DNS provider trait for ACME DNS-01 challenge operations
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create or update a TXT record for ACME challenge
    async fn create_txt_record(&self, domain: &str, txt_value: &str) -> Result<()>;

    /// Delete a TXT record after challenge validation
    async fn delete_txt_record(&self, domain: &str, txt_value: &str) -> Result<()>;

    /// Get provider name for logging
    fn provider_name(&self) -> &str;
}

/// Extract the base domain for DNS operations
/// Examples:
/// - "example.com" -> "example.com"
/// - "www.example.com" -> "example.com"
/// - "_acme-challenge.sub.example.com" -> "example.com"
pub fn extract_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();

    // If we have 2+ parts, return the last 2 parts as base domain
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("example.com"), "example.com");
        assert_eq!(extract_base_domain("www.example.com"), "example.com");
        assert_eq!(extract_base_domain("sub.www.example.com"), "example.com");
        assert_eq!(extract_base_domain("single"), "single");
    }
}
