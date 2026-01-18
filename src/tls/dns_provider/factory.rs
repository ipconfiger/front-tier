//! Factory for creating DNS provider instances from configuration

use super::{DnsProvider, AliyunDnsProvider};
use crate::config::DnsProviderConfig;
use anyhow::Result;

/// Create a DNS provider instance from configuration
pub fn create_dns_provider(config: &DnsProviderConfig) -> Result<Box<dyn DnsProvider>> {
    match config {
        DnsProviderConfig::Aliyun { access_key_id, access_key_secret } => {
            Ok(Box::new(AliyunDnsProvider::new(
                access_key_id.clone(),
                access_key_secret.clone(),
            )))
        }
        DnsProviderConfig::Cloudflare { api_token: _ } => {
            // TODO: Implement Cloudflare provider
            Err(anyhow::anyhow!("Cloudflare provider not yet implemented"))
        }
        DnsProviderConfig::Dnspod { secret_id: _, secret_key: _ } => {
            // TODO: Implement DNSPod provider
            Err(anyhow::anyhow!("DNSPod provider not yet implemented"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_aliyun_provider() {
        let config = DnsProviderConfig::Aliyun {
            access_key_id: "test_id".to_string(),
            access_key_secret: "test_secret".to_string(),
        };

        let provider = create_dns_provider(&config).unwrap();
        assert_eq!(provider.provider_name(), "Aliyun DNS");
    }

    #[test]
    fn test_unimplemented_providers() {
        let cf_config = DnsProviderConfig::Cloudflare {
            api_token: "test_token".to_string(),
        };

        assert!(create_dns_provider(&cf_config).is_err());
    }
}
