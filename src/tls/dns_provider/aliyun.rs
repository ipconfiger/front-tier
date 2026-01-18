//! Aliyun (Alibaba Cloud) DNS provider for ACME DNS-01 challenges

use super::{DnsProvider, extract_base_domain};
use anyhow::{Result, anyhow, Context};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use std::collections::HashMap;
use tracing::{info, debug, error};
use base64::Engine as _;

const ALIYUN_API_ENDPOINT: &str = "https://alidns.aliyuncs.com/";

/// RFC 3986 percent encoding for Aliyun API signature
/// Aliyun requires: %20 for spaces, %2A for *, %7E becomes ~
fn percent_encode(s: &str) -> String {
    urlencoding::encode(s)
        .replace("+", "%20")
        .replace("*", "%2A")
        .replace("%7E", "~")
}

/// Aliyun DNS provider credentials
#[derive(Clone)]
pub struct AliyunDnsProvider {
    access_key_id: String,
    access_key_secret: String,
    client: Client,
}

impl std::fmt::Debug for AliyunDnsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AliyunDnsProvider")
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"<REDACTED>")
            .finish()
    }
}

impl AliyunDnsProvider {
    pub fn new(access_key_id: String, access_key_secret: String) -> Self {
        Self {
            access_key_id,
            access_key_secret,
            client: Client::new(),
        }
    }

    /// Generate Aliyun API signature
    fn sign_request(&self, params: &mut HashMap<String, String>) -> String {
        // Add common parameters
        params.insert("AccessKeyId".to_string(), self.access_key_id.clone());
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("Version".to_string(), "2015-01-09".to_string());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("SignatureNonce".to_string(), uuid::Uuid::new_v4().to_string());
        params.insert("Timestamp".to_string(), Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());

        // Sort parameters
        let mut sorted_keys: Vec<String> = params.keys().cloned().collect();
        sorted_keys.sort();

        // DEBUG: Log all parameters before encoding
        debug!("=== Aliyun Signature Debug ===");
        debug!("Parameters (before encoding):");
        for key in &sorted_keys {
            debug!("  {} = {}", key, params[key]);
        }

        // Create canonical query string with full RFC 3986 encoding
        let canonical_query_string: String = sorted_keys
            .iter()
            .map(|key| {
                format!("{}={}", percent_encode(key), percent_encode(&params[key]))
            })
            .collect::<Vec<_>>()
            .join("&");

        // DEBUG: Log canonical query string
        debug!("Canonical query string: {}", canonical_query_string);

        // Create string to sign (encode canonical query string)
        let string_to_sign = format!("GET&%2F&{}", percent_encode(&canonical_query_string));

        // DEBUG: Log string to sign
        debug!("String to sign: {}", string_to_sign);
        debug!("String to sign (bytes): {:?}", string_to_sign.as_bytes());

        // Generate HMAC-SHA1 signature
        use hmac::{Hmac, Mac};
        type HmacSha1 = Hmac<sha1::Sha1>;

        let key = format!("{}&", self.access_key_secret);
        debug!("HMAC key: {}&", self.access_key_id);
        debug!("HMAC key (bytes): {:?}", key.as_bytes());

        let mut mac = HmacSha1::new_from_slice(key.as_bytes()).unwrap();
        mac.update(string_to_sign.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature = base64::engine::general_purpose::STANDARD.encode(&signature_bytes);

        // DEBUG: Log signature
        debug!("Signature (Base64): {}", signature);
        debug!("========================");

        signature
    }

    /// Make API request to Aliyun
    async fn make_request(&self, action: &str, mut params: HashMap<String, String>) -> Result<serde_json::Value> {
        params.insert("Action".to_string(), action.to_string());

        let signature = self.sign_request(&mut params);
        params.insert("Signature".to_string(), signature);

        // Build URL manually with proper encoding
        let mut sorted_keys: Vec<String> = params.keys().cloned().collect();
        sorted_keys.sort();

        let query_string: String = sorted_keys
            .iter()
            .map(|key| {
                format!("{}={}", percent_encode(key), percent_encode(&params[key]))
            })
            .collect::<Vec<_>>()
            .join("&");

        let url = format!("{}?{}", ALIYUN_API_ENDPOINT.trim_end_matches('/'), query_string);

        // DEBUG: Log the full URL
        debug!("Request URL: {}", url);
        info!("Making Aliyun API request: {}", action);

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to Aliyun API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // DEBUG: Log error details
            error!("Aliyun API error!");
            error!("Status: {}", status);
            error!("Response body: {}", body);

            return Err(anyhow!("Aliyun API returned error {}: {}", status, body));
        }

        let json: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse Aliyun API response")?;

        Ok(json)
    }

    /// Get record ID for a specific TXT record
    async fn find_txt_record_id(&self, domain: &str, txt_value: &str) -> Result<Option<String>> {
        let base_domain = extract_base_domain(domain);
        let record_name = format!("_acme-challenge.{}", domain);

        // RR must be relative to the domain (not the full FQDN)
        let rr = record_name
            .strip_suffix(&format!(".{}", base_domain))
            .unwrap_or(&record_name);

        let mut params = HashMap::new();
        params.insert("DomainName".to_string(), base_domain);
        params.insert("TypeKeyWord".to_string(), "TXT".to_string());
        params.insert("RRKeyWord".to_string(), rr.to_string());

        let response = self.make_request("DescribeDomainRecords", params).await?;

        if let Some(records) = response["DomainRecords"]["Record"].as_array() {
            for record in records {
                if record["Value"].as_str() == Some(txt_value) {
                    if let Some(record_id) = record["RecordId"].as_str() {
                        return Ok(Some(record_id.to_string()));
                    }
                }
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl DnsProvider for AliyunDnsProvider {
    async fn create_txt_record(&self, domain: &str, txt_value: &str) -> Result<()> {
        let base_domain = extract_base_domain(domain);
        let record_name = format!("_acme-challenge.{}", domain);

        info!(
            "Creating TXT record on Aliyun: {} = {}",
            record_name, txt_value
        );

        // Check if record already exists
        if let Some(existing_id) = self.find_txt_record_id(domain, txt_value).await? {
            debug!("TXT record already exists with ID: {}", existing_id);
            return Ok(());
        }

        // RR must be relative to the domain (not the full FQDN)
        // For "_acme-challenge.front-tier.xrays.tech" with domain "xrays.tech",
        // RR should be "_acme-challenge.front-tier"
        let rr = record_name
            .strip_suffix(&format!(".{}", base_domain))
            .unwrap_or(&record_name);

        let mut params = HashMap::new();
        params.insert("DomainName".to_string(), base_domain);
        params.insert("RR".to_string(), rr.to_string());
        params.insert("Type".to_string(), "TXT".to_string());
        params.insert("Value".to_string(), txt_value.to_string());
        params.insert("TTL".to_string(), "600".to_string());

        let response = self.make_request("AddDomainRecord", params).await?;

        if let Some(record_id) = response["RecordId"].as_str() {
            info!("Created TXT record with ID: {}", record_id);
            Ok(())
        } else {
            Err(anyhow!("Failed to create TXT record: no RecordId in response"))
        }
    }

    async fn delete_txt_record(&self, domain: &str, txt_value: &str) -> Result<()> {
        if let Some(record_id) = self.find_txt_record_id(domain, txt_value).await? {
            info!("Deleting TXT record with ID: {}", record_id);

            let mut params = HashMap::new();
            params.insert("RecordId".to_string(), record_id);

            self.make_request("DeleteSubDomainRecord", params).await?;

            info!("Deleted TXT record successfully");
        }

        Ok(())
    }

    fn provider_name(&self) -> &str {
        "Aliyun DNS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aliyun_provider_creation() {
        let provider = AliyunDnsProvider::new(
            "test_key".to_string(),
            "test_secret".to_string(),
        );
        assert_eq!(provider.provider_name(), "Aliyun DNS");
    }
}
