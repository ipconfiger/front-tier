use pingora_vhost::config::{load_config, validate_tls_config, CertificateSource};
use std::fs::File;
use std::io::Write;

#[test]
fn test_parse_tls_config_file_source() {
    // Create a temporary config file with TLS settings
    let config_content = r#"
[proxy]
listen_addr = "0.0.0.0:443"
listen_addr_http = "0.0.0.0:80"
management_api_addr = "127.0.0.1:8080"

[lets_encrypt]
email = "admin@example.com"
staging = true
cache_dir = "/etc/pingora-ssl/certs"

[logging]
level = "info"
format = "text"
output = "console"

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
enabled_backends_tag = "a"
http_to_https = true
tls_enabled = false

[[virtual_hosts]]
domain = "secure.example.com"
enabled_backends_tag = "a"
http_to_https = true
tls_enabled = true
[virtual_hosts.certificate_source]
type = "file"
cert_path = "/etc/ssl/certs/secure.example.com.crt"
key_path = "/etc/ssl/private/secure.example.com.key"

[[virtual_hosts]]
domain = "auto-secure.example.com"
enabled_backends_tag = "a"
http_to_https = true
tls_enabled = true
[virtual_hosts.certificate_source]
type = "lets_encrypt"

[[backends]]
id = "web-v1"
address = "localhost:3001"
tags = ["a"]
"#;

    let temp_file = "/tmp/test_tls_parsing.toml";
    File::create(temp_file).unwrap().write_all(config_content.as_bytes()).unwrap();

    // Parse the config
    let config = load_config(temp_file).unwrap();

    // Verify we have 3 virtual hosts
    assert_eq!(config.virtual_hosts.len(), 3);

    // Check first host (TLS disabled)
    let vh1 = &config.virtual_hosts[0];
    assert_eq!(vh1.domain, "example.com");
    assert_eq!(vh1.tls_enabled, false);
    assert!(vh1.certificate_source.is_none());

    // Check second host (file-based TLS)
    let vh2 = &config.virtual_hosts[1];
    assert_eq!(vh2.domain, "secure.example.com");
    assert_eq!(vh2.tls_enabled, true);
    match &vh2.certificate_source {
        Some(CertificateSource::File { cert_path, key_path }) => {
            assert_eq!(cert_path, "/etc/ssl/certs/secure.example.com.crt");
            assert_eq!(key_path, "/etc/ssl/private/secure.example.com.key");
        }
        _ => panic!("Expected File certificate source"),
    }

    // Check third host (Let's Encrypt TLS)
    let vh3 = &config.virtual_hosts[2];
    assert_eq!(vh3.domain, "auto-secure.example.com");
    assert_eq!(vh3.tls_enabled, true);
    match &vh3.certificate_source {
        Some(CertificateSource::LetsEncrypt) => {}
        _ => panic!("Expected LetsEncrypt certificate source"),
    }

    // Verify TLS validation fails for non-existent files
    let result = validate_tls_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("certificate file does not exist"));

    // Clean up
    std::fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_parse_tls_config_lets_encrypt_valid() {
    // Create a temporary config file with Let's Encrypt
    let config_content = r#"
[proxy]
listen_addr = "0.0.0.0:443"
listen_addr_http = "0.0.0.0:80"
management_api_addr = "127.0.0.1:8080"

[lets_encrypt]
email = "admin@example.com"
staging = true
cache_dir = "/etc/pingora-ssl/certs"

[logging]
level = "info"
format = "text"
output = "console"

[metrics]
enabled = true
listen_addr = "0.0.0.0:9090"

[health_check]
interval_secs = 10
timeout_secs = 5
unhealthy_threshold = 3
healthy_threshold = 2

[[virtual_hosts]]
domain = "auto.example.com"
enabled_backends_tag = "a"
http_to_https = true
tls_enabled = true
[virtual_hosts.certificate_source]
type = "lets_encrypt"

[[backends]]
id = "web-v1"
address = "localhost:3001"
tags = ["a"]
"#;

    let temp_file = "/tmp/test_tls_letsencrypt.toml";
    File::create(temp_file).unwrap().write_all(config_content.as_bytes()).unwrap();

    // Parse the config
    let config = load_config(temp_file).unwrap();

    // Verify TLS validation passes (Let's Encrypt doesn't require files)
    let result = validate_tls_config(&config);
    assert!(result.is_ok());

    // Clean up
    std::fs::remove_file(temp_file).unwrap();
}
