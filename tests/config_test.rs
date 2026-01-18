use pingora_vhost::config::{Config, validate_config, validate_tls_config, CertificateSource};

#[test]
fn test_validate_config_invalid_backend_address() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: None,
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "invalid-address".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_config(&config);
    assert!(result.is_err());
}

#[test]
fn test_validate_config_valid() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: None,
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![pingora_vhost::config::VirtualHost {
            domain: "test.com".to_string(),
            enabled_backends_tag: "a".to_string(),
            http_to_https: true,
            tls_enabled: false,
            certificate_source: None,
        }],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "127.0.0.1:3001".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_config(&config);
    assert!(result.is_ok());
}

#[test]
fn test_validate_tls_config_disabled_by_default() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: None,
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![pingora_vhost::config::VirtualHost {
            domain: "test.com".to_string(),
            enabled_backends_tag: "a".to_string(),
            http_to_https: true,
            tls_enabled: false,
            certificate_source: None,
        }],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "127.0.0.1:3001".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_tls_config(&config);
    assert!(result.is_ok());
}

#[test]
fn test_validate_tls_config_enabled_no_source() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: None,
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![pingora_vhost::config::VirtualHost {
            domain: "test.com".to_string(),
            enabled_backends_tag: "a".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: None,
        }],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "127.0.0.1:3001".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_tls_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no certificate_source configured"));
}

#[test]
fn test_validate_tls_config_file_source_missing_files() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: None,
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![pingora_vhost::config::VirtualHost {
            domain: "test.com".to_string(),
            enabled_backends_tag: "a".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::File {
                cert_path: "/nonexistent/cert.crt".to_string(),
                key_path: "/nonexistent/cert.key".to_string(),
            }),
        }],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "127.0.0.1:3001".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_tls_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("certificate file does not exist"));
}

#[test]
fn test_validate_tls_config_lets_encrypt_no_config() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: None,
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![pingora_vhost::config::VirtualHost {
            domain: "test.com".to_string(),
            enabled_backends_tag: "a".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::LetsEncrypt),
        }],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "127.0.0.1:3001".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_tls_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("[lets_encrypt] section is not configured"));
}

#[test]
fn test_validate_tls_config_lets_encrypt_with_config() {
    let config = Config {
        proxy: pingora_vhost::config::ProxyConfig {
            listen_addr: "0.0.0.0:443".to_string(),
            listen_addr_http: Some("0.0.0.0:80".to_string()),
            management_api_addr: "127.0.0.1:8080".to_string(),
        },
        lets_encrypt: Some({
            let mut le_config = pingora_vhost::config::LetEncryptConfig::default();
            le_config.email = "admin@example.com".to_string();
            le_config.cache_dir = "/etc/pingora-ssl/certs".to_string();
            le_config
        }),
        logging: pingora_vhost::config::LoggingConfig {
            level: "info".to_string(),
            format: "text".to_string(),
            output: "console".to_string(),
            file_path: None,
        },
        metrics: pingora_vhost::config::MetricsConfig {
            enabled: true,
            listen_addr: "0.0.0.0:9090".to_string(),
        },
        health_check: pingora_vhost::config::HealthCheckConfig {
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        },
        virtual_hosts: vec![pingora_vhost::config::VirtualHost {
            domain: "test.com".to_string(),
            enabled_backends_tag: "a".to_string(),
            http_to_https: true,
            tls_enabled: true,
            certificate_source: Some(CertificateSource::LetsEncrypt),
        }],
        backends: vec![pingora_vhost::config::Backend {
            id: "test".to_string(),
            address: "127.0.0.1:3001".to_string(),
            tags: vec!["a".to_string()],
        }],
    };

    let result = validate_tls_config(&config);
    assert!(result.is_ok());
}
