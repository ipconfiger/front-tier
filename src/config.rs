use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub lets_encrypt: Option<LetEncryptConfig>,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub health_check: HealthCheckConfig,
    pub virtual_hosts: Vec<VirtualHost>,
    pub backends: Vec<Backend>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    #[serde(default)]
    pub listen_addr_http: Option<String>,
    pub management_api_addr: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LetEncryptConfig {
    pub email: String,
    #[serde(default)]
    pub staging: bool,
    pub cache_dir: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_output")]
    pub output: String,
    #[serde(default)]
    pub file_path: Option<String>,
}

fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "json".to_string() }
fn default_log_output() -> String { "console".to_string() }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_addr")]
    pub listen_addr: String,
}

fn default_metrics_addr() -> String { "0.0.0.0:9090".to_string() }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthCheckConfig {
    #[serde(default = "default_check_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_check_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

fn default_check_interval() -> u64 { 10 }
fn default_check_timeout() -> u64 { 5 }
fn default_unhealthy_threshold() -> u32 { 3 }
fn default_healthy_threshold() -> u32 { 2 }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VirtualHost {
    pub domain: String,
    pub enabled_backends_tag: String,
    #[serde(default = "default_http_to_https")]
    pub http_to_https: bool,
}

fn default_http_to_https() -> bool { true }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Backend {
    pub id: String,
    pub address: String,
    pub tags: Vec<String>,
}

pub fn load_config(path: &str) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path))?;

    let config: Config = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse config file: {}", path))?;

    // Validate config has at least some content
    if config.virtual_hosts.is_empty() && config.backends.is_empty() {
        anyhow::bail!(
            "Config validation failed: must have at least one virtual_host or backend"
        );
    }

    Ok(config)
}

pub fn validate_config(config: &Config) -> Result<(), String> {
    // Validate backends have valid addresses
    for backend in &config.backends {
        if backend.address.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!("Invalid backend address: {}", backend.address));
        }
        if backend.tags.is_empty() {
            return Err(format!("Backend {} has no tags", backend.id));
        }
    }

    // Validate virtual hosts have valid backend tags
    let all_tags: std::collections::HashSet<&String> = config.backends
        .iter()
        .flat_map(|b| &b.tags)
        .collect();

    for vh in &config.virtual_hosts {
        if !all_tags.contains(&vh.enabled_backends_tag) {
            return Err(format!(
                "Domain {} references non-existent tag '{}'",
                vh.domain, vh.enabled_backends_tag
            ));
        }
    }

    Ok(())
}
