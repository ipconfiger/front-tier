use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_proxy")]
    pub proxy: ProxyConfig,

    #[serde(default = "default_management")]
    pub management: ManagementConfig,

    #[serde(default)]
    pub vhosts: HashMap<String, VhostConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_listen")]
    pub listen: String,

    #[serde(default = "default_proxy_threads")]
    pub threads: usize,

    #[serde(default = "default_proxy_client_timeout")]
    pub client_timeout_secs: u64,
}

fn default_proxy() -> ProxyConfig {
    ProxyConfig {
        listen: default_proxy_listen(),
        threads: default_proxy_threads(),
        client_timeout_secs: default_proxy_client_timeout(),
    }
}

fn default_proxy_listen() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_proxy_threads() -> usize {
    4
}

fn default_proxy_client_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementConfig {
    #[serde(default = "default_management_listen")]
    pub listen: String,

    #[serde(default = "default_management_api_token")]
    pub api_token: String,

    #[serde(default = "default_management_enable_tls")]
    pub enable_tls: bool,

    #[serde(default = "default_management_cert_path")]
    pub cert_path: String,

    #[serde(default = "default_management_key_path")]
    pub key_path: String,
}

fn default_management() -> ManagementConfig {
    ManagementConfig {
        listen: default_management_listen(),
        api_token: default_management_api_token(),
        enable_tls: default_management_enable_tls(),
        cert_path: default_management_cert_path(),
        key_path: default_management_key_path(),
    }
}

fn default_management_listen() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_management_api_token() -> String {
    "change-me-in-production".to_string()
}

fn default_management_enable_tls() -> bool {
    false
}

fn default_management_cert_path() -> String {
    "".to_string()
}

fn default_management_key_path() -> String {
    "".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VhostConfig {
    pub domain: String,

    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    #[serde(default)]
    pub backends: Vec<BackendConfig>,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub ab_test: Option<AbTestConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub path_prefix: String,
    pub backend_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    pub address: String,

    #[serde(default = "default_backend_port")]
    pub port: u16,

    #[serde(default = "default_backend_weight")]
    pub weight: u32,

    #[serde(default)]
    pub health_check: HealthCheckConfig,
}

fn default_backend_port() -> u16 {
    80
}

fn default_backend_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default = "default_health_check_path")]
    pub path: String,

    #[serde(default = "default_health_check_interval")]
    pub interval_secs: u64,

    #[serde(default = "default_health_check_timeout")]
    pub timeout_secs: u64,

    #[serde(default = "default_health_check_threshold")]
    pub unhealthy_threshold: u32,

    #[serde(default = "default_health_check_threshold")]
    pub healthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: default_health_check_path(),
            interval_secs: default_health_check_interval(),
            timeout_secs: default_health_check_timeout(),
            unhealthy_threshold: default_health_check_threshold(),
            healthy_threshold: default_health_check_threshold(),
        }
    }
}

fn default_health_check_path() -> String {
    "/health".to_string()
}

fn default_health_check_interval() -> u64 {
    10
}

fn default_health_check_timeout() -> u64 {
    5
}

fn default_health_check_threshold() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub cert_type: CertType,

    #[serde(default)]
    pub cert_path: String,

    #[serde(default)]
    pub key_path: String,

    #[serde(default)]
    pub lets_encrypt: Option<LetsEncryptConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_type: CertType::Rsa,
            cert_path: String::new(),
            key_path: String::new(),
            lets_encrypt: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertType {
    Rsa,
    Ecdsa,
}

impl Default for CertType {
    fn default() -> Self {
        Self::Rsa
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LetsEncryptConfig {
    pub email: String,

    #[serde(default = "default_lets_encrypt_staging")]
    pub staging: bool,

    #[serde(default = "default_lets_encrypt_cache_dir")]
    pub cache_dir: String,
}

fn default_lets_encrypt_staging() -> bool {
    false
}

fn default_lets_encrypt_cache_dir() -> String {
    "./certs/le".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbTestConfig {
    pub header_name: String,

    #[serde(default = "default_ab_test_header_value_a")]
    pub header_value_a: String,

    #[serde(default = "default_ab_test_header_value_b")]
    pub header_value_b: String,

    #[serde(default = "default_ab_test_percentage")]
    pub percentage_b: u32,
}

fn default_ab_test_header_value_a() -> String {
    "A".to_string()
}

fn default_ab_test_header_value_b() -> String {
    "B".to_string()
}

fn default_ab_test_percentage() -> u32 {
    50
}

pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy: default_proxy(),
            management: default_management(),
            vhosts: HashMap::new(),
        }
    }
}
