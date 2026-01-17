use crate::config::{BackendConfig, Config, VhostConfig};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BackendHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

impl Default for BackendHealth {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Default)]
pub struct BackendStatus {
    pub health: BackendHealth,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub vhost_configs: Arc<RwLock<HashMap<String, VhostConfig>>>,
    pub backend_status: Arc<RwLock<HashMap<String, BackendStatus>>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let vhost_configs = config.vhosts.clone();
        Self {
            config: Arc::new(RwLock::new(config)),
            vhost_configs: Arc::new(RwLock::new(vhost_configs)),
            backend_status: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_vhost_config(&self, domain: &str) -> Option<VhostConfig> {
        self.vhost_configs.read().await.get(domain).cloned()
    }

    pub async fn update_vhost_config(&self, domain: String, config: VhostConfig) {
        let mut vhosts = self.vhost_configs.write().await;
        vhosts.insert(domain, config);
    }

    pub async fn remove_vhost_config(&self, domain: &str) {
        let mut vhosts = self.vhost_configs.write().await;
        vhosts.remove(domain);
    }

    pub async fn get_backend_status(&self, backend_id: &str) -> Option<BackendStatus> {
        self.backend_status.read().await.get(backend_id).cloned()
    }

    pub async fn update_backend_status(&self, backend_id: String, status: BackendStatus) {
        let mut backends = self.backend_status.write().await;
        backends.insert(backend_id, status);
    }
}
