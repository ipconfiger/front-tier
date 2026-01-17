use crate::config::{Backend, VirtualHost};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct BackendHealth {
    pub healthy: bool,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub virtual_hosts: Arc<RwLock<HashMap<String, VirtualHost>>>,
    pub backends: Arc<RwLock<HashMap<String, Backend>>>,
    pub backend_health: Arc<RwLock<HashMap<String, BackendHealth>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            virtual_hosts: Arc::new(RwLock::new(HashMap::new())),
            backends: Arc::new(RwLock::new(HashMap::new())),
            backend_health: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[allow(dead_code)]
impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn from_config(
        virtual_hosts: Vec<VirtualHost>,
        backends: Vec<Backend>,
    ) -> Self {
        let vh_map: HashMap<String, VirtualHost> = virtual_hosts
            .into_iter()
            .map(|vh| (vh.domain.clone(), vh))
            .collect();

        let backend_map: HashMap<String, Backend> = backends
            .into_iter()
            .map(|b| (b.id.clone(), b))
            .collect();

        // Initialize backend health with default values for each backend
        let health_map: HashMap<String, BackendHealth> = backend_map
            .keys()
            .map(|id| (id.clone(), BackendHealth::default()))
            .collect();

        Self {
            virtual_hosts: Arc::new(RwLock::new(vh_map)),
            backends: Arc::new(RwLock::new(backend_map)),
            backend_health: Arc::new(RwLock::new(health_map)),
        }
    }
}
