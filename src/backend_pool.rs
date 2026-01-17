use crate::config::Backend;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Thread-safe backend pool with tag-based lookup
#[derive(Clone)]
pub struct BackendPool {
    backends: Arc<RwLock<HashMap<String, Backend>>>,
    tag_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl BackendPool {
    /// Create a new empty backend pool
    pub fn new() -> Self {
        Self {
            backends: Arc::new(RwLock::new(HashMap::new())),
            tag_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a backend to the pool
    pub async fn add_backend(&self, backend: Backend) {
        // Add to main storage
        let mut backends = self.backends.write().await;
        let backend_id = backend.id.clone();
        let backend_tags = backend.tags.clone();

        backends.insert(backend_id.clone(), backend);

        // Update tag index
        let mut tag_index = self.tag_index.write().await;
        for tag in backend_tags {
            tag_index
                .entry(tag)
                .or_insert_with(Vec::new)
                .push(backend_id.clone());
        }
    }

    /// Get a backend by ID
    pub async fn get_backend(&self, id: &str) -> Option<Backend> {
        let backends = self.backends.read().await;
        backends.get(id).cloned()
    }

    /// Get all backends with a specific tag
    pub async fn get_backends_by_tag(&self, tag: &str) -> Vec<Backend> {
        let tag_index = self.tag_index.read().await;
        let backends = self.backends.read().await;

        if let Some(backend_ids) = tag_index.get(tag) {
            backend_ids
                .iter()
                .filter_map(|id| backends.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Remove a backend from the pool
    pub async fn remove_backend(&self, id: &str) {
        // Get backend info before removing
        let backend_tags = {
            let backends = self.backends.read().await;
            backends.get(id).map(|b| b.tags.clone())
        };

        if let Some(tags) = backend_tags {
            // Remove from tag index
            let mut tag_index = self.tag_index.write().await;
            for tag in &tags {
                if let Some(backend_list) = tag_index.get_mut(tag) {
                    backend_list.retain(|backend_id| backend_id != id);
                    // Clean up empty tag entries
                    if backend_list.is_empty() {
                        tag_index.remove(tag);
                    }
                }
            }

            // Remove from main storage
            let mut backends = self.backends.write().await;
            backends.remove(id);
        }
    }

    /// Get all backends
    pub async fn list_backends(&self) -> Vec<Backend> {
        let backends = self.backends.read().await;
        backends.values().cloned().collect()
    }

    /// Get all tags
    pub async fn list_tags(&self) -> Vec<String> {
        let tag_index = self.tag_index.read().await;
        tag_index.keys().cloned().collect()
    }
}

impl Default for BackendPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backend_pool() {
        let pool = BackendPool::new();

        // Test adding backends
        pool.add_backend(Backend {
            id: "backend-1".to_string(),
            address: "localhost:3001".to_string(),
            tags: vec!["tag1".to_string()],
        })
        .await;

        pool.add_backend(Backend {
            id: "backend-2".to_string(),
            address: "localhost:3002".to_string(),
            tags: vec!["tag2".to_string(), "tag1".to_string()],
        })
        .await;

        // Test get_backend
        let backend = pool.get_backend("backend-1").await;
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().address, "localhost:3001");

        // Test get_backends_by_tag
        let tag1_backends = pool.get_backends_by_tag("tag1").await;
        assert_eq!(tag1_backends.len(), 2);

        let tag2_backends = pool.get_backends_by_tag("tag2").await;
        assert_eq!(tag2_backends.len(), 1);

        // Test remove_backend
        pool.remove_backend("backend-1").await;
        let backend = pool.get_backend("backend-1").await;
        assert!(backend.is_none());

        // Verify tag index was updated
        let tag1_backends = pool.get_backends_by_tag("tag1").await;
        assert_eq!(tag1_backends.len(), 1);
    }
}
