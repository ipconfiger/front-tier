use crate::config::Backend;
use anyhow::{anyhow, Result};
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
    /// Returns an error if a backend with the same ID already exists
    pub async fn add_backend(&self, backend: Backend) -> Result<()> {
        let backend_id = backend.id.clone();
        let backend_tags = backend.tags.clone();

        // Acquire both locks simultaneously to prevent race conditions
        // Order: backends first, then tag_index (consistent ordering prevents deadlock)
        let mut backends = self.backends.write().await;
        let mut tag_index = self.tag_index.write().await;

        // Check for duplicate
        if backends.contains_key(&backend_id) {
            return Err(anyhow!("Backend with ID '{}' already exists", backend_id));
        }

        // Add to main storage
        backends.insert(backend_id.clone(), backend);

        // Update tag index
        for tag in backend_tags {
            tag_index
                .entry(tag)
                .or_insert_with(Vec::new)
                .push(backend_id.clone());
        }

        Ok(())
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
    /// Returns an error if the backend doesn't exist
    pub async fn remove_backend(&self, id: &str) -> Result<()> {
        // Acquire both locks simultaneously to prevent race conditions
        // Same order as add_backend: backends first, then tag_index
        let mut backends = self.backends.write().await;
        let mut tag_index = self.tag_index.write().await;

        // Check if backend exists and get its tags
        let backend = backends
            .get(id)
            .ok_or_else(|| anyhow!("Backend with ID '{}' not found", id))?;
        let backend_tags = backend.tags.clone();

        // Remove from tag index
        for tag in &backend_tags {
            if let Some(backend_list) = tag_index.get_mut(tag) {
                backend_list.retain(|backend_id| backend_id != id);
                // Clean up empty tag entries
                if backend_list.is_empty() {
                    tag_index.remove(tag);
                }
            }
        }

        // Remove from main storage
        backends.remove(id);

        Ok(())
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
        .await
        .unwrap();

        pool.add_backend(Backend {
            id: "backend-2".to_string(),
            address: "localhost:3002".to_string(),
            tags: vec!["tag2".to_string(), "tag1".to_string()],
        })
        .await
        .unwrap();

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
        pool.remove_backend("backend-1").await.unwrap();
        let backend = pool.get_backend("backend-1").await;
        assert!(backend.is_none());

        // Verify tag index was updated
        let tag1_backends = pool.get_backends_by_tag("tag1").await;
        assert_eq!(tag1_backends.len(), 1);
    }

    #[tokio::test]
    async fn test_duplicate_prevention() {
        let pool = BackendPool::new();

        let backend = Backend {
            id: "backend-1".to_string(),
            address: "localhost:3001".to_string(),
            tags: vec!["tag1".to_string()],
        };

        // First add should succeed
        pool.add_backend(backend.clone())
            .await
            .unwrap();

        // Second add should fail
        let result = pool.add_backend(backend).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn test_remove_nonexistent_backend() {
        let pool = BackendPool::new();

        // Removing non-existent backend should fail
        let result = pool.remove_backend("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }
}
