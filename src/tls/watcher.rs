//! Certificate hot reload watcher for automatic certificate reloading when files change on disk

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::CertificateManager;

/// Certificate watcher for automatic hot reload
#[derive(Debug)]
pub struct CertificateWatcher {
    /// Certificate manager for reloading certificates
    cert_manager: Arc<CertificateManager>,
    /// Map of file path to domain name
    /// Used to determine which domain's certificate to reload when a file changes
    watched_paths: Mutex<HashMap<String, String>>,
    /// Debounce duration to prevent rapid reloads
    debounce_duration: Duration,
}

impl CertificateWatcher {
    /// Create a new certificate watcher
    ///
    /// # Arguments
    /// * `cert_manager` - Certificate manager for reloading certificates
    /// * `debounce_secs` - Debounce duration in seconds (default: 1)
    pub fn new(cert_manager: Arc<CertificateManager>, debounce_secs: u64) -> Self {
        Self {
            cert_manager,
            watched_paths: Mutex::new(HashMap::new()),
            debounce_duration: Duration::from_secs(debounce_secs),
        }
    }

    /// Add a file path to watch and associate it with a domain
    ///
    /// # Arguments
    /// * `path` - Path to certificate or key file
    /// * `domain` - Domain name to reload when this file changes
    pub async fn add_watch(&self, path: String, domain: String) {
        let mut watched = self.watched_paths.lock().await;
        watched.insert(path.clone(), domain.clone());
        debug!("Added watch for domain: {} (total watched paths: {})", domain, watched.len());
    }

    /// Add multiple watch paths from a virtual host configuration
    ///
    /// # Arguments
    /// * `domain` - Domain name
    /// * `cert_path` - Path to certificate file (optional)
    /// * `key_path` - Path to key file (optional)
    pub async fn add_watch_paths(
        &self,
        domain: &str,
        cert_path: Option<&String>,
        key_path: Option<&String>,
    ) {
        if let Some(cert_path) = cert_path {
            self.add_watch(cert_path.clone(), domain.to_string()).await;
        }
        if let Some(key_path) = key_path {
            self.add_watch(key_path.clone(), domain.to_string()).await;
        }
    }

    /// Extract directory path from file path
    ///
    /// We watch the parent directory instead of the file itself because:
    /// - notify crate works better with directory watching
    /// - Some filesystems don't support individual file watching
    /// - We can filter events by file path in the event handler
    fn extract_directory(path: &str) -> Result<PathBuf> {
        let path = Path::new(path);
        path.parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| anyhow::anyhow!("Failed to extract parent directory from path: {:?}", path))
    }

    /// Start the file watcher as a background task
    ///
    /// This method spawns a tokio task that:
    /// 1. Creates a notify watcher
    /// 2. Adds watch for each certificate directory
    /// 3. Receives file change events
    /// 4. Debounces events
    /// 5. Calls cert_manager.reload_certificate() for affected domains
    ///
    /// # Errors
    /// Returns error if watcher creation fails
    ///
    /// # Note
    /// This method must be called from a thread that can block (not from within an async runtime).
    /// In async tests, you'll need to use `tokio::task::spawn_blocking` or call from outside async context.
    pub fn start(self: Arc<Self>) -> Result<tokio::task::JoinHandle<()>> {
        // Get unique set of directories to watch
        // Use try_lock for non-blocking, or blocking_lock in non-async context
        let dirs_to_watch = {
            let watched = self.watched_paths.try_lock()
                .map_err(|_| anyhow::anyhow!("Failed to acquire lock on watched_paths"))?;
            let mut dirs = std::collections::HashSet::new();
            for path in watched.keys() {
                match Self::extract_directory(path) {
                    Ok(dir) => {
                        debug!("Watching directory: {:?}", dir);
                        dirs.insert(dir);
                    }
                    Err(e) => {
                        error!("Failed to extract directory for path {}: {}", path, e);
                    }
                }
            }
            dirs
        };

        if dirs_to_watch.is_empty() {
            warn!("No certificate paths to watch, watcher not starting");
            return Err(anyhow::anyhow!("No certificate paths configured for watching"));
        }

        // Create notify watcher channel
        let (tx, rx) = std::sync::mpsc::channel();

        // Create watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if let Err(e) = tx.send(event) {
                    error!("Failed to send watcher event: {}", e);
                }
            }
        })
        .context("Failed to create file watcher")?;

        // Add watch for each directory
        for dir in &dirs_to_watch {
            watcher
                .watch(dir, RecursiveMode::NonRecursive)
                .with_context(|| format!("Failed to watch directory: {:?}", dir))?;
        }

        info!(
            "Certificate watcher started for {} directories",
            dirs_to_watch.len()
        );

        // Spawn background task to handle events
        let handle = tokio::spawn(async move {
            let mut pending_reloads: HashMap<String, tokio::time::Instant> = HashMap::new();

            // Receive events in a loop
            while let Ok(event) = rx.recv() {
                debug!("Received file event: {:?}", event);

                // Process event paths
                for path in event.paths {
                    let path_str = path.to_string_lossy().to_string();

                    // Check if this path is being watched
                    let domain = {
                        let watched = self.watched_paths.lock().await;
                        watched.get(&path_str).cloned()
                    };

                    if let Some(domain) = domain {
                        // Check if event is relevant (Create, Modify, Remove)
                        match event.kind {
                            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                                debug!("File change detected for domain {}: {:?}", domain, event.kind);

                                // Record pending reload with timestamp
                                pending_reloads.insert(domain.clone(), tokio::time::Instant::now());
                            }
                            _ => {
                                // Ignore other events (Access, etc.)
                                debug!("Ignoring event kind: {:?}", event.kind);
                            }
                        }
                    }
                }

                // If we have pending reloads, process them after debounce
                if !pending_reloads.is_empty() {
                    // Sleep for debounce duration
                    sleep(self.debounce_duration).await;

                    // Process all pending reloads
                    let domains_to_reload: Vec<String> = pending_reloads.keys().cloned().collect();
                    pending_reloads.clear();

                    for domain in domains_to_reload {
                        info!("Reloading certificate for domain: {}", domain);

                        match self.cert_manager.reload_certificate(&domain).await {
                            Ok(_) => {
                                info!("Successfully reloaded certificate for domain: {}", domain);
                            }
                            Err(e) => {
                                error!("Failed to reload certificate for domain {}: {}", domain, e);
                            }
                        }
                    }
                }
            }

            warn!("Certificate watcher event loop terminated");
        });

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_certificate_watcher_creation() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let watcher = CertificateWatcher::new(cert_manager, 1);

        // Verify watcher is created
        let watched = watcher.watched_paths.lock().await;
        assert_eq!(watched.len(), 0);
    }

    #[tokio::test]
    async fn test_add_watch() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let watcher = CertificateWatcher::new(cert_manager, 1);

        // Add a watch
        watcher.add_watch("/path/to/cert.pem".to_string(), "example.com".to_string()).await;

        // Verify it's tracked
        let watched = watcher.watched_paths.lock().await;
        assert_eq!(watched.len(), 1);
        assert_eq!(watched.get("/path/to/cert.pem"), Some(&"example.com".to_string()));
    }

    #[tokio::test]
    async fn test_add_watch_paths() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let watcher = CertificateWatcher::new(cert_manager, 1);

        // Add watch paths
        let cert_path = Some(&"/path/to/cert.pem".to_string());
        let key_path = Some(&"/path/to/key.pem".to_string());
        watcher.add_watch_paths("example.com", cert_path, key_path).await;

        // Verify both paths are tracked
        let watched = watcher.watched_paths.lock().await;
        assert_eq!(watched.len(), 2);
        assert_eq!(watched.get("/path/to/cert.pem"), Some(&"example.com".to_string()));
        assert_eq!(watched.get("/path/to/key.pem"), Some(&"example.com".to_string()));
    }

    #[tokio::test]
    async fn test_add_watch_paths_none() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let watcher = CertificateWatcher::new(cert_manager, 1);

        // Add watch paths with None
        watcher.add_watch_paths("example.com", None, None).await;

        // Verify no paths are tracked
        let watched = watcher.watched_paths.lock().await;
        assert_eq!(watched.len(), 0);
    }

    #[test]
    fn test_extract_directory() {
        let test_cases = vec![
            ("/path/to/cert.pem", "/path/to"),
            ("/cert.pem", "/"),
            ("relative/path/cert.pem", "relative/path"),
            ("./cert.pem", "."),
        ];

        for (path, expected_dir) in test_cases {
            let result = CertificateWatcher::extract_directory(path);
            assert!(result.is_ok(), "Failed to extract directory from: {}", path);
            let dir = result.unwrap();
            assert_eq!(dir.to_str().unwrap(), expected_dir);
        }
    }

    #[test]
    fn test_extract_directory_error() {
        // Test with root directory which has no parent
        let result = CertificateWatcher::extract_directory("/");
        // Root "/" has no parent, so this should fail
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to extract parent directory"));
    }

    #[tokio::test]
    async fn test_multiple_domains_same_cert() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let watcher = CertificateWatcher::new(cert_manager, 1);

        // Add same cert path for multiple domains
        watcher.add_watch("/path/to/cert.pem".to_string(), "example.com".to_string()).await;
        watcher.add_watch("/path/to/cert.pem".to_string(), "www.example.com".to_string()).await;

        // Verify only one entry (last write wins)
        let watched = watcher.watched_paths.lock().await;
        assert_eq!(watched.len(), 1);
        // The second add should have overwritten the first
        assert_eq!(
            watched.get("/path/to/cert.pem"),
            Some(&"www.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_watcher_start_no_paths() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let watcher = Arc::new(CertificateWatcher::new(cert_manager, 1));

        // Try to start watcher with no paths (using spawn_blocking to avoid runtime conflict)
        let watcher_clone = watcher.clone();
        let result = tokio::task::spawn_blocking(move || watcher_clone.start()).await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No certificate paths"));
    }

    #[tokio::test]
    async fn test_watcher_start_with_paths() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let watcher = Arc::new(CertificateWatcher::new(cert_manager, 1));

        // Create a temporary directory with a test file
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        File::create(&cert_path).unwrap();

        // Add watch
        watcher
            .add_watch(cert_path.to_str().unwrap().to_string(), "example.com".to_string())
            .await;

        // Start watcher using spawn_blocking to avoid runtime conflict
        let watcher_clone = watcher.clone();
        let result = tokio::task::spawn_blocking(move || watcher_clone.start()).await.unwrap();
        assert!(result.is_ok());

        // The watcher task is now running in background
        let handle = result.unwrap();
        // Abort the watcher task to clean up
        handle.abort();
    }

    #[test]
    fn test_debounce_duration() {
        let cert_manager = Arc::new(CertificateManager::new(None));
        let watcher = CertificateWatcher::new(cert_manager, 5);
        assert_eq!(watcher.debounce_duration, Duration::from_secs(5));
    }
}
