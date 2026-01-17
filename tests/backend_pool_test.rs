use pingora_vhost::backend_pool::BackendPool;
use pingora_vhost::config::Backend;

#[tokio::test]
async fn test_add_backend() {
    let pool = BackendPool::new();
    let backend = Backend {
        id: "test-1".to_string(),
        address: "localhost:3001".to_string(),
        tags: vec!["a".to_string()],
    };

    pool.add_backend(backend.clone()).await;
    let retrieved = pool.get_backend("test-1").await;

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, "test-1");
}

#[tokio::test]
async fn test_get_backends_by_tag() {
    let pool = BackendPool::new();

    pool.add_backend(Backend {
        id: "backend-1".to_string(),
        address: "localhost:3001".to_string(),
        tags: vec!["a".to_string()],
    }).await;

    pool.add_backend(Backend {
        id: "backend-2".to_string(),
        address: "localhost:3002".to_string(),
        tags: vec!["b".to_string()],
    }).await;

    pool.add_backend(Backend {
        id: "backend-3".to_string(),
        address: "localhost:3003".to_string(),
        tags: vec!["a".to_string(), "b".to_string()],
    }).await;

    let tag_a_backends = pool.get_backends_by_tag("a").await;
    assert_eq!(tag_a_backends.len(), 2);

    let tag_b_backends = pool.get_backends_by_tag("b").await;
    assert_eq!(tag_b_backends.len(), 2);
}

#[tokio::test]
async fn test_remove_backend() {
    let pool = BackendPool::new();
    let backend = Backend {
        id: "test-1".to_string(),
        address: "localhost:3001".to_string(),
        tags: vec!["a".to_string()],
    };

    pool.add_backend(backend.clone()).await;
    pool.remove_backend("test-1").await;

    let retrieved = pool.get_backend("test-1").await;
    assert!(retrieved.is_none());
}
