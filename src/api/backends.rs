use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::Backend;
use crate::state::AppState;
use crate::observability::metrics::MetricsCollector;
use tracing::info;

/// Request payload for adding a backend
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateBackendRequest {
    pub id: String,
    pub address: String,
    pub tags: Vec<String>,
}

/// Request payload for updating a backend (all fields optional)
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateBackendRequest {
    pub address: Option<String>,
    pub tags: Option<Vec<String>>,
}

impl From<CreateBackendRequest> for Backend {
    fn from(req: CreateBackendRequest) -> Self {
        Self {
            id: req.id,
            address: req.address,
            tags: req.tags,
        }
    }
}

/// Response payload for backend operations
#[derive(Debug, Serialize)]
pub struct BackendResponse {
    pub id: String,
    pub address: String,
    pub tags: Vec<String>,
}

impl From<Backend> for BackendResponse {
    fn from(backend: Backend) -> Self {
        Self {
            id: backend.id,
            address: backend.address,
            tags: backend.tags,
        }
    }
}

/// GET /api/v1/backends - List all backends
pub async fn list_backends(State((state, _)): State<(AppState, Arc<MetricsCollector>)>) -> Result<Json<Vec<BackendResponse>>, StatusCode> {
    let backends = state.backends.read().await;
    let backend_list: Vec<BackendResponse> = backends
        .values()
        .cloned()
        .map(BackendResponse::from)
        .collect();
    info!("Listed {} backends", backend_list.len());
    Ok(Json(backend_list))
}

/// POST /api/v1/backends - Add a new backend
pub async fn add_backend(
    State((state, _)): State<(AppState, Arc<MetricsCollector>)>,
    Json(req): Json<CreateBackendRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut backends = state.backends.write().await;

    // Check if backend ID already exists
    if backends.contains_key(&req.id) {
        info!("Failed to add backend {}: already exists", req.id);
        return Err(StatusCode::CONFLICT);
    }

    let backend: Backend = req.into();
    let response = BackendResponse::from(backend.clone());
    backends.insert(backend.id.clone(), backend);

    info!("Added backend: {}", response.id);
    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/backends/:id - Get a specific backend
pub async fn get_backend(
    State((state, _)): State<(AppState, Arc<MetricsCollector>)>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let backends = state.backends.read().await;

    match backends.get(&id) {
        Some(backend) => {
            info!("Retrieved backend: {}", id);
            Ok(Json(BackendResponse::from(backend.clone())))
        }
        None => {
            info!("Backend not found: {}", id);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// PUT /api/v1/backends/:id - Update a backend (partial update supported)
pub async fn update_backend(
    State((state, _)): State<(AppState, Arc<MetricsCollector>)>,
    Path(id): Path<String>,
    Json(req): Json<UpdateBackendRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut backends = state.backends.write().await;

    // Check if backend exists
    if !backends.contains_key(&id) {
        info!("Failed to update backend {}: not found", id);
        return Err(StatusCode::NOT_FOUND);
    }

    // Get existing backend and apply partial updates
    let existing = backends.get(&id).unwrap().clone();

    let updated_backend = Backend {
        id: existing.id,
        address: req.address.unwrap_or(existing.address),
        tags: req.tags.unwrap_or(existing.tags),
    };

    let response = BackendResponse::from(updated_backend.clone());
    backends.insert(id, updated_backend);

    info!("Updated backend: {}", response.id);
    Ok(Json(response))
}

/// DELETE /api/v1/backends/:id - Delete a backend
pub async fn delete_backend(
    State((state, _)): State<(AppState, Arc<MetricsCollector>)>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut backends = state.backends.write().await;

    match backends.remove(&id) {
        Some(_) => {
            info!("Deleted backend: {}", id);
            Ok(StatusCode::NO_CONTENT)
        }
        None => {
            info!("Failed to delete backend {}: not found", id);
            Err(StatusCode::NOT_FOUND)
        }
    }
}
