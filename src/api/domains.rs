use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use crate::config::VirtualHost;
use crate::state::AppState;

/// Request payload for adding/updating a domain
#[derive(Debug, Deserialize, Serialize)]
pub struct DomainRequest {
    pub domain: String,
    pub enabled_backends_tag: String,
    #[serde(default = "default_http_to_https")]
    pub http_to_https: bool,
}

fn default_http_to_https() -> bool {
    true
}

impl From<DomainRequest> for VirtualHost {
    fn from(req: DomainRequest) -> Self {
        Self {
            domain: req.domain,
            enabled_backends_tag: req.enabled_backends_tag,
            http_to_https: req.http_to_https,
        }
    }
}

/// Response payload for domain operations
#[derive(Debug, Serialize)]
pub struct DomainResponse {
    pub domain: String,
    pub enabled_backends_tag: String,
    pub http_to_https: bool,
}

impl From<VirtualHost> for DomainResponse {
    fn from(vh: VirtualHost) -> Self {
        Self {
            domain: vh.domain,
            enabled_backends_tag: vh.enabled_backends_tag,
            http_to_https: vh.http_to_https,
        }
    }
}

/// GET /api/v1/domains - List all domains
pub async fn list_domains(State(state): State<AppState>) -> Result<Json<Vec<DomainResponse>>, StatusCode> {
    let vhosts = state.virtual_hosts.read().await;
    let domains: Vec<DomainResponse> = vhosts
        .values()
        .cloned()
        .map(DomainResponse::from)
        .collect();
    Ok(Json(domains))
}

/// POST /api/v1/domains - Add a new domain
pub async fn add_domain(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut vhosts = state.virtual_hosts.write().await;

    // Check if domain already exists
    if vhosts.contains_key(&req.domain) {
        return Err(StatusCode::CONFLICT);
    }

    let vh: VirtualHost = req.into();
    let response = DomainResponse::from(vh.clone());
    vhosts.insert(vh.domain.clone(), vh);

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/domains/:domain - Get a specific domain
pub async fn get_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let vhosts = state.virtual_hosts.read().await;

    match vhosts.get(&domain) {
        Some(vh) => Ok(Json(DomainResponse::from(vh.clone()))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// PUT /api/v1/domains/:domain - Update a domain
pub async fn update_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Json(req): Json<DomainRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut vhosts = state.virtual_hosts.write().await;

    // Check if domain exists
    if !vhosts.contains_key(&domain) {
        return Err(StatusCode::NOT_FOUND);
    }

    let vh: VirtualHost = req.into();
    vhosts.insert(vh.domain.clone(), vh.clone());

    Ok(Json(DomainResponse::from(vh)))
}

/// DELETE /api/v1/domains/:domain - Delete a domain
pub async fn delete_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut vhosts = state.virtual_hosts.write().await;

    match vhosts.remove(&domain) {
        Some(_) => Ok(StatusCode::NO_CONTENT),
        None => Err(StatusCode::NOT_FOUND),
    }
}
