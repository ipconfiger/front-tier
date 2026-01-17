use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::VirtualHost;
use crate::state::AppState;
use crate::observability::metrics::MetricsCollector;
use crate::tls::certificate_manager::CertificateManager;
use tracing::info;

/// Request payload for adding a domain
#[derive(Debug, Deserialize, Serialize)]
pub struct DomainRequest {
    pub domain: String,
    pub enabled_backends_tag: String,
    #[serde(default = "default_http_to_https")]
    pub http_to_https: bool,
}

/// Request payload for updating a domain (all fields optional)
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateDomainRequest {
    pub enabled_backends_tag: Option<String>,
    #[serde(default)]
    pub http_to_https: Option<bool>,
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
            tls_enabled: false,
            certificate_source: None,
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
pub async fn list_domains(
    State((state, _, _)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>
) -> Result<Json<Vec<DomainResponse>>, StatusCode> {
    let vhosts = state.virtual_hosts.read().await;
    let domains: Vec<DomainResponse> = vhosts
        .values()
        .cloned()
        .map(DomainResponse::from)
        .collect();
    info!("Listed {} domains", domains.len());
    Ok(Json(domains))
}

/// POST /api/v1/domains - Add a new domain
pub async fn add_domain(
    State((state, _, _)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>,
    Json(req): Json<DomainRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut vhosts = state.virtual_hosts.write().await;

    // Check if domain already exists
    if vhosts.contains_key(&req.domain) {
        info!("Failed to add domain {}: already exists", req.domain);
        return Err(StatusCode::CONFLICT);
    }

    let vh: VirtualHost = req.into();
    let response = DomainResponse::from(vh.clone());
    vhosts.insert(vh.domain.clone(), vh);

    info!("Added domain: {}", response.domain);
    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/domains/:domain - Get a specific domain
pub async fn get_domain(
    State((state, _, _)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let vhosts = state.virtual_hosts.read().await;

    match vhosts.get(&domain) {
        Some(vh) => {
            info!("Retrieved domain: {}", domain);
            Ok(Json(DomainResponse::from(vh.clone())))
        }
        None => {
            info!("Domain not found: {}", domain);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// PUT /api/v1/domains/:domain - Update a domain (partial update supported)
pub async fn update_domain(
    State((state, _, _)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>,
    Path(domain): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut vhosts = state.virtual_hosts.write().await;

    // Check if domain exists
    if !vhosts.contains_key(&domain) {
        info!("Failed to update domain {}: not found", domain);
        return Err(StatusCode::NOT_FOUND);
    }

    // Get existing domain and apply partial updates
    let existing = vhosts.get(&domain).unwrap().clone();

    let updated_vh = VirtualHost {
        domain: existing.domain,
        enabled_backends_tag: req.enabled_backends_tag.unwrap_or(existing.enabled_backends_tag),
        http_to_https: req.http_to_https.unwrap_or(existing.http_to_https),
        tls_enabled: existing.tls_enabled,
        certificate_source: existing.certificate_source,
    };

    let response = DomainResponse::from(updated_vh.clone());
    vhosts.insert(domain, updated_vh);

    info!("Updated domain: {}", response.domain);
    Ok(Json(response))
}

/// DELETE /api/v1/domains/:domain - Delete a domain
pub async fn delete_domain(
    State((state, _, _)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut vhosts = state.virtual_hosts.write().await;

    match vhosts.remove(&domain) {
        Some(_) => {
            info!("Deleted domain: {}", domain);
            Ok(StatusCode::NO_CONTENT)
        }
        None => {
            info!("Failed to delete domain {}: not found", domain);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Request payload for switching backend tag
#[derive(Debug, Deserialize)]
pub struct SwitchTagRequest {
    pub new_tag: String,
}

/// POST /api/v1/domains/:domain/switch - Switch backend tag for AB testing
pub async fn switch_domain_tag(
    State((state, _, _)): State<(AppState, Arc<MetricsCollector>, Arc<CertificateManager>)>,
    Path(domain): Path<String>,
    Json(req): Json<SwitchTagRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut vhosts = state.virtual_hosts.write().await;

    // Check if domain exists
    if !vhosts.contains_key(&domain) {
        info!("Failed to switch tag for domain {}: not found", domain);
        return Err(StatusCode::NOT_FOUND);
    }

    // Get existing domain and update tag
    let existing = vhosts.get(&domain).unwrap().clone();

    let updated_vh = VirtualHost {
        domain: existing.domain,
        enabled_backends_tag: req.new_tag,
        http_to_https: existing.http_to_https,
        tls_enabled: existing.tls_enabled,
        certificate_source: existing.certificate_source,
    };

    let response = DomainResponse::from(updated_vh.clone());
    vhosts.insert(domain.clone(), updated_vh);

    info!("Switched backend tag for domain {} to {}", domain, response.enabled_backends_tag);
    Ok(Json(response))
}
