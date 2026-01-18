// Certificate manager module for TLS certificate loading and caching

pub mod acme_manager;
pub mod certificate_manager;
pub mod challenge_handler;
pub mod dns_provider;
pub mod proxy_service;
pub mod renewal;
pub mod watcher;

pub use acme_manager::{AcmeManager, ChallengeData};
pub use certificate_manager::{CertificateManager, LoadedCertificate};
pub use challenge_handler::handle_acme_challenge;
pub use proxy_service::{MyProxyService, HttpRedirectService};
pub use renewal::{RenewalManager, RenewalConfig};
pub use watcher::CertificateWatcher;
