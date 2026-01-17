use prometheus::{
    Encoder, Histogram, IntCounter, IntGauge, Registry, TextEncoder,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DomainStats {
    pub total_requests: u64,
    pub success_requests: u64,
    pub error_requests: u64,
    pub avg_latency_ms: f64,
}

pub struct MetricsCollector {
    registry: Registry,
    request_count: IntCounter,
    request_duration: Histogram,
    active_connections: IntGauge,
    domain_stats: Arc<RwLock<HashMap<String, DomainStats>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        let registry = Registry::new();

        let request_count = IntCounter::new(
            "proxy_requests_total",
            "Total number of requests"
        ).unwrap();

        let request_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "proxy_request_duration_ms",
                "Request duration in milliseconds"
            ).buckets(vec![0.1, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0])
        ).unwrap();

        let active_connections = IntGauge::new(
            "proxy_active_connections",
            "Number of active connections"
        ).unwrap();

        registry.register(Box::new(request_count.clone())).unwrap();
        registry.register(Box::new(request_duration.clone())).unwrap();
        registry.register(Box::new(active_connections.clone())).unwrap();

        Self {
            registry,
            request_count,
            request_duration,
            active_connections,
            domain_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn record_request(&self, domain: &str, status: u16, duration_ms: f64) {
        self.request_count.inc();
        self.request_duration.observe(duration_ms);

        let mut stats = self.domain_stats.write().await;
        let domain_stat = stats.entry(domain.to_string()).or_insert_with(|| DomainStats {
            total_requests: 0,
            success_requests: 0,
            error_requests: 0,
            avg_latency_ms: 0.0,
        });

        domain_stat.total_requests += 1;
        if status >= 200 && status < 400 {
            domain_stat.success_requests += 1;
        } else {
            domain_stat.error_requests += 1;
        }

        // Update rolling average
        let n = domain_stat.total_requests as f64;
        domain_stat.avg_latency_ms =
            (domain_stat.avg_latency_ms * (n - 1.0) + duration_ms) / n;
    }

    pub async fn get_stats(&self, domain: &str) -> DomainStats {
        let stats = self.domain_stats.read().await;
        stats.get(domain)
            .cloned()
            .unwrap_or(DomainStats {
                total_requests: 0,
                success_requests: 0,
                error_requests: 0,
                avg_latency_ms: 0.0,
            })
    }

    pub fn export_metrics(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
