use crate::config::LoggingConfig;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_logging(config: &LoggingConfig) -> Option<WorkerGuard> {
    // Validate and set log level, warn if invalid
    let log_level = match config.level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        invalid => {
            eprintln!("Warning: Invalid log level '{}', defaulting to 'info'", invalid);
            Level::INFO
        }
    };

    let env_filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy();

    let guard = match (config.output.as_str(), config.format.as_str()) {
        ("console", "text") => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .init();
            None
        }
        ("console", "json") => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_writer(std::io::stdout))
                .init();
            None
        }
        ("file", "text") => {
            // Validate file_path is present for file output
            let path = match &config.file_path {
                Some(p) => p,
                None => {
                    eprintln!("Warning: file_path is required for file output, falling back to console");
                    // Fall back to console logging
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(fmt::layer().with_writer(std::io::stdout))
                        .init();
                    return None;
                }
            };
            let file_appender = tracing_appender::rolling::daily(path, "proxy.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(non_blocking))
                .init();
            Some(guard)
        }
        ("file", "json") => {
            // Validate file_path is present for file output
            let path = match &config.file_path {
                Some(p) => p,
                None => {
                    eprintln!("Warning: file_path is required for file output, falling back to console");
                    // Fall back to console logging
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(fmt::layer().with_writer(std::io::stdout))
                        .init();
                    return None;
                }
            };
            let file_appender = tracing_appender::rolling::daily(path, "proxy.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_writer(non_blocking))
                .init();
            Some(guard)
        }
        _ => {
            // Invalid output/format combination - log warning and fall back to console
            eprintln!(
                "Warning: Invalid logging config (output='{}', format='{}'), falling back to console text output",
                config.output, config.format
            );
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .init();
            None
        }
    };

    guard
}
