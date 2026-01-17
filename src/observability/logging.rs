use crate::config::LoggingConfig;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_logging(config: &LoggingConfig) -> Option<WorkerGuard> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(match config.level.as_str() {
            "trace" => Level::TRACE.into(),
            "debug" => Level::DEBUG.into(),
            "info" => Level::INFO.into(),
            "warn" => Level::WARN.into(),
            "error" => Level::ERROR.into(),
            _ => Level::INFO.into(),
        })
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
            let file_appender = tracing_appender::rolling::daily(
                config.file_path.as_ref().unwrap(),
                "proxy.log",
            );
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(non_blocking))
                .init();
            Some(guard)
        }
        ("file", "json") => {
            let file_appender = tracing_appender::rolling::daily(
                config.file_path.as_ref().unwrap(),
                "proxy.log",
            );
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_writer(non_blocking))
                .init();
            Some(guard)
        }
        _ => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .init();
            None
        }
    };

    guard
}
