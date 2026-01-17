use crate::config::Config;
use crate::state::AppState;
use anyhow::Result;
use pingora::prelude::*;
use std::sync::Arc;
use tracing::info;

#[allow(dead_code)]
pub struct MyProxy {
    server: Option<Server>,
    config: Config,
    state: Arc<AppState>,
}

#[allow(dead_code)]
impl MyProxy {
    pub fn new(config: Config, state: Arc<AppState>) -> Self {
        Self {
            server: None,
            config,
            state,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        let mut my_proxy = Server::new(None)?;
        my_proxy.bootstrap();

        // TODO: Set up Pingora proxy with SNI routing
        // This requires Pingora's specific APIs for upstream selection
        // and adding services to the server

        info!("Proxy server initialized (will bind to {})",
              self.config.proxy.listen_addr);

        self.server = Some(my_proxy);
        Ok(())
    }
}
