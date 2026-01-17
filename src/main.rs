mod config;
mod state;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Pingora Virtual Host Proxy starting...");
    Ok(())
}
