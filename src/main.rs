mod auth;
mod config;
mod db;
mod error;
mod handlers;
mod manager;
mod message;
mod router;
mod state;
mod topic;
mod visitor;

use clap::Parser;
use config::{load_file_config, Config};
use state::AppState;
use std::net::SocketAddr;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = config::Cli::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level));
    fmt().with_env_filter(filter).init();

    let file_cfg = load_file_config(&cli.config)?;
    let cfg = Config::resolve(file_cfg, &cli);

    tracing::info!(listen = %cfg.listen_http, auth = cfg.auth_enabled, "starting ntfy-rs");

    // Open message cache DB.
    let db = db::open(cfg.cache_file.as_ref())?;

    // Open auth DB (separate file when auth_file differs from cache_file).
    let auth_db = if cfg.auth_enabled {
        Some(db::open(cfg.auth_file.as_ref())?)
    } else {
        None
    };

    let state = AppState::new(cfg.clone(), db, auth_db);

    {
        let s = state.clone();
        tokio::spawn(async move { manager::run(s).await });
    }

    let app = router::build(state);

    let addr: SocketAddr = normalise_addr(&cfg.listen_http)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");

    axum::serve(listener, app).await?;
    Ok(())
}

fn normalise_addr(s: &str) -> anyhow::Result<SocketAddr> {
    let s = if s.starts_with(':') {
        format!("0.0.0.0{s}")
    } else {
        s.to_string()
    };
    Ok(s.parse()?)
}
