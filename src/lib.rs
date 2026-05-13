mod auth;
pub mod config;
mod db;
mod error;
mod handlers;
mod manager;
mod message;
mod router;
mod state;
mod topic;
mod upstream;
mod visitor;

pub use config::{Config, FileConfig, ServeArgs};

use state::AppState;
use std::net::SocketAddr;

/// Handle to a running ntfy-rs server. Call `shutdown()` to stop it.
pub struct ServerHandle {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    port: u16,
}

impl ServerHandle {
    /// Shut down the server gracefully.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Get the port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Publish a message directly via HTTP POST to localhost.
    pub fn publish(
        &self,
        topic: &str,
        title: &str,
        message: &str,
        priority: &str,
    ) -> anyhow::Result<()> {
        let url = format!("http://127.0.0.1:{}/{}", self.port, topic);
        let mut req = reqwest::blocking::Client::new()
            .post(&url)
            .header("Title", title);

        if !priority.is_empty() {
            req = req.header("Priority", priority);
        }

        req.body(message.to_string())
            .send()
            .map_err(|e| anyhow::anyhow!("failed to publish: {}", e))?;

        Ok(())
    }
}

/// Start the ntfy-rs server on a background thread.
///
/// Blocks until the server has bound its port (or returns an error).
/// Returns a handle that can be used to publish messages and shut down the server.
pub fn start(config: Config) -> anyhow::Result<ServerHandle> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (started_tx, started_rx) = std::sync::mpsc::channel::<anyhow::Result<u16>>();

    std::thread::Builder::new()
        .name("ntfy-rs-server".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(async move {
                if let Err(e) = run_server(config, shutdown_rx, started_tx).await {
                    tracing::error!(error = %e, "ntfy-rs server error");
                }
            });
        })
        .map_err(|e| anyhow::anyhow!("failed to spawn server thread: {}", e))?;

    // Wait for the server to bind (or fail).
    let port = started_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("server thread exited before startup"))?
        .map_err(|e| anyhow::anyhow!("server failed to start: {}", e))?;

    Ok(ServerHandle {
        shutdown_tx,
        port,
    })
}

// ── Internal server runner ───────────────────────────────────────────────

async fn run_server(
    config: Config,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    started_tx: std::sync::mpsc::Sender<anyhow::Result<u16>>,
) -> anyhow::Result<()> {
    // Install the aws-lc-rs crypto provider for rustls.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Open message cache DB.
    let db = db::open(config.cache_file.as_ref())?;

    // Open auth DB (separate file when auth is enabled).
    let auth_db = if config.auth_enabled {
        Some(db::open(config.auth_file.as_ref())?)
    } else {
        None
    };

    let state = AppState::new(config.clone(), db, auth_db);

    // Background manager.
    {
        let s = state.clone();
        tokio::spawn(async move { manager::run(s).await });
    }

    let app = router::build(state);

    // ── HTTP listener ─────────────────────────────────────────────────────
    let http_addr: SocketAddr = normalise_addr(&config.listen_http)?;
    let http_listener = tokio::net::TcpListener::bind(http_addr).await;
    match http_listener {
        Ok(listener) => {
            let local_addr = listener.local_addr()?;
            let port = local_addr.port();
            tracing::info!(addr = %local_addr, "HTTP listening");
            let _ = started_tx.send(Ok(port));
            run_select(listener, app, config, shutdown_rx).await?;
        }
        Err(e) => {
            let _ = started_tx.send(Err(anyhow::anyhow!("bind failed: {}", e)));
        }
    }

    Ok(())
}

async fn run_select(
    http_listener: tokio::net::TcpListener,
    app: axum::Router,
    config: Config,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    // ── HTTPS listener (optional) ─────────────────────────────────────────
    let tls_server = match (&config.listen_https, &config.cert_file, &config.key_file) {
        (Some(addr), Some(cert), Some(key)) => {
            let tls_cfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .map_err(|e| anyhow::anyhow!("failed to load TLS cert/key: {e}"))?;
            let tls_addr: SocketAddr = normalise_addr(addr)?;
            tracing::info!(%tls_addr, "HTTPS listening");
            Some((tls_addr, tls_cfg))
        }
        (Some(_), _, _) => {
            tracing::warn!("listen_https set but cert_file/key_file missing — TLS disabled");
            None
        }
        _ => None,
    };

    #[allow(unused_variables)]
    let unix_path = config.listen_unix.clone();

    tokio::select! {
        res = axum::serve(http_listener, app.clone())
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            }) => {
            res?;
        }
        res = async {
            if let Some((tls_addr, tls_cfg)) = tls_server {
                axum_server::bind_rustls(tls_addr, tls_cfg)
                    .serve(app.clone().into_make_service())
                    .await
            } else {
                std::future::pending::<Result<(), std::io::Error>>().await
            }
        } => {
            res?;
        }
        res = async {
            #[cfg(unix)]
            if let Some(path) = unix_path {
                return serve_unix(path, app.clone()).await;
            }
            std::future::pending::<anyhow::Result<()>>().await
        } => {
            res?;
        }
    }

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

/// Serve an axum Router over a Unix domain socket.
#[cfg(unix)]
async fn serve_unix(path: std::path::PathBuf, app: axum::Router) -> anyhow::Result<()> {
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use tower::ServiceExt as _;

    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)
        .map_err(|e| anyhow::anyhow!("failed to bind Unix socket {}: {e}", path.display()))?;
    tracing::info!(path = %path.display(), "Unix socket listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let tower_svc = app.clone();
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req| {
                        let svc = tower_svc.clone();
                        async move { svc.oneshot(req).await }
                    }),
                )
                .with_upgrades()
                .await;
        });
    }
}
