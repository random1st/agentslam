//! Application state, router assembly and server start-up.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::middleware;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::core::clock::Clock;
use crate::core::config::Config;
use crate::core::db::Db;
use crate::identity::cimd::CimdCache;
use crate::identity::oidc::Oidc;
use crate::rooms::mcp::RoomsMcp;
use crate::rooms::notify::Hub;

pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    pub clock: Arc<Clock>,
    pub hub: Hub,
    pub oidc: Oidc,
    pub cimd: CimdCache,
    /// Outbound HTTP (IdP, CIMD): short timeouts, no redirects followed.
    pub http: reqwest::Client,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(config: Config) -> anyhow::Result<Shared> {
        let db = Db::open(&config.database)?;
        let clock = Arc::new(Clock::default());
        // B13: people and rooms from before organizations join one (nothing is lost).
        let now = clock.now();
        let moved = db
            .blocking(|c| crate::identity::orgs::backfill(c, &config, now))
            .map_err(|e| anyhow::anyhow!("organization backfill: {e}"))?;
        if moved > 0 {
            tracing::info!(people = moved, "assigned existing people to organizations");
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("agentslam/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build HTTP client")?;
        Ok(Arc::new(AppState {
            config: Arc::new(config),
            db,
            clock,
            hub: Hub::default(),
            oidc: Oidc::default(),
            cimd: CimdCache::default(),
            http,
        }))
    }
}

fn allowed_hosts(config: &Config) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Ok(u) = url::Url::parse(&config.public_url)
        && let Some(h) = u.host_str()
    {
        hosts.push(h.to_string());
        if let Some(p) = u.port() {
            hosts.push(format!("{h}:{p}"));
        }
    }
    hosts
}

pub fn router(state: Shared) -> Router {
    let st = state.clone();
    let mcp_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_allowed_hosts(allowed_hosts(&state.config));
    let mcp_service = StreamableHttpService::new(
        move || Ok(RoomsMcp::new(st.clone())),
        Arc::new(LocalSessionManager::default()),
        mcp_config,
    );
    // route_layer, not layer: the bearer check must guard /mcp only. `layer`
    // also wraps the router's fallback, which turned every unknown path into a
    // 401 bearer challenge instead of a 404.
    let mcp = Router::new()
        .route_service("/mcp", mcp_service)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::identity::auth::mcp_auth,
        ));
    Router::new()
        .merge(crate::identity::routes())
        .merge(crate::web::routes())
        .merge(crate::hook::api::routes())
        .merge(mcp)
        .with_state(state)
}

/// A running server (used by `main` and by integration tests).
pub struct Running {
    pub addr: SocketAddr,
    pub state: Shared,
    shutdown: Option<oneshot::Sender<()>>,
    pub handle: JoinHandle<()>,
}

impl Running {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.handle.await;
    }
}

/// Start serving on `listener` (or bind `config.bind`).
pub async fn serve(config: Config, listener: Option<TcpListener>) -> anyhow::Result<Running> {
    let listener = match listener {
        Some(l) => l,
        None => TcpListener::bind(config.bind)
            .await
            .with_context(|| format!("bind {}", config.bind))?,
    };
    let addr = listener.local_addr()?;
    let state = AppState::new(config)?;
    let app = router(state.clone());
    crate::rooms::summary::spawn_timer(state.clone());
    let (tx, rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
        if let Err(e) = result {
            tracing::error!(error = %e, "server stopped with an error");
        }
    });
    tracing::info!(%addr, "agentslam listening");
    Ok(Running {
        addr,
        state,
        shutdown: Some(tx),
        handle,
    })
}
