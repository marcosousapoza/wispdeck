use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode, header::SEC_WEBSOCKET_PROTOCOL},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tokio::{net::TcpListener, signal};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::{
    admin::routes,
    auth::{admin::AdminAuth, wisp::WispUsers},
    config::storage::load_or_create,
    core::{metrics::Metrics, sessions::SessionRegistry, state::AppState},
    protocol::{ProtocolBackend, wisp_mux::WispMuxBackend},
};

pub async fn serve(data_dir: PathBuf) -> Result<()> {
    let mut config = load_or_create(&data_dir).await?;
    if let Ok(listen) = std::env::var("WISPDECK_LISTEN") {
        listen
            .parse::<SocketAddr>()
            .context("invalid WISPDECK_LISTEN address")?;
        config.listen = listen;
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new(format!(
                "wispdeck={},tower_http={}",
                config.log_level, config.log_level
            ))
        }))
        .init();
    let admin_auth = AdminAuth::initialize(&data_dir, config.admin.session_minutes).await?;
    let wisp_users = WispUsers::load(&data_dir).await?;
    let backend: Arc<dyn ProtocolBackend> = Arc::new(WispMuxBackend);
    let state = Arc::new(AppState {
        data_dir,
        started: Instant::now(),
        config: tokio::sync::RwLock::new(config.clone()),
        config_save: tokio::sync::Mutex::new(()),
        metrics: Arc::new(Metrics::default()),
        sessions: Arc::new(SessionRegistry::default()),
        admin_auth,
        wisp_users,
        client_slots: Arc::new(tokio::sync::Semaphore::new(config.limits.max_clients)),
        dial_slots: Arc::new(tokio::sync::Semaphore::new(config.limits.pending_dials)),
        recent_errors: tokio::sync::RwLock::new(Default::default()),
        backend: backend.info(),
        protocol_backend: backend,
    });

    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/wisp/", get(wisp_upgrade))
        .route("/admin/login", get(routes::login_page).post(routes::login))
        .route("/admin/", get(routes::dashboard))
        .route("/admin/users", get(routes::users).post(routes::add_user))
        .route("/admin/users/disable", post(routes::disable_user))
        .route("/admin/users/remove", post(routes::remove_user))
        .route("/admin/connections", get(routes::connections))
        .route("/admin/connections/disconnect", post(routes::disconnect))
        .route(
            "/admin/policy",
            get(routes::policy).post(routes::update_policy),
        )
        .route(
            "/admin/settings",
            get(routes::settings).post(routes::update_settings),
        )
        .route("/admin/account", get(routes::admin_settings))
        .route("/admin/account/password", post(routes::change_password))
        .route("/admin/logout", post(routes::logout))
        .route("/static/style.css", get(stylesheet))
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    let address: SocketAddr = config.listen.parse().context("invalid listen address")?;
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind {address}"))?;
    tracing::info!(%address, "Wispdeck listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn wisp_upgrade(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(protocol) = headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find(|value| !value.is_empty())
        })
        .map(str::to_owned)
    else {
        return (
            StatusCode::UPGRADE_REQUIRED,
            "Sec-WebSocket-Protocol is required for authenticated Wisp v2",
        )
            .into_response();
    };
    let limit = state.config.read().await.limits.websocket_message_bytes;
    ws.protocols([protocol])
        .max_message_size(limit)
        .max_frame_size(limit)
        .on_upgrade(move |socket| async move {
            let backend = Arc::clone(&state.protocol_backend);
            backend.serve(socket, peer, state).await;
        })
}

async fn stylesheet() -> impl IntoResponse {
    (
        [("content-type", "text/css; charset=utf-8")],
        include_str!("../static/style.css"),
    )
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
    tracing::info!("shutdown requested");
}
