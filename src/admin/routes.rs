use std::{net::SocketAddr, sync::Arc};

use askama::Template;
use axum::{
    extract::{ConnectInfo, Form, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{COOKIE, SET_COOKIE},
    },
    response::{Html, IntoResponse, Redirect, Response},
};

use crate::{
    admin::forms::{ActionForm, LoginForm, PasswordForm, PolicyForm, ServerForm, UserForm},
    auth::{admin::VerifiedSession, wisp::WispUser},
    config::{storage::save_toml, validation::validate},
    core::{metrics::MetricsSnapshot, sessions::SessionView, state::AppState},
};

const COOKIE_NAME: &str = "wispdeck_admin";

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: bool,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    uptime_seconds: u64,
    backend_name: &'static str,
    protocol: &'static str,
    limitations: &'static str,
    active_sessions: usize,
    active_streams: usize,
    metrics: MetricsSnapshot,
    errors: Vec<String>,
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersTemplate {
    csrf: String,
    users: Vec<WispUser>,
}

#[derive(Template)]
#[template(path = "connections.html")]
struct ConnectionsTemplate {
    csrf: String,
    sessions: Vec<SessionView>,
}

#[derive(Template)]
#[template(path = "policy.html")]
struct PolicyTemplate {
    csrf: String,
    allowed_ports: String,
    allowed_hosts: String,
    blocked_hosts: String,
    allow_direct_ip: bool,
    allow_non_public_ips: bool,
    max_clients: usize,
    streams_per_client: usize,
    pending_dials: usize,
    message: String,
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    csrf: String,
    listen: String,
    log_level: String,
    dns_seconds: u64,
    dial_seconds: u64,
    idle_seconds: u64,
    message: String,
}

#[derive(Template)]
#[template(path = "admin_settings.html")]
struct AdminSettingsTemplate {
    csrf: String,
    error: String,
}

pub async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie(&headers)
        && state.admin_auth.verify(&token).await.is_some()
    {
        return Redirect::to("/admin/").into_response();
    }
    render(LoginTemplate { error: false })
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> Response {
    match state
        .admin_auth
        .login(&form.password, &peer.ip().to_string())
        .await
    {
        Ok(Some((token, _))) => {
            let secure = state.config.read().await.admin.secure_cookie;
            let mut response = Redirect::to("/admin/").into_response();
            let max_age = state.config.read().await.admin.session_minutes * 60;
            let value = format!(
                "{COOKIE_NAME}={token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
                if secure { "; Secure" } else { "" }
            );
            if let Ok(header) = HeaderValue::from_str(&value) {
                response.headers_mut().insert(SET_COOKIE, header);
            }
            response
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            render(LoginTemplate { error: true }),
        )
            .into_response(),
    }
}

pub async fn dashboard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(_session) = authenticated(&state, &headers).await else {
        return Redirect::to("/admin/login").into_response();
    };
    let sessions = state.sessions.list().await;
    render(DashboardTemplate {
        uptime_seconds: state.started.elapsed().as_secs(),
        backend_name: state.backend.name,
        protocol: state.backend.protocol,
        limitations: state.backend.limitations,
        active_sessions: sessions.len(),
        active_streams: sessions.iter().map(|item| item.streams).sum(),
        metrics: state.metrics.snapshot(),
        errors: state.recent_errors.read().await.iter().cloned().collect(),
    })
}

pub async fn users(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(session) = authenticated(&state, &headers).await else {
        return Redirect::to("/admin/login").into_response();
    };
    render(UsersTemplate {
        csrf: session.csrf,
        users: state.wisp_users.list().await,
    })
}

pub async fn add_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<UserForm>,
) -> Response {
    let Some(token) = csrf_token(&state, &headers, &form.csrf).await else {
        return forbidden();
    };
    let _ = token;
    let username = form.username.clone();
    match state
        .wisp_users
        .add_or_reset(form.username, form.password)
        .await
    {
        Ok(()) => {
            state.sessions.disconnect_user(&username).await;
            Redirect::to("/admin/users").into_response()
        }
        Err(error) => bad_request(error),
    }
}

pub async fn disable_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ActionForm>,
) -> Response {
    if csrf_token(&state, &headers, &form.csrf).await.is_none() {
        return forbidden();
    }
    let Some(username) = form.username else {
        return (StatusCode::BAD_REQUEST, "missing username").into_response();
    };
    match state.wisp_users.disable(&username).await {
        Ok(true) => {
            state.sessions.disconnect_user(&username).await;
            Redirect::to("/admin/users").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "unknown user").into_response(),
        Err(error) => bad_request(error),
    }
}

pub async fn remove_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ActionForm>,
) -> Response {
    if csrf_token(&state, &headers, &form.csrf).await.is_none() {
        return forbidden();
    }
    let Some(username) = form.username else {
        return (StatusCode::BAD_REQUEST, "missing username").into_response();
    };
    match state.wisp_users.remove(&username).await {
        Ok(true) => {
            state.sessions.disconnect_user(&username).await;
            Redirect::to("/admin/users").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "unknown user").into_response(),
        Err(error) => bad_request(error),
    }
}

pub async fn connections(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(session) = authenticated(&state, &headers).await else {
        return Redirect::to("/admin/login").into_response();
    };
    render(ConnectionsTemplate {
        csrf: session.csrf,
        sessions: state.sessions.list().await,
    })
}

pub async fn disconnect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ActionForm>,
) -> Response {
    if csrf_token(&state, &headers, &form.csrf).await.is_none() {
        return forbidden();
    }
    let Some(id) = form.session_id else {
        return (StatusCode::BAD_REQUEST, "missing session ID").into_response();
    };
    if state.sessions.disconnect(&id).await {
        Redirect::to("/admin/connections").into_response()
    } else {
        (StatusCode::NOT_FOUND, "unknown session").into_response()
    }
}

pub async fn policy(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(session) = authenticated(&state, &headers).await else {
        return Redirect::to("/admin/login").into_response();
    };
    policy_response(&state, session.csrf, String::new()).await
}

pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<PolicyForm>,
) -> Response {
    let Some(session) = csrf_token(&state, &headers, &form.csrf).await else {
        return forbidden();
    };
    let mut config = state.config.read().await.clone();
    let ports = form
        .allowed_ports
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<u16>, _>>();
    let Ok(ports) = ports else {
        return policy_response(
            &state,
            session.csrf,
            "Allowed ports must be comma-separated integers.".into(),
        )
        .await;
    };
    config.policy.allowed_ports = ports;
    config.policy.allowed_hosts = lines(&form.allowed_hosts);
    config.policy.blocked_hosts = lines(&form.blocked_hosts);
    config.policy.allow_direct_ip = form.allow_direct_ip.is_some();
    config.policy.allow_non_public_ips = form.allow_non_public_ips.is_some();
    config.limits.max_clients = form.max_clients;
    config.limits.streams_per_client = form.streams_per_client;
    config.limits.pending_dials = form.pending_dials;
    if let Err(error) = validate(&config) {
        return policy_response(&state, session.csrf, error.to_string()).await;
    }
    if let Err(error) = save_toml(&state.data_dir.join("config.toml"), &config, false).await {
        return policy_response(&state, session.csrf, error.to_string()).await;
    }
    *state.config.write().await = config;
    policy_response(
        &state,
        session.csrf,
        "Saved. Policy applies to new streams; semaphore capacity changes require restart.".into(),
    )
    .await
}

pub async fn settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(session) = authenticated(&state, &headers).await else {
        return Redirect::to("/admin/login").into_response();
    };
    let config = state.config.read().await;
    render(SettingsTemplate {
        csrf: session.csrf,
        listen: config.listen.clone(),
        log_level: config.log_level.clone(),
        dns_seconds: config.timeouts.dns_seconds,
        dial_seconds: config.timeouts.dial_seconds,
        idle_seconds: config.timeouts.idle_seconds,
        message: String::new(),
    })
}

pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ServerForm>,
) -> Response {
    let Some(session) = csrf_token(&state, &headers, &form.csrf).await else {
        return forbidden();
    };
    let mut config = state.config.read().await.clone();
    config.listen = form.listen;
    config.log_level = form.log_level;
    config.timeouts.dns_seconds = form.dns_seconds;
    config.timeouts.dial_seconds = form.dial_seconds;
    config.timeouts.idle_seconds = form.idle_seconds;
    let message = match validate(&config) {
        Err(error) => error.to_string(),
        Ok(()) => match save_toml(&state.data_dir.join("config.toml"), &config, false).await {
            Err(error) => error.to_string(),
            Ok(()) => {
                *state.config.write().await = config.clone();
                "Saved. Timeout changes apply to new streams; listen address and log level require restart.".into()
            }
        },
    };
    render(SettingsTemplate {
        csrf: session.csrf,
        listen: config.listen,
        log_level: config.log_level,
        dns_seconds: config.timeouts.dns_seconds,
        dial_seconds: config.timeouts.dial_seconds,
        idle_seconds: config.timeouts.idle_seconds,
        message,
    })
}

pub async fn admin_settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(session) = authenticated(&state, &headers).await else {
        return Redirect::to("/admin/login").into_response();
    };
    render(AdminSettingsTemplate {
        csrf: session.csrf,
        error: String::new(),
    })
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let Some(session) = csrf_token(&state, &headers, &form.csrf).await else {
        return forbidden();
    };
    match state
        .admin_auth
        .change_password(&form.current_password, &form.new_password)
        .await
    {
        Ok(true) => clear_cookie(Redirect::to("/admin/login").into_response()),
        Ok(false) => render(AdminSettingsTemplate {
            csrf: session.csrf,
            error: "Current password is incorrect.".into(),
        }),
        Err(error) => render(AdminSettingsTemplate {
            csrf: session.csrf,
            error: error.to_string(),
        }),
    }
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ActionForm>,
) -> Response {
    let Some(token) = cookie(&headers) else {
        return forbidden();
    };
    if !state.admin_auth.verify_csrf(&token, &form.csrf).await {
        return forbidden();
    }
    state.admin_auth.logout(&token).await;
    clear_cookie(Redirect::to("/admin/login").into_response())
}

async fn policy_response(state: &AppState, csrf: String, message: String) -> Response {
    let config = state.config.read().await;
    render(PolicyTemplate {
        csrf,
        allowed_ports: config
            .policy
            .allowed_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        allowed_hosts: config.policy.allowed_hosts.join("\n"),
        blocked_hosts: config.policy.blocked_hosts.join("\n"),
        allow_direct_ip: config.policy.allow_direct_ip,
        allow_non_public_ips: config.policy.allow_non_public_ips,
        max_clients: config.limits.max_clients,
        streams_per_client: config.limits.streams_per_client,
        pending_dials: config.limits.pending_dials,
        message,
    })
}

async fn authenticated(state: &AppState, headers: &HeaderMap) -> Option<VerifiedSession> {
    state.admin_auth.verify(&cookie(headers)?).await
}
async fn csrf_token(state: &AppState, headers: &HeaderMap, csrf: &str) -> Option<VerifiedSession> {
    let token = cookie(headers)?;
    if state.admin_auth.verify_csrf(&token, csrf).await {
        state.admin_auth.verify(&token).await
    } else {
        None
    }
}
fn cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| {
            part.strip_prefix(&format!("{COOKIE_NAME}="))
                .map(str::to_owned)
        })
}
fn clear_cookie(mut response: Response) -> Response {
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "wispdeck_admin=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0; Secure",
        ),
    );
    response
}
fn lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}
fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "invalid session or CSRF token").into_response()
}
fn bad_request(error: anyhow::Error) -> Response {
    (StatusCode::BAD_REQUEST, error.to_string()).into_response()
}
fn render(template: impl Template) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "template rendering failed",
        )
            .into_response(),
    }
}
