use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginForm {
    pub password: String,
}

#[derive(Deserialize)]
pub struct UserForm {
    pub csrf: String,
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ActionForm {
    pub csrf: String,
    pub username: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Deserialize)]
pub struct PasswordForm {
    pub csrf: String,
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct PolicyForm {
    pub csrf: String,
    pub allowed_ports: String,
    pub allowed_hosts: String,
    pub blocked_hosts: String,
    pub allow_direct_ip: Option<String>,
    pub allow_non_public_ips: Option<String>,
    pub max_clients: usize,
    pub streams_per_client: usize,
    pub pending_dials: usize,
}

#[derive(Deserialize)]
pub struct ServerForm {
    pub csrf: String,
    pub listen: String,
    pub log_level: String,
    pub secure_cookie: Option<String>,
    pub dns_seconds: u64,
    pub dial_seconds: u64,
    pub idle_seconds: u64,
}
