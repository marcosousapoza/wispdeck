pub mod storage;
pub mod validation;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub log_level: String,
    pub admin: AdminConfig,
    pub policy: PolicyConfig,
    pub limits: LimitsConfig,
    pub timeouts: TimeoutConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub secure_cookie: bool,
    pub session_minutes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub allowed_ports: Vec<u16>,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    pub allow_direct_ip: bool,
    pub allow_non_public_ips: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_clients: usize,
    pub streams_per_client: usize,
    pub pending_dials: usize,
    pub websocket_message_bytes: usize,
    pub stream_buffer_messages: u32,
    pub max_total_buffered_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutConfig {
    pub dns_seconds: u64,
    pub dial_seconds: u64,
    pub idle_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            log_level: "info".into(),
            admin: AdminConfig::default(),
            policy: PolicyConfig::default(),
            limits: LimitsConfig::default(),
            timeouts: TimeoutConfig::default(),
        }
    }
}
impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            secure_cookie: false,
            session_minutes: 30,
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allowed_ports: vec![465, 587, 993],
            allowed_hosts: vec![],
            blocked_hosts: vec![],
            allow_direct_ip: false,
            allow_non_public_ips: false,
        }
    }
}
impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_clients: 64,
            streams_per_client: 16,
            pending_dials: 64,
            websocket_message_bytes: 65_536,
            stream_buffer_messages: 8,
            max_total_buffered_bytes: 536_870_912,
        }
    }
}
impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            dns_seconds: 5,
            dial_seconds: 10,
            idle_seconds: 300,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn secure_cookie_starts_disabled_for_http_bootstrap() {
        assert!(!Config::default().admin.secure_cookie);
    }
}
