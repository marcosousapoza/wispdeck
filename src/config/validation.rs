use super::Config;
use anyhow::{Result, ensure};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

pub fn validate(config: &Config) -> Result<()> {
    config.listen.parse::<SocketAddr>()?;
    ensure!(
        !config.policy.allowed_ports.is_empty(),
        "at least one outbound port must be allowed"
    );
    ensure!(
        config.policy.allowed_ports.iter().all(|port| *port > 0),
        "outbound port zero is invalid"
    );
    ensure!(
        config.limits.max_clients > 0 && config.limits.streams_per_client > 0,
        "client and stream limits must be nonzero"
    );
    ensure!(
        config.limits.pending_dials > 0,
        "pending dial limit must be nonzero"
    );
    ensure!(
        (1..=3600).contains(&config.admin.session_minutes),
        "admin session duration must be 1..=3600 minutes"
    );
    ensure!(
        config.timeouts.dns_seconds > 0 && config.timeouts.dial_seconds > 0,
        "DNS and dial timeouts must be nonzero"
    );
    ensure!(
        config.limits.websocket_message_bytes >= 1024,
        "WebSocket message limit is too small"
    );
    let theoretical_buffer_bytes = config
        .limits
        .max_clients
        .checked_mul(config.limits.streams_per_client)
        .and_then(|value| value.checked_mul(config.limits.stream_buffer_messages as usize))
        .and_then(|value| value.checked_mul(config.limits.websocket_message_bytes))
        .ok_or_else(|| anyhow::anyhow!("buffer limits overflow"))?;
    ensure!(
        theoretical_buffer_bytes <= config.limits.max_total_buffered_bytes,
        "client, stream, message, and buffer limits exceed max_total_buffered_bytes"
    );
    for rule in config
        .policy
        .allowed_hosts
        .iter()
        .chain(&config.policy.blocked_hosts)
    {
        let host = rule.strip_prefix("*.").unwrap_or(rule);
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && host.is_ascii()
                && host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')),
            "invalid hostname rule {rule:?}"
        );
    }
    EnvFilter::try_new(&config.log_level)
        .map_err(|error| anyhow::anyhow!("invalid log level/filter: {error}"))?;
    Ok(())
}
