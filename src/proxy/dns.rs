use std::{collections::HashSet, net::SocketAddr, time::Duration};

use tokio::{
    net::{TcpStream, lookup_host},
    time::timeout,
};

use crate::{
    config::Config,
    proxy::policy::{authorize_host, authorize_ip},
};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("destination blocked by policy: {0}")]
    Blocked(String),
    #[error("DNS lookup timed out")]
    DnsTimeout,
    #[error("DNS lookup failed: {0}")]
    Dns(#[source] std::io::Error),
    #[error("DNS returned no allowed addresses")]
    NoAddresses,
    #[error("outbound connection failed: {0}")]
    Dial(#[source] std::io::Error),
    #[error("outbound connection timed out")]
    DialTimeout,
}

pub async fn connect_validated(
    config: &Config,
    host: &str,
    port: u16,
) -> Result<TcpStream, ConnectError> {
    authorize_host(&config.policy, host, port)
        .map_err(|denial| ConnectError::Blocked(format!("{denial:?}")))?;
    let addresses = timeout(
        Duration::from_secs(config.timeouts.dns_seconds),
        lookup_host((host, port)),
    )
    .await
    .map_err(|_| ConnectError::DnsTimeout)?
    .map_err(ConnectError::Dns)?;
    let mut validated = Vec::new();
    let mut seen = HashSet::new();
    for address in addresses {
        let ip = authorize_ip(&config.policy, address.ip())
            .map_err(|denial| ConnectError::Blocked(format!("resolved address: {denial:?}")))?;
        let exact = SocketAddr::new(ip, port);
        if seen.insert(exact) {
            validated.push(exact);
        }
    }
    if validated.is_empty() {
        return Err(ConnectError::NoAddresses);
    }
    let mut last_error = None;
    for address in validated {
        match timeout(
            Duration::from_secs(config.timeouts.dial_seconds),
            TcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(ConnectError::Dial(error)),
            Err(_) => last_error = Some(ConnectError::DialTimeout),
        }
    }
    Err(last_error.unwrap_or(ConnectError::NoAddresses))
}
