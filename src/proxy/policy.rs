use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::PolicyConfig;

#[derive(Debug, PartialEq, Eq)]
pub enum Denial {
    Port,
    Host,
    DirectIp,
    Address,
}

pub fn authorize_host(policy: &PolicyConfig, host: &str, port: u16) -> Result<(), Denial> {
    if !policy.allowed_ports.contains(&port) {
        return Err(Denial::Port);
    }
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized.parse::<IpAddr>().is_ok() && !policy.allow_direct_ip {
        return Err(Denial::DirectIp);
    }
    if policy
        .blocked_hosts
        .iter()
        .any(|rule| host_matches(&normalized, rule))
    {
        return Err(Denial::Host);
    }
    if !policy.allowed_hosts.is_empty()
        && !policy
            .allowed_hosts
            .iter()
            .any(|rule| host_matches(&normalized, rule))
    {
        return Err(Denial::Host);
    }
    Ok(())
}

pub fn authorize_ip(policy: &PolicyConfig, ip: IpAddr) -> Result<IpAddr, Denial> {
    let ip = match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        value => value,
    };
    if !policy.allow_non_public_ips && !is_public(ip) {
        return Err(Denial::Address);
    }
    Ok(ip)
}

fn host_matches(host: &str, rule: &str) -> bool {
    let rule = rule.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = rule.strip_prefix("*.") {
        host != suffix && host.ends_with(&format!(".{suffix}"))
    } else {
        host == rule
    }
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && matches!(octets[2], 0 | 2))
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 224)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !((segments[0] & 0xe000) != 0x2000
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x2001 && matches!(segments[1], 0 | 2 | 0x10 | 0x20))
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && segments[1] < 0x1000)
        || ip.to_ipv4_mapped().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_and_mapped_addresses() {
        let policy = PolicyConfig::default();
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "::ffff:192.168.1.1",
            "2001:db8::1",
        ] {
            assert_eq!(
                authorize_ip(&policy, address.parse().unwrap()),
                Err(Denial::Address)
            );
        }
    }

    #[test]
    fn default_ports_and_direct_ip_policy() {
        let policy = PolicyConfig::default();
        assert_eq!(authorize_host(&policy, "mail.example", 993), Ok(()));
        assert_eq!(
            authorize_host(&policy, "mail.example", 25),
            Err(Denial::Port)
        );
        assert_eq!(
            authorize_host(&policy, "8.8.8.8", 993),
            Err(Denial::DirectIp)
        );
    }
}
