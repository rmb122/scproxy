use std::net::IpAddr;

use crate::proxy::{ProxyConfig, ProxyTarget};
use crate::rule::RuleMatcher;

#[derive(Debug, Clone)]
pub struct Config {
    /// Route used when no rule matches the destination.
    pub default_proxy: ProxyConfig,
    pub command: Vec<String>,
    pub rules: RuleMatcher,
}

impl Config {
    /// Select the first applicable rule route, or fall back to `-x`.
    pub fn proxy_for(&self, target: &ProxyTarget) -> &ProxyConfig {
        let matched = match target {
            ProxyTarget::Domain { host, .. } => self.rules.match_domain(host),
            ProxyTarget::Ip { addr, .. } => match addr {
                IpAddr::V4(v4) => self.rules.match_ip(*v4),
                IpAddr::V6(_) => None,
            },
        };
        matched.unwrap_or(&self.default_proxy)
    }
}

/// The resolver address is virtual; seccomp redirects it to the broker.
pub mod net {
    use std::net::Ipv4Addr;
    pub const DNS_ADDR: Ipv4Addr = Ipv4Addr::new(172, 23, 255, 254);
    pub const DNS_PORT: u16 = 53;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_rule_overrides_default_and_miss_falls_back() {
        let config = Config {
            default_proxy: ProxyConfig::Direct,
            command: Vec::new(),
            rules: RuleMatcher::from_specs(&["ip:1.1.1.1=socks5://127.0.0.1:1081"]).unwrap(),
        };

        let matched = ProxyTarget::Ip {
            addr: "1.1.1.1".parse().unwrap(),
            port: 443,
        };
        let missed = ProxyTarget::Ip {
            addr: "8.8.8.8".parse().unwrap(),
            port: 443,
        };

        assert!(matches!(
            config.proxy_for(&matched),
            ProxyConfig::Socks5 { .. }
        ));
        assert_eq!(config.proxy_for(&missed), &ProxyConfig::Direct);
    }
}
