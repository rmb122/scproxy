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
    /// Explicit rules override local-address defaults, then fall back to `-x`.
    pub fn proxy_for(&self, target: &ProxyTarget) -> &ProxyConfig {
        let matched = match target {
            ProxyTarget::Domain { host, .. } => self.rules.match_domain(host),
            ProxyTarget::Ip { addr, .. } => match addr {
                IpAddr::V4(v4) => self.rules.match_ip(*v4).or_else(|| {
                    (v4.is_loopback() || v4.is_unspecified()).then_some(&ProxyConfig::Direct)
                }),
                IpAddr::V6(_) => None,
            },
        };
        matched.unwrap_or(&self.default_proxy)
    }
}

/// The resolver address is virtual; seccomp redirects it to the broker.
pub mod net {
    use std::net::Ipv4Addr;
    /// Reserved for DNS; domain FakeIPs are allocated after this address.
    pub const DNS_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
    pub const DNS_PORT: u16 = 53;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(ip: &str) -> ProxyTarget {
        ProxyTarget::Ip {
            addr: ip.parse().unwrap(),
            port: 443,
        }
    }

    #[test]
    fn explicit_ip_rules_override_local_defaults_without_aliasing_zero() {
        let mut config = Config {
            default_proxy: ProxyConfig::parse("http://127.0.0.1:8080").unwrap(),
            command: Vec::new(),
            rules: RuleMatcher::default(),
        };
        for ip in ["0.0.0.0", "127.0.0.1", "127.42.1.2", "127.255.255.255"] {
            assert_eq!(config.proxy_for(&address(ip)), &ProxyConfig::Direct);
        }
        assert_eq!(
            config.proxy_for(&address("203.0.113.1")),
            &config.default_proxy
        );
        let socks = ProxyConfig::parse("socks5://127.0.0.1:1080").unwrap();
        for (rule, covered, uncovered) in [
            (
                "cidr:127.0.0.0/8=socks5://127.0.0.1:1080",
                "127.42.1.2",
                "0.0.0.0",
            ),
            ("ip:0.0.0.0=socks5://127.0.0.1:1080", "0.0.0.0", "127.0.0.1"),
        ] {
            config.rules = RuleMatcher::from_specs(&[rule]).unwrap();
            assert_eq!(config.proxy_for(&address(covered)), &socks);
            assert_eq!(config.proxy_for(&address(uncovered)), &ProxyConfig::Direct);
        }
        config.rules = RuleMatcher::from_specs(&[
            "cidr:0.0.0.0/0=socks5://127.0.0.1:1080",
            "ip:127.0.0.1=direct",
            "domain:localhost=direct",
        ])
        .unwrap();
        assert_eq!(
            config.proxy_for(&address("127.0.0.1")),
            &ProxyConfig::Direct
        );
        assert_eq!(config.proxy_for(&address("0.0.0.0")), &socks);
        assert_eq!(config.proxy_for(&address("127.0.0.2")), &socks);
        assert_eq!(
            config.proxy_for(&ProxyTarget::Domain {
                host: "localhost".into(),
                port: 443
            }),
            &ProxyConfig::Direct
        );
    }
}
