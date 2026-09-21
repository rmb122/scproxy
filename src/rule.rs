//! Ordered outbound-routing rules for `--rule`.

use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use regex::{Regex, RegexSet};

use crate::proxy::ProxyConfig;

#[derive(Debug, Clone)]
struct MatchAction {
    proxy: ProxyConfig,
}

/// IPv4 longest-prefix matcher. The first rule wins when prefix lengths tie.
#[derive(Debug, Clone, Default)]
struct PrefixTrie {
    children: [Option<Box<PrefixTrie>>; 2],
    action: Option<MatchAction>,
}

impl PrefixTrie {
    fn insert(&mut self, value: u32, prefix: u8, action: MatchAction) {
        debug_assert!(prefix <= 32);
        let mut node = self;
        for i in 0..prefix {
            let bit = ((value >> (31 - i)) & 1) as usize;
            node = node.children[bit].get_or_insert_with(Default::default);
        }
        if node.action.is_none() {
            node.action = Some(action);
        }
    }

    fn get(&self, value: u32) -> Option<&MatchAction> {
        let mut node = self;
        let mut best = node.action.as_ref();
        for i in 0..32 {
            let bit = ((value >> (31 - i)) & 1) as usize;
            let Some(child) = node.children[bit].as_deref() else {
                break;
            };
            node = child;
            if node.action.is_some() {
                best = node.action.as_ref();
            }
        }
        best
    }
}

enum RuleMatch {
    Ip(Ipv4Addr),
    Cidr { network: Ipv4Addr, prefix: u8 },
    Domain(String),
    DomainRegex(String),
}

impl RuleMatch {
    fn parse(spec: &str) -> Result<Self> {
        let (kind, value) = spec
            .split_once(':')
            .with_context(|| format!("rule '{spec}' is missing a '<kind>:' prefix"))?;

        match kind {
            "ip" => {
                let addr = value.parse().with_context(|| {
                    format!("rule '{spec}': invalid IPv4 address (IPv6 is not supported)")
                })?;
                Ok(Self::Ip(addr))
            }
            "cidr" => {
                let (network, prefix) = value
                    .split_once('/')
                    .with_context(|| format!("rule '{spec}': CIDR must be 'addr/prefix'"))?;
                let network = network.parse().with_context(|| {
                    format!("rule '{spec}': invalid IPv4 CIDR network (IPv6 is not supported)")
                })?;
                let prefix: u8 = prefix
                    .parse()
                    .with_context(|| format!("rule '{spec}': invalid CIDR prefix"))?;
                if prefix > 32 {
                    bail!("rule '{spec}': prefix /{prefix} out of range (max /32)");
                }
                Ok(Self::Cidr { network, prefix })
            }
            "domain" => {
                if value.is_empty() {
                    bail!("rule '{spec}': empty domain");
                }
                Ok(Self::Domain(value.to_string()))
            }
            "domain-regex" => {
                Regex::new(value).with_context(|| format!("rule '{spec}': invalid regex"))?;
                Ok(Self::DomainRegex(value.to_string()))
            }
            other => bail!(
                "rule '{spec}': unknown kind '{other}' (expected ip / cidr / domain / domain-regex)"
            ),
        }
    }
}

/// Pre-built rules. Domain rules preserve CLI order; IP rules use longest-prefix matching.
#[derive(Debug, Clone, Default)]
pub struct RuleMatcher {
    domains: Option<RegexSet>,
    domain_actions: Vec<MatchAction>,
    cidr: PrefixTrie,
}

impl RuleMatcher {
    pub fn from_specs<S: AsRef<str>>(specs: &[S]) -> Result<Self> {
        let mut domain_patterns = Vec::new();
        let mut domain_actions = Vec::new();
        let mut cidr = PrefixTrie::default();

        for full_spec in specs {
            let full_spec = full_spec.as_ref();
            let (match_spec, proxy_spec) = full_spec
                .split_once('=')
                .with_context(|| format!("rule '{full_spec}' must use '<match>=<proxy>'"))?;
            if match_spec.is_empty() {
                bail!("rule '{full_spec}': empty match");
            }
            if proxy_spec.is_empty() {
                bail!("rule '{full_spec}': empty proxy");
            }

            let proxy = ProxyConfig::parse(proxy_spec)
                .with_context(|| format!("rule '{full_spec}': invalid proxy"))?;
            let action = MatchAction { proxy };

            match RuleMatch::parse(match_spec)? {
                RuleMatch::Ip(addr) => cidr.insert(u32::from(addr), 32, action),
                RuleMatch::Cidr { network, prefix } => {
                    cidr.insert(u32::from(network), prefix, action)
                }
                RuleMatch::Domain(domain) => {
                    domain_patterns.push(format!("(?i)^{}$", regex::escape(&domain)));
                    domain_actions.push(action);
                }
                RuleMatch::DomainRegex(pattern) => {
                    domain_patterns.push(pattern);
                    domain_actions.push(action);
                }
            }
        }

        let domains = if domain_patterns.is_empty() {
            None
        } else {
            Some(RegexSet::new(&domain_patterns).context("compile rule RegexSet")?)
        };

        Ok(Self {
            domains,
            domain_actions,
            cidr,
        })
    }

    pub fn match_domain(&self, host: &str) -> Option<&ProxyConfig> {
        let index = self.domains.as_ref()?.matches(host).iter().next()?;
        Some(&self.domain_actions[index].proxy)
    }

    pub fn match_ip(&self, ip: Ipv4Addr) -> Option<&ProxyConfig> {
        self.cidr.get(u32::from(ip)).map(|action| &action.proxy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct() -> ProxyConfig {
        ProxyConfig::Direct
    }

    fn v4(value: &str) -> Ipv4Addr {
        value.parse().unwrap()
    }

    #[test]
    fn requires_match_and_proxy() {
        assert!(RuleMatcher::from_specs(&["ip:1.2.3.4"]).is_err());
        assert!(RuleMatcher::from_specs(&["=direct"]).is_err());
        assert!(RuleMatcher::from_specs(&["ip:1.2.3.4="]).is_err());
        assert!(RuleMatcher::from_specs(&["ip:1.2.3.4=unknown"]).is_err());
    }

    #[test]
    fn exact_ip_rule_returns_its_proxy() {
        let rules = RuleMatcher::from_specs(&["ip:1.2.3.4=direct"]).unwrap();
        assert_eq!(rules.match_ip(v4("1.2.3.4")), Some(&direct()));
        assert_eq!(rules.match_ip(v4("1.2.3.5")), None);
    }

    #[test]
    fn longest_ip_prefix_wins() {
        let rules = RuleMatcher::from_specs(&[
            "cidr:10.0.0.0/8=direct",
            "cidr:10.1.0.0/16=socks5://127.0.0.1:1081",
        ])
        .unwrap();
        assert!(matches!(
            rules.match_ip(v4("10.1.2.3")),
            Some(ProxyConfig::Socks5 { .. })
        ));
        assert_eq!(rules.match_ip(v4("10.2.2.3")), Some(&direct()));
    }

    #[test]
    fn first_ip_rule_wins_equal_prefix_tie() {
        let rules = RuleMatcher::from_specs(&[
            "ip:1.1.1.1=direct",
            "cidr:1.1.1.1/32=http://127.0.0.1:8080",
        ])
        .unwrap();
        assert_eq!(rules.match_ip(v4("1.1.1.1")), Some(&direct()));
    }

    #[test]
    fn first_matching_domain_rule_wins_in_mixed_order() {
        let rules = RuleMatcher::from_specs(&[
            r"domain-regex:.*\.example\.com=direct",
            "domain:www.example.com=http://127.0.0.1:8080",
        ])
        .unwrap();
        assert_eq!(rules.match_domain("www.example.com"), Some(&direct()));
    }

    #[test]
    fn domain_literal_is_exact_and_case_insensitive() {
        let rules = RuleMatcher::from_specs(&["domain:Example.COM=direct"]).unwrap();
        assert_eq!(rules.match_domain("example.com"), Some(&direct()));
        assert_eq!(rules.match_domain("sub.example.com"), None);
    }

    #[test]
    fn rejects_bad_match_specs() {
        assert!(RuleMatcher::from_specs(&["foo:bar=direct"]).is_err());
        assert!(RuleMatcher::from_specs(&["cidr:1.2.3.4/40=direct"]).is_err());
        assert!(RuleMatcher::from_specs(&["domain-regex:[=direct"]).is_err());
        assert!(RuleMatcher::from_specs(&["ip:2001:db8::1=direct"]).is_err());
    }
}
