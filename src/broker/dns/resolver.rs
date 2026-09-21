use super::lookup::{self, SERVFAIL};
use crate::config::Config;
use crate::fake_dns::{self, FakeDns};
use crate::proxy::{ProxyConfig, ProxyTarget};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::Instant;

const DIRECT_TTL: u32 = 60;
const MAX_DIRECT_ADDRESSES: usize = 65536;

#[derive(Default)]
struct Addresses {
    fake: FakeDns,
    direct: HashMap<Ipv4Addr, Instant>,
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(in crate::broker) struct Resolver {
    config: Arc<Config>,
    addresses: Mutex<Addresses>,
    lookups: Arc<Semaphore>,
}

impl Resolver {
    pub(super) fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            addresses: Mutex::new(Addresses::default()),
            lookups: Arc::new(Semaphore::new(32)),
        }
    }

    pub(super) fn target(&self, address: SocketAddrV4) -> ProxyTarget {
        let addresses = self.addresses.lock().unwrap();
        match addresses.fake.lookup(*address.ip()) {
            Some(domain) => ProxyTarget::Domain {
                host: domain.to_owned(),
                port: address.port(),
            },
            None => ProxyTarget::Ip {
                addr: (*address.ip()).into(),
                port: address.port(),
            },
        }
    }

    pub(super) fn is_direct(&self, address: Ipv4Addr) -> bool {
        self.addresses
            .lock()
            .unwrap()
            .direct
            .get(&address)
            .is_some_and(|expiry| *expiry > Instant::now())
    }

    fn remember_direct(&self, resolved: &[Ipv4Addr]) -> Result<(), u8> {
        let mut addresses = self.addresses.lock().unwrap();
        // The synthetic pool is reserved for domain identity; host DNS must
        // never turn an existing proxy domain's FakeIP into a direct route.
        if resolved.iter().any(|ip| addresses.fake.is_fake_ip(*ip)) {
            return Err(SERVFAIL);
        }
        let now = Instant::now();
        addresses.direct.retain(|_, expiry| *expiry > now);
        let additional = resolved
            .iter()
            .filter(|ip| !addresses.direct.contains_key(ip))
            .count();
        if addresses.direct.len() + additional > MAX_DIRECT_ADDRESSES {
            return Err(SERVFAIL);
        }
        let expiry = now + Duration::from_secs(u64::from(DIRECT_TTL));
        for &ip in resolved {
            addresses.direct.insert(ip, expiry);
        }
        Ok(())
    }

    pub(super) async fn answer(&self, query: &[u8], limit: usize) -> Option<Vec<u8>> {
        let (id, domain, kind) = fake_dns::parse_query(query)?;
        if kind != 1 {
            return Some(fake_dns::build_empty_response(id, &domain, kind));
        }
        let target = ProxyTarget::Domain {
            host: domain.clone(),
            port: 0,
        };
        if self.config.proxy_for(&target) != &ProxyConfig::Direct {
            let ip = self.addresses.lock().unwrap().fake.resolve(&domain);
            tracing::debug!(%domain, %ip, "proxy DNS");
            return Some(fake_dns::build_a_response(id, &domain, ip));
        }
        let result = lookup::ipv4(domain.clone(), self.lookups.clone())
            .await
            .and_then(|addresses| {
                self.remember_direct(&addresses)?;
                Ok(addresses)
            });
        Some(match result {
            Ok(addresses) => {
                tracing::debug!(%domain, ?addresses, "direct DNS");
                fake_dns::build_a_records(id, &domain, &addresses, DIRECT_TTL, limit)
            }
            Err(rcode) => {
                tracing::debug!(%domain, rcode, "direct DNS failed");
                fake_dns::build_error_response(id, &domain, kind, rcode)
            }
        })
    }
}
