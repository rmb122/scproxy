use super::*;
use crate::rule::RuleMatcher;

fn resolver(default_proxy: &str, rules: &[&str]) -> Resolver {
    Resolver::new(Arc::new(Config {
        default_proxy: ProxyConfig::parse(default_proxy).unwrap(),
        command: Vec::new(),
        rules: RuleMatcher::from_specs(rules).unwrap(),
    }))
}

fn query(domain: &str) -> Vec<u8> {
    let mut query = fake_dns::build_empty_response(0x1234, domain, 1);
    query[2] = 1;
    query[3] = 0;
    query
}

#[tokio::test]
async fn proxy_queries_do_not_need_host_lookup_capacity() {
    let resolver = resolver("direct", &["domain:proxy.invalid=http://127.0.0.1:1"]);
    let _occupied = resolver
        .lookups
        .clone()
        .acquire_many_owned(32)
        .await
        .unwrap();
    let answer = resolver.answer(&query("proxy.invalid"), 512).await.unwrap();
    assert_eq!(answer[3] & 0xf, 0);
    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&answer[answer.len() - 4..]).unwrap());
    assert!(
        matches!(resolver.target(SocketAddrV4::new(ip, 443)), ProxyTarget::Domain {host, ..} if host == "proxy.invalid")
    );
    assert!(!resolver.is_direct(ip));
    let failed = resolver.answer(&query("localhost"), 512).await.unwrap();
    assert_eq!(failed[3] & 0xf, SERVFAIL);
    assert_eq!(&failed[6..8], &[0, 0]);
}

#[tokio::test]
async fn direct_dns_returns_host_ipv4_with_a_matching_route_lifetime() {
    let resolver = resolver("http://127.0.0.1:1", &["domain:localhost=direct"]);
    let answer = resolver.answer(&query("localhost"), 512).await.unwrap();
    assert_eq!(answer[3] & 0xf, 0);
    assert_eq!(&answer[answer.len() - 4..], &[127, 0, 0, 1]);
    assert_eq!(
        u32::from_be_bytes(
            answer[answer.len() - 10..answer.len() - 6]
                .try_into()
                .unwrap()
        ),
        DIRECT_TTL
    );
    assert!(resolver.is_direct(Ipv4Addr::LOCALHOST));
    assert!(matches!(
        resolver.target(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
        ProxyTarget::Ip { .. }
    ));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(u64::from(DIRECT_TTL))).await;
    assert!(!resolver.is_direct(Ipv4Addr::LOCALHOST));
}

#[tokio::test(start_paused = true)]
async fn full_direct_cache_preserves_live_routes_and_reclaims_expired_entries() {
    let resolver = resolver("direct", &[]);
    let addresses: Vec<_> = (0..MAX_DIRECT_ADDRESSES)
        .map(|i| Ipv4Addr::from(0x0a000000 + i as u32))
        .collect();
    resolver.remember_direct(&addresses).unwrap();
    assert_eq!(
        resolver.remember_direct(&[Ipv4Addr::new(198, 18, 0, 1)]),
        Err(SERVFAIL)
    );
    assert_eq!(
        resolver.remember_direct(&[Ipv4Addr::LOCALHOST]),
        Err(SERVFAIL)
    );
    assert!(resolver.is_direct(addresses[0]));
    resolver.remember_direct(&addresses[..1]).unwrap();
    tokio::time::advance(Duration::from_secs(u64::from(DIRECT_TTL))).await;
    resolver.remember_direct(&[Ipv4Addr::LOCALHOST]).unwrap();
    assert!(!resolver.is_direct(addresses[0]));
    assert_eq!(resolver.addresses.lock().unwrap().direct.len(), 1);
}
