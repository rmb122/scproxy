//! Fake-DNS module for scproxy.
//!
//! Intercepts DNS queries, allocates synthetic IPv4 addresses from the
//! 198.18.0.0/15 pool (RFC 2544 benchmarking range, never routed on the
//! public internet), and keeps a bidirectional domain ↔ fake-IP mapping.
//! When the guest application connects to one of these fake IPs the proxy
//! engine looks up the original domain and opens a real connection through
//! the upstream proxy.

use std::collections::HashMap;
use std::net::Ipv4Addr;

// ── Pool constants ────────────────────────────────────────────────────────────

/// First usable address in the pool (198.18.0.1).
const POOL_START: u32 = u32::from_be_bytes([198, 18, 0, 1]);

/// Last usable address in the pool (198.19.255.254).
const POOL_END: u32 = u32::from_be_bytes([198, 19, 255, 254]);

/// Total number of usable addresses (131 070).
const POOL_SIZE: u32 = POOL_END - POOL_START + 1;

// ── FakeDns ───────────────────────────────────────────────────────────────────

/// Bidirectional domain ↔ fake-IP mapping with a bounded address pool.
///
/// When the pool is exhausted allocations wrap around and the oldest
/// mapping is silently overwritten.
pub struct FakeDns {
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_domain: HashMap<Ipv4Addr, String>,
    /// Index into the pool (0 … POOL_SIZE-1) for the *next* allocation.
    next_offset: u32,
}

impl FakeDns {
    /// Create an empty instance.
    pub fn new() -> Self {
        Self {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
            next_offset: 0,
        }
    }

    /// Return the fake IP allocated for `domain`, allocating a new one if
    /// this domain has not been seen before.  The same domain always gets
    /// the same IP until it is evicted by pool wrap-around.
    pub fn resolve(&mut self, domain: &str) -> Ipv4Addr {
        // Fast path: already have a mapping.
        if let Some(&ip) = self.domain_to_ip.get(domain) {
            return ip;
        }

        let ip = Ipv4Addr::from(POOL_START + self.next_offset);
        self.next_offset = (self.next_offset + 1) % POOL_SIZE;

        // Evict the previous mapping for this IP slot (wrap-around case).
        if let Some(old_domain) = self.ip_to_domain.remove(&ip) {
            self.domain_to_ip.remove(&old_domain);
        }

        self.ip_to_domain.insert(ip, domain.to_string());
        self.domain_to_ip.insert(domain.to_string(), ip);

        ip
    }

    /// Reverse-lookup: return the domain name for a fake IP, if any.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&str> {
        self.ip_to_domain.get(&ip).map(String::as_str)
    }

    /// Return `true` iff `ip` falls within the fake-IP pool range.
    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        let n = u32::from(ip);
        (POOL_START..=POOL_END).contains(&n)
    }
}

impl Default for FakeDns {
    fn default() -> Self {
        Self::new()
    }
}

// ── DNS packet helpers ────────────────────────────────────────────────────────

/// Parse a raw DNS query datagram.
///
/// Returns `(transaction_id, domain, qtype)` on success, or `None` if the
/// datagram is too short, malformed, or is itself a response.
///
/// Only the first question record is examined; QCLASS is ignored.
pub fn parse_query(data: &[u8]) -> Option<(u16, String, u16)> {
    // Minimum DNS header is 12 bytes.
    if data.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);

    // QR bit (bit 15) must be 0 for a query.
    if flags & 0x8000 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }

    // Decode QNAME starting immediately after the 12-byte header.
    let mut pos = 12usize;
    let mut labels: Vec<&str> = Vec::new();

    loop {
        if pos >= data.len() {
            return None;
        }
        let label_len = data[pos] as usize;
        if label_len == 0 {
            pos += 1; // consume the terminating zero
            break;
        }
        // Compression pointers (top two bits set) are not expected in
        // client queries, but guard against them to avoid a panic.
        if label_len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        let end = pos + label_len;
        if end > data.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&data[pos..end]).ok()?);
        pos = end;
    }

    // Need 4 more bytes for QTYPE + QCLASS.
    if pos + 4 > data.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let domain = labels.join(".");

    Some((id, domain, qtype))
}

/// Build a DNS response with a single A record answer.
///
/// The question section is rebuilt from `domain`; the answer uses the
/// standard `0xC00C` name-compression pointer back to offset 12.
pub fn build_a_response(id: u16, domain: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // ── Header ────────────────────────────────────────────────────────────
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // QR AA RD RA
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // ── Question section (offset 12) ──────────────────────────────────────
    encode_name(&mut pkt, domain);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE  A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    // ── Answer section ────────────────────────────────────────────────────
    pkt.extend_from_slice(&0xC00Cu16.to_be_bytes()); // NAME: pointer → offset 12
    pkt.extend_from_slice(&1u16.to_be_bytes()); // TYPE  A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL 300 s
    pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH 4
    pkt.extend_from_slice(&ip.octets()); // RDATA

    pkt
}

/// Build a DNS response with an empty answer section (zero records).
///
/// Used for AAAA queries (or any unsupported QTYPE) to return a clean
/// NOERROR/no-data response so the resolver does not time out.
pub fn build_empty_response(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(32);

    // ── Header ────────────────────────────────────────────────────────────
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // QR AA RD RA
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // ── Question section ──────────────────────────────────────────────────
    encode_name(&mut pkt, domain);
    pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE (echoed)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    pkt
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Encode a dotted-label domain name into the DNS wire format
/// (length-prefixed labels terminated by a zero byte).
fn encode_name(buf: &mut Vec<u8>, domain: &str) {
    if !domain.is_empty() {
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0); // root label terminator
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FakeDns ───────────────────────────────────────────────────────────

    #[test]
    fn resolve_and_lookup() {
        let mut dns = FakeDns::new();
        let ip = dns.resolve("example.com");
        assert_eq!(
            dns.lookup(ip),
            Some("example.com"),
            "reverse lookup should return the domain that was resolved"
        );
    }

    #[test]
    fn same_domain_same_ip() {
        let mut dns = FakeDns::new();
        let ip1 = dns.resolve("example.com");
        let ip2 = dns.resolve("example.com");
        assert_eq!(
            ip1, ip2,
            "resolving the same domain twice must return the same IP"
        );
    }

    #[test]
    fn different_domains_get_different_ips() {
        let mut dns = FakeDns::new();
        let ip1 = dns.resolve("foo.example.com");
        let ip2 = dns.resolve("bar.example.com");
        assert_ne!(ip1, ip2, "distinct domains must receive distinct fake IPs");
    }

    #[test]
    fn unknown_ip_returns_none() {
        let dns = FakeDns::new();
        assert_eq!(dns.lookup(Ipv4Addr::new(1, 2, 3, 4)), None);
    }

    #[test]
    fn is_fake_ip_inside_pool() {
        let dns = FakeDns::new();
        // First usable address
        assert!(dns.is_fake_ip(Ipv4Addr::new(198, 18, 0, 1)));
        // Last usable address
        assert!(dns.is_fake_ip(Ipv4Addr::new(198, 19, 255, 254)));
        // Somewhere in the middle
        assert!(dns.is_fake_ip(Ipv4Addr::new(198, 18, 128, 1)));
        assert!(dns.is_fake_ip(Ipv4Addr::new(198, 19, 0, 1)));
    }

    #[test]
    fn is_fake_ip_outside_pool() {
        let dns = FakeDns::new();
        // Network address (excluded)
        assert!(!dns.is_fake_ip(Ipv4Addr::new(198, 18, 0, 0)));
        // Broadcast address (excluded)
        assert!(!dns.is_fake_ip(Ipv4Addr::new(198, 19, 255, 255)));
        // Before the pool
        assert!(!dns.is_fake_ip(Ipv4Addr::new(198, 17, 255, 255)));
        // After the pool
        assert!(!dns.is_fake_ip(Ipv4Addr::new(198, 20, 0, 1)));
        // Completely unrelated
        assert!(!dns.is_fake_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!dns.is_fake_ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn first_allocation_starts_at_pool_start() {
        let mut dns = FakeDns::new();
        let ip = dns.resolve("first.test");
        assert_eq!(
            u32::from(ip),
            POOL_START,
            "first allocation must be POOL_START"
        );
    }

    #[test]
    fn wrap_around_overwrites_oldest_mapping() {
        let mut dns = FakeDns::new();

        // Fill the entire pool.
        for i in 0..POOL_SIZE {
            dns.resolve(&format!("d{}.test", i));
        }

        // The very next allocation wraps back to POOL_START and evicts "d0.test".
        let wrapped_ip = dns.resolve("new.test");
        assert_eq!(
            u32::from(wrapped_ip),
            POOL_START,
            "wrap-around must reuse POOL_START"
        );
        assert_eq!(
            dns.lookup(Ipv4Addr::from(POOL_START)),
            Some("new.test"),
            "POOL_START must now map to the new domain"
        );
        // The evicted domain no longer has a mapping.
        assert!(
            !dns.domain_to_ip.contains_key("d0.test"),
            "evicted domain must be removed from forward map"
        );
    }

    // ── DNS packet helpers ────────────────────────────────────────────────

    /// Build a minimal query datagram for `domain` with the given qtype.
    fn make_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        encode_name(&mut pkt, domain);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        pkt
    }

    #[test]
    fn parse_query_a_record() {
        let pkt = make_query(0x1234, "example.com", 1 /* A */);
        let result = parse_query(&pkt);
        assert!(result.is_some(), "valid A query must parse successfully");
        let (id, domain, qtype) = result.unwrap();
        assert_eq!(id, 0x1234);
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn parse_query_aaaa_record() {
        let pkt = make_query(0xBEEF, "ipv6.example.com", 28 /* AAAA */);
        let (id, domain, qtype) = parse_query(&pkt).expect("AAAA query should parse");
        assert_eq!(id, 0xBEEF);
        assert_eq!(domain, "ipv6.example.com");
        assert_eq!(qtype, 28);
    }

    #[test]
    fn root_ns_query_preserves_question_wire_format() {
        // Construct the wire query independently of encode_name.
        let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
        let (id, domain, qtype) = parse_query(&query).unwrap();
        assert_eq!(domain, "");
        assert_eq!(qtype, 2);

        let response = build_empty_response(id, &domain, qtype);
        assert_eq!(&response[12..], &query[12..]);
        assert_eq!(response.len(), 17);
    }

    #[test]
    fn parse_query_rejects_response() {
        // Set QR bit → this is a response, not a query.
        let mut pkt = make_query(0x0001, "example.com", 1);
        pkt[2] = 0x80; // set QR bit in flags high byte
        assert!(
            parse_query(&pkt).is_none(),
            "parse_query must reject DNS response packets"
        );
    }

    #[test]
    fn parse_query_rejects_too_short() {
        assert!(parse_query(&[0u8; 11]).is_none());
        assert!(parse_query(&[]).is_none());
    }

    #[test]
    fn build_a_response_header_fields() {
        let id = 0xABCD;
        let ip = Ipv4Addr::new(198, 18, 0, 42);
        let resp = build_a_response(id, "test.example.com", ip);

        assert_eq!(
            u16::from_be_bytes([resp[0], resp[1]]),
            id,
            "ID must be echoed"
        );
        assert_eq!(
            u16::from_be_bytes([resp[2], resp[3]]),
            0x8180,
            "flags must be 0x8180"
        );
        assert_eq!(
            u16::from_be_bytes([resp[4], resp[5]]),
            1,
            "QDCOUNT must be 1"
        );
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            1,
            "ANCOUNT must be 1"
        );
        assert_eq!(
            u16::from_be_bytes([resp[8], resp[9]]),
            0,
            "NSCOUNT must be 0"
        );
        assert_eq!(
            u16::from_be_bytes([resp[10], resp[11]]),
            0,
            "ARCOUNT must be 0"
        );
    }

    #[test]
    fn build_a_response_ip_in_rdata() {
        let ip = Ipv4Addr::new(198, 18, 7, 255);
        let resp = build_a_response(0x0001, "a.b.c", ip);
        // Last 4 bytes of the answer section are the IPv4 RDATA.
        let n = resp.len();
        assert_eq!(
            &resp[n - 4..],
            &ip.octets(),
            "RDATA must contain the fake IP"
        );
    }

    #[test]
    fn build_a_response_uses_name_compression() {
        let resp = build_a_response(0x0001, "example.com", Ipv4Addr::new(198, 18, 0, 1));
        // The answer section starts right after the question section.
        // Question section starts at byte 12; its size is:
        //   7+1 + 3+1 + 1 (QNAME) + 2 (QTYPE) + 2 (QCLASS)
        //   = 8 + 4 + 1 + 4 = 17 bytes
        // So answer section starts at byte 12 + 17 = 29.
        let qname_len: usize = 1 + 7 + 1 + 3 + 1; // len+label+len+label+0
        let question_len = qname_len + 2 + 2;
        let ans_start = 12 + question_len;
        // First two bytes of the answer NAME field must be the compression pointer.
        assert_eq!(
            u16::from_be_bytes([resp[ans_start], resp[ans_start + 1]]),
            0xC00C,
            "answer NAME must use 0xC00C compression pointer"
        );
    }

    #[test]
    fn build_empty_response_header_fields() {
        let id = 0x5678;
        let resp = build_empty_response(id, "example.com", 28 /* AAAA */);

        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), id);
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0x8180);
        assert_eq!(
            u16::from_be_bytes([resp[4], resp[5]]),
            1,
            "QDCOUNT must be 1"
        );
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            0,
            "ANCOUNT must be 0 for empty response"
        );
    }

    #[test]
    fn build_empty_response_echoes_qtype() {
        let resp = build_empty_response(0x0001, "example.com", 28);
        // QTYPE sits at offset 12 + QNAME-length (15 bytes for "example.com") = 27.
        let qname_len: usize = 1 + 7 + 1 + 3 + 1; // "example.com"
        let qtype_offset = 12 + qname_len;
        let echoed_qtype = u16::from_be_bytes([resp[qtype_offset], resp[qtype_offset + 1]]);
        assert_eq!(
            echoed_qtype, 28,
            "QTYPE in question section must match input"
        );
    }

    #[test]
    fn parse_build_roundtrip() {
        let mut dns = FakeDns::new();
        let query = make_query(0xCAFE, "roundtrip.test", 1 /* A */);

        let (id, domain, qtype) = parse_query(&query).expect("query should parse");
        assert_eq!(qtype, 1);

        let fake_ip = dns.resolve(&domain);
        let response = build_a_response(id, &domain, fake_ip);

        // Verify the response header correctly echoes the transaction ID.
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            0xCAFE,
            "transaction ID must be preserved through the round-trip"
        );
        // Verify the fake IP appears in the RDATA.
        let n = response.len();
        assert_eq!(
            Ipv4Addr::from(<[u8; 4]>::try_from(&response[n - 4..]).unwrap()),
            fake_ip,
        );
    }
}
