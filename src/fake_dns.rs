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

    #[test]
    fn mappings_are_stable_distinct_and_reversible() {
        let mut dns = FakeDns::new();
        let first = dns.resolve("first.test");
        let second = dns.resolve("second.test");
        assert_eq!(dns.resolve("first.test"), first);
        assert_ne!(first, second);
        assert_eq!(dns.lookup(first), Some("first.test"));
        assert_eq!(dns.lookup(second), Some("second.test"));
        assert_eq!(dns.lookup(Ipv4Addr::new(1, 2, 3, 4)), None);
        for (address, expected) in [
            (POOL_START - 1, false),
            (POOL_START, true),
            (POOL_END, true),
            (POOL_END + 1, false),
        ] {
            assert_eq!(dns.is_fake_ip(Ipv4Addr::from(address)), expected);
        }
    }

    #[test]
    fn pool_wraparound_evicts_both_mapping_directions() {
        let mut dns = FakeDns::new();
        let first = dns.resolve("first.test");
        for i in 1..POOL_SIZE {
            dns.resolve(&format!("{i}.test"));
        }
        assert_eq!(dns.resolve("new.test"), first);
        assert_eq!(dns.lookup(first), Some("new.test"));
        assert_ne!(dns.resolve("first.test"), first);
    }

    fn query(qtype: u16) -> Vec<u8> {
        let mut packet =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00".to_vec();
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn a_and_aaaa_queries_preserve_the_question_and_answer_policy() {
        let ip = Ipv4Addr::new(198, 18, 0, 42);
        for qtype in [1, 28] {
            let request = query(qtype);
            let (id, domain, kind) = parse_query(&request).unwrap();
            assert_eq!((id, domain.as_str(), kind), (0x1234, "example.com", qtype));
            let response = if kind == 1 {
                build_a_response(id, &domain, ip)
            } else {
                build_empty_response(id, &domain, kind)
            };
            assert_eq!(&response[..6], b"\x12\x34\x81\x80\x00\x01");
            assert_eq!(&response[6..8], &u16::from(kind == 1).to_be_bytes());
            assert_eq!(&response[12..request.len()], &request[12..]);
            if kind == 1 {
                assert_eq!(&response[response.len() - 4..], &ip.octets());
            } else {
                assert_eq!(response.len(), request.len());
            }
        }
    }

    #[test]
    fn malformed_queries_and_response_packets_are_rejected() {
        let request = query(1);
        assert!(parse_query(&request[..11]).is_none());
        assert!(parse_query(&request[..request.len() - 1]).is_none());
        let mut response = request;
        response[2] |= 0x80;
        assert!(parse_query(&response).is_none());
    }

    #[test]
    fn root_ns_query_preserves_question_wire_format() {
        let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
        let (id, domain, qtype) = parse_query(&query).unwrap();
        assert_eq!(domain, "");
        assert_eq!(qtype, 2);
        let response = build_empty_response(id, &domain, qtype);
        assert_eq!(&response[12..], &query[12..]);
        assert_eq!(response.len(), query.len());
    }
}
