//! Synthetic DNS over UDP and TCP; host resolution happens only on connection.
use crate::config::net::{DNS_ADDR, DNS_PORT};
use crate::fake_dns::{self, FakeDns};
use crate::proxy::ProxyTarget;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

pub(super) fn virtual_address() -> SocketAddrV4 {
    SocketAddrV4::new(DNS_ADDR, DNS_PORT)
}
pub(super) fn is_dns(address: SocketAddrV4) -> bool {
    address.port() == DNS_PORT
}

#[derive(Default)]
pub(super) struct Resolver {
    mapping: Mutex<FakeDns>,
}

impl Resolver {
    fn target(&self, address: SocketAddrV4) -> io::Result<ProxyTarget> {
        let mapping = self.mapping.lock().unwrap();
        if mapping.is_fake_ip(*address.ip()) {
            let domain = mapping
                .lookup(*address.ip())
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENETUNREACH))?;
            Ok(ProxyTarget::Domain {
                host: domain.to_owned(),
                port: address.port(),
            })
        } else {
            Ok(ProxyTarget::Ip {
                addr: (*address.ip()).into(),
                port: address.port(),
            })
        }
    }

    fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let (id, domain, kind) = fake_dns::parse_query(query)?;
        Some(if kind == 1 {
            let ip = self.mapping.lock().unwrap().resolve(&domain);
            tracing::debug!(%domain, %ip, "fake DNS");
            fake_dns::build_a_response(id, &domain, ip)
        } else {
            fake_dns::build_empty_response(id, &domain, kind)
        })
    }
}

#[derive(Default)]
struct Servers {
    forward: HashMap<SocketAddrV4, SocketAddrV4>,
    reverse: HashMap<SocketAddrV4, SocketAddrV4>,
}

pub(super) struct Dns {
    pub resolver: Arc<Resolver>,
    servers: Mutex<Servers>,
    tasks: Mutex<JoinSet<io::Result<()>>>,
}
impl Dns {
    pub fn new() -> io::Result<Self> {
        let dns = Self {
            resolver: Arc::new(Resolver::default()),
            servers: Mutex::new(Servers::default()),
            tasks: Mutex::new(JoinSet::new()),
        };
        // Keep one service registered so run() can always wait on the JoinSet.
        dns.server_for(virtual_address())?;
        Ok(dns)
    }

    pub fn server_for(&self, destination: SocketAddrV4) -> io::Result<SocketAddrV4> {
        if !is_dns(destination) {
            return Err(io::Error::from_raw_os_error(libc::ENETUNREACH));
        }
        let mut servers = self.servers.lock().unwrap();
        if let Some(&local) = servers.forward.get(&destination) {
            return Ok(local);
        }
        if servers.forward.len() >= 128 {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
        }
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let SocketAddr::V4(local) = socket.local_addr()? else {
            unreachable!()
        };
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket)?;
        let resolver = self.resolver.clone();
        self.tasks
            .lock()
            .unwrap()
            .spawn(serve_udp(socket, resolver));
        // Distinct local endpoints preserve the source of overlapping requests
        // to multiple resolvers, even on one application socket with equal IDs.
        servers.forward.insert(destination, local);
        servers.reverse.insert(local, destination);
        Ok(local)
    }

    pub fn original_server(&self, local: SocketAddrV4) -> Option<SocketAddrV4> {
        self.servers.lock().unwrap().reverse.get(&local).copied()
    }

    pub fn target(&self, address: SocketAddrV4) -> io::Result<ProxyTarget> {
        self.resolver.target(address)
    }

    pub async fn run(&self) -> io::Result<()> {
        match std::future::poll_fn(|cx| self.tasks.lock().unwrap().poll_join_next(cx)).await {
            Some(Ok(Err(error))) => Err(error),
            Some(Err(error)) => Err(io::Error::other(error)),
            _ => Err(io::Error::other("DNS service stopped unexpectedly")),
        }
    }
}

async fn serve_udp(socket: UdpSocket, resolver: Arc<Resolver>) -> io::Result<()> {
    let mut buffer = vec![0; 65536];
    loop {
        let (length, source) = match socket.recv_from(&mut buffer).await {
            Ok(packet) => packet,
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOMEM | libc::ENOBUFS)) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Some(response) = resolver.answer(&buffer[..length])
            && let Err(error) = socket.send_to(&response, source).await
        {
            tracing::debug!(%error, "DNS reply discarded");
        }
    }
}

pub(super) async fn serve_tcp(mut socket: TcpStream, resolver: Arc<Resolver>) -> io::Result<()> {
    loop {
        let exchange = async {
            let mut prefix = [0; 2];
            if let Err(error) = socket.read_exact(&mut prefix).await {
                return if error.kind() == io::ErrorKind::UnexpectedEof {
                    Ok(false)
                } else {
                    Err(error)
                };
            }
            let mut query = vec![0; u16::from_be_bytes(prefix) as usize];
            socket.read_exact(&mut query).await?;
            let response = resolver.answer(&query).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid TCP DNS query")
            })?;
            let length = u16::try_from(response.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "TCP DNS response is too large")
            })?;
            socket.write_all(&length.to_be_bytes()).await?;
            socket.write_all(&response).await?;
            Ok(true)
        };
        if !tokio::time::timeout(Duration::from_secs(32), exchange)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??
        {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_recover_domains_and_reject_unknown_fake_addresses() {
        let resolver = Resolver::default();
        let fake = "198.18.0.2:443".parse().unwrap();
        assert_eq!(
            resolver.target(fake).unwrap_err().raw_os_error(),
            Some(libc::ENETUNREACH)
        );
        assert!(matches!(
            resolver.target("203.0.113.1:443".parse().unwrap()).unwrap(),
            ProxyTarget::Ip { .. }
        ));
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07missing\x07invalid\x00\x00\x01\x00\x01";
        let answer = resolver.answer(query).unwrap();
        assert_eq!(&answer[answer.len() - 4..], &[198, 18, 0, 2]);
        assert!(
            matches!(resolver.target(fake).unwrap(), ProxyTarget::Domain {host, port:443} if host == "missing.invalid")
        );
        assert_eq!(
            resolver
                .target(SocketAddrV4::new(DNS_ADDR, 443))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENETUNREACH)
        );
    }
}
