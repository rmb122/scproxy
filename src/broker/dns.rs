//! Fake DNS over UDP and TCP, sharing one bounded domain-to-address mapping.
use crate::config::net::{DNS_ADDR, DNS_PORT};
use crate::{
    fake_dns::{self, FakeDns},
    proxy::ProxyTarget,
};
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
struct Servers {
    forward: HashMap<SocketAddrV4, SocketAddrV4>,
    reverse: HashMap<SocketAddrV4, SocketAddrV4>,
}

pub(super) struct Dns {
    pub mapping: Arc<Mutex<FakeDns>>,
    servers: Mutex<Servers>,
    tasks: Mutex<JoinSet<io::Result<()>>>,
}
impl Dns {
    pub fn new() -> io::Result<Self> {
        let dns = Self {
            mapping: Arc::new(Mutex::new(FakeDns::new())),
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
        let mapping = self.mapping.clone();
        self.tasks.lock().unwrap().spawn(serve_udp(socket, mapping));
        // Distinct local endpoints preserve the source of overlapping requests
        // to multiple resolvers, even on one application socket with equal IDs.
        servers.forward.insert(destination, local);
        servers.reverse.insert(local, destination);
        Ok(local)
    }

    pub fn original_server(&self, local: SocketAddrV4) -> Option<SocketAddrV4> {
        self.servers.lock().unwrap().reverse.get(&local).copied()
    }

    pub fn target(&self, address: SocketAddrV4) -> ProxyTarget {
        let mapping = self.mapping.lock().unwrap();
        if mapping.is_fake_ip(*address.ip())
            && let Some(domain) = mapping.lookup(*address.ip())
        {
            ProxyTarget::Domain {
                host: domain.to_owned(),
                port: address.port(),
            }
        } else {
            ProxyTarget::Ip {
                addr: (*address.ip()).into(),
                port: address.port(),
            }
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        match std::future::poll_fn(|cx| self.tasks.lock().unwrap().poll_join_next(cx)).await {
            Some(Ok(Err(error))) => Err(error),
            Some(Err(error)) => Err(io::Error::other(error)),
            _ => Err(io::Error::other("DNS service stopped unexpectedly")),
        }
    }
}

fn answer(mapping: &Mutex<FakeDns>, query: &[u8]) -> Option<Vec<u8>> {
    let (id, domain, kind) = fake_dns::parse_query(query)?;
    Some(if kind == 1 {
        let ip = mapping.lock().unwrap().resolve(&domain);
        tracing::debug!(%domain, %ip, "fake DNS");
        fake_dns::build_a_response(id, &domain, ip)
    } else {
        fake_dns::build_empty_response(id, &domain, kind)
    })
}

async fn serve_udp(socket: UdpSocket, mapping: Arc<Mutex<FakeDns>>) -> io::Result<()> {
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
        if let Some(response) = answer(&mapping, &buffer[..length])
            && let Err(error) = socket.send_to(&response, source).await
        {
            tracing::debug!(%error, "DNS reply discarded");
        }
    }
}

pub(super) async fn serve_tcp(
    mut socket: TcpStream,
    mapping: Arc<Mutex<FakeDns>>,
) -> io::Result<()> {
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
            let response = answer(&mapping, &query).ok_or_else(|| {
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
