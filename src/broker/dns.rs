//! Local fake DNS service. Only the virtual resolver is redirected here.
use crate::config::net::{DNS_ADDR, DNS_PORT};
use crate::{
    fake_dns::{self, FakeDns},
    proxy::ProxyTarget,
};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Mutex;
use tokio::net::UdpSocket;

pub(super) fn virtual_address() -> SocketAddrV4 {
    SocketAddrV4::new(DNS_ADDR, DNS_PORT)
}

pub(super) struct Dns {
    socket: UdpSocket,
    pub address: SocketAddrV4,
    mapping: Mutex<FakeDns>,
}
impl Dns {
    pub fn new() -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let SocketAddr::V4(address) = socket.local_addr()? else {
            unreachable!()
        };
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: UdpSocket::from_std(socket)?,
            address,
            mapping: Mutex::new(FakeDns::new()),
        })
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
        let mut buffer = vec![0; 65536];
        loop {
            let (length, source) = match self.socket.recv_from(&mut buffer).await {
                Ok(packet) => packet,
                Err(error)
                    if matches!(error.raw_os_error(), Some(libc::ENOMEM | libc::ENOBUFS)) =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let Some((id, domain, kind)) = fake_dns::parse_query(&buffer[..length]) else {
                continue;
            };
            let response = if kind == 1 {
                let ip = self.mapping.lock().unwrap().resolve(&domain);
                tracing::debug!(%domain, %ip, "fake DNS");
                fake_dns::build_a_response(id, &domain, ip)
            } else {
                fake_dns::build_empty_response(id, &domain, kind)
            };
            if let Err(error) = self.socket.send_to(&response, source).await {
                tracing::debug!(%error, "DNS reply discarded");
            }
        }
    }
}
