use super::{
    connect, dns,
    engine::{Broker, Reply},
    memory, relay,
    seccomp::Notification,
    sockets,
};
use crate::proxy::{ProxyConfig, ProxyTarget};
use std::io;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(super) struct Peer {
    pub target: SocketAddrV4,
    pub internal: SocketAddrV4,
    pub created: Instant,
    pub pending: bool,
}

struct PendingPeer<'a> {
    broker: &'a Broker,
    cookie: u64,
    committed: bool,
}

impl Drop for PendingPeer<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.broker.peers.lock().unwrap().remove(&self.cookie);
        }
    }
}

impl Broker {
    pub async fn connect_tcp(
        self: &Arc<Self>,
        fd: OwnedFd,
        notification: &Notification,
    ) -> io::Result<Reply> {
        let args = notification.data.args;
        if memory::family(notification.pid, args[1], args[2])? == libc::AF_UNSPEC as u16 {
            return Ok(Reply::Continue);
        }
        let target = memory::ipv4(notification.pid, args[1], args[2])?;
        let cookie = sockets::cookie(fd.as_raw_fd())?;
        let lock = {
            let mut locks = self.locks.lock().unwrap();
            match locks.get(&cookie).and_then(std::sync::Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                    locks.insert(cookie, Arc::downgrade(&lock));
                    lock
                }
            }
        };
        let _guard = lock.lock().await;
        self.valid(notification)?;
        if sockets::state(fd.as_raw_fd())? != 7 {
            let peer = self.peers.lock().unwrap().get(&cookie).copied();
            if let Some(peer) = peer {
                connect::run(Arc::new(fd), peer.internal, || self.valid(notification)).await?;
                return Ok(Reply::Value(0));
            }
            return Ok(Reply::Continue);
        }
        self.peers.lock().unwrap().remove(&cookie);
        let is_dns = dns::is_dns(target);
        // DNS interception precedes route selection, even for an otherwise
        // unknown FakeIP. Its original resolver address is only source metadata.
        let proxy_target = if is_dns {
            ProxyTarget::Ip {
                addr: (*target.ip()).into(),
                port: target.port(),
            }
        } else {
            self.dns.target(target)?
        };
        let route = self.config.proxy_for(&proxy_target).clone();
        if !is_dns && matches!(proxy_target, ProxyTarget::Ip { .. }) && route == ProxyConfig::Direct
        {
            // Only numeric direct destinations use native connect. Domain
            // targets need the relay to resolve without blocking the caller.
            return Ok(Reply::Continue);
        }
        let permit = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| memory::error(libc::EAGAIN))?;
        let internal = self.tcp_ingress.address;
        let dns_resolver = is_dns.then(|| self.dns.resolver.clone());
        let direct = self.direct.clone();
        self.valid(notification)?;
        self.peers.lock().unwrap().insert(
            cookie,
            Peer {
                target,
                internal,
                created: Instant::now(),
                pending: true,
            },
        );
        let mut pending_peer = PendingPeer {
            broker: self,
            cookie,
            committed: false,
        };
        let registration = self.tcp_ingress.register(fd)?;
        let result = connect::run(registration.socket.clone(), internal, || {
            self.valid(notification)
        })
        .await;
        if let Err(error) = &result
            && error.raw_os_error() != Some(libc::EINPROGRESS)
        {
            return result.map(|()| Reply::Value(0));
        }
        if let Some(peer) = self.peers.lock().unwrap().get_mut(&cookie) {
            peer.pending = false;
            peer.created = Instant::now();
        }
        self.relays.lock().unwrap().spawn(async move {
            if let Some(resolver) = dns_resolver {
                let accepted =
                    tokio::time::timeout(Duration::from_secs(32), registration.accept()).await;
                drop(permit);
                if let Ok(Ok(app)) = accepted
                    && let Err(error) = dns::serve_tcp(app, resolver).await
                {
                    tracing::debug!(%error, "TCP DNS closed");
                }
                return;
            }
            let connection = tokio::time::timeout(Duration::from_secs(32), async {
                let app = registration.accept().await?;
                tracing::debug!(target = %proxy_target, %route, "outbound connection");
                let upstream = match (&route, &proxy_target) {
                    (ProxyConfig::Direct, ProxyTarget::Domain { host, port }) => {
                        direct.connect(host, *port).await?
                    }
                    _ => route.connect(&proxy_target).await?,
                };
                Ok::<_, anyhow::Error>((app, upstream))
            })
            .await;
            drop(permit);
            match connection {
                Ok(Ok((app, upstream))) => {
                    if let Err(error) = relay::run(app, upstream).await {
                        tracing::debug!(%error, "relay closed");
                    }
                }
                Ok(Err(error)) => tracing::debug!(%error, "upstream connection failed"),
                Err(error) => tracing::debug!(%error, "upstream connection timed out"),
            }
        });
        pending_peer.committed = true;
        result.map(|()| Reply::Value(0))
    }

    pub fn tcp_target(&self, fd: RawFd, socket_option: bool) -> io::Result<Option<SocketAddrV4>> {
        let cookie = sockets::cookie(fd)?;
        let peer = self.peers.lock().unwrap().get(&cookie).copied();
        let Some(peer) = peer else {
            return Ok(None);
        };
        match sockets::peer_address(fd, socket_option) {
            Ok(actual) => Ok((actual == peer.internal).then_some(peer.target)),
            Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn tcp_peer(&self, fd: OwnedFd, notification: &Notification) -> io::Result<Reply> {
        let socket_option = notification.data.nr as libc::c_long == libc::SYS_getsockopt;
        let Some(target) = self.tcp_target(fd.as_raw_fd(), socket_option)? else {
            return Ok(Reply::Continue);
        };
        self.valid(notification)?;
        memory::peer_name(notification, target)?;
        Ok(Reply::Value(0))
    }
}
