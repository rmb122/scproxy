use super::{
    connect,
    engine::{Broker, Reply},
    memory, relay,
    seccomp::Notification,
    sockets,
};
use std::io;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, OwnedFd};
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
        if target.ip().is_loopback() {
            return Ok(Reply::Continue);
        }
        let permit = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| memory::error(libc::EAGAIN))?;
        let internal = self.tcp_ingress.address;
        let proxy_target = self.dns.target(target);
        let route = self.config.proxy_for(&proxy_target).clone();
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
        let registration = self.tcp_ingress.register(fd);
        let result = connect::run(registration.socket.clone(), internal, || {
            self.valid(notification)
        })
        .await;
        if let Err(error) = &result
            && error.raw_os_error() != Some(libc::EINPROGRESS)
        {
            return result.map(|()| Reply::Value(0));
        }
        registration.connected()?;
        if let Some(peer) = self.peers.lock().unwrap().get_mut(&cookie) {
            peer.pending = false;
            peer.created = Instant::now();
        }
        self.relays.lock().unwrap().spawn(async move {
            let connection = tokio::time::timeout(Duration::from_secs(32), async {
                let app = registration.accept().await?;
                tracing::debug!(target = %proxy_target, %route, "outbound connection");
                let upstream = route.connect(&proxy_target).await?;
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
    pub fn tcp_peer(&self, fd: OwnedFd, notification: &Notification) -> io::Result<Reply> {
        let cookie = sockets::cookie(fd.as_raw_fd())?;
        let peer = self.peers.lock().unwrap().get(&cookie).copied();
        let Some(peer) = peer else {
            return Ok(Reply::Continue);
        };
        if sockets::address(fd.as_raw_fd(), true)? != peer.internal {
            return Ok(Reply::Continue);
        }
        self.valid(notification)?;
        memory::peer_name(
            notification.pid,
            notification.data.args[1],
            notification.data.args[2],
            peer.target,
        )?;
        Ok(Reply::Value(0))
    }
}
