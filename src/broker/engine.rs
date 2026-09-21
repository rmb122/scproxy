//! Dispatch notifications without serializing unrelated sockets or blocking DNS readers.
use super::{
    Shutdown,
    access::SocketAccess,
    datagram, diagnostics,
    dns::Dns,
    files::ResolverFiles,
    memory,
    seccomp::{self, Notification},
    sockets,
    tcp::Peer,
    tcp_ingress::Ingress,
};
use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

pub(super) enum Reply {
    Continue,
    Value(i64),
    Sent,
}

const RELAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(32);

pub(super) struct Broker {
    pub listener: Arc<OwnedFd>,
    pub access: SocketAccess,
    pub config: Arc<crate::config::Config>,
    pub dns: Dns,
    pub resolver_files: ResolverFiles,
    pub tcp_ingress: Arc<Ingress>,
    pub peers: Mutex<HashMap<u64, Peer>>,
    pub locks: Mutex<HashMap<u64, Weak<tokio::sync::Mutex<()>>>>,
    pub pending: Arc<Semaphore>,
    pub relays: Mutex<JoinSet<()>>,
}
impl Broker {
    pub fn new(
        listener: Arc<OwnedFd>,
        access: SocketAccess,
        config: crate::config::Config,
    ) -> io::Result<Arc<Self>> {
        let config = Arc::new(config);
        Ok(Arc::new(Self {
            listener,
            access,
            config: config.clone(),
            dns: Dns::new(config)?,
            resolver_files: ResolverFiles::new()?,
            tcp_ingress: Ingress::new()?,
            peers: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            pending: Arc::new(Semaphore::new(128)),
            relays: Mutex::new(JoinSet::new()),
        }))
    }
    pub fn valid(&self, notification: &Notification) -> io::Result<()> {
        if seccomp::valid(self.listener.as_raw_fd(), notification.id)? {
            Ok(())
        } else {
            Err(memory::error(libc::EINTR))
        }
    }
    fn respond(&self, notification: &Notification, result: io::Result<Reply>) -> io::Result<()> {
        let (value, errno, passthrough) = match result {
            Ok(Reply::Sent) => return Ok(()),
            Ok(Reply::Continue) => (0, 0, true),
            Ok(Reply::Value(value)) => (value, 0, false),
            Err(error) => {
                tracing::trace!(tid = notification.pid, syscall = notification.data.nr, %error, "notification failed");
                (0, error.raw_os_error().unwrap_or(libc::EIO), false)
            }
        };
        match seccomp::respond(
            self.listener.as_raw_fd(),
            notification.id,
            value,
            errno,
            passthrough,
        ) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            result => result,
        }
    }
    pub async fn run(
        self: Arc<Self>,
        mut notifications: mpsc::Receiver<io::Result<Notification>>,
        mut shutdown: watch::Receiver<Shutdown>,
    ) -> io::Result<()> {
        let mut requests = JoinSet::new();
        let mut snapshot: Option<JoinHandle<io::Result<HashSet<u64>>>> = None;
        let mut snapshot_started = Instant::now();
        let mut cleanup = tokio::time::interval(Duration::from_millis(100));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let dns = self.dns.run();
        tokio::pin!(dns);
        let ingress = self.tcp_ingress.run();
        tokio::pin!(ingress);
        let result = loop {
            if *shutdown.borrow() != Shutdown::Running {
                break Ok(());
            }
            tokio::select! {
                _ = shutdown.changed() => break Ok(()),
                result = &mut dns => break result,
                result = &mut ingress => break result,
                notification = notifications.recv() => match notification {
                    Some(Ok(notification)) => {
                        if requests.len() >= 256 {
                            self.respond(&notification, Err(memory::error(libc::EAGAIN)))?;
                        } else {
                            let broker = self.clone();
                            requests.spawn(async move {
                                let result = broker.dispatch(&notification).await;
                                broker.respond(&notification, result)
                            });
                        }
                    },
                    Some(Err(error)) => break Err(error),
                    None => break Ok(()),
                },
                result = requests.join_next(), if !requests.is_empty() => match result {
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(error)) => break Err(io::Error::other(error)),
                    _ => {},
                },
                result = async {
                    match snapshot.as_mut() {
                        Some(task) => task.await,
                        None => std::future::pending().await,
                    }
                } => {
                    snapshot.take();
                    match result {
                        Ok(Ok(cookies)) => self.peers.lock().unwrap().retain(|cookie, peer| peer.pending || peer.created >= snapshot_started || cookies.contains(cookie)),
                        result => tracing::debug!(?result, "socket cleanup deferred"),
                    }
                },
                _ = cleanup.tick() => {
                    while let Some(result) = self.relays.lock().unwrap().try_join_next() {
                        if let Err(error) = result { tracing::warn!(%error, "relay task failed"); }
                    }
                    self.locks.lock().unwrap().retain(|_, lock| lock.strong_count() > 0);
                    if snapshot.is_none() && !self.peers.lock().unwrap().is_empty() {
                        snapshot_started = Instant::now();
                        snapshot = Some(tokio::task::spawn_blocking(diagnostics::snapshot));
                    }
                }
            }
        };
        requests.abort_all();
        while requests.join_next().await.is_some() {}
        // Notification EOF can precede completion of the last command's writes
        // and proxy handshakes. Keep accepting registered sockets while draining.
        // JoinSet also owns cancellation if this drain future is dropped.
        let relays = std::mem::take(&mut *self.relays.lock().unwrap());
        result?;
        drain_relays(relays, &mut shutdown, &mut ingress).await
    }
    async fn dispatch(self: &Arc<Self>, notification: &Notification) -> io::Result<Reply> {
        self.valid(notification)?;
        let call = notification.data.nr as libc::c_long;
        let args = notification.data.args;
        if seccomp::is_open(call) {
            return self.resolver_files.open(self, notification);
        }
        if call == libc::SYS_socket {
            let family = args[0] as i32;
            if family == libc::AF_UNIX || family == libc::AF_NETLINK {
                return Ok(Reply::Continue);
            }
            if family != libc::AF_INET {
                return Err(memory::error(libc::EAFNOSUPPORT));
            }
            let kind = args[1] as i32 & !(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC);
            let protocol = args[2] as i32;
            if (kind == libc::SOCK_STREAM && [0, libc::IPPROTO_TCP].contains(&protocol))
                || (kind == libc::SOCK_DGRAM && [0, libc::IPPROTO_UDP].contains(&protocol))
            {
                return Ok(Reply::Continue);
            }
            return Err(memory::error(libc::EPROTONOSUPPORT));
        }
        let flags = match call {
            libc::SYS_sendto | libc::SYS_recvfrom | libc::SYS_sendmmsg | libc::SYS_recvmmsg => {
                args[3]
            }
            libc::SYS_sendmsg | libc::SYS_recvmsg => args[2],
            _ => 0,
        };
        if matches!(
            call,
            libc::SYS_sendto | libc::SYS_sendmsg | libc::SYS_sendmmsg
        ) && flags as i32 & libc::MSG_FASTOPEN != 0
        {
            return Err(memory::error(libc::EOPNOTSUPP));
        }
        let fd = self.access.get(notification.pid, args[0] as i32)?;
        self.valid(notification)?;
        let domain = sockets::option_int(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_DOMAIN)?;
        if domain == libc::AF_UNIX && call == libc::SYS_connect {
            self.resolver_files.check_unix_connect(notification)?;
        }
        if domain != libc::AF_INET {
            return Ok(Reply::Continue);
        }
        let protocol = sockets::option_int(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PROTOCOL)?;
        if protocol == libc::IPPROTO_TCP {
            if flags as i32 & libc::MSG_OOB != 0 && self.tcp_target(fd.as_raw_fd(), true)?.is_some()
            {
                return Err(memory::error(libc::EOPNOTSUPP));
            }
            if call == libc::SYS_connect {
                self.connect_tcp(fd, notification).await
            } else if matches!(call, libc::SYS_getpeername | libc::SYS_getsockopt) {
                self.tcp_peer(fd, notification)
            } else {
                Ok(Reply::Continue)
            }
        } else if protocol == libc::IPPROTO_UDP {
            datagram::dispatch(self, fd, notification).await
        } else {
            Err(memory::error(libc::EPROTONOSUPPORT))
        }
    }
}
async fn drain_relays(
    mut relays: JoinSet<()>,
    shutdown: &mut watch::Receiver<Shutdown>,
    ingress: impl std::future::Future<Output = io::Result<()>>,
) -> io::Result<()> {
    let deadline = tokio::time::sleep(RELAY_DRAIN_TIMEOUT);
    tokio::pin!(deadline, ingress);
    while !relays.is_empty() {
        if *shutdown.borrow() == Shutdown::Abort {
            return Ok(());
        }
        tokio::select! {
            result = relays.join_next() => {
                if let Some(result) = result { result.map_err(io::Error::other)?; }
            },
            result = &mut ingress => return result,
            changed = shutdown.changed() => {
                if changed.is_err() { return Ok(()); }
            },
            _ = &mut deadline => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "relay draining timed out after 32 seconds"));
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stalled_relay() -> (JoinSet<()>, tokio::sync::oneshot::Receiver<()>) {
        let mut relays = JoinSet::new();
        let (sender, closed) = tokio::sync::oneshot::channel();
        relays.spawn(async move {
            let _lifetime = sender;
            std::future::pending::<()>().await;
        });
        (relays, closed)
    }

    #[tokio::test(start_paused = true)]
    async fn graceful_drain_times_out_and_releases_remaining_relays() {
        let (relays, closed) = stalled_relay();
        let (_sender, mut shutdown) = watch::channel(Shutdown::Drain);
        let started = tokio::time::Instant::now();
        let error = drain_relays(relays, &mut shutdown, std::future::pending())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), RELAY_DRAIN_TIMEOUT);
        assert!(closed.await.is_err(), "timed-out relay was detached");
    }

    #[tokio::test]
    async fn draining_keeps_shared_ingress_accepting_registered_connections() {
        let ingress = Ingress::new().unwrap();
        let registration = ingress.register(sockets::stream().unwrap());
        let result = sockets::connect(registration.socket.as_raw_fd(), ingress.address);
        assert!(result.is_ok() || result.unwrap_err().raw_os_error() == Some(libc::EINPROGRESS));
        registration.connected().unwrap();
        let mut relays = JoinSet::new();
        let (accepted, receiver) = tokio::sync::oneshot::channel();
        relays.spawn(async move {
            let socket = registration.accept().await.unwrap();
            accepted.send(socket.local_addr().unwrap()).unwrap();
        });
        let (_sender, mut shutdown) = watch::channel(Shutdown::Drain);
        tokio::time::timeout(
            Duration::from_secs(3),
            drain_relays(relays, &mut shutdown, ingress.run()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            receiver.await.unwrap(),
            std::net::SocketAddr::V4(ingress.address)
        );
    }
}
