//! One loopback listener shared by all outbound connections.
use super::sockets;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct Pending {
    socket: Arc<OwnedFd>,
    source: Option<SocketAddrV4>,
    sender: Option<oneshot::Sender<TcpStream>>,
}

#[derive(Default)]
struct Dispatch {
    waiting: HashMap<RawFd, Pending>,
    sources: HashMap<SocketAddrV4, RawFd>,
}

pub(super) struct Ingress {
    listener: TcpListener,
    pub address: SocketAddrV4,
    dispatch: Mutex<Dispatch>,
}

impl Ingress {
    pub fn new() -> io::Result<Arc<Self>> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let SocketAddr::V4(address) = listener.local_addr()? else {
            unreachable!()
        };
        listener.set_nonblocking(true)?;
        let ingress = Arc::new(Self {
            listener: TcpListener::from_std(listener)?,
            address,
            dispatch: Mutex::new(Dispatch::default()),
        });
        tracing::debug!(%address, "TCP relay listening");
        Ok(ingress)
    }

    /// Hold the original socket before connect can enqueue an accepted stream.
    /// Entries are bounded by the broker's pending-connection semaphore.
    pub fn register(self: &Arc<Self>, socket: OwnedFd) -> Registration {
        let socket = Arc::new(socket);
        let (sender, receiver) = oneshot::channel();
        self.dispatch.lock().unwrap().waiting.insert(
            socket.as_raw_fd(),
            Pending {
                socket: socket.clone(),
                source: None,
                sender: Some(sender),
            },
        );
        Registration {
            ingress: self.clone(),
            socket,
            receiver,
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        loop {
            let (stream, source) = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let SocketAddr::V4(source) = source {
                self.deliver(stream, source);
            }
        }
    }

    fn deliver(&self, stream: TcpStream, source: SocketAddrV4) {
        let sender = {
            let mut dispatch = self.dispatch.lock().unwrap();
            let matches = |pending: &Pending| {
                let fd = pending.socket.as_raw_fd();
                pending.sender.is_some()
                    && sockets::address(fd, false).ok() == Some(source)
                    && sockets::address(fd, true).ok() == Some(self.address)
            };
            // accept can win the race with connect's completion on another
            // thread. Inspect only sockets whose source is not published yet;
            // never retain an unrecognized incoming connection for later use.
            let fd = dispatch.sources.get(&source).copied().or_else(|| {
                dispatch.waiting.iter().find_map(|(&fd, pending)| {
                    (pending.source.is_none() && matches(pending)).then_some(fd)
                })
            });
            fd.and_then(|fd| dispatch.waiting.get_mut(&fd))
                .filter(|pending| matches(pending))
                .and_then(|pending| pending.sender.take())
        };
        if let Some(sender) = sender {
            let _ = sender.send(stream);
        }
    }
}

pub(super) struct Registration {
    ingress: Arc<Ingress>,
    pub socket: Arc<OwnedFd>,
    receiver: oneshot::Receiver<TcpStream>,
}

impl Registration {
    pub fn connected(&self) -> io::Result<()> {
        let fd = self.socket.as_raw_fd();
        let source = sockets::address(fd, false)?;
        let mut dispatch = self.ingress.dispatch.lock().unwrap();
        if dispatch
            .sources
            .get(&source)
            .is_some_and(|&other| other != fd)
        {
            return Err(io::Error::from_raw_os_error(libc::EADDRINUSE));
        }
        dispatch.waiting.get_mut(&fd).unwrap().source = Some(source);
        dispatch.sources.insert(source, fd);
        Ok(())
    }

    pub async fn accept(mut self) -> io::Result<TcpStream> {
        (&mut self.receiver)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let fd = self.socket.as_raw_fd();
        let mut dispatch = self.ingress.dispatch.lock().unwrap();
        if let Some(pending) = dispatch.waiting.remove(&fd)
            && let Some(source) = pending.source
            && dispatch.sources.get(&source) == Some(&fd)
        {
            dispatch.sources.remove(&source);
        }
    }
}

#[cfg(test)]
#[path = "tcp_ingress/tests.rs"]
mod tests;
