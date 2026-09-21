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
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Running {
        ingress: Arc<Ingress>,
        task: tokio::task::JoinHandle<io::Result<()>>,
    }

    impl Running {
        fn new() -> Self {
            let ingress = Ingress::new().unwrap();
            let service = ingress.clone();
            let task = tokio::spawn(async move { service.run().await });
            Self { ingress, task }
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn connect(socket: &OwnedFd, address: SocketAddrV4) {
        let result = sockets::connect(socket.as_raw_fd(), address);
        assert!(
            result.is_ok()
                || result.as_ref().unwrap_err().raw_os_error() == Some(libc::EINPROGRESS),
            "{result:?}"
        );
    }

    fn stream(socket: &OwnedFd) -> TcpStream {
        let copy = socket.as_fd().try_clone_to_owned().unwrap();
        TcpStream::from_std(std::net::TcpStream::from(copy)).unwrap()
    }

    fn bound(ip: Ipv4Addr, port: u16) -> OwnedFd {
        let socket = sockets::stream().unwrap();
        let address = sockets::sockaddr(SocketAddrV4::new(ip, port));
        sockets::check(unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&address) as _,
            )
        })
        .unwrap();
        socket
    }

    #[tokio::test]
    async fn reversed_accepts_match_source_ip_and_port_before_publication() {
        let running = Running::new();
        let first = bound(Ipv4Addr::new(127, 0, 0, 2), 0);
        let port = sockets::address(first.as_raw_fd(), false).unwrap().port();
        let second = bound(Ipv4Addr::new(127, 0, 0, 3), port);
        let first = running.ingress.register(first);
        let second = running.ingress.register(second);
        let first_socket = first.socket.clone();
        let second_socket = second.socket.clone();
        connect(&second_socket, running.ingress.address);
        second.connected().unwrap();
        connect(&first_socket, running.ingress.address);
        // Omit first.connected(): accept must find the unpublished source itself.
        let (first, second) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(first.accept(), second.accept())
        })
        .await
        .unwrap();
        let mut first = first.unwrap();
        let mut second = second.unwrap();
        stream(&first_socket).write_all(b"first").await.unwrap();
        stream(&second_socket).write_all(b"other").await.unwrap();
        let mut bytes = [0; 5];
        first.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"first");
        second.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"other");
    }

    #[tokio::test]
    async fn accept_drains_strangers_while_original_blocking_connect_runs() {
        let ingress = Ingress::new().unwrap();
        assert_eq!(unsafe { libc::listen(ingress.listener.as_raw_fd(), 1) }, 0);
        // Fill the small accept queue before starting the independent accept loop.
        let first = std::net::TcpStream::connect(ingress.address).unwrap();
        let second = std::net::TcpStream::connect(ingress.address).unwrap();
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0);
        use std::os::fd::FromRawFd;
        let registration = ingress.register(unsafe { OwnedFd::from_raw_fd(raw) });
        let socket = registration.socket.clone();
        let address = ingress.address;
        let connecting =
            tokio::task::spawn_blocking(move || sockets::connect(socket.as_raw_fd(), address));
        let service = ingress.clone();
        let running = Running {
            ingress,
            task: tokio::spawn(async move { service.run().await }),
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            connecting.await.unwrap().unwrap();
            registration.connected().unwrap();
            registration.accept().await.unwrap();
        })
        .await
        .expect("accept must keep running while connect waits");
        drop((first, second, running));
    }
}
