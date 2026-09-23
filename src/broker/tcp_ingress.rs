//! One loopback listener shared by all outbound connections.
use super::{sockets, tcp_bind};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct Pending {
    socket: Arc<OwnedFd>,
    sender: Option<oneshot::Sender<TcpStream>>,
}

pub(super) struct Ingress {
    listener: TcpListener,
    pub address: SocketAddrV4,
    waiting: Mutex<HashMap<u16, Vec<Pending>>>,
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
            waiting: Mutex::new(HashMap::new()),
        });
        tracing::debug!(%address, "TCP relay listening");
        Ok(ingress)
    }

    /// Reserve and register the source port before connect can enqueue a stream.
    /// Entries are bounded by the broker's pending-connection semaphore.
    pub fn register(self: &Arc<Self>, socket: OwnedFd) -> io::Result<Registration> {
        let port = tcp_bind::prepare(socket.as_raw_fd())?;
        let socket = Arc::new(socket);
        let (sender, receiver) = oneshot::channel();
        self.waiting
            .lock()
            .unwrap()
            .entry(port)
            .or_default()
            .push(Pending {
                socket: socket.clone(),
                sender: Some(sender),
            });
        Ok(Registration {
            ingress: self.clone(),
            port,
            socket,
            receiver,
        })
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
            let mut waiting = self.waiting.lock().unwrap();
            // Wildcard bindings acquire their actual source IP during connect.
            // A port narrows the candidates; both endpoints identify the socket.
            waiting.get_mut(&source.port()).and_then(|candidates| {
                candidates.iter_mut().find_map(|pending| {
                    let fd = pending.socket.as_raw_fd();
                    if pending.sender.is_some()
                        && sockets::address(fd, false).ok() == Some(source)
                        && sockets::address(fd, true).ok() == Some(self.address)
                    {
                        pending.sender.take()
                    } else {
                        None
                    }
                })
            })
        };
        if let Some(sender) = sender {
            let _ = sender.send(stream);
        }
    }
}

pub(super) struct Registration {
    ingress: Arc<Ingress>,
    port: u16,
    pub socket: Arc<OwnedFd>,
    receiver: oneshot::Receiver<TcpStream>,
}

impl Registration {
    pub async fn accept(mut self) -> io::Result<TcpStream> {
        (&mut self.receiver)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let fd = self.socket.as_raw_fd();
        let mut waiting = self.ingress.waiting.lock().unwrap();
        if let Some(candidates) = waiting.get_mut(&self.port) {
            candidates.retain(|pending| pending.socket.as_raw_fd() != fd);
            if candidates.is_empty() {
                waiting.remove(&self.port);
            }
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
        sockets::bind(socket.as_raw_fd(), SocketAddrV4::new(ip, port)).unwrap();
        socket
    }

    #[tokio::test]
    async fn reversed_accepts_match_registered_sockets_sharing_a_source_port() {
        let running = Running::new();
        let first = bound(Ipv4Addr::new(127, 0, 0, 2), 0);
        let port = sockets::address(first.as_raw_fd(), false).unwrap().port();
        let second = bound(Ipv4Addr::new(127, 0, 0, 3), port);
        let first = running.ingress.register(first).unwrap();
        let second = running.ingress.register(second).unwrap();
        // Removing one registration must keep other candidates for that port.
        let cancelled = running
            .ingress
            .register(bound(Ipv4Addr::new(127, 0, 0, 4), port))
            .unwrap();
        drop(cancelled);
        let first_socket = first.socket.clone();
        let second_socket = second.socket.clone();
        connect(&second_socket, running.ingress.address);
        connect(&first_socket, running.ingress.address);
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
        assert!(running.ingress.waiting.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn source_port_match_alone_cannot_claim_a_registration() {
        let running = Running::new();
        let socket = bound(Ipv4Addr::new(127, 0, 0, 2), 0);
        let port = sockets::address(socket.as_raw_fd(), false).unwrap().port();
        let registration = running.ingress.register(socket).unwrap();
        let stranger = bound(Ipv4Addr::new(127, 0, 0, 3), port);
        connect(&stranger, running.ingress.address);
        let mut stranger = stream(&stranger);
        let mut byte = [0];
        let result = tokio::time::timeout(Duration::from_secs(3), stranger.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(result, Ok(0))
                || result.is_err_and(|error| error.kind() == io::ErrorKind::ConnectionReset)
        );

        let socket = registration.socket.clone();
        connect(&socket, running.ingress.address);
        let mut accepted = tokio::time::timeout(Duration::from_secs(3), registration.accept())
            .await
            .unwrap()
            .unwrap();
        stream(&socket).write_all(b"!").await.unwrap();
        accepted.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"!");
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
        let registration = ingress
            .register(unsafe { OwnedFd::from_raw_fd(raw) })
            .unwrap();
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
            registration.accept().await.unwrap();
        })
        .await
        .expect("accept must keep running while connect waits");
        drop((first, second, running));
    }
}
