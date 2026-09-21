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
        result.is_ok() || result.as_ref().unwrap_err().raw_os_error() == Some(libc::EINPROGRESS),
        "{result:?}"
    );
}

fn stream(socket: &OwnedFd) -> TcpStream {
    let copy = socket.as_fd().try_clone_to_owned().unwrap();
    TcpStream::from_std(std::net::TcpStream::from(copy)).unwrap()
}

async fn closed(mut stream: TcpStream) {
    let result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut [0]))
        .await
        .expect("unregistered connection must be closed");
    assert!(
        matches!(result, Ok(0))
            || result.is_err_and(|error| error.kind() == io::ErrorKind::ConnectionReset)
    );
}

#[tokio::test]
async fn accept_can_arrive_before_source_publication() {
    let running = Running::new();
    let registration = running.ingress.register(sockets::stream().unwrap());
    let socket = registration.socket.clone();
    connect(&socket, running.ingress.address);
    // Deliberately omit connected(): the accept loop must resolve the race
    // from the live original socket, not wait for a later table insertion.
    let mut accepted = tokio::time::timeout(Duration::from_secs(3), registration.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accepted.peer_addr().unwrap(),
        SocketAddr::V4(sockets::address(socket.as_raw_fd(), false).unwrap())
    );
    let mut client = stream(&socket);
    client.write_all(b"original").await.unwrap();
    let mut bytes = [0; 8];
    accepted.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"original");
    assert!(running.ingress.dispatch.lock().unwrap().waiting.is_empty());
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
async fn dispatch_uses_source_ip_and_port_with_reversed_arrival_order() {
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
    first.connected().unwrap();
    let (first, second) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(first.accept(), second.accept())
    })
    .await
    .unwrap();
    let mut first = first.unwrap();
    let mut second = second.unwrap();
    let mut first_client = stream(&first_socket);
    let mut second_client = stream(&second_socket);
    first_client.write_all(b"first").await.unwrap();
    second_client.write_all(b"other").await.unwrap();
    let mut bytes = [0; 5];
    first.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"first");
    second.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"other");
    let dispatch = running.ingress.dispatch.lock().unwrap();
    assert!(dispatch.waiting.is_empty());
    assert!(dispatch.sources.is_empty());
}

#[tokio::test]
async fn unrelated_and_cancelled_connections_are_closed_without_stopping_listener() {
    let running = Running::new();
    for published in [false, true] {
        let registration = running.ingress.register(sockets::stream().unwrap());
        let cancelled_socket = registration.socket.clone();
        // A pending registration must not authorize an unrelated local client.
        let stranger = TcpStream::connect(running.ingress.address).await.unwrap();
        closed(stranger).await;
        if published {
            connect(&cancelled_socket, running.ingress.address);
            registration.connected().unwrap();
        }
        drop(registration);
        if !published {
            connect(&cancelled_socket, running.ingress.address);
        }
        closed(stream(&cancelled_socket)).await;
    }

    let registration = running.ingress.register(sockets::stream().unwrap());
    connect(&registration.socket, running.ingress.address);
    registration.connected().unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(3), registration.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accepted.local_addr().unwrap(),
        running.ingress.address.into()
    );
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
