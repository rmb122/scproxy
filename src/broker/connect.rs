//! Cancellable native connect without changing the application's shared flags.
use super::{memory, sockets};
use std::io;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(32);

struct PendingConnect {
    socket: Arc<OwnedFd>,
    task: JoinHandle<io::Result<()>>,
}

impl PendingConnect {
    fn start(socket: Arc<OwnedFd>, target: SocketAddrV4) -> Self {
        let worker_socket = socket.clone();
        let task = tokio::task::spawn_blocking(move || {
            sockets::connect(worker_socket.as_raw_fd(), target)
        });
        Self { socket, task }
    }

    async fn wait(mut self, valid: impl Fn() -> io::Result<()>) -> io::Result<()> {
        tokio::time::timeout(CONNECT_TIMEOUT, async {
            let mut check = tokio::time::interval(Duration::from_millis(10));
            check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    result = &mut self.task => return result.map_err(io::Error::other)?,
                    _ = check.tick() => valid()?,
                }
            }
        })
        .await
        .map_err(|_| memory::error(libc::ETIMEDOUT))?
    }
}

impl Drop for PendingConnect {
    fn drop(&mut self) {
        // abort() stops a queued worker but cannot interrupt one inside
        // connect(2). Linux shutdown disconnects SYN_SENT and wakes that waiter.
        // Repeat to cover cancellation racing with entry to connect, retaining
        // the duplicate until the worker stops. O_NONBLOCK remains untouched.
        self.task.abort();
        while !self.task.is_finished() {
            unsafe {
                libc::shutdown(self.socket.as_raw_fd(), libc::SHUT_RDWR);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

pub(super) async fn run(
    socket: Arc<OwnedFd>,
    target: SocketAddrV4,
    valid: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    valid()?;
    PendingConnect::start(socket, target).wait(valid).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    fn blocked_connect() -> (Arc<OwnedFd>, PendingConnect, std::net::TcpListener, i32) {
        let routes = std::fs::read_to_string("/proc/net/route").unwrap();
        let device = routes
            .lines()
            .skip(1)
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let device = fields.next()?;
                (fields.next()? == "00000000" && device != "lo").then_some(device)
            })
            .expect("test requires a non-loopback default route");
        let device = std::ffi::CString::new(device).unwrap();
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0);
        let socket = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    device.as_ptr().cast(),
                    device.as_bytes_with_nul().len() as _,
                )
            },
            0
        );
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        assert_eq!(flags & libc::O_NONBLOCK, 0);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(target) = listener.local_addr().unwrap() else {
            unreachable!()
        };
        let pending = PendingConnect::start(socket.clone(), target);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while sockets::state(raw).unwrap() != 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "socket did not enter SYN_SENT"
            );
            assert!(!pending.task.is_finished(), "connect unexpectedly finished");
            std::thread::sleep(Duration::from_millis(1));
        }
        (socket, pending, listener, flags)
    }

    #[tokio::test(start_paused = true)]
    #[ignore = "requires Linux SO_BINDTODEVICE permissions and a non-loopback default route"]
    async fn timeout_and_cancellation_stop_native_worker_without_changing_flags() {
        for timeout in [true, false] {
            let (socket, pending, _listener, flags) = blocked_connect();
            let started = Arc::new(tokio::sync::Notify::new());
            let check = started.clone();
            let task = tokio::spawn(pending.wait(move || {
                check.notify_one();
                Ok(())
            }));
            started.notified().await;
            if timeout {
                tokio::time::advance(CONNECT_TIMEOUT).await;
                assert_eq!(
                    task.await.unwrap().unwrap_err().raw_os_error(),
                    Some(libc::ETIMEDOUT)
                );
            } else {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            }
            assert_eq!(
                Arc::strong_count(&socket),
                1,
                "worker still holds the socket"
            );
            assert_ne!(sockets::state(socket.as_raw_fd()).unwrap(), 2);
            assert_eq!(
                unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) },
                flags
            );
        }
    }
}
