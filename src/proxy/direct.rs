//! Direct upstream connections for relayed FakeIP domains.
use super::{CONNECT_TIMEOUT, ProxyStream};
use anyhow::{Context, Result};
use std::ffi::CString;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, oneshot};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
// Linux glibc and musl define this extension, but libc does not expose it.
const EAI_ADDRFAMILY: libc::c_int = -9;

#[derive(Clone)]
pub(crate) struct DirectConnector {
    lookups: Arc<Semaphore>,
}

impl Default for DirectConnector {
    fn default() -> Self {
        Self {
            lookups: Arc::new(Semaphore::new(32)),
        }
    }
}

impl DirectConnector {
    pub(crate) async fn connect(&self, host: &str, port: u16) -> Result<ProxyStream> {
        connect_with_lookup(lookup_ipv4(host.to_owned(), self.lookups.clone()), port)
            .await
            .with_context(|| format!("direct TCP connection to {host}:{port}"))
    }
}

async fn connect_with_lookup(
    lookup: impl Future<Output = io::Result<Vec<Ipv4Addr>>>,
    port: u16,
) -> Result<ProxyStream> {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let addresses = lookup.await.context("resolve direct hostname")?;
        let mut last_error = io::Error::from_raw_os_error(libc::EHOSTUNREACH);
        for address in addresses {
            match TcpStream::connect(SocketAddrV4::new(address, port)).await {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(ProxyStream::new(stream, Vec::new()));
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error.into())
    })
    .await
    .context("direct upstream connection timed out after 32 seconds")?
}

async fn lookup_ipv4(domain: String, capacity: Arc<Semaphore>) -> io::Result<Vec<Ipv4Addr>> {
    run_lookup(capacity, move || resolve_ipv4(&domain)).await
}

async fn run_lookup(
    capacity: Arc<Semaphore>,
    lookup: impl FnOnce() -> io::Result<Vec<Ipv4Addr>> + Send + 'static,
) -> io::Result<Vec<Ipv4Addr>> {
    let permit = capacity
        .try_acquire_owned()
        .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))?;
    let (sender, receiver) = oneshot::channel();
    // NSS can block inside a plugin and has no portable cancellation API.
    // Keep its permit until the native call really ends, even after a timeout.
    // Detached, bounded workers cannot hold up runtime or supervisor shutdown.
    std::thread::Builder::new()
        .name("dns-lookup".into())
        .spawn(move || {
            let _permit = permit;
            let _ = sender.send(lookup());
        })?;
    tokio::time::timeout(LOOKUP_TIMEOUT, receiver)
        .await
        .map_err(|_| io::Error::from_raw_os_error(libc::ETIMEDOUT))?
        .map_err(|_| io::Error::other("host resolver worker stopped"))?
}

fn resolve_ipv4(domain: &str) -> io::Result<Vec<Ipv4Addr>> {
    if domain.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::EHOSTUNREACH));
    }
    let name = CString::new(domain).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // Explicit hints restrict lookups to IPv4, without AI_ADDRCONFIG filtering
    // loopback-only hosts. No target-process resolver configuration is used.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut result = std::ptr::null_mut();
    let error = unsafe { libc::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut result) };
    match error {
        0 => {}
        libc::EAI_NONAME | libc::EAI_NODATA | EAI_ADDRFAMILY => {
            return Err(io::Error::from_raw_os_error(libc::EHOSTUNREACH));
        }
        libc::EAI_AGAIN => return Err(io::Error::from_raw_os_error(libc::EAGAIN)),
        libc::EAI_SYSTEM => return Err(io::Error::last_os_error()),
        _ => return Err(io::Error::from_raw_os_error(libc::EIO)),
    }
    let mut addresses = Vec::new();
    let mut next = result;
    while let Some(entry) = unsafe { next.as_ref() } {
        if entry.ai_family == libc::AF_INET
            && !entry.ai_addr.is_null()
            && entry.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in>()
        {
            let address = unsafe { &*entry.ai_addr.cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        next = entry.ai_next;
    }
    unsafe { libc::freeaddrinfo(result) };
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tries_resolved_addresses_in_order_and_reports_lookup_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let result = connect_with_lookup(
            async { Ok(vec![Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::LOCALHOST]) },
            address.port(),
        )
        .await
        .unwrap();
        assert_eq!(result.inner.peer_addr().unwrap(), address);
        assert!(result.inner.nodelay().unwrap());
        let (peer, _) = listener.accept().await.unwrap();
        drop((result, peer));
        for errno in [libc::EHOSTUNREACH, libc::EAGAIN, libc::ETIMEDOUT] {
            let error = connect_with_lookup(
                async { Err(io::Error::from_raw_os_error(errno)) },
                address.port(),
            )
            .await
            .err()
            .unwrap();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(errno)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn overall_deadline_includes_resolution() {
        let started = tokio::time::Instant::now();
        let error = connect_with_lookup(std::future::pending(), 80)
            .await
            .err()
            .unwrap();
        assert_eq!(started.elapsed(), CONNECT_TIMEOUT);
        assert!(error.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn timeout_and_cancellation_keep_capacity_until_native_lookup_finishes() {
        for cancel in [false, true] {
            let capacity = Arc::new(Semaphore::new(1));
            let (entered, started) = oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let task = tokio::spawn(run_lookup(capacity.clone(), move || {
                let _ = entered.send(());
                let _ = wait.recv();
                Ok(vec![Ipv4Addr::LOCALHOST])
            }));
            started.await.unwrap();
            if cancel {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                // Only pause after the OS worker has entered. Otherwise the
                // idle runtime may advance to the timeout before it starts.
                tokio::time::pause();
                tokio::time::advance(LOOKUP_TIMEOUT).await;
                assert_eq!(
                    task.await.unwrap().unwrap_err().raw_os_error(),
                    Some(libc::ETIMEDOUT)
                );
                tokio::time::resume();
            }
            assert_eq!(capacity.available_permits(), 0);
            assert_eq!(
                lookup_ipv4("127.0.0.1".into(), capacity.clone())
                    .await
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EAGAIN)
            );
            drop(release);
            drop(capacity.acquire().await.unwrap());
            assert_eq!(capacity.available_permits(), 1);
        }
    }
}
