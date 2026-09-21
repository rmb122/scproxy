//! Bounded host NSS lookups, independent of Tokio's blocking worker lifetime.
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, oneshot};

pub(super) const SERVFAIL: u8 = 2;
const NXDOMAIN: u8 = 3;
const TIMEOUT: Duration = Duration::from_secs(5);
// Linux glibc and musl define this extension, but libc does not expose it.
const EAI_ADDRFAMILY: libc::c_int = -9;

pub(super) async fn ipv4(domain: String, capacity: Arc<Semaphore>) -> Result<Vec<Ipv4Addr>, u8> {
    run(capacity, move || resolve(&domain)).await
}

async fn run(
    capacity: Arc<Semaphore>,
    lookup: impl FnOnce() -> Result<Vec<Ipv4Addr>, u8> + Send + 'static,
) -> Result<Vec<Ipv4Addr>, u8> {
    let permit = capacity.try_acquire_owned().map_err(|_| SERVFAIL)?;
    let (sender, receiver) = oneshot::channel();
    // NSS can block inside a plugin and has no portable cancellation API.
    // Keep its permit until the native call really ends, even after a timeout.
    // Detached, bounded workers cannot hold up runtime or supervisor shutdown.
    std::thread::Builder::new()
        .name("dns-lookup".into())
        .spawn(move || {
            let _permit = permit;
            let _ = sender.send(lookup());
        })
        .map_err(|_| SERVFAIL)?;
    tokio::time::timeout(TIMEOUT, receiver)
        .await
        .map_err(|_| SERVFAIL)?
        .map_err(|_| SERVFAIL)?
}

fn resolve(domain: &str) -> Result<Vec<Ipv4Addr>, u8> {
    if domain.is_empty() {
        return Ok(Vec::new());
    }
    let name = CString::new(domain).map_err(|_| SERVFAIL)?;
    // Explicit hints restrict lookups to IPv4, without AI_ADDRCONFIG filtering
    // loopback-only hosts. No target-process resolver configuration is used.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut result = std::ptr::null_mut();
    let error = unsafe { libc::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut result) };
    match error {
        0 => {}
        libc::EAI_NONAME => return Err(NXDOMAIN),
        libc::EAI_NODATA | EAI_ADDRFAMILY => return Ok(Vec::new()),
        _ => return Err(SERVFAIL),
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

    #[tokio::test]
    async fn timeout_and_cancellation_keep_capacity_until_native_lookup_finishes() {
        for cancel in [false, true] {
            let capacity = Arc::new(Semaphore::new(1));
            let (entered, started) = oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let task = tokio::spawn(run(capacity.clone(), move || {
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
                tokio::time::advance(TIMEOUT).await;
                assert_eq!(task.await.unwrap(), Err(SERVFAIL));
                tokio::time::resume();
            }
            assert_eq!(capacity.available_permits(), 0);
            assert_eq!(
                ipv4("127.0.0.1".into(), capacity.clone()).await,
                Err(SERVFAIL)
            );
            drop(release);
            drop(capacity.acquire().await.unwrap());
            assert_eq!(capacity.available_permits(), 1);
        }
    }
}
