//! Bounded TCP forwarding with whole-connection close-after-drain semantics.

use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

use tokio::net::TcpStream;

use super::sockets;

const BUFFER: usize = 65536;

/// After either EOF, drain buffered data and its TCP queues before dropping
/// both streams. Never propagate independent per-direction shutdowns.
pub(super) async fn run(
    application: TcpStream,
    mut host: crate::proxy::ProxyStream,
) -> io::Result<()> {
    // These are relay-owned streams, not duplicates of application sockets.
    // Avoid Nagle/delayed-ACK stalls between independently buffered TCP legs.
    application.set_nodelay(true)?;
    host.inner.set_nodelay(true)?;
    let mut to_application = Vec::new();
    let mut to_host = Vec::new();
    let mut buffer = vec![0u8; BUFFER];
    let mut close_after_drain = false;
    loop {
        let mut progress = false;
        if !close_after_drain && to_application.len() < BUFFER {
            let space = BUFFER - to_application.len();
            match host.try_read(&mut buffer[..space]) {
                Ok(0) => {
                    close_after_drain = true;
                    progress = true;
                }
                Ok(count) => {
                    to_application.extend_from_slice(&buffer[..count]);
                    progress = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        progress |= flush(&application, &mut to_application)?;
        let queued = sockets::queue_len(application.as_raw_fd(), libc::FIONREAD as _)?;
        if (!close_after_drain || queued > 0) && to_host.len() < BUFFER {
            let space = BUFFER - to_host.len();
            match application.try_read(&mut buffer[..space]) {
                Ok(0) => {
                    close_after_drain = true;
                    progress = true;
                }
                Ok(count) => {
                    to_host.extend_from_slice(&buffer[..count]);
                    progress = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        progress |= flush(&host.inner, &mut to_host)?;
        if close_after_drain
            && to_application.is_empty()
            && to_host.is_empty()
            && sockets::queue_len(application.as_raw_fd(), libc::TIOCOUTQ as _)? == 0
            && sockets::queue_len(application.as_raw_fd(), libc::FIONREAD as _)? == 0
        {
            return Ok(());
        }
        if progress {
            tokio::task::consume_budget().await;
            continue;
        }
        tokio::select! {
            result = std::future::poll_fn(|cx| host.poll_read_ready(cx)), if !close_after_drain && to_application.len() < BUFFER => { result?; }
            result = application.readable(), if (!close_after_drain || queued > 0) && to_host.len() < BUFFER => { result?; }
            result = host.inner.writable(), if !to_host.is_empty() => { result?; }
            result = application.writable(), if !to_application.is_empty() => { result?; }
            _ = tokio::time::sleep(Duration::from_millis(10)), if close_after_drain => {}
        }
    }
}

fn flush(stream: &TcpStream, pending: &mut Vec<u8>) -> io::Result<bool> {
    if pending.is_empty() {
        return Ok(false);
    }
    match stream.try_write(pending) {
        Ok(0) => Err(io::Error::from(io::ErrorKind::WriteZero)),
        Ok(count) => {
            pending.drain(..count);
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}
