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
        if close_after_drain && let Some(error) = application.take_error()? {
            // EOF can disable further reads. Still observe resets: TIOCOUTQ
            // may retain an unacknowledged sequence count after TCP_CLOSE.
            return Err(error);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, OwnedFd};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpSocket};
    use tokio::task::JoinHandle;
    use tokio::time::{sleep, timeout};

    async fn backpressured_drain() -> (TcpStream, OwnedFd, JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let application = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (relay_application, _) = listener.accept().await.unwrap();
        let monitor = relay_application.as_fd().try_clone_to_owned().unwrap();
        let host = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let host_monitor = host.as_fd().try_clone_to_owned().unwrap();
        let (mut upstream, _) = listener.accept().await.unwrap();
        let relay = tokio::spawn(run(
            relay_application,
            crate::proxy::ProxyStream::new(host, Vec::new()),
        ));
        upstream.write_all(&vec![0x5a; BUFFER * 2]).await.unwrap();
        upstream.shutdown().await.unwrap();
        timeout(Duration::from_secs(2), async {
            loop {
                // The upstream FIN and all payload must reach the relay before
                // the application closes, leaving only its send queue blocked.
                if sockets::state(host_monitor.as_raw_fd()).unwrap() == 8
                    && sockets::queue_len(host_monitor.as_raw_fd(), libc::FIONREAD as _).unwrap()
                        == 0
                    && sockets::queue_len(monitor.as_raw_fd(), libc::TIOCOUTQ as _).unwrap() > 0
                {
                    break;
                }
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("relay must consume upstream payload and FIN");
        sleep(Duration::from_millis(20)).await;
        assert!(
            !relay.is_finished(),
            "unacknowledged data must keep the relay alive"
        );
        (application, monitor, relay)
    }

    #[tokio::test]
    async fn reset_during_drain_does_not_wait_for_stale_output_queue() {
        let (application, monitor, relay) = backpressured_drain().await;
        assert!(sockets::queue_len(application.as_raw_fd(), libc::FIONREAD as _).unwrap() > 0);
        drop(application);
        let error = timeout(Duration::from_secs(2), relay)
            .await
            .expect("reset must finish the relay without the global drain deadline")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(sockets::state(monitor.as_raw_fd()).unwrap(), 7);
        assert!(sockets::queue_len(monitor.as_raw_fd(), libc::TIOCOUTQ as _).unwrap() > 0);
    }

    #[tokio::test]
    async fn healthy_drain_still_delivers_all_backpressured_data() {
        let (mut application, monitor, relay) = backpressured_drain().await;
        // A duplicate would otherwise keep the relay endpoint open after run.
        drop(monitor);
        let mut received = vec![0; BUFFER * 2];
        timeout(
            Duration::from_secs(2),
            application.read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, vec![0x5a; BUFFER * 2]);
        timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
