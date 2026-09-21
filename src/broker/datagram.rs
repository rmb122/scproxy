//! DNS datagrams use the application's real UDP socket and kernel readiness.
use super::{
    access,
    engine::{Broker, Reply},
    memory,
    message::Message,
    seccomp::Notification,
    sockets,
};
use std::io;
use std::mem::{size_of, zeroed};
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::time::Instant;

pub(super) async fn dispatch(
    broker: &Broker,
    fd: OwnedFd,
    notification: &Notification,
) -> io::Result<Reply> {
    let call = notification.data.nr as libc::c_long;
    let args = notification.data.args;
    if call == libc::SYS_connect {
        if memory::family(notification.pid, args[1], args[2])? == libc::AF_UNSPEC as u16 {
            return Ok(Reply::Continue);
        }
        let target = memory::ipv4(notification.pid, args[1], args[2])?;
        let local = broker.dns.server_for(target)?;
        broker.valid(notification)?;
        sockets::connect(fd.as_raw_fd(), local)?;
        return Ok(Reply::Value(0));
    }
    if matches!(call, libc::SYS_getpeername | libc::SYS_getsockopt) {
        let actual = sockets::peer_address(fd.as_raw_fd(), call == libc::SYS_getsockopt)?;
        let Some(original) = broker.dns.original_server(actual) else {
            return Ok(Reply::Continue);
        };
        broker.valid(notification)?;
        memory::peer_name(notification, original)?;
        return Ok(Reply::Value(0));
    }
    let receive = [libc::SYS_recvfrom, libc::SYS_recvmsg, libc::SYS_recvmmsg].contains(&call);
    let batch = [libc::SYS_sendmmsg, libc::SYS_recvmmsg].contains(&call);
    let flat = [libc::SYS_sendto, libc::SYS_recvfrom].contains(&call);
    let flags = if flat || batch {
        args[3] as i32
    } else {
        args[2] as i32
    };
    let fd = AsyncFd::new(fd)?;
    let timeout: libc::timeval = sockets::option(
        fd.as_raw_fd(),
        libc::SOL_SOCKET,
        if receive {
            libc::SO_RCVTIMEO
        } else {
            libc::SO_SNDTIMEO
        },
    )?;
    let socket_deadline = if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
        None
    } else {
        Some(
            Instant::now()
                + Duration::new(
                    timeout.tv_sec.max(0) as u64,
                    timeout.tv_usec.max(0) as u32 * 1000,
                ),
        )
    };
    let batch_deadline = if call == libc::SYS_recvmmsg && args[4] != 0 {
        let bytes = memory::read(notification.pid, args[4], 16)?;
        let seconds = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
        let nanos = i64::from_ne_bytes(bytes[8..].try_into().unwrap());
        if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
            return Err(memory::error(libc::EINVAL));
        }
        Some(
            Instant::now()
                .checked_add(Duration::new(seconds as u64, nanos as u32))
                .ok_or_else(|| memory::error(libc::EINVAL))?,
        )
    } else {
        None
    };
    let deadline = match (socket_deadline, batch_deadline) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let count = if batch {
        (args[2] as u32).min(1024) as usize
    } else {
        1
    };
    let mut completed = 0;
    let mut result = Ok(Reply::Value(0));
    for index in 0..count {
        let current_flags = if index > 0 && receive && flags & libc::MSG_WAITFORONE != 0 {
            flags | libc::MSG_DONTWAIT
        } else {
            flags
        } & !libc::MSG_WAITFORONE;
        let header = args[1]
            .checked_add((index * 64) as u64)
            .ok_or_else(|| memory::error(libc::EFAULT))?;
        let message = if flat {
            Message::flat(
                notification.pid,
                args[1],
                args[2],
                args[4],
                args[5],
                receive,
            )
        } else {
            Message::header(notification.pid, header)
        };
        let operation = match message {
            Ok(message) => {
                transfer(
                    broker,
                    &fd,
                    notification,
                    &message,
                    current_flags,
                    deadline,
                    receive,
                )
                .await
            }
            Err(error) => Err(error),
        };
        match operation {
            Ok(length) => {
                if !batch {
                    return Ok(Reply::Value(length as i64));
                }
                broker.valid(notification)?;
                if let Err(error) = access::write_exact(
                    notification.pid,
                    header + 56,
                    &(length as u32).to_ne_bytes(),
                ) {
                    result = Err(error);
                    break;
                }
                completed += 1;
            }
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    if let Some(deadline) = batch_deadline {
        broker.valid(notification)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&(remaining.as_secs() as i64).to_ne_bytes());
        bytes[8..].copy_from_slice(&(remaining.subsec_nanos() as i64).to_ne_bytes());
        access::write_exact(notification.pid, args[4], &bytes)?;
        if completed == 0
            && Instant::now() >= deadline
            && result.as_ref().err().and_then(io::Error::raw_os_error) == Some(libc::EAGAIN)
        {
            return Ok(Reply::Value(0));
        }
    }
    if completed > 0 {
        Ok(Reply::Value(completed))
    } else {
        result
    }
}

async fn transfer(
    broker: &Broker,
    fd: &AsyncFd<OwnedFd>,
    notification: &Notification,
    message: &Message,
    flags: i32,
    deadline: Option<Instant>,
    receive: bool,
) -> io::Result<usize> {
    let capacity = message.capacity()?.min(65536);
    // UDP ancillary data is bounded independently from the payload.
    if !receive && message.control_length > 65536 {
        return Err(memory::error(libc::ENOBUFS));
    }
    let mut payload = if receive {
        vec![0; capacity]
    } else {
        message.read_payload(notification.pid)?
    };
    let mut control = if receive {
        vec![0; message.control_length.min(65536)]
    } else {
        memory::read(notification.pid, message.control, message.control_length)?
    };
    let destination = if receive {
        // recvmsg overwrites this initialized sockaddr with the packet source.
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)
    } else if message.name != 0 {
        let target = memory::ipv4(notification.pid, message.name, message.name_length as u64)?;
        broker.dns.server_for(target)?
    } else {
        match sockets::address(fd.as_raw_fd(), true) {
            Ok(address) if broker.dns.original_server(address).is_some() => address,
            Ok(_) => return Err(memory::error(libc::ENETUNREACH)),
            Err(_) => return Err(memory::error(libc::EDESTADDRREQ)),
        }
    };
    loop {
        broker.valid(notification)?;
        match transfer_now(
            fd.as_raw_fd(),
            destination,
            &mut payload,
            &mut control,
            flags,
            receive,
        ) {
            Ok((length, source, control_length, output_flags)) => {
                if receive {
                    broker.valid(notification)?;
                    message
                        .write_payload(notification.pid, &payload[..length.min(payload.len())])?;
                    let source = broker.dns.original_server(source).unwrap_or(source);
                    message.finish(
                        notification.pid,
                        source,
                        &control[..control_length],
                        output_flags,
                    )?;
                }
                return Ok(length);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if memory::nonblocking(fd.as_raw_fd(), flags)?
                    || deadline.is_some_and(|end| Instant::now() >= end)
                {
                    return Err(error);
                }
                // Cancellation checks also release duplicated FDs when a target
                // exits or abandons a notification while the UDP socket is idle.
                let tick = deadline
                    .map(|end| end.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::from_millis(10))
                    .min(Duration::from_millis(10));
                tokio::select! {
                    ready = async { if receive { fd.readable().await } else { fd.writable().await } } => { ready?.clear_ready(); },
                    _ = tokio::time::sleep(tick) => {},
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn transfer_now(
    fd: i32,
    target: SocketAddrV4,
    payload: &mut [u8],
    control: &mut [u8],
    flags: i32,
    receive: bool,
) -> io::Result<(usize, SocketAddrV4, usize, i32)> {
    let mut address = sockets::sockaddr(target);
    let mut vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_name = (&mut address as *mut libc::sockaddr_in).cast();
    message.msg_namelen = size_of::<libc::sockaddr_in>() as _;
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !control.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len() as _;
    }
    let count = unsafe {
        if receive {
            libc::recvmsg(fd, &mut message, flags | libc::MSG_DONTWAIT)
        } else {
            libc::sendmsg(
                fd,
                &message,
                flags | libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        }
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        count as usize,
        sockets::decode(address),
        message.msg_controllen as usize,
        message.msg_flags,
    ))
}
