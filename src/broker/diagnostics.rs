//! TCP socket cookies used to discard metadata after the last socket closes.
use super::sockets;
use std::collections::HashSet;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

fn diagnostic_socket() -> io::Result<OwnedFd> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
    addr.nl_family = libc::AF_NETLINK as _;
    sockets::check(unsafe {
        libc::connect(
            raw,
            (&addr as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as _,
        )
    })?;
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    sockets::check(unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as _,
        )
    })?;
    Ok(fd)
}

pub(super) fn snapshot() -> io::Result<HashSet<u64>> {
    let fd = diagnostic_socket()?;
    // nlmsghdr followed by inet_diag_req_v2. Integer fields use native order.
    let mut request = [0u8; 72];
    request[0..4].copy_from_slice(&72u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20u16.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[16] = libc::AF_INET as u8;
    request[17] = libc::IPPROTO_TCP as u8;
    request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
    request[64..72].fill(0xff);
    let written = unsafe {
        libc::send(
            fd.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sockets = HashSet::new();
    let mut buffer = vec![0u8; 65536];
    loop {
        let count = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 || count as usize > buffer.len() {
            return Err(io::Error::other("truncated socket diagnostic response"));
        }
        let mut offset = 0;
        while offset + 16 <= count as usize {
            let header = &buffer[offset..offset + 16];
            let len = u32::from_ne_bytes(header[0..4].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(header[4..6].try_into().unwrap());
            let flags = u16::from_ne_bytes(header[6..8].try_into().unwrap());
            if len < 16 || offset + len > count as usize {
                return Err(io::Error::other("invalid socket diagnostic message"));
            }
            if flags & 0x10 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "socket diagnostic dump interrupted",
                ));
            }
            let payload = &buffer[offset + 16..offset + len];
            if kind == 3 {
                return Ok(sockets);
            }
            if kind == 2 {
                let code = payload
                    .get(..4)
                    .ok_or_else(|| io::Error::other("invalid netlink error"))?;
                let errno = i32::from_ne_bytes(code.try_into().unwrap());
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(-errno));
                }
            } else if kind == 20 && payload.len() >= 72 {
                let low = u32::from_ne_bytes(payload[44..48].try_into().unwrap());
                let high = u32::from_ne_bytes(payload[48..52].try_into().unwrap());
                sockets.insert(u64::from(low) | (u64::from(high) << 32));
            }
            offset += (len + 3) & !3;
        }
    }
}
