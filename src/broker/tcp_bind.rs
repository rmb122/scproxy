//! Reserve an application's source port before connecting to the shared relay.
use super::sockets;
use std::io;
use std::os::fd::RawFd;

pub(super) fn prepare(fd: RawFd) -> io::Result<u16> {
    let source = sockets::address(fd, false)?;
    if source.port() != 0 {
        return Ok(source.port());
    }
    let delayed = sockets::option_int(fd, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT)?;
    if delayed != 0 {
        defer_port(fd, 0)?;
    }
    let bound = sockets::bind(fd, source);
    if bound.is_err() {
        // Failed reservations can clear an IP bound before delayed allocation
        // was disabled. Restore the address without claiming another port.
        let restored = defer_port(fd, 1).and_then(|()| sockets::bind(fd, source));
        // Always try to restore the original option, even if rebinding failed.
        let option_restored = defer_port(fd, delayed);
        restored?;
        option_restored?;
    } else if delayed != 0 {
        // Re-enabling delayed allocation does not release the reserved port.
        defer_port(fd, delayed)?;
    }
    bound?;
    let port = sockets::address(fd, false)?.port();
    if port == 0 {
        return Err(io::Error::from_raw_os_error(libc::EADDRNOTAVAIL));
    }
    Ok(port)
}

fn defer_port(fd: RawFd, enabled: i32) -> io::Result<()> {
    sockets::check(unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_BIND_ADDRESS_NO_PORT,
            (&enabled as *const i32).cast(),
            std::mem::size_of_val(&enabled) as _,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::{AsRawFd, OwnedFd};

    // Linux 6.3 socket option used to exercise port exhaustion without changing
    // the host's ephemeral port range. Older kernels skip this scenario.
    const IP_LOCAL_PORT_RANGE: libc::c_int = 51;

    fn set_option(fd: RawFd, name: i32, value: u32) -> io::Result<()> {
        sockets::check(unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                name,
                (&value as *const u32).cast(),
                std::mem::size_of_val(&value) as _,
            )
        })
    }

    fn deferred(source: SocketAddrV4) -> OwnedFd {
        let socket = sockets::stream().unwrap();
        defer_port(socket.as_raw_fd(), 1).unwrap();
        sockets::bind(socket.as_raw_fd(), source).unwrap();
        socket
    }

    #[test]
    fn preparation_preserves_source_bindings_options_and_descriptor_identity() {
        for source in [
            None,
            Some(Ipv4Addr::UNSPECIFIED),
            Some(Ipv4Addr::new(127, 0, 0, 2)),
        ] {
            for delayed in [false, true] {
                let socket = sockets::stream().unwrap();
                let fd = socket.as_raw_fd();
                defer_port(fd, i32::from(delayed)).unwrap();
                if let Some(ip) = source {
                    sockets::bind(fd, SocketAddrV4::new(ip, 0)).unwrap();
                }
                let original = sockets::address(fd, false).unwrap();
                let cookie = sockets::cookie(fd).unwrap();
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                let port = prepare(fd).unwrap();
                assert_ne!(port, 0);
                assert_eq!(
                    sockets::address(fd, false).unwrap(),
                    SocketAddrV4::new(*original.ip(), port)
                );
                if original.port() != 0 {
                    assert_eq!(port, original.port());
                }
                assert_eq!(sockets::cookie(fd).unwrap(), cookie);
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
                assert_eq!(
                    sockets::option_int(fd, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT)
                        .unwrap(),
                    i32::from(delayed)
                );
            }
        }
    }

    fn occupied_port_range() -> ([OwnedFd; 2], u16, u16) {
        for _ in 0..16 {
            let first = sockets::stream().unwrap();
            sockets::bind(
                first.as_raw_fd(),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            )
            .unwrap();
            let lower = sockets::address(first.as_raw_fd(), false).unwrap().port();
            let Some(upper) = lower.checked_add(1) else {
                continue;
            };
            let second = sockets::stream().unwrap();
            match sockets::bind(
                second.as_raw_fd(),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, upper),
            ) {
                Ok(()) => return ([first, second], lower, upper),
                Err(error) if error.raw_os_error() == Some(libc::EADDRINUSE) => continue,
                Err(error) => panic!("reserve adjacent port: {error}"),
            }
        }
        panic!("could not reserve adjacent source ports");
    }

    #[test]
    fn port_exhaustion_restores_binding_and_options_before_returning() {
        for (bind_address, delayed) in [(false, false), (true, true), (true, false)] {
            let (occupied, lower, upper) = occupied_port_range();
            let socket = if bind_address {
                deferred(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0))
            } else {
                sockets::stream().unwrap()
            };
            let fd = socket.as_raw_fd();
            // Turning off delayed allocation after bind keeps the source IP.
            defer_port(fd, i32::from(delayed)).unwrap();
            let range = u32::from(lower) | (u32::from(upper) << 16);
            match set_option(fd, IP_LOCAL_PORT_RANGE, range) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::ENOPROTOOPT) => return,
                Err(error) => panic!("set IP_LOCAL_PORT_RANGE: {error}"),
            }
            let source = sockets::address(fd, false).unwrap();
            let error = prepare(fd).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EADDRINUSE));
            assert_eq!(sockets::address(fd, false).unwrap(), source);
            assert_eq!(
                sockets::option_int(fd, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT).unwrap(),
                i32::from(delayed)
            );

            drop(occupied);
            let port = prepare(fd).unwrap();
            assert!((lower..=upper).contains(&port));
            assert_eq!(sockets::address(fd, false).unwrap().ip(), source.ip());
            assert_eq!(
                sockets::option_int(fd, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT).unwrap(),
                i32::from(delayed)
            );
            assert_eq!(
                sockets::option::<u32>(fd, libc::IPPROTO_IP, IP_LOCAL_PORT_RANGE).unwrap(),
                range
            );

            // The reserved port must still identify the actual connection,
            // including after restoring a binding with delayed allocation off.
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let destination =
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
            if let Err(error) = sockets::connect(fd, destination) {
                assert_eq!(error.raw_os_error(), Some(libc::EINPROGRESS));
            }
            let mut readiness = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut readiness, 1, 2000) }, 1);
            let (_accepted, peer) = listener.accept().unwrap();
            let expected_ip = if source.ip().is_unspecified() {
                Ipv4Addr::LOCALHOST
            } else {
                *source.ip()
            };
            assert_eq!(peer, SocketAddrV4::new(expected_ip, port).into());
        }
    }
}
