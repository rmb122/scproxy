//! Native socket operations that never change application descriptor flags.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub(super) fn check(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn sockaddr(addr: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

pub(super) fn decode(addr: libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(addr.sin_port),
    )
}

pub(super) fn address(fd: RawFd, peer: bool) -> io::Result<SocketAddrV4> {
    let mut addr: libc::sockaddr_storage = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ptr = (&mut addr as *mut libc::sockaddr_storage).cast();
    check(unsafe {
        if peer {
            libc::getpeername(fd, ptr, &mut len)
        } else {
            libc::getsockname(fd, ptr, &mut len)
        }
    })?;
    if addr.ss_family != libc::AF_INET as _ {
        return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
    }
    Ok(decode(unsafe {
        std::ptr::read((&addr as *const libc::sockaddr_storage).cast())
    }))
}

pub(super) fn option<T: Copy>(fd: RawFd, level: i32, name: i32) -> io::Result<T> {
    let mut value: T = unsafe { zeroed() };
    let mut len = size_of::<T>() as libc::socklen_t;
    check(unsafe { libc::getsockopt(fd, level, name, (&mut value as *mut T).cast(), &mut len) })?;
    if len as usize != size_of::<T>() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(value)
}

pub(super) fn option_int(fd: RawFd, level: i32, name: i32) -> io::Result<i32> {
    option(fd, level, name)
}

pub(super) fn peer_address(fd: RawFd, socket_option: bool) -> io::Result<SocketAddrV4> {
    if socket_option {
        // SO_PEERNAME also accepts a peer while TCP is still connecting.
        option(fd, libc::SOL_SOCKET, libc::SO_PEERNAME).map(decode)
    } else {
        address(fd, true)
    }
}

pub(super) fn cookie(fd: RawFd) -> io::Result<u64> {
    option(fd, libc::SOL_SOCKET, libc::SO_COOKIE)
}

pub(super) fn is_tcp_v4(fd: RawFd) -> io::Result<bool> {
    Ok(
        option_int(fd, libc::SOL_SOCKET, libc::SO_DOMAIN)? == libc::AF_INET
            && option_int(fd, libc::SOL_SOCKET, libc::SO_TYPE)? == libc::SOCK_STREAM
            && option_int(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL)? == libc::IPPROTO_TCP,
    )
}

pub(super) fn state(fd: RawFd) -> io::Result<u8> {
    let mut info: libc::tcp_info = unsafe { zeroed() };
    let mut len = size_of::<libc::tcp_info>() as libc::socklen_t;
    check(unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut len,
        )
    })?;
    Ok(info.tcpi_state)
}

pub(super) fn stream() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(super) fn bind(fd: RawFd, addr: SocketAddrV4) -> io::Result<()> {
    let addr = sockaddr(addr);
    check(unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as _,
        )
    })
}

pub(super) fn connect(fd: RawFd, addr: SocketAddrV4) -> io::Result<()> {
    let addr = sockaddr(addr);
    check(unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as _,
        )
    })
}

pub(super) fn queue_len(fd: RawFd, request: libc::c_ulong) -> io::Result<usize> {
    let mut value: libc::c_int = 0;
    check(unsafe { libc::ioctl(fd, request as _, &mut value) })?;
    Ok(value.max(0) as usize)
}
