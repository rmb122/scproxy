//! Native 64-bit ABI memory access, with bounded copies and explicit wire layouts.
use super::{access, seccomp::Notification, sockets};
use std::io;
use std::net::SocketAddrV4;

pub(super) fn error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

pub(super) fn read(tid: u32, address: u64, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    access::read_exact(tid, address, &mut bytes)?;
    Ok(bytes)
}

pub(super) fn path(tid: u32, address: u64) -> io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut bytes = Vec::new();
    while bytes.len() < 4096 {
        let pointer = address
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| error(libc::EFAULT))?;
        // Do not read past a page boundary: the next page can be unmapped even
        // when the pathname is valid and ends just before that boundary.
        let count = (4096 - bytes.len())
            .min(256)
            .min(4096 - (pointer as usize & 4095));
        let chunk = read(tid, pointer, count)?;
        if let Some(end) = chunk.iter().position(|&byte| byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Ok(std::ffi::OsString::from_vec(bytes).into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Err(error(libc::ENAMETOOLONG))
}
pub(super) fn u32_at(tid: u32, address: u64) -> io::Result<u32> {
    let mut bytes = [0; 4];
    access::read_exact(tid, address, &mut bytes)?;
    Ok(u32::from_ne_bytes(bytes))
}
pub(super) fn family(tid: u32, address: u64, length: u64) -> io::Result<u16> {
    if length < 2 || length > i32::MAX as u64 {
        return Err(error(libc::EINVAL));
    }
    let mut bytes = [0; 2];
    access::read_exact(tid, address, &mut bytes)?;
    Ok(u16::from_ne_bytes(bytes))
}
pub(super) fn ipv4(tid: u32, address: u64, length: u64) -> io::Result<SocketAddrV4> {
    if family(tid, address, length)? != libc::AF_INET as u16 {
        return Err(error(libc::EAFNOSUPPORT));
    }
    if length < 16 {
        return Err(error(libc::EINVAL));
    }
    let bytes = read(tid, address, 16)?;
    Ok(SocketAddrV4::new(
        [bytes[4], bytes[5], bytes[6], bytes[7]].into(),
        u16::from_be_bytes([bytes[2], bytes[3]]),
    ))
}
pub(super) fn address_bytes(address: SocketAddrV4) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
    bytes[4..8].copy_from_slice(&address.ip().octets());
    bytes
}
pub(super) fn put_address(
    tid: u32,
    pointer: u64,
    capacity: u32,
    address: SocketAddrV4,
) -> io::Result<()> {
    if capacity > i32::MAX as u32 {
        return Err(error(libc::EINVAL));
    }
    access::write_exact(
        tid,
        pointer,
        &address_bytes(address)[..(capacity as usize).min(16)],
    )
}
pub(super) fn peer_name(notification: &Notification, address: SocketAddrV4) -> io::Result<()> {
    let tid = notification.pid;
    let args = notification.data.args;
    let socket_option = notification.data.nr as libc::c_long == libc::SYS_getsockopt;
    let (pointer, length) = if socket_option {
        (args[3], args[4])
    } else {
        (args[1], args[2])
    };
    let capacity = u32_at(tid, length)?;
    // SO_PEERNAME preserves optlen on truncation and rejects oversized buffers.
    if socket_option && capacity > 16 {
        return Err(error(libc::EINVAL));
    }
    put_address(tid, pointer, capacity, address)?;
    let returned = if socket_option { capacity } else { 16 };
    access::write_exact(tid, length, &returned.to_ne_bytes())
}
pub(super) fn nonblocking(fd: i32, flags: i32) -> io::Result<bool> {
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    sockets::check(status)?;
    Ok(status & libc::O_NONBLOCK != 0 || flags & libc::MSG_DONTWAIT != 0)
}
