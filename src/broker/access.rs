use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

const PIDFD_THREAD: libc::c_uint = libc::O_EXCL as libc::c_uint;
const KCMP_FILE: libc::c_int = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Method {
    Thread,
    Process,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SocketAccess {
    method: Method,
}

impl SocketAccess {
    pub(super) fn probe() -> io::Result<Self> {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        let (method, pidfd) = choose_method(|| pidfd_open(tid, PIDFD_THREAD))?;
        let access = Self { method };
        let (socket, _) = UnixStream::pair()?;
        // Probe the actual duplication and permission checks, not kernel versions.
        let duplicate = if let Some(pidfd) = pidfd {
            pidfd_getfd(pidfd.as_raw_fd(), socket.as_raw_fd())?
        } else {
            access.get(tid, socket.as_raw_fd())?
        };
        drop(duplicate);

        let mut value = [0x5a_u8];
        let address = value.as_mut_ptr() as u64;
        let mut copy = [0_u8];
        read_exact(tid, address, &mut copy)?;
        write_exact(tid, address, &copy)?;
        Ok(access)
    }

    pub(super) fn get(&self, tid: u32, fd: RawFd) -> io::Result<OwnedFd> {
        check_tid(tid)?;
        if fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        match self.method {
            Method::Thread => {
                let pidfd = pidfd_open(tid, PIDFD_THREAD)?;
                pidfd_getfd(pidfd.as_raw_fd(), fd)
            }
            Method::Process => {
                let tgid = thread_group(tid)?;
                let pidfd = pidfd_open(tgid, 0)?;
                let duplicate = pidfd_getfd(pidfd.as_raw_fd(), fd)?;
                verify_file(tid, fd, duplicate.as_raw_fd())?;
                Ok(duplicate)
            }
        }
    }
}

fn choose_method(
    open_thread: impl FnOnce() -> io::Result<OwnedFd>,
) -> io::Result<(Method, Option<OwnedFd>)> {
    match open_thread() {
        Ok(fd) => Ok((Method::Thread, Some(fd))),
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok((Method::Process, None)),
        Err(error) => Err(error),
    }
}

fn check_tid(tid: u32) -> io::Result<()> {
    if tid == 0 || tid > libc::pid_t::MAX as u32 {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

fn pidfd_open(tid: u32, flags: libc::c_uint) -> io::Result<OwnedFd> {
    check_tid(tid)?;
    let result = unsafe { libc::syscall(libc::SYS_pidfd_open, tid as libc::pid_t, flags) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) })
}

fn pidfd_getfd(pidfd: RawFd, target_fd: RawFd) -> io::Result<OwnedFd> {
    let result = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, target_fd, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) })
}

fn thread_group(tid: u32) -> io::Result<u32> {
    let status = fs::read_to_string(format!("/proc/{tid}/status"))?;
    parse_thread_group(&status)
}

fn parse_thread_group(status: &str) -> io::Result<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|&tgid| tgid > 0 && tgid <= libc::pid_t::MAX as u32)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing or invalid thread group ID",
            )
        })
}

fn verify_file(tid: u32, target_fd: RawFd, duplicate: RawFd) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            libc::syscall(libc::SYS_gettid) as libc::pid_t,
            tid as libc::pid_t,
            KCMP_FILE,
            duplicate as libc::c_ulong,
            target_fd as libc::c_ulong,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result != 0 {
        // A private thread FD table or a concurrent close/reuse can produce this.
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    Ok(())
}

pub(super) fn read_exact(tid: u32, address: u64, buffer: &mut [u8]) -> io::Result<()> {
    copy_memory(tid, address, buffer.as_mut_ptr(), buffer.len(), false)
}

pub(super) fn write_exact(tid: u32, address: u64, buffer: &[u8]) -> io::Result<()> {
    copy_memory(tid, address, buffer.as_ptr().cast_mut(), buffer.len(), true)
}

fn copy_memory(
    tid: u32,
    address: u64,
    buffer: *mut u8,
    length: usize,
    write: bool,
) -> io::Result<()> {
    if length == 0 {
        return Ok(());
    }
    check_tid(tid)?;
    if address == 0 || address.checked_add(length as u64).is_none() {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    let mut copied = 0;
    while copied < length {
        let local = libc::iovec {
            iov_base: unsafe { buffer.add(copied) }.cast(),
            iov_len: length - copied,
        };
        let remote = libc::iovec {
            iov_base: (address + copied as u64) as *mut libc::c_void,
            iov_len: length - copied,
        };
        let count = unsafe {
            if write {
                libc::process_vm_writev(tid as libc::pid_t, &local, 1, &remote, 1, 0)
            } else {
                libc::process_vm_readv(tid as libc::pid_t, &local, 1, &remote, 1, 0)
            }
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(io::Error::from_raw_os_error(libc::EFAULT));
        }
        copied += count as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_thread_flag_selects_process_but_permissions_do_not() {
        let fallback = choose_method(|| Err(io::Error::from_raw_os_error(libc::EINVAL))).unwrap();
        assert_eq!(fallback.0, Method::Process);
        for errno in [libc::EPERM, libc::EACCES, libc::ENOSYS, libc::ESRCH] {
            let error = choose_method(|| Err(io::Error::from_raw_os_error(errno))).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
        }
    }

    #[test]
    #[ignore = "requires Linux pidfd_getfd, kcmp, and unshare(CLONE_FILES) permissions"]
    fn private_thread_table_never_returns_the_leaders_different_object() {
        let access = SocketAccess::probe().unwrap();
        let (first, _first_peer) = UnixStream::pair().unwrap();
        let (second, _second_peer) = UnixStream::pair().unwrap();
        let first_fd = first.as_raw_fd();
        let second_fd = second.as_raw_fd();
        std::thread::spawn(move || {
            assert_eq!(unsafe { libc::unshare(libc::CLONE_FILES) }, 0);
            assert_eq!(unsafe { libc::dup2(second_fd, first_fd) }, first_fd);
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
            let compatible = SocketAccess {
                method: Method::Process,
            };
            assert_eq!(
                compatible.get(tid, first_fd).unwrap_err().raw_os_error(),
                Some(libc::EOPNOTSUPP),
            );
            if access.method == Method::Thread {
                let duplicate = access.get(tid, first_fd).unwrap();
                verify_file(tid, first_fd, duplicate.as_raw_fd()).unwrap();
            }
        })
        .join()
        .unwrap();
    }
}
