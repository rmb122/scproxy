use std::io;
use std::mem::{offset_of, size_of};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xc000_00b7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("scproxy supports native x86_64 and aarch64 only");

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Data {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Notification {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: Data,
}

#[repr(C)]
#[derive(Default)]
struct Response {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct NotificationSizes {
    notification: u16,
    response: u16,
    data: u16,
}

// Both supported architectures use the generic Linux ioctl encoding.
const fn ioctl_request(direction: u32, number: u32, size: usize) -> libc::c_ulong {
    ((direction << 30) | ((size as u32) << 16) | ((b'!' as u32) << 8) | number) as libc::c_ulong
}

const NOTIF_RECV: libc::c_ulong = ioctl_request(3, 0, size_of::<Notification>());
const NOTIF_SEND: libc::c_ulong = ioctl_request(3, 1, size_of::<Response>());
const NOTIF_ID_VALID: libc::c_ulong = ioctl_request(1, 2, size_of::<u64>());

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn filter() -> Vec<libc::sock_filter> {
    const LOAD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const JSET: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    let mut filter = vec![
        statement(LOAD, offset_of!(Data, arch) as u32),
        jump(JEQ, NATIVE_ARCH, 1, 0),
        statement(RET, SECCOMP_RET_KILL_PROCESS),
        statement(LOAD, offset_of!(Data, nr) as u32),
        jump(JSET, 0x4000_0000, 0, 1),
        statement(RET, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
    ];
    for syscall in [
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ] {
        filter.push(jump(JEQ, syscall as u32, 0, 1));
        filter.push(statement(RET, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
    }
    for syscall in [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_getpeername,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
    ] {
        filter.push(jump(JEQ, syscall as u32, 0, 1));
        filter.push(statement(RET, SECCOMP_RET_USER_NOTIF));
    }
    filter.push(statement(RET, SECCOMP_RET_ALLOW));
    filter
}

pub(super) fn install() -> io::Result<OwnedFd> {
    let mut sizes = NotificationSizes::default();
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut NotificationSizes,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::from(sizes.notification) > size_of::<Notification>()
        || usize::from(sizes.response) > size_of::<Response>()
        || usize::from(sizes.data) > size_of::<Data>()
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel seccomp notification structures exceed supported sizes",
        ));
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut instructions = filter();
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &program as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // The seccomp notification descriptor has FD_CLOEXEC set by the kernel.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// The caller must own notification reception and arrange wakeup/shutdown.
pub(super) fn receive(fd: RawFd) -> io::Result<Notification> {
    // Every receive requires a completely zeroed request, including padding.
    let mut notification: Notification = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, NOTIF_RECV as _, &mut notification) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(notification)
}

/// `error` accepts a positive errno or the kernel's negative errno convention.
pub(super) fn respond(
    fd: RawFd,
    id: u64,
    val: i64,
    error: i32,
    continue_syscall: bool,
) -> io::Result<()> {
    if continue_syscall && (val != 0 || error != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "continued seccomp calls cannot include a result or error",
        ));
    }
    let response = Response {
        id,
        val,
        error: if error > 0 { -error } else { error },
        flags: if continue_syscall {
            SECCOMP_USER_NOTIF_FLAG_CONTINUE
        } else {
            0
        },
    };
    if unsafe { libc::ioctl(fd, NOTIF_SEND as _, &response) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn valid(fd: RawFd, id: u64) -> io::Result<bool> {
    if unsafe { libc::ioctl(fd, NOTIF_ID_VALID as _, &id) } >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(arch: u32, syscall: i32) -> u32 {
        let instructions = filter();
        let mut accumulator = 0;
        let mut pc = 0;
        loop {
            let instruction = instructions[pc];
            match u32::from(instruction.code) {
                code if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS => {
                    accumulator = if instruction.k == offset_of!(Data, arch) as u32 {
                        arch
                    } else {
                        syscall as u32
                    };
                }
                code if code == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K => {
                    pc += usize::from(if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                code if code == libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K => {
                    pc += usize::from(if accumulator & instruction.k != 0 {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                code if code == libc::BPF_RET | libc::BPF_K => return instruction.k,
                _ => panic!("unexpected filter instruction"),
            }
            pc += 1;
        }
    }

    #[test]
    fn filter_intercepts_network_calls() {
        for syscall in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_getpeername,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            libc::SYS_recvmmsg,
        ] {
            assert_eq!(
                evaluate(NATIVE_ARCH, syscall as i32),
                SECCOMP_RET_USER_NOTIF
            );
        }
        for syscall in [
            libc::SYS_listen,
            libc::SYS_bind,
            libc::SYS_accept4,
            libc::SYS_read,
            libc::SYS_write,
        ] {
            assert_eq!(evaluate(NATIVE_ARCH, syscall as i32), SECCOMP_RET_ALLOW);
        }
    }

    #[test]
    fn uring_is_unavailable() {
        for syscall in [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert_eq!(
                evaluate(NATIVE_ARCH, syscall as i32),
                SECCOMP_RET_ERRNO | libc::ENOSYS as u32
            );
        }
    }

    #[test]
    fn filter_rejects_other_architectures_and_x32() {
        assert_eq!(
            evaluate(0x4000_0003, libc::SYS_connect as i32),
            SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            evaluate(NATIVE_ARCH, 0x4000_0000 | libc::SYS_connect as i32),
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        );
    }

    #[test]
    #[ignore = "requires Linux seccomp user notification"]
    fn actual_notification_can_return_errno_or_continue_the_original_call() {
        use std::os::fd::AsRawFd;
        use std::time::Duration;

        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sender.send(install().unwrap()).unwrap();
            for errno in [libc::EADDRINUSE, libc::EBADF] {
                assert_eq!(unsafe { libc::connect(-1, std::ptr::null(), 0) }, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(errno));
            }
        });
        let listener = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        for continue_syscall in [false, true] {
            let mut event = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut event, 1, 5000) }, 1);
            let notification = receive(listener.as_raw_fd()).unwrap();
            assert_eq!(notification.data.nr, libc::SYS_connect as i32);
            assert_eq!(notification.data.args[0] as i32, -1);
            assert!(valid(listener.as_raw_fd(), notification.id).unwrap());
            respond(
                listener.as_raw_fd(),
                notification.id,
                0,
                if continue_syscall {
                    0
                } else {
                    libc::EADDRINUSE
                },
                continue_syscall,
            )
            .unwrap();
            assert!(!valid(listener.as_raw_fd(), notification.id).unwrap());
        }
        worker.join().unwrap();
    }
}
