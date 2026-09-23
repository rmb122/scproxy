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

#[repr(C)]
struct AddFd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

// Both supported architectures use the generic Linux ioctl encoding.
const fn ioctl_request(direction: u32, number: u32, size: usize) -> libc::c_ulong {
    ((direction << 30) | ((size as u32) << 16) | ((b'!' as u32) << 8) | number) as libc::c_ulong
}

const NOTIF_RECV: libc::c_ulong = ioctl_request(3, 0, size_of::<Notification>());
const NOTIF_SEND: libc::c_ulong = ioctl_request(3, 1, size_of::<Response>());
const NOTIF_ID_VALID: libc::c_ulong = ioctl_request(1, 2, size_of::<u64>());
const NOTIF_ADDFD: libc::c_ulong = ioctl_request(1, 3, size_of::<AddFd>());

pub(super) fn addfd_send(listener: RawFd, id: u64, source: RawFd, cloexec: bool) -> io::Result<()> {
    let request = AddFd {
        id,
        flags: 2,
        srcfd: source as u32,
        newfd: 0,
        newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
    };
    if unsafe { libc::ioctl(listener, NOTIF_ADDFD as _, &request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Before exec there are no pending notifications. ENOENT proves that the
/// kernel recognizes atomic ADDFD_SEND without injecting an unsolicited FD.
pub(super) fn probe_addfd(listener: RawFd, source: RawFd) -> io::Result<()> {
    match addfd_send(listener, u64::MAX, source, true) {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) => Err(error),
        Ok(()) => Err(io::Error::other(
            "unexpected notification during ADDFD probe",
        )),
    }
}

pub(super) fn is_open(call: libc::c_long) -> bool {
    #[cfg(target_arch = "x86_64")]
    if call == libc::SYS_open {
        return true;
    }
    matches!(call, libc::SYS_openat | libc::SYS_openat2)
}

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
    // Only SO_PEERNAME needs virtualization; other socket options stay native.
    filter.extend([
        jump(JEQ, libc::SYS_getsockopt as u32, 0, 6),
        statement(LOAD, (offset_of!(Data, args) + 8) as u32),
        jump(JEQ, libc::SOL_SOCKET as u32, 0, 3),
        statement(LOAD, (offset_of!(Data, args) + 16) as u32),
        jump(JEQ, libc::SO_PEERNAME as u32, 0, 1),
        statement(RET, SECCOMP_RET_USER_NOTIF),
        statement(RET, SECCOMP_RET_ALLOW),
    ]);
    // Connected UDP already has its DNS peer redirected by connect. Plain
    // send/recv need no broker work, but addresses and special flags still do.
    for (syscall, flags) in [
        (libc::SYS_sendto, libc::MSG_OOB | libc::MSG_FASTOPEN),
        (libc::SYS_recvfrom, libc::MSG_OOB),
    ] {
        filter.extend([
            jump(JEQ, syscall as u32, 0, 8),
            statement(LOAD, (offset_of!(Data, args) + 3 * 8) as u32),
            jump(JSET, flags as u32, 5, 0),
            // Test both halves of the native 64-bit address pointer.
            statement(LOAD, (offset_of!(Data, args) + 4 * 8) as u32),
            jump(JEQ, 0, 0, 3),
            statement(LOAD, (offset_of!(Data, args) + 4 * 8 + 4) as u32),
            jump(JEQ, 0, 0, 1),
            statement(RET, SECCOMP_RET_ALLOW),
            statement(RET, SECCOMP_RET_USER_NOTIF),
        ]);
    }
    for syscall in [
        #[cfg(target_arch = "x86_64")]
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_getpeername,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
    ] {
        filter.push(jump(JEQ, syscall as u32, 0, 1));
        filter.push(statement(RET, SECCOMP_RET_USER_NOTIF));
    }
    filter.push(statement(RET, SECCOMP_RET_ALLOW));
    filter
}

fn has_sys_admin() -> io::Result<bool> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_SYS_ADMIN: u32 = 21;

    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::pid_t,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Capabilities {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut header = Header {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0, // Query the calling thread, not its thread-group leader.
    };
    let mut data = [Capabilities::default(); 2];
    if unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut Header,
            data.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(data[0].effective & (1 << CAP_SYS_ADMIN) != 0)
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
    // CAP_SYS_ADMIN permits installing the filter without restricting exec
    // privilege transitions. An inherited no_new_privs flag remains set.
    if !has_sys_admin()? && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
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
        evaluate_with_args(arch, syscall, [0; 6])
    }

    fn evaluate_with_args(arch: u32, syscall: i32, args: [u64; 6]) -> u32 {
        let instructions = filter();
        let mut accumulator = 0;
        let mut pc = 0;
        loop {
            let instruction = instructions[pc];
            match u32::from(instruction.code) {
                code if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS => {
                    accumulator = if instruction.k == offset_of!(Data, arch) as u32 {
                        arch
                    } else if instruction.k == offset_of!(Data, nr) as u32 {
                        syscall as u32
                    } else {
                        let offset = instruction.k as usize - offset_of!(Data, args);
                        (args[offset / 8] >> ((offset % 8) * 8)) as u32
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
    fn address_free_io_skips_notifications_but_preserves_special_cases() {
        for syscall in [libc::SYS_sendto, libc::SYS_recvfrom] {
            for flags in [0, libc::MSG_DONTWAIT, libc::MSG_NOSIGNAL, libc::MSG_PEEK] {
                assert_eq!(
                    evaluate_with_args(
                        NATIVE_ARCH,
                        syscall as i32,
                        [3, 0x1000, 4096, flags as u64, 0, 0],
                    ),
                    SECCOMP_RET_ALLOW,
                );
            }
            for address in [1, 0x1000, 1 << 32, u64::MAX] {
                assert_eq!(
                    evaluate_with_args(NATIVE_ARCH, syscall as i32, [3, 0, 0, 0, address, 16]),
                    SECCOMP_RET_USER_NOTIF,
                );
            }
            assert_eq!(
                evaluate_with_args(
                    NATIVE_ARCH,
                    syscall as i32,
                    [3, 0, 0, (libc::MSG_OOB | libc::MSG_DONTWAIT) as u64, 0, 0],
                ),
                SECCOMP_RET_USER_NOTIF,
            );
        }
        assert_eq!(
            evaluate_with_args(
                NATIVE_ARCH,
                libc::SYS_sendto as i32,
                [3, 0, 0, libc::MSG_FASTOPEN as u64, 0, 0],
            ),
            SECCOMP_RET_USER_NOTIF,
        );
        for syscall in [
            libc::SYS_connect,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
            libc::SYS_recvmsg,
            libc::SYS_recvmmsg,
        ] {
            assert_eq!(
                evaluate(NATIVE_ARCH, syscall as i32),
                SECCOMP_RET_USER_NOTIF,
            );
        }
    }

    #[test]
    fn only_peer_name_socket_option_is_intercepted() {
        for (level, option, expected) in [
            (libc::SOL_SOCKET, libc::SO_PEERNAME, SECCOMP_RET_USER_NOTIF),
            (libc::SOL_SOCKET, libc::SO_ERROR, SECCOMP_RET_ALLOW),
            (libc::SOL_SOCKET, libc::SO_TYPE, SECCOMP_RET_ALLOW),
            (libc::IPPROTO_TCP, libc::SO_PEERNAME, SECCOMP_RET_ALLOW),
        ] {
            assert_eq!(
                evaluate_with_args(
                    NATIVE_ARCH,
                    libc::SYS_getsockopt as i32,
                    [0, level as u64, option as u64, 0, 0, 0],
                ),
                expected,
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
}
