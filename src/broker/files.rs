//! Read-only resolver configuration supplied through atomic seccomp FD injection.
use super::{
    engine::{Broker, Reply},
    memory,
    seccomp::{self, Notification},
};
use crate::config::net::DNS_ADDR;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;

struct ConfigFile {
    path: PathBuf,
    canonical: Option<PathBuf>,
    file: File,
}

pub(super) struct ResolverFiles {
    files: [ConfigFile; 2],
}

fn resolv_conf() -> String {
    format!("nameserver {DNS_ADDR}\n")
}

fn nsswitch_conf(original: &str) -> String {
    let mut lines: Vec<&str> = original
        .lines()
        .filter(|line| {
            !line
                .split_once(':')
                .is_some_and(|(name, _)| name.trim() == "hosts")
        })
        .collect();
    lines.push("hosts: files dns");
    lines.join("\n") + "\n"
}

impl ConfigFile {
    fn new(path: &str, contents: &str) -> io::Result<Self> {
        let raw = unsafe {
            libc::memfd_create(
                c"scproxy-resolver".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(contents.as_bytes())?;
        super::sockets::check(unsafe { libc::fchmod(raw, 0o444) })?;
        super::sockets::check(unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, SEALS) })?;
        Ok(Self {
            path: path.into(),
            canonical: std::fs::canonicalize(path).ok(),
            file,
        })
    }

    fn reopen(&self, flags: i32) -> io::Result<File> {
        // Each open needs a new open-file description, not a dup sharing its
        // offset with every other resolver reader in the command tree.
        let path =
            std::ffi::CString::new(format!("/proc/self/fd/{}", self.file.as_raw_fd())).unwrap();
        let flags = (flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW)) | libc::O_CLOEXEC;
        let raw = unsafe { libc::open(path.as_ptr(), flags) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

impl ResolverFiles {
    pub fn new() -> io::Result<Self> {
        let nss = nsswitch_conf(&std::fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default());
        Ok(Self {
            files: [
                ConfigFile::new("/etc/resolv.conf", &resolv_conf())?,
                ConfigFile::new("/etc/nsswitch.conf", &nss)?,
            ],
        })
    }

    pub fn open(&self, broker: &Broker, request: &Notification) -> io::Result<Reply> {
        let args = request.data.args;
        let call = request.data.nr as libc::c_long;
        let (dirfd, path_arg, flags_arg) = if call == libc::SYS_openat || call == libc::SYS_openat2
        {
            (args[0] as i32, args[1], args[2])
        } else {
            (libc::AT_FDCWD, args[0], args[1])
        };
        let path = memory::path(request.pid, path_arg)?;
        // Ordinary file opens avoid filesystem lookups. The standard paths,
        // relative spellings, and their resolved symlink targets are handled.
        if !self.files.iter().any(|file| {
            path.file_name() == file.path.file_name()
                || file
                    .canonical
                    .as_ref()
                    .is_some_and(|alias| path.file_name() == alias.file_name())
        }) {
            return Ok(Reply::Continue);
        }
        let path = absolute_path(broker, request.pid, dirfd, &path)?;
        let canonical = std::fs::canonicalize(&path).ok();
        let Some(file) = self.files.iter().find(|file| {
            file.path == path
                || file
                    .canonical
                    .as_ref()
                    .is_some_and(|alias| alias == &path || Some(alias) == canonical.as_ref())
        }) else {
            return Ok(Reply::Continue);
        };
        let flags = if call == libc::SYS_openat2 {
            open_how(request.pid, flags_arg, args[3])?
        } else {
            flags_arg as i32
        };
        let spelling = path.as_os_str().as_bytes();
        if spelling.ends_with(b"/") || spelling.ends_with(b"/.") {
            return Err(memory::error(libc::ENOTDIR));
        }
        if flags & libc::O_DIRECTORY != 0 {
            return Err(memory::error(libc::ENOTDIR));
        }
        if flags & libc::O_PATH == 0 {
            if flags & (libc::O_CREAT | libc::O_EXCL) == libc::O_CREAT | libc::O_EXCL {
                return Err(memory::error(libc::EEXIST));
            }
            if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_TRUNC != 0 {
                return Err(memory::error(libc::EACCES));
            }
        }
        if flags & libc::O_NOFOLLOW != 0
            && std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_symlink())
        {
            return if flags & libc::O_PATH != 0 {
                Ok(Reply::Continue)
            } else {
                Err(memory::error(libc::ELOOP))
            };
        }
        let descriptor = file.reopen(flags)?;
        broker.valid(request)?;
        seccomp::addfd_send(
            broker.listener.as_raw_fd(),
            request.id,
            descriptor.as_raw_fd(),
            flags & libc::O_CLOEXEC != 0,
        )?;
        Ok(Reply::Sent)
    }

    pub fn check_unix_connect(&self, request: &Notification) -> io::Result<()> {
        let args = request.data.args;
        if memory::family(request.pid, args[1], args[2])? != libc::AF_UNIX as u16 {
            return Ok(());
        }
        if args[2] > std::mem::size_of::<libc::sockaddr_un>() as u64 {
            return Err(memory::error(libc::EINVAL));
        }
        let bytes = memory::read(request.pid, args[1] + 2, args[2] as usize - 2)?;
        if bytes.first().is_none_or(|&byte| byte == 0) {
            return Ok(());
        }
        let end = bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(bytes.len());
        let path = Path::new(std::ffi::OsStr::from_bytes(&bytes[..end]));
        if resolver_socket(path) {
            return Err(memory::error(libc::ECONNREFUSED));
        }
        Ok(())
    }
}

fn absolute_path(broker: &Broker, tid: u32, dirfd: i32, path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    let base = if dirfd == libc::AT_FDCWD {
        std::fs::read_link(format!("/proc/{tid}/cwd"))?
    } else {
        let directory = broker.access.get(tid, dirfd)?;
        std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))?
    };
    Ok(base.join(path))
}

fn open_how(tid: u32, address: u64, size: u64) -> io::Result<i32> {
    if size < 24 {
        return Err(memory::error(libc::EINVAL));
    }
    if size > 4096 {
        return Err(memory::error(libc::E2BIG));
    }
    let bytes = memory::read(tid, address, size as usize)?;
    if bytes[24..].iter().any(|&byte| byte != 0) {
        return Err(memory::error(libc::E2BIG));
    }
    let flags = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let mode = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    let resolve = u64::from_ne_bytes(bytes[16..24].try_into().unwrap());
    if flags > i32::MAX as u64
        || mode & !0o7777 != 0
        || (mode != 0 && flags & libc::O_CREAT as u64 == 0)
    {
        return Err(memory::error(libc::EINVAL));
    }
    // Path resolution constraints cannot be applied to a substituted inode.
    // Reject them explicitly instead of silently ignoring openat2 restrictions.
    if resolve != 0 {
        return Err(memory::error(libc::EOPNOTSUPP));
    }
    Ok(flags as i32)
}

fn resolver_socket(path: &Path) -> bool {
    matches!(
        path.as_os_str().as_bytes(),
        b"/run/nscd/socket"
            | b"/var/run/nscd/socket"
            | b"/run/systemd/resolve/io.systemd.Resolve"
            | b"/var/run/systemd/resolve/io.systemd.Resolve"
    )
}

pub(super) fn verify_bootstrap() -> io::Result<()> {
    let mut file = File::open("/etc/resolv.conf")?;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } != SEALS {
        return Err(io::Error::other(
            "resolver configuration was not injected as a sealed memfd",
        ));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    if contents != resolv_conf() {
        return Err(io::Error::other("invalid injected resolver configuration"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nss_override_preserves_other_databases() {
        let result = nsswitch_conf(
            "passwd: files systemd\n hosts : resolve [!UNAVAIL=return] dns\ngroup: files\n",
        );
        assert_eq!(
            result,
            "passwd: files systemd\ngroup: files\nhosts: files dns\n"
        );
    }
}
