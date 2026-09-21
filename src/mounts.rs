//! Private mount namespace and file bind mounts. Networking stays on the host.

use std::collections::HashSet;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::sched::{CloneFlags, unshare};

use crate::config::net::DNS_ADDR;

const INTERNAL_BIND_TARGETS: [&str; 2] = ["/etc/resolv.conf", "/etc/nsswitch.conf"];

/// A validated file bind mount. Both paths are absolute and preserve their
/// directly named file or symlink object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
}

/// Parse and validate repeatable `src:dst` bind-mount specifications.
///
/// Relative paths are made absolute against `cwd` without following the final
/// symlink. Both sides must name regular files or symlinks (including dangling
/// symlinks). Duplicate and internal DNS targets are rejected before fork.
pub fn parse_bind_mounts(specs: &[String], cwd: &Path) -> Result<Vec<BindMount>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }

    let internal_targets = INTERNAL_BIND_TARGETS
        .iter()
        .map(Path::new)
        .map(std::fs::symlink_metadata)
        .map(|metadata| metadata.map(|metadata| (metadata.dev(), metadata.ino())))
        .collect::<std::io::Result<HashSet<_>>>()
        .context("inspect internal bind-mount targets")?;
    let mut targets = HashSet::new();
    let mut mounts = Vec::with_capacity(specs.len());

    for spec in specs {
        let mut fields = spec.split(':');
        let source = fields.next().unwrap_or_default();
        let target = fields.next().unwrap_or_default();
        if source.is_empty() || target.is_empty() || fields.next().is_some() {
            anyhow::bail!("invalid bind mount {spec:?}: expected exactly SRC:DST");
        }

        let (source, _) = inspect_bind_path(source, cwd, "source", spec)?;
        let (target, target_id) = inspect_bind_path(target, cwd, "target", spec)?;

        if internal_targets.contains(&target_id) {
            anyhow::bail!(
                "bind mount target {:?} conflicts with an internal DNS mount",
                target
            );
        }
        if !targets.insert(target_id) {
            anyhow::bail!("duplicate bind mount target {:?}", target);
        }

        mounts.push(BindMount { source, target });
    }

    Ok(mounts)
}

fn inspect_bind_path(
    path: &str,
    cwd: &Path,
    side: &str,
    spec: &str,
) -> Result<(PathBuf, (u64, u64))> {
    let path = Path::new(path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let path = std::path::absolute(&path)
        .with_context(|| format!("make bind mount {side} {:?} absolute", path))?;
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("inspect bind mount {side} {:?} in {spec:?}", path))?;
    let file_type = metadata.file_type();
    if !file_type.is_file() && !file_type.is_symlink() {
        anyhow::bail!(
            "bind mount {side} {:?} in {spec:?} is not a regular file or symlink",
            path
        );
    }
    let identity = (metadata.dev(), metadata.ino());
    Ok((path, identity))
}

/// Enter a mount namespace, falling back to a user namespace for privileges.
pub fn create_namespace() -> Result<bool> {
    match unshare(CloneFlags::CLONE_NEWNS) {
        Ok(()) => Ok(false),
        Err(_) => {
            unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
                .context("unshare(CLONE_NEWUSER|CLONE_NEWNS)")?;
            Ok(true)
        }
    }
}

/// Write uid/gid maps for a child process from the PARENT side.
/// This avoids AppArmor restrictions on /proc/self/* writes after unshare.
pub fn write_id_maps(child_pid: u32, uid: u32, gid: u32) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    fn proc_write(path: &str, data: &str) -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open {}", path))?;
        f.write_all(data.as_bytes())
            .with_context(|| format!("write {}", path))?;
        Ok(())
    }

    let setgroups_path = format!("/proc/{}/setgroups", child_pid);
    let uid_map_path = format!("/proc/{}/uid_map", child_pid);
    let gid_map_path = format!("/proc/{}/gid_map", child_pid);

    // Deny setgroups (required before gid_map write)
    proc_write(&setgroups_path, "deny")?;

    // Write uid_map: "<uid> <uid> 1" — map real uid to itself inside namespace.
    // The initial user of a user namespace has full capabilities regardless of uid,
    // so uid 1000 still has CAP_SYS_ADMIN for mount configuration.
    // This keeps file ownership correct (home dir, ssh keys, etc.).
    proc_write(&uid_map_path, &format!("{} {} 1\n", uid, uid))?;

    // Write gid_map: "<gid> <gid> 1"
    proc_write(&gid_map_path, &format!("{} {} 1\n", gid, gid))?;

    tracing::debug!(
        "wrote id maps for pid {} (uid={}, gid={})",
        child_pid,
        uid,
        gid
    );
    Ok(())
}

// ── Mount namespace + resolv.conf ────────────────────────────────────────────

/// Create a private mount namespace and bind-mount custom `resolv.conf` and
/// `nsswitch.conf` to force DNS through our fake resolver.
pub fn setup_mount_namespace(bind_mounts: &[BindMount]) -> Result<()> {
    // Make the mount namespace fully private (no propagation to/from host)
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("make root mount private")?;

    // Create temp files with random names, bind-mount them, then unlink.
    // The mount keeps the inode alive even after unlink (no leftover files).
    let resolv_conf = format!("nameserver {}\n", DNS_ADDR);
    bind_mount_tmpfile(&resolv_conf, "/etc/resolv.conf").context("bind-mount resolv.conf")?;

    bind_mount_tmpfile("hosts: files dns\n", "/etc/nsswitch.conf")
        .context("bind-mount nsswitch.conf")?;

    for bind in bind_mounts {
        bind_mount_nofollow(bind)?;
        tracing::debug!(source = ?bind.source, target = ?bind.target, "file bind-mounted");
    }

    // WORKAROUND: ssh complains about "Bad owner or permissions" on config files
    // because inside the user namespace, file owners map to nobody (65534).
    // Mount a tmpfs over ssh_config.d to hide the problematic files.
    let _ = nix::mount::mount(
        Some("tmpfs"),
        "/etc/ssh/ssh_config.d",
        Some("tmpfs"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    );

    tracing::debug!("mount namespace set up; DNS → {}", DNS_ADDR);
    Ok(())
}

/// Bind-mount the directly named source object over the directly named target
/// object. The new mount API lets both pathname lookups stop at a final
/// symlink instead of following it as the classic `mount(2)` API does.
fn bind_mount_nofollow(bind: &BindMount) -> Result<()> {
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;

    let source = CString::new(bind.source.as_os_str().as_bytes())
        .with_context(|| format!("bind mount source {:?} contains a NUL byte", bind.source))?;
    let target = CString::new(bind.target.as_os_str().as_bytes())
        .with_context(|| format!("bind mount target {:?} contains a NUL byte", bind.target))?;

    let open_tree_flags =
        libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_SYMLINK_NOFOLLOW as libc::c_uint;
    // SAFETY: `source` is a valid NUL-terminated pathname. On success the
    // returned fd is uniquely owned and immediately wrapped in `OwnedFd`.
    let mount_fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            source.as_ptr(),
            open_tree_flags,
        )
    };
    if mount_fd == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            anyhow::bail!(
                "file bind mounts require Linux 5.2 or newer: open_tree is unavailable ({error})"
            );
        }
        return Err(error)
            .with_context(|| format!("open bind-mount source object {:?}", bind.source));
    }
    // SAFETY: a successful `open_tree` returns a new owned file descriptor.
    let mount_fd = unsafe { OwnedFd::from_raw_fd(mount_fd as RawFd) };

    // Do not pass MOVE_MOUNT_T_SYMLINKS: the target lookup must stop at the
    // directly named symlink object. The empty source path addresses the
    // detached mount object through `mount_fd`.
    // SAFETY: both path pointers are NUL-terminated and `mount_fd` is valid.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount_fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if moved == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            anyhow::bail!(
                "file bind mounts require Linux 5.2 or newer: move_mount is unavailable ({error})"
            );
        }
        return Err(error).with_context(|| {
            format!(
                "attach bind-mount source {:?} over target {:?}",
                bind.source, bind.target
            )
        });
    }

    Ok(())
}

/// RAII guard that unlinks a path when dropped. Used to ensure temp files are
/// cleaned up on every early-return path, whether or not the bind-mount
/// succeeded. (After a successful bind-mount, unlinking the source path is
/// harmless — the kernel keeps the inode alive via the mount reference.)
struct UnlinkOnDrop(std::path::PathBuf);

impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        let _ = nix::unistd::unlink(&self.0);
    }
}

/// Create a temporary file with random name, write `content`, bind-mount over
/// `target`, then unlink the temp file (mount keeps inode alive).
fn bind_mount_tmpfile(content: &str, target: &str) -> Result<()> {
    use std::io::Write;

    // An outer launcher may already have mounted and unlinked its DNS files.
    // Linux refuses to mount over those disconnected dentries (ENOENT). Reuse
    // an identical readable private inode after making our mount tree private.
    if let Ok(metadata) = std::fs::metadata(target)
        && metadata.nlink() == 0
        && metadata.permissions().mode() & 0o444 == 0o444
        && std::fs::read_to_string(target).is_ok_and(|current| current == content)
    {
        return Ok(());
    }

    // nix::unistd::mkstemp creates a temp file and returns (OwnedFd, PathBuf)
    let (fd, path) = nix::unistd::mkstemp("/tmp/scproxy-XXXXXX").context("mkstemp")?;

    // Guard ensures the on-disk path is unlinked on every exit path (success,
    // write error, mount error, utf-8 error, ...). After bind_mount, the
    // inode survives because the mount itself references it.
    let _guard = UnlinkOnDrop(path.clone());

    let mut file = std::fs::File::from(fd);
    file.write_all(content.as_bytes())
        .with_context(|| format!("write {:?}", path))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o644))
        .context("make internal DNS configuration readable by all users")?;
    drop(file);

    // Bind-mount
    let path_str = path.to_str().context("temp path not utf8")?;
    nix::mount::mount(
        Some(path_str),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("bind-mount {:?} → {}", path, target))?;

    Ok(())
}

#[cfg(test)]
mod bind_mount_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "scproxy-bind-test-{}-{nanos}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, name).unwrap();
            path
        }

        fn symlink(&self, target: &str, name: &str) -> PathBuf {
            let path = self.0.join(name);
            symlink(target, &path).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_absolute_and_relative_file_paths() {
        let temp = TempDir::new();
        let source = temp.file("source");
        let target = temp.file("target");
        let absolute = format!("{}:{}", source.display(), target.display());

        let absolute_mounts = parse_bind_mounts(&[absolute], &temp.0).unwrap();
        let relative_mounts = parse_bind_mounts(&["source:target".to_owned()], &temp.0).unwrap();

        assert_eq!(absolute_mounts, relative_mounts);
        assert!(absolute_mounts[0].source.is_absolute());
        assert!(absolute_mounts[0].target.is_absolute());
    }

    #[test]
    fn rejects_invalid_bind_syntax() {
        let cwd = std::env::current_dir().unwrap();
        for spec in ["source", ":target", "source:", "a:b:c"] {
            assert!(parse_bind_mounts(&[spec.to_owned()], &cwd).is_err());
        }
    }

    #[test]
    fn rejects_missing_paths_and_directories() {
        let temp = TempDir::new();
        let source = temp.file("source");
        let target = temp.file("target");

        assert!(parse_bind_mounts(&["missing:target".to_owned()], &temp.0).is_err());
        assert!(parse_bind_mounts(&["source:missing".to_owned()], &temp.0).is_err());
        assert!(
            parse_bind_mounts(
                &[format!("{}:{}", temp.0.display(), target.display())],
                &temp.0
            )
            .is_err()
        );
        assert!(
            parse_bind_mounts(
                &[format!("{}:{}", source.display(), temp.0.display())],
                &temp.0
            )
            .is_err()
        );
    }

    #[test]
    fn preserves_valid_and_dangling_symlink_objects() {
        let temp = TempDir::new();
        temp.file("final-source");
        temp.symlink("final-source", "second-link");
        let source = temp.symlink("second-link", "source-link");
        let target = temp.symlink("missing-target", "target-link");

        let mounts = parse_bind_mounts(&["source-link:target-link".to_owned()], &temp.0).unwrap();

        assert_eq!(mounts[0].source, source);
        assert_eq!(mounts[0].target, target);
        assert_eq!(
            fs::read_link(&mounts[0].source).unwrap(),
            Path::new("second-link")
        );
        assert!(
            fs::symlink_metadata(&mounts[0].target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn preserves_symlink_components_in_parent_path() {
        let temp = TempDir::new();
        let real_parent = temp.0.join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        fs::write(real_parent.join("source"), "source").unwrap();
        fs::write(real_parent.join("target"), "target").unwrap();
        temp.symlink("real-parent", "parent-link");

        let mounts = parse_bind_mounts(
            &["parent-link/source:parent-link/target".to_owned()],
            &temp.0,
        )
        .unwrap();

        assert_eq!(mounts[0].source, temp.0.join("parent-link/source"));
        assert_eq!(mounts[0].target, temp.0.join("parent-link/target"));
    }

    #[test]
    fn rejects_duplicate_and_internal_targets() {
        let temp = TempDir::new();
        temp.file("source-one");
        temp.file("source-two");
        temp.file("target");
        let duplicates = vec![
            "source-one:target".to_owned(),
            "source-two:./target".to_owned(),
        ];

        assert!(parse_bind_mounts(&duplicates, &temp.0).is_err());

        let internal = "source-one:/etc/resolv.conf".to_owned();
        assert!(parse_bind_mounts(&[internal], &temp.0).is_err());
    }
}
