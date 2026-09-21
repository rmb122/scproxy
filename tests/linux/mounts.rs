use super::support::*;
use std::os::unix::fs::symlink;

#[test]
#[ignore = "requires Linux user/mount namespaces and seccomp"]
fn file_and_symlink_bind_mounts_preserve_contents_and_write_through() {
    let temp = TestDir::new("bind");
    std::fs::write(temp.0.join("source"), "source").unwrap();
    std::fs::write(temp.0.join("target"), "target").unwrap();
    symlink("source", temp.0.join("source-link")).unwrap();
    symlink("missing", temp.0.join("target-link")).unwrap();
    let output=scproxy("direct").current_dir(&temp.0).args(["-b","source:target","-b","source-link:target-link","sh","-c",r#"
test "$(cat target)" = source && test "$(readlink target-link)" = source && test "$(cat target-link)" = source && printf updated > target
"#]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(temp.0.join("source")).unwrap(), b"updated");
    assert_eq!(std::fs::read(temp.0.join("target")).unwrap(), b"target");
    assert_eq!(
        std::fs::read_link(temp.0.join("target-link")).unwrap(),
        std::path::Path::new("missing")
    );
}

#[test]
#[ignore = "requires Linux user/mount namespaces and seccomp"]
fn identical_inherited_unlinked_dns_mounts_are_reused() {
    let output=std::process::Command::new("unshare").args(["-Urm","sh","-ec",r#"
mount -t tmpfs tmpfs /etc
touch /etc/resolv.conf /etc/nsswitch.conf
for file in resolv.conf nsswitch.conf; do
    source=$(mktemp)
    if [ "$file" = resolv.conf ]; then printf 'nameserver 172.23.255.254\n' > "$source"; else printf 'hosts: files dns\n' > "$source"; fi
    chmod 644 "$source"
    mount --bind "$source" "/etc/$file"
    rm "$source"
done
exec "$@"
"#,"scproxy-test",env!("CARGO_BIN_EXE_scproxy"),"-x","direct","cat","/etc/resolv.conf","/etc/nsswitch.conf"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"nameserver 172.23.255.254\nhosts: files dns\n"
    );
}
