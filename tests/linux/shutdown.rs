//! Command exit, relay draining, and cancellation of native connection setup.
use super::support::*;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn pending_handshake() -> (ManagedChild, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut command = scproxy(&format!("http://{}", listener.local_addr().unwrap()));
    command.stdin(std::process::Stdio::piped());
    let mut managed = ManagedChild::spawn_with_command(
        command,
        r#"
import os, socket, sys
print(os.getppid(), os.getpid(), flush=True)
s = socket.create_connection(('203.0.113.9', 443), timeout=3)
s.sendall(b'x' * 8192)
print('written', flush=True)
assert sys.stdin.readline().strip() == 'exit'
s.close()
"#,
    );
    managed.read_process_ids();
    assert_eq!(managed.read_line(), "written");
    let mut proxy = accept_with_timeout(listener);
    let mut reader = BufReader::new(&mut proxy);
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    assert_eq!(first, "CONNECT 203.0.113.9:443 HTTP/1.1\r\n");
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if line == "\r\n" {
            break;
        }
    }
    (managed, proxy)
}

fn exit_command(managed: &mut ManagedChild) {
    managed
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"exit\n")
        .unwrap();
    let pid = managed.descendants[1];
    let deadline = Instant::now() + Duration::from_secs(3);
    while std::path::Path::new(&format!("/proc/{pid}")).exists() {
        assert!(Instant::now() < deadline, "command did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn normal_exit_drains_payload_after_delayed_proxy_handshake() {
    let (mut managed, mut proxy) = pending_handshake();
    exit_command(&mut managed);
    // The command has exited while the upstream handshake is still pending.
    std::thread::sleep(Duration::from_millis(300));
    let _ = proxy.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
    let mut payload = Vec::new();
    if let Err(error) = proxy.read_to_end(&mut payload) {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    assert_eq!(payload.len(), 8192);
    assert!(payload.iter().all(|&byte| byte == b'x'));
    assert!(managed.wait().success());
    managed.descendants.clear();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn termination_interrupts_drain_after_command_exit() {
    let (mut managed, mut proxy) = pending_handshake();
    exit_command(&mut managed);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        managed.child.try_wait().unwrap().is_none(),
        "broker must be draining"
    );
    kill(Pid::from_raw(managed.child.id() as i32), Signal::SIGTERM).unwrap();
    assert_eq!(
        managed.wait_timeout(Duration::from_secs(4)).code(),
        Some(143)
    );
    let mut byte = [0];
    match proxy.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        result => panic!("pending upstream was not closed: {result:?}"),
    }
    managed.descendants.clear();
}

#[test]
#[ignore = "requires Linux seccomp, Python 3, and a non-loopback default route"]
fn termination_cancels_connect_on_a_non_loopback_device() {
    let routes = std::fs::read_to_string("/proc/net/route").unwrap();
    let device = routes
        .lines()
        .skip(1)
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let device = fields.next()?;
            (fields.next()? == "00000000" && device != "lo").then_some(device)
        })
        .expect("test requires a non-loopback default route");
    let mut command = scproxy("direct");
    command.env("SCPROXY_TEST_DEVICE", device);
    let mut managed = ManagedChild::spawn_with_command(
        command,
        r#"
import os, socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, os.environ['SCPROXY_TEST_DEVICE'].encode() + b'\0')
print(os.getppid(), os.getpid(), flush=True)
s.connect(('203.0.113.9', 443))
"#,
    );
    managed.read_process_ids();
    let broker = managed.child.id();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let pending = std::fs::read_dir(format!("/proc/{broker}/task"))
            .unwrap()
            .any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| std::fs::read_to_string(entry.path().join("syscall")).ok())
                    .and_then(|state| {
                        state
                            .split_whitespace()
                            .next()?
                            .parse::<libc::c_long>()
                            .ok()
                    })
                    == Some(libc::SYS_connect)
            });
        if pending {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "supervisor did not enter native connect"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    kill(Pid::from_raw(broker as i32), Signal::SIGTERM).unwrap();
    assert_eq!(
        managed.wait_timeout(Duration::from_secs(4)).code(),
        Some(143)
    );
    for pid in &managed.descendants {
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "unreaped process {pid}"
        );
    }
    managed.descendants.clear();
}
