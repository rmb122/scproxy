//! Command-tree cleanup, signal deadlines, relay draining, and cancellation.
use super::support::*;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn sigterm_terminates_and_reaps_the_entire_managed_tree() {
    let mut managed = ManagedChild::spawn(
        r#"
import os, signal, subprocess, sys, time
regular = subprocess.Popen(['sleep', '60'])
detached = subprocess.Popen(
    [sys.executable, '-u', '-c',
     'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print("ready"); time.sleep(60)'],
    start_new_session=True, stdout=subprocess.PIPE)
assert detached.stdout.readline() == b'ready\n'
print(os.getppid(), os.getpid(), regular.pid, detached.pid, flush=True)
time.sleep(60)
"#,
    );
    managed.read_process_ids();
    assert_eq!(managed.descendants.len(), 4);
    kill(Pid::from_raw(managed.child.id() as i32), Signal::SIGTERM).unwrap();
    assert_eq!(managed.wait().code(), Some(143));
    for pid in &managed.descendants {
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "managed process {pid} was not reaped"
        );
    }
    managed.descendants.clear();
}

fn signal_recording_command() -> ManagedChild {
    let mut managed = ManagedChild::spawn(
        r#"
import os, signal
def handle(signum, frame):
    name = signal.Signals(signum).name
    print(name, flush=True)
signal.signal(signal.SIGTERM, handle)
signal.signal(signal.SIGINT, handle)
print(os.getppid(), os.getpid(), flush=True)
while True:
    signal.pause()
"#,
    );
    managed.read_process_ids();
    managed
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn later_termination_signals_preserve_the_first_grace_deadline() {
    let mut managed = signal_recording_command();
    let parent = Pid::from_raw(managed.child.id() as i32);
    kill(parent, Signal::SIGTERM).unwrap();
    assert_eq!(managed.read_line(), "SIGTERM");
    std::thread::sleep(Duration::from_millis(1500));
    let second_signal = Instant::now();
    kill(parent, Signal::SIGINT).unwrap();
    assert_eq!(managed.read_line(), "SIGINT");
    assert_eq!(managed.wait().code(), Some(137));
    assert!(
        second_signal.elapsed() < Duration::from_millis(1500),
        "later signals must not restart the two-second grace period"
    );
    managed.descendants.clear();
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn normal_command_exit_still_waits_for_descendants() {
    let output = scproxy("direct").args(["python3", "-c", r#"
import subprocess, sys
subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.1); print("descendant finished")'])
sys.exit(7)
"#]).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"descendant finished\n");
}

#[test]
#[ignore = "requires Linux seccomp and Python 3"]
fn killed_broker_does_not_leave_a_command_tree_running() {
    let mut managed = ManagedChild::spawn(
        r#"
import os,signal,subprocess,sys,time
child=subprocess.Popen([sys.executable,'-u','-c','import time; print("ready", flush=True); time.sleep(60)'],stdout=subprocess.PIPE)
assert child.stdout.readline()==b'ready\n'
signal.signal(signal.SIGTERM,signal.SIG_IGN)
print(os.getppid(),os.getpid(),child.pid,flush=True)
time.sleep(60)
"#,
    );
    managed.read_process_ids();
    kill(Pid::from_raw(managed.child.id() as i32), Signal::SIGKILL).unwrap();
    managed.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let live = managed.descendants.iter().any(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .is_ok_and(|stat| stat.rsplit_once(") ").unwrap().1.as_bytes()[0] != b'Z')
        });
        if !live {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "broker death left a descendant running"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    managed.descendants.clear();
}

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
    let mut command = scproxy("http://127.0.0.1:1");
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
