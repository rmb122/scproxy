use super::support::*;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires Linux user/mount namespaces and seccomp, and Python 3"]
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

fn signal_recording_command(exit_on_interrupt: bool) -> ManagedChild {
    let mut command = scproxy("direct");
    command.env(
        "SCPROXY_TEST_EXIT_ON_INTERRUPT",
        if exit_on_interrupt { "1" } else { "0" },
    );
    let mut managed = ManagedChild::spawn_with_command(
        command,
        r#"
import os, signal, sys
received = []
def handle(signum, frame):
    name = signal.Signals(signum).name
    received.append(name)
    print(name, flush=True)
    if signum == signal.SIGINT and os.environ['SCPROXY_TEST_EXIT_ON_INTERRUPT'] == '1':
        sys.exit(0 if received == ['SIGTERM', 'SIGINT'] else 1)
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
#[ignore = "requires Linux user/mount namespaces and seccomp, and Python 3"]
fn sigint_after_sigterm_reaches_the_command_as_sigint() {
    let mut managed = signal_recording_command(true);
    let parent = Pid::from_raw(managed.child.id() as i32);
    kill(parent, Signal::SIGTERM).unwrap();
    assert_eq!(managed.read_line(), "SIGTERM");
    kill(parent, Signal::SIGINT).unwrap();
    assert_eq!(managed.read_line(), "SIGINT");
    assert!(managed.wait().success());
    managed.descendants.clear();
}

#[test]
#[ignore = "requires Linux user/mount namespaces and seccomp, and Python 3"]
fn later_termination_signals_preserve_the_first_grace_deadline() {
    let mut managed = signal_recording_command(false);
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
#[ignore = "requires Linux user/mount namespaces and seccomp, and Python 3"]
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
#[ignore = "requires Linux seccomp, user/mount namespaces, and Python 3"]
fn killed_broker_does_not_leave_a_command_tree_running() {
    let mut managed = ManagedChild::spawn(
        r#"
import os,signal,subprocess,time
child=subprocess.Popen(['sleep','60'])
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
