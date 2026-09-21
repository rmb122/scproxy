use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

pub(super) const SOCKET_API: &str = include_str!("../fixtures/socket_api.py");
pub(super) const DNS_API: &str = include_str!("../fixtures/dns_api.py");

pub(super) fn scproxy(proxy: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_scproxy"));
    command.args(["-x", proxy]);
    command
}

pub(super) struct ManagedChild {
    pub(super) child: Child,
    pub(super) descendants: Vec<Pid>,
    output: std::sync::mpsc::Receiver<String>,
}

impl ManagedChild {
    pub(super) fn spawn(script: &str) -> Self {
        Self::spawn_with_command(scproxy("direct"), script)
    }

    pub(super) fn spawn_with_command(mut command: Command, script: &str) -> Self {
        let mut child = command
            .args(["python3", "-u", "-c", script])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            descendants: Vec::new(),
            output,
        }
    }

    pub(super) fn read_line(&self) -> String {
        self.output
            .recv_timeout(Duration::from_secs(10))
            .expect("command must report its progress")
    }

    pub(super) fn read_process_ids(&mut self) {
        let line = self.read_line();
        assert!(
            !line.is_empty(),
            "command exited before reporting its process tree"
        );
        self.descendants = line
            .split_whitespace()
            .map(|pid| Pid::from_raw(pid.parse().unwrap()))
            .collect();
    }

    pub(super) fn wait(&mut self) -> std::process::ExitStatus {
        self.wait_timeout(Duration::from_secs(10))
    }

    pub(super) fn wait_timeout(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "managed command did not terminate"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        // Clean up known fixture processes even if the regression test fails.
        for &pid in self.descendants.iter().rev() {
            let _ = kill(pid, Signal::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(super) fn accept_with_timeout(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream.set_nodelay(true).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "proxy connection did not arrive");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

pub(super) struct TestDir(pub(super) std::path::PathBuf);
impl TestDir {
    pub(super) fn new(label: &str) -> Self {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("scproxy-{label}-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
