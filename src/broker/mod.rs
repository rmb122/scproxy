//! Seccomp notification supervision. All application sockets retain their identity.
mod access;
mod connect;
mod datagram;
mod diagnostics;
mod dns;
mod engine;
mod files;
mod memory;
mod message;
mod receiver;
mod relay;
mod seccomp;
mod sockets;
mod tcp;
mod tcp_ingress;

use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Shutdown {
    Running,
    Drain,
    Abort,
}

pub(crate) struct ChildSetup {
    control: File,
    life: UnixStream,
}
impl ChildSetup {
    pub(crate) fn new(control: File, life: UnixStream) -> Self {
        Self { control, life }
    }

    pub(crate) fn command(mut self) -> Result<()> {
        drop(self.life);
        let probe = sockets::stream()?;
        let mut memory = [0x6eu8];
        let listener = seccomp::install().context("install seccomp filter")?;
        let mut metadata = [0u8; 20];
        metadata[0..4]
            .copy_from_slice(&(unsafe { libc::syscall(libc::SYS_gettid) } as u32).to_ne_bytes());
        metadata[4..8].copy_from_slice(&listener.as_raw_fd().to_ne_bytes());
        metadata[8..12].copy_from_slice(&probe.as_raw_fd().to_ne_bytes());
        metadata[12..20].copy_from_slice(&(memory.as_mut_ptr() as u64).to_ne_bytes());
        // File uses write(2), unlike UnixStream's send(2). No filter exemption
        // or application-visible bootstrap FD is needed.
        self.control.write_all(&metadata)?;
        let mut ready = [0];
        self.control.read_exact(&mut ready)?;
        if ready != [1] || memory != [0x6e] {
            bail!("seccomp startup handshake failed");
        }
        files::verify_bootstrap().context("verify seccomp DNS configuration injection")?;
        Ok(())
    }

    pub(crate) fn reaper(self) -> Result<()> {
        drop(self.control);
        let mut life = self.life;
        std::thread::Builder::new()
            .name("broker-lifetime".into())
            .spawn(move || {
                let mut byte = [0];
                loop {
                    match life.read(&mut byte) {
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        _ => break,
                    }
                }
                let _ = crate::process::forward_signal(
                    nix::unistd::getpid(),
                    nix::sys::signal::Signal::SIGTERM,
                );
            })?;
        Ok(())
    }
}

pub(crate) struct Service {
    task: Option<JoinHandle<std::io::Result<()>>>,
    shutdown: watch::Sender<Shutdown>,
    receiver: Option<receiver::Receiver>,
}
impl Service {
    pub(crate) fn start(control: &mut File, config: crate::config::Config) -> Result<Self> {
        let mut metadata = [0u8; 20];
        control
            .read_exact(&mut metadata)
            .context("receive seccomp listener metadata")?;
        let tid = u32::from_ne_bytes(metadata[..4].try_into().unwrap());
        let listener_fd = i32::from_ne_bytes(metadata[4..8].try_into().unwrap());
        let probe_fd = i32::from_ne_bytes(metadata[8..12].try_into().unwrap());
        let address = u64::from_ne_bytes(metadata[12..].try_into().unwrap());
        let access = access::SocketAccess::probe().context("probe pidfd capabilities")?;
        let listener = Arc::new(
            access
                .get(tid, listener_fd)
                .context("get seccomp listener with pidfd_getfd")?,
        );
        let probe = access.get(tid, probe_fd).context("access command socket")?;
        if !sockets::is_tcp_v4(probe.as_raw_fd())? {
            bail!("socket access probe failed");
        }
        seccomp::probe_addfd(listener.as_raw_fd(), probe.as_raw_fd())
            .context("probe seccomp ADDFD_SEND (requires Linux 5.14 or newer)")?;
        let mut memory = [0];
        access::read_exact(tid, address, &mut memory).context("read command memory")?;
        access::write_exact(tid, address, &memory).context("write command memory")?;
        if memory != [0x6e] {
            bail!("memory access probe failed");
        }
        diagnostics::snapshot().context("probe socket diagnostics")?;
        let (receiver, notifications) = receiver::Receiver::start(listener.clone())?;
        let (shutdown, shutdown_rx) = watch::channel(Shutdown::Running);
        let broker = engine::Broker::new(listener, access, config)?;
        let task = tokio::spawn(broker.run(notifications, shutdown_rx));
        let service = Self {
            task: Some(task),
            shutdown,
            receiver: Some(receiver),
        };
        control.write_all(&[1])?;
        Ok(service)
    }
    pub(crate) async fn wait(&mut self) -> std::io::Result<()> {
        let Some(task) = self.task.as_mut() else {
            return std::future::pending().await;
        };
        let result = task.await;
        self.task.take();
        result.map_err(std::io::Error::other)?
    }
    pub(crate) async fn stop(&mut self) {
        self.begin_shutdown(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.receiver.take();
    }

    pub(crate) fn is_running(&self) -> bool {
        self.task.is_some()
    }

    pub(crate) fn begin_shutdown(&self, force: bool) {
        self.shutdown.send_if_modified(|state| {
            if *state == Shutdown::Abort {
                return false;
            }
            *state = if force {
                Shutdown::Abort
            } else {
                Shutdown::Drain
            };
            true
        });
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.shutdown.send(Shutdown::Abort);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
