mod broker;
mod config;
mod fake_dns;
mod mounts;
mod process;
mod proxy;
mod rule;

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, bail};
use clap::Parser;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use tokio::signal::unix::{SignalKind, signal};

use config::Config;
use proxy::ProxyConfig;
use rule::RuleMatcher;

/// Run a command with transparent IPv4 TCP proxying through seccomp.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Default route: direct, socks5://[user:pass@]host:port, or http://[user:pass@]host:port
    #[arg(short = 'x', long = "proxy")]
    proxy: String,
    /// Routing rule: ip:<ip>=<route>, cidr:<net>/<prefix>=<route>, domain:<host>=<route>, domain-regex:<regex>=<route>
    #[arg(short = 'r', long = "rule", value_name = "RULE")]
    rules: Vec<String>,
    /// Bind-mount a file or symlink in the command's private mount namespace
    #[arg(short = 'b', long = "bind", value_name = "SRC:DST")]
    binds: Vec<String>,
    /// Enable debug output; repeat for trace output
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("scproxy: {error:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    if cli.verbose > 0 {
        tracing_subscriber::fmt()
            .with_max_level(if cli.verbose == 1 {
                tracing::Level::DEBUG
            } else {
                tracing::Level::TRACE
            })
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
    }
    let config = Config {
        default_proxy: ProxyConfig::parse(&cli.proxy).context("parse --proxy")?,
        rules: RuleMatcher::from_specs(&cli.rules).context("parse --rule")?,
        bind_mounts: mounts::parse_bind_mounts(&cli.binds, &std::env::current_dir()?)
            .context("parse --bind")?,
        command: cli.command,
    };
    let (parent_control, child_control) = UnixStream::pair()?;
    let (parent_life, child_life) = UnixStream::pair()?;
    // No threads or runtime exist before fork.
    match unsafe { fork() }.context("fork reaper")? {
        ForkResult::Child => {
            drop(parent_control);
            drop(parent_life);
            let mut control = File::from(std::os::fd::OwnedFd::from(child_control));
            let needs_maps = mounts::create_namespace()?;
            control.write_all(&[u8::from(needs_maps)])?;
            if needs_maps {
                expect_ready(&mut control)?;
            }
            mounts::setup_mount_namespace(&config.bind_mounts)?;
            process::run_command_tree(
                &config.command,
                broker::ChildSetup::new(control, child_life),
            )
        }
        ForkResult::Parent { child } => {
            drop(child_control);
            drop(child_life);
            let result = supervise(
                File::from(std::os::fd::OwnedFd::from(parent_control)),
                parent_life,
                child,
                config,
            );
            if result.is_err() {
                let _ = process::forward_signal(child, Signal::SIGTERM);
                let _ = wait_child(child);
            }
            result
        }
    }
}

fn expect_ready(control: &mut File) -> Result<()> {
    let mut byte = [0];
    control
        .read_exact(&mut byte)
        .context("setup channel closed before acknowledgement")?;
    if byte != [1] {
        bail!("invalid setup acknowledgement");
    }
    Ok(())
}

fn wait_child(child: Pid) -> Result<i32> {
    loop {
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, signal, _)) => return Ok(128 + signal as i32),
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn supervise(mut control: File, _life: UnixStream, child: Pid, config: Config) -> Result<i32> {
    let mut maps = [0];
    control
        .read_exact(&mut maps)
        .context("receive namespace setup")?;
    match maps[0] {
        0 => {}
        1 => {
            mounts::write_id_maps(
                child.as_raw() as u32,
                nix::unistd::getuid().as_raw(),
                nix::unistd::getgid().as_raw(),
            )?;
            control.write_all(&[1])?;
        }
        _ => bail!("invalid namespace setup message"),
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (mut term, mut int, mut hup, mut service) = {
        let _guard = runtime.enter();
        let term = signal(SignalKind::terminate())?;
        let int = signal(SignalKind::interrupt())?;
        let hup = signal(SignalKind::hangup())?;
        let service =
            broker::Service::start(&mut control, config).context("start seccomp broker")?;
        (term, int, hup, service)
    };
    drop(control);
    runtime.block_on(async move {
        let mut wait = tokio::task::spawn_blocking(move || wait_child(child));
        let mut failed = false;
        let mut terminating = false;
        let status = loop {
            let received = tokio::select! {
                result = &mut wait => break result??,
                _ = term.recv() => Signal::SIGTERM,
                _ = int.recv() => Signal::SIGINT,
                _ = hup.recv() => Signal::SIGHUP,
                result = service.wait() => {
                    if let Err(error) = result {
                        eprintln!("scproxy: broker failed: {error}");
                        failed = true;
                        Signal::SIGTERM
                    } else { continue; }
                }
            };
            terminating = true;
            process::forward_signal(child, received)?;
        };
        service.begin_shutdown(terminating || failed);
        let mut interrupted = None;
        while service.is_running() {
            let received = tokio::select! {
                result = service.wait() => {
                    if let Err(error) = result {
                        eprintln!("scproxy: broker failed: {error}");
                        failed = true;
                    }
                    continue;
                },
                _ = term.recv() => Signal::SIGTERM,
                _ = int.recv() => Signal::SIGINT,
                _ = hup.recv() => Signal::SIGHUP,
            };
            // The command tree is reaped. Cancel draining without signalling a
            // PID that could now belong to an unrelated process.
            interrupted.get_or_insert(128 + received as i32);
            service.begin_shutdown(true);
        }
        service.stop().await;
        Ok(if failed {
            1
        } else {
            interrupted.unwrap_or(status)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn options_stop_at_command_and_removed_flag_is_rejected() {
        let cli = Cli::try_parse_from([
            "scproxy",
            "-x",
            "direct",
            "-b",
            "a:b",
            "-b",
            "c:d",
            "command",
            "--host-forward",
            "-v",
        ])
        .unwrap();
        assert_eq!(cli.binds, ["a:b", "c:d"]);
        assert_eq!(cli.command, ["command", "--host-forward", "-v"]);
        assert!(
            Cli::try_parse_from(["scproxy", "-x", "direct", "--host-forward", "true"]).is_err()
        );
    }
}
