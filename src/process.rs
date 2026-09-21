//! Run and reap the managed command tree, including termination propagation.

use std::collections::HashSet;
use std::ffi::CString;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::sys::signal::{SigSet, SigmaskHow, Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execvp, fork, getpid};

const TERMINATION_GRACE: Duration = Duration::from_secs(2);

pub fn run_command_tree(command: &[String], setup: crate::broker::ChildSetup) -> Result<i32> {
    set_child_subreaper().context("set child subreaper")?;

    // Block before fork so termination and child-exit signals cannot be lost
    // between checking child status and waiting for the next signal.
    let mut signals = SigSet::empty();
    for signal in [
        Signal::SIGCHLD,
        Signal::SIGTERM,
        Signal::SIGINT,
        Signal::SIGHUP,
    ] {
        signals.add(signal);
    }
    let previous_mask = signals.thread_swap_mask(SigmaskHow::SIG_BLOCK)?;

    // SAFETY: the reaper is still single-threaded.
    let command_pid = match unsafe { fork() }.context("fork command")? {
        ForkResult::Child => {
            previous_mask.thread_set_mask()?;
            setup.command()?;
            if let Err(error) = exec_command(command) {
                eprintln!("scproxy: {error:#}");
                std::process::exit(1);
            }
            unreachable!()
        }
        ForkResult::Parent { child } => {
            setup.reaper()?;
            child
        }
    };

    wait_for_command_tree(command_pid, &signals)
}

/// Replace the current process with the requested command.
fn exec_command(command: &[String]) -> Result<()> {
    if command.is_empty() {
        bail!("no command specified");
    }

    let prog = CString::new(command[0].as_str()).context("CString prog")?;
    let args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()).context("CString arg"))
        .collect::<Result<_>>()?;

    execvp(&prog, &args)
        .context("execvp")
        .map(|never| match never {})
}

fn set_child_subreaper() -> Result<()> {
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_CHILD_SUBREAPER,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };

    if rc == -1 {
        return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_CHILD_SUBREAPER)");
    }

    Ok(())
}

fn wait_for_command_tree(command_pid: Pid, signals: &SigSet) -> Result<i32> {
    let mut command_exit_code = None;
    let mut termination: Option<(Signal, Instant)> = None;

    loop {
        loop {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(pid, code)) => {
                    if pid == command_pid {
                        command_exit_code = Some(code);
                    }
                }
                Ok(WaitStatus::Signaled(pid, signal, _)) => {
                    if pid == command_pid {
                        command_exit_code = Some(128 + signal as i32);
                    }
                }
                Ok(WaitStatus::StillAlive) => break,
                Ok(_) => continue,
                Err(Errno::EINTR) => continue,
                Err(Errno::ECHILD) => {
                    return command_exit_code.context("command process exited without status");
                }
                Err(error) => return Err(error).context("waitpid command tree"),
            }
        }

        let timeout = if let Some((signal, deadline)) = termination {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let signal = if remaining.is_zero() {
                Signal::SIGKILL
            } else {
                signal
            };
            signal_descendants(getpid(), signal)?;
            // Keep the reaper alive until every descendant has been collected.
            Some(if remaining.is_zero() {
                Duration::from_millis(100)
            } else {
                remaining
            })
        } else {
            None
        };

        let timeout = timeout.map(|duration| libc::timespec {
            tv_sec: duration.as_secs() as _,
            tv_nsec: duration.subsec_nanos() as libc::c_long,
        });
        // SAFETY: signals and the optional timeout remain valid throughout
        // this synchronous call; siginfo is optional.
        let received = unsafe {
            libc::sigtimedwait(
                signals.as_ref(),
                std::ptr::null_mut(),
                timeout.as_ref().map_or(std::ptr::null(), |value| value),
            )
        };
        if received == -1 {
            match Errno::last() {
                Errno::EINTR | Errno::EAGAIN => continue,
                error => return Err(error).context("wait for command-tree signal"),
            }
        }
        let signal = Signal::try_from(received)?;
        if signal != Signal::SIGCHLD {
            // Preserve the first deadline, but forward the signal just received.
            let (last_signal, _) =
                termination.get_or_insert((signal, Instant::now() + TERMINATION_GRACE));
            *last_signal = signal;
        }
    }
}

/// Include children in other process groups or sessions, and children forked
/// by any thread. The subreaper adopts descendants when their parents exit.
fn signal_descendants(root: Pid, signal: Signal) -> Result<()> {
    let mut pending = vec![root];
    let mut descendants = Vec::new();
    let mut seen = HashSet::from([root]);
    while let Some(pid) = pending.pop() {
        let tasks = match std::fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("list managed process threads"),
        };
        for task in tasks {
            let path = task?.path().join("children");
            let children = match std::fs::read_to_string(path) {
                Ok(children) => children,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("list managed child processes"),
            };
            for child in children.split_whitespace() {
                let child = Pid::from_raw(child.parse()?);
                if seen.insert(child) {
                    pending.push(child);
                    descendants.push(child);
                }
            }
        }
    }
    // Signal children before their parents to reduce reparenting races.
    for pid in descendants.into_iter().rev() {
        forward_signal(pid, signal)?;
    }
    Ok(())
}

pub fn forward_signal(pid: Pid, signal: Signal) -> Result<()> {
    match kill(pid, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error).with_context(|| format!("send {signal} to managed process {pid}")),
    }
}
