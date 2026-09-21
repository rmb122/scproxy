//! A cancellable owner of the blocking seccomp notification receive ioctl.

use std::io;
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::thread::JoinHandleExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::mpsc;

use super::{seccomp, sockets};

pub(super) struct Receiver {
    stop: Arc<AtomicBool>,
    wake: Arc<OwnedFd>,
    thread: Option<JoinHandle<()>>,
    previous_signal: libc::sigaction,
}

extern "C" fn interrupt_receive(_: libc::c_int) {}

impl Receiver {
    pub(super) fn start(
        listener: Arc<OwnedFd>,
    ) -> io::Result<(Self, mpsc::Receiver<io::Result<seccomp::Notification>>)> {
        // SIGURG normally has no effect on this supervisor. A targeted signal
        // interrupts RECV if a notification disappeared after poll readiness.
        let mut action: libc::sigaction = unsafe { zeroed() };
        action.sa_sigaction = interrupt_receive as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
        }
        let mut previous_signal = unsafe { zeroed() };
        sockets::check(unsafe { libc::sigaction(libc::SIGURG, &action, &mut previous_signal) })?;
        let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if wake < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::sigaction(libc::SIGURG, &previous_signal, std::ptr::null_mut());
            }
            return Err(error);
        }
        let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(wake) });
        let poller = poller(listener.as_raw_fd(), wake.as_raw_fd()).inspect_err(|_| unsafe {
            libc::sigaction(libc::SIGURG, &previous_signal, std::ptr::null_mut());
        })?;
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel(256);
        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("seccomp-recv".into())
            .spawn(move || {
                let mut signals: libc::sigset_t = unsafe { zeroed() };
                unsafe {
                    libc::sigemptyset(&mut signals);
                    libc::sigaddset(&mut signals, libc::SIGURG);
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut());
                }
                while !thread_stop.load(Ordering::Acquire) {
                    // Unlike poll(2), epoll_wait keeps working when a live
                    // supervisor's RLIMIT_NOFILE is lowered below its FD count.
                    let mut events: [libc::epoll_event; 2] = unsafe { zeroed() };
                    let count =
                        unsafe { libc::epoll_wait(poller.as_raw_fd(), events.as_mut_ptr(), 2, -1) };
                    if count < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        let _ = tx.try_send(Err(error));
                        return;
                    }
                    if thread_stop.load(Ordering::Acquire) {
                        return;
                    }
                    let Some(event) = events[..count as usize].iter().find(|event| event.u64 == 1)
                    else {
                        continue;
                    };
                    if event.events & libc::EPOLLIN as u32 != 0 {
                        match seccomp::receive(listener.as_raw_fd()) {
                            Ok(notification) => match tx.try_send(Ok(notification)) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    let _ = seccomp::respond(
                                        listener.as_raw_fd(),
                                        notification.id,
                                        0,
                                        libc::EAGAIN,
                                        false,
                                    );
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => return,
                            },
                            Err(error)
                                if matches!(
                                    error.raw_os_error(),
                                    Some(libc::EINTR | libc::ENOENT | libc::EAGAIN)
                                ) => {}
                            Err(error)
                                if matches!(
                                    error.raw_os_error(),
                                    Some(libc::ENOMEM | libc::ENOBUFS)
                                ) =>
                            {
                                std::thread::sleep(Duration::from_millis(100));
                            }
                            Err(error) => {
                                let _ = tx.try_send(Err(error));
                                return;
                            }
                        }
                    } else if event.events & (libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                        return;
                    }
                }
            })
            .inspect_err(|_| unsafe {
                libc::sigaction(libc::SIGURG, &previous_signal, std::ptr::null_mut());
            })?;
        Ok((
            Self {
                stop,
                wake,
                thread: Some(thread),
                previous_signal,
            },
            rx,
        ))
    }
}

fn poller(listener: i32, wake: i32) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    for (watched, tag) in [(listener, 1), (wake, 2)] {
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: tag,
        };
        sockets::check(unsafe { libc::epoll_ctl(raw, libc::EPOLL_CTL_ADD, watched, &mut event) })?;
    }
    Ok(fd)
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let value = 1u64;
        unsafe {
            libc::write(self.wake.as_raw_fd(), (&value as *const u64).cast(), 8);
        }
        if let Some(thread) = self.thread.take() {
            while !thread.is_finished() {
                unsafe {
                    libc::pthread_kill(thread.as_pthread_t() as libc::pthread_t, libc::SIGURG);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = thread.join();
        }
        unsafe {
            libc::sigaction(libc::SIGURG, &self.previous_signal, std::ptr::null_mut());
        }
    }
}
