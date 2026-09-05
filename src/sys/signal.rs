//! Signal handling built on `signalfd(2)` rather than async handlers.
//!
//! Container PID 1 and the shim both need to multiplex "a signal arrived"
//! with "a file descriptor became readable".  Classic `sigaction` handlers
//! cannot do that safely (almost nothing is async-signal-safe), so we block
//! the signals we care about and read them as bytes from a file descriptor,
//! which composes perfectly with `poll(2)`.

use super::ffi::*;
use super::{chk, close_fd};
use crate::error::{Error, Result};
use std::os::raw::{c_int, c_void};

/// Signals that PID 1 forwards to the container workload.
pub const FORWARDED: &[c_int] = &[
    SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGUSR1, SIGUSR2, SIGWINCH, SIGPIPE,
];

pub fn block(signals: &[c_int]) -> Result<SigSet> {
    let mut set = SigSet::empty();
    for s in signals {
        set.add(*s);
    }
    let mut old = SigSet::empty();
    let rc = unsafe { sigprocmask(SIG_BLOCK, &set, &mut old) };
    chk(rc, "sigprocmask", "SIG_BLOCK")?;
    Ok(old)
}

pub fn set_mask(set: &SigSet) -> Result<()> {
    let rc = unsafe { sigprocmask(SIG_SETMASK, set, std::ptr::null_mut()) };
    chk(rc, "sigprocmask", "SIG_SETMASK").map(|_| ())
}

/// Unblock everything — used in the workload child so the application starts
/// with a clean, default signal environment.
pub fn unblock_all() -> Result<()> {
    let empty = SigSet::empty();
    set_mask(&empty)
}

/// Restore default dispositions for all catchable signals.
pub fn reset_handlers() {
    for sig in 1..NSIG {
        if sig == SIGKILL || sig == SIGSTOP {
            continue;
        }
        unsafe {
            signal(sig, SIG_DFL);
        }
    }
}

pub struct SignalFd {
    fd: c_int,
}

impl SignalFd {
    /// Block `signals` and return a descriptor that reports them.
    pub fn new(signals: &[c_int]) -> Result<SignalFd> {
        let mut set = SigSet::empty();
        for s in signals {
            set.add(*s);
        }
        let rc = unsafe { sigprocmask(SIG_BLOCK, &set, std::ptr::null_mut()) };
        chk(rc, "sigprocmask", "SIG_BLOCK for signalfd")?;
        let fd = unsafe { signalfd(-1, &set, SFD_CLOEXEC | SFD_NONBLOCK) };
        let fd = chk(fd, "signalfd", "")?;
        Ok(SignalFd { fd })
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }

    /// Read one pending signal, if any.
    pub fn next_signal(&self) -> Result<Option<SignalfdSiginfo>> {
        let mut info = SignalfdSiginfo::default();
        let n = unsafe {
            read(
                self.fd,
                &mut info as *mut SignalfdSiginfo as *mut c_void,
                std::mem::size_of::<SignalfdSiginfo>(),
            )
        };
        if n < 0 {
            let e = errno();
            if e == EAGAIN || e == EINTR {
                return Ok(None);
            }
            return Err(Error::Syscall {
                call: "read",
                errno: e,
                ctx: "signalfd".into(),
            });
        }
        if n as usize != std::mem::size_of::<SignalfdSiginfo>() {
            return Ok(None);
        }
        Ok(Some(info))
    }
}

impl Drop for SignalFd {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

/// `poll(2)` with EINTR retry.  `timeout_ms < 0` blocks forever.
pub fn poll_fds(fds: &mut [PollFd], timeout_ms: i32) -> Result<usize> {
    loop {
        for f in fds.iter_mut() {
            f.revents = 0;
        }
        let rc = unsafe { poll(fds.as_mut_ptr(), fds.len() as nfds_t, timeout_ms) };
        if rc < 0 {
            let e = errno();
            if e == EINTR {
                continue;
            }
            return Err(Error::Syscall {
                call: "poll",
                errno: e,
                ctx: format!("{} fds", fds.len()),
            });
        }
        return Ok(rc as usize);
    }
}

/// Wait for a descriptor to become readable (or hang up).
pub fn wait_readable(fd: c_int, timeout_ms: i32) -> Result<bool> {
    let mut pfd = [PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    }];
    let n = poll_fds(&mut pfd, timeout_ms)?;
    Ok(n > 0 && (pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    const SYS_GETTID: i64 = 186;
    #[cfg(target_arch = "x86_64")]
    const SYS_TGKILL: i64 = 234;
    #[cfg(target_arch = "aarch64")]
    const SYS_GETTID: i64 = 178;
    #[cfg(target_arch = "aarch64")]
    const SYS_TGKILL: i64 = 131;

    #[test]
    fn signalfd_receives_self_signal() {
        // SIGUSR1 is blocked by SignalFd::new, so raising it must land in the
        // fd rather than killing the process.  The signal is sent
        // *thread-directed* with tgkill(2): `cargo test` is multi-threaded and
        // sigprocmask only masks the calling thread, so a process-directed
        // kill(2) could be delivered to an unrelated test thread.
        let sfd = SignalFd::new(&[SIGUSR1]).unwrap();
        unsafe {
            let tid = syscall(SYS_GETTID);
            syscall(
                SYS_TGKILL,
                super::super::getpid() as i64,
                tid,
                SIGUSR1 as i64,
            );
        }
        assert!(wait_readable(sfd.fd(), 1000).unwrap());
        let info = sfd.next_signal().unwrap().expect("a signal");
        assert_eq!(info.ssi_signo as i32, SIGUSR1);
        // Nothing left.
        assert!(sfd.next_signal().unwrap().is_none());
        // Restore the mask so later tests are unaffected.
        let empty = SigSet::empty();
        let _ = set_mask(&empty);
    }

    #[test]
    fn poll_timeout_returns_zero() {
        let (mut fds, r) = {
            let mut p = [0i32; 2];
            let rc = unsafe { pipe2(p.as_mut_ptr(), O_CLOEXEC) };
            assert_eq!(rc, 0);
            (
                [PollFd {
                    fd: p[0],
                    events: POLLIN,
                    revents: 0,
                }],
                p,
            )
        };
        assert_eq!(poll_fds(&mut fds, 10).unwrap(), 0);
        close_fd(r[0]);
        close_fd(r[1]);
    }

    #[test]
    fn forwarded_list_excludes_unblockable() {
        assert!(!FORWARDED.contains(&SIGKILL));
        assert!(!FORWARDED.contains(&SIGSTOP));
        assert!(FORWARDED.contains(&SIGTERM));
    }
}
