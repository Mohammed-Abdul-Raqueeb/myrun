//! Process creation and inspection.
//!
//! The centrepiece is [`clone_child`], which creates the container's PID 1
//! with `clone3(2)` and immediately `execveat(2)`s a **sealed in-memory copy**
//! of the `myrun` binary.
//!
//! Two design decisions worth calling out:
//!
//! 1. **Re-exec instead of a callback.** Many toy runtimes call
//!    `clone(child_fn, stack, ...)` and then run arbitrary Rust in the child.
//!    That is unsafe: after `clone(2)` the child may only run
//!    async-signal-safe code, and anything that allocates can deadlock on a
//!    lock held by another thread at clone time.  We instead do the absolute
//!    minimum in the child (a few `dup2`s) and `exec` ourselves back as
//!    `myrun __init`, which starts from a clean, single-threaded state
//!    already inside the new namespaces.
//!
//! 2. **Sealed memfd self-copy.** Executing `/proc/self/exe` from a process
//!    that is about to enter a container-controlled filesystem is how
//!    CVE-2019-5736 (runc breakout) worked: a malicious container could
//!    overwrite the runtime binary through `/proc/<pid>/exe`.  We copy our
//!    own binary into a `memfd`, apply `F_SEAL_WRITE`, and exec that fd, so
//!    the container has nothing writable to point at.

use super::ffi::*;
use super::{chk, chk_long, cstr};
use crate::error::{Error, Result};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

/// A cloned child.
#[derive(Debug)]
pub struct Child {
    pub pid: pid_t,
    /// `pidfd` from `CLONE_PIDFD`; `-1` when the kernel did not provide one.
    pub pidfd: c_int,
}

/// Everything the child needs in order to `exec`, pre-computed in the parent
/// so that no allocation happens between `clone3` and `execveat`.
pub struct ExecPlan {
    _argv_store: Vec<CString>,
    _envp_store: Vec<CString>,
    argv: Vec<*const c_char>,
    envp: Vec<*const c_char>,
    exe_fd: c_int,
    empty: CString,
}

impl ExecPlan {
    pub fn new(exe_fd: c_int, argv: &[String], envp: &[String]) -> Result<ExecPlan> {
        let argv_store: Vec<CString> = argv.iter().map(|s| cstr(s)).collect::<Result<Vec<_>>>()?;
        let envp_store: Vec<CString> = envp.iter().map(|s| cstr(s)).collect::<Result<Vec<_>>>()?;
        let mut argv_ptrs: Vec<*const c_char> = argv_store.iter().map(|c| c.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut envp_ptrs: Vec<*const c_char> = envp_store.iter().map(|c| c.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());
        Ok(ExecPlan {
            _argv_store: argv_store,
            _envp_store: envp_store,
            argv: argv_ptrs,
            envp: envp_ptrs,
            exe_fd,
            empty: CString::new("").unwrap(),
        })
    }

    /// `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`.  Only returns on error.
    ///
    /// # Safety
    /// Must only be called in a freshly cloned/forked child.
    pub unsafe fn exec(&self) -> c_int {
        syscall(
            nr::EXECVEAT,
            self.exe_fd as i64,
            self.empty.as_ptr() as i64,
            self.argv.as_ptr() as i64,
            self.envp.as_ptr() as i64,
            AT_EMPTY_PATH as i64,
        ) as c_int
    }
}

/// Parameters for [`clone_child`].
pub struct CloneRequest<'a> {
    /// `CLONE_NEW*` flags.
    pub flags: u64,
    /// When `Some`, the child is placed into this cgroup atomically at
    /// creation time via `CLONE_INTO_CGROUP` (Linux >= 5.7).
    pub cgroup_fd: Option<c_int>,
    /// Child end of the synchronisation socketpair; becomes fd 3.
    pub sync_fd: c_int,
    /// Signal delivered to us when the child dies (normally `SIGCHLD`).
    pub exit_signal: c_int,
    /// Signal delivered to the *child* when we die.
    pub pdeathsig: Option<c_int>,
    pub plan: &'a ExecPlan,
}

const CHILD_SYNC_FD: c_int = 3;
const CHILD_EXE_FD: c_int = 4;
const F_DUPFD_CLOEXEC: c_int = 1030;

/// Move an fd out of the low range so the child can safely `dup2` onto 3/4.
fn move_fd_high(fd: c_int) -> Result<c_int> {
    let n = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 10 as c_int) };
    chk(n, "fcntl", "F_DUPFD_CLOEXEC")
}

/// Create the container's init process.
///
/// Returns in the **parent** only; the child `exec`s or `_exit(127)`s.
pub fn clone_child(req: &CloneRequest) -> Result<Child> {
    // Relocate the two fds the child needs so that dup2 onto 3/4 cannot
    // clobber the source fd.
    let sync_high = move_fd_high(req.sync_fd)?;
    let exe_high = move_fd_high(req.plan.exe_fd)?;

    let mut pidfd: c_int = -1;
    let mut flags = req.flags | CLONE_PIDFD;
    let mut cgroup_val = 0u64;
    if let Some(fd) = req.cgroup_fd {
        flags |= CLONE_INTO_CGROUP;
        cgroup_val = fd as u64;
    }

    let mut args = CloneArgs {
        flags,
        pidfd: &mut pidfd as *mut c_int as u64,
        exit_signal: req.exit_signal as u64,
        cgroup: cgroup_val,
        ..Default::default()
    };

    let rc = unsafe {
        syscall(
            nr::CLONE3,
            &mut args as *mut CloneArgs as i64,
            std::mem::size_of::<CloneArgs>() as i64,
        )
    };

    if rc == 0 {
        // ---------------- CHILD ----------------
        // Async-signal-safe only from here to exec: no allocation, no
        // Rust std IO, no panics.
        unsafe {
            if let Some(sig) = req.pdeathsig {
                prctl(PR_SET_PDEATHSIG, sig as u64);
            }
            if dup2(sync_high, CHILD_SYNC_FD) < 0 {
                _exit(126);
            }
            if dup2(exe_high, CHILD_EXE_FD) < 0 {
                _exit(126);
            }
            // Close everything above the fds we deliberately pass through.
            // Older kernels lack close_range(2); CLOEXEC covers us there.
            syscall(
                nr::CLOSE_RANGE,
                (CHILD_EXE_FD + 1) as i64,
                u32::MAX as i64,
                0i64,
            );
            // argv/envp pointer arrays were built before the clone, so no
            // allocation happens here.  The exe fd was relocated to 4.
            syscall(
                nr::EXECVEAT,
                CHILD_EXE_FD as i64,
                b"\0".as_ptr() as i64,
                req.plan.argv.as_ptr() as i64,
                req.plan.envp.as_ptr() as i64,
                AT_EMPTY_PATH as i64,
            );
            // exec failed — 127 is the shell convention for "command not
            // found" and is what the parent reports.
            _exit(127);
        }
    }

    // ---------------- PARENT ----------------
    super::close_fd(sync_high);
    super::close_fd(exe_high);

    if rc < 0 {
        let e = errno();
        if e == ENOSYS || e == EINVAL {
            // Fall back to legacy clone(2) for kernels without clone3 or
            // without CLONE_INTO_CGROUP support.
            return clone_child_legacy(req);
        }
        return Err(Error::Syscall {
            call: "clone3",
            errno: e,
            ctx: format!("flags {:#x}", flags),
        });
    }

    Ok(Child {
        pid: rc as pid_t,
        pidfd,
    })
}

/// `clone(2)` fallback.  Passing a NULL stack makes the child continue at the
/// same instruction (fork semantics), which is exactly what we want since we
/// exec immediately.
fn clone_child_legacy(req: &CloneRequest) -> Result<Child> {
    let sync_high = move_fd_high(req.sync_fd)?;
    let exe_high = move_fd_high(req.plan.exe_fd)?;
    let mut pidfd: c_int = -1;
    let flags = req.flags | CLONE_PIDFD | (req.exit_signal as u64 & 0xff);

    let rc = unsafe {
        syscall(
            nr::CLONE,
            flags as i64,
            0i64,                            // stack (NULL => fork-like)
            &mut pidfd as *mut c_int as i64, // parent_tid <- pidfd
            0i64,                            // child_tid
            0i64,                            // tls
        )
    };

    if rc == 0 {
        unsafe {
            if let Some(sig) = req.pdeathsig {
                prctl(PR_SET_PDEATHSIG, sig as u64);
            }
            if dup2(sync_high, CHILD_SYNC_FD) < 0 {
                _exit(126);
            }
            if dup2(exe_high, CHILD_EXE_FD) < 0 {
                _exit(126);
            }
            syscall(
                nr::CLOSE_RANGE,
                (CHILD_EXE_FD + 1) as i64,
                u32::MAX as i64,
                0i64,
            );
            syscall(
                nr::EXECVEAT,
                CHILD_EXE_FD as i64,
                b"\0".as_ptr() as i64,
                req.plan.argv.as_ptr() as i64,
                req.plan.envp.as_ptr() as i64,
                AT_EMPTY_PATH as i64,
            );
            _exit(127);
        }
    }

    super::close_fd(sync_high);
    super::close_fd(exe_high);
    if rc < 0 {
        return Err(Error::Syscall {
            call: "clone",
            errno: errno(),
            ctx: format!("flags {:#x}", flags),
        });
    }
    Ok(Child {
        pid: rc as pid_t,
        pidfd,
    })
}

/// Plain `fork(2)`.
pub fn fork_process() -> Result<pid_t> {
    let pid = unsafe { fork() };
    chk(pid, "fork", "").map(|p| p as pid_t)
}

// ---------------------------------------------------------------------------
// Sealed self-exec
// ---------------------------------------------------------------------------

/// Copy this executable into a sealed `memfd` and return its fd.
///
/// Falls back to an `O_PATH`-less read-only fd on `/proc/self/exe` if memfd
/// or sealing is unavailable (very old kernels); the fallback is functionally
/// identical but loses the CVE-2019-5736 mitigation, so we say so in the log.
pub fn sealed_self_exe() -> Result<(c_int, bool)> {
    let data = std::fs::read("/proc/self/exe")
        .map_err(|e| Error::io(format!("read /proc/self/exe: {}", e)))?;

    let name = cstr("myrun-sealed")?;
    let fd = unsafe {
        syscall(
            nr::MEMFD_CREATE,
            name.as_ptr() as i64,
            (MFD_CLOEXEC | MFD_ALLOW_SEALING) as i64,
        )
    };
    if fd < 0 {
        let fallback = unsafe {
            let p = cstr("/proc/self/exe")?;
            open(p.as_ptr(), O_RDONLY | O_CLOEXEC)
        };
        return chk(fallback, "open", "/proc/self/exe").map(|f| (f, false));
    }
    let fd = fd as c_int;

    let mut off = 0usize;
    while off < data.len() {
        let n = unsafe { write(fd, data[off..].as_ptr() as *const c_void, data.len() - off) };
        if n < 0 {
            let e = errno();
            if e == EINTR {
                continue;
            }
            super::close_fd(fd);
            return Err(Error::Syscall {
                call: "write",
                errno: e,
                ctx: "memfd self-copy".into(),
            });
        }
        off += n as usize;
    }

    let seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL;
    let rc = unsafe { fcntl(fd, F_ADD_SEALS, seals) };
    if rc < 0 {
        // Sealing failed: still usable, just without the hardening.
        return Ok((fd, false));
    }
    Ok((fd, true))
}

// ---------------------------------------------------------------------------
// pidfd
// ---------------------------------------------------------------------------

/// `pidfd_open(2)` — a race-free handle to a process.
///
/// PIDs are recycled; a `pidfd` is not.  The shim polls this fd to learn that
/// the container exited, and `myrun kill` uses `pidfd_send_signal(2)` so it
/// can never signal an unrelated process that inherited the PID.
pub fn pidfd_open(pid: pid_t) -> Result<c_int> {
    let rc = unsafe { syscall(nr::PIDFD_OPEN, pid as i64, 0i64) };
    chk_long(rc, "pidfd_open", format!("pid {}", pid)).map(|v| v as c_int)
}

pub fn pidfd_send_signal(pidfd: c_int, sig: c_int) -> Result<()> {
    let rc = unsafe { syscall(nr::PIDFD_SEND_SIGNAL, pidfd as i64, sig as i64, 0i64, 0i64) };
    chk_long(rc, "pidfd_send_signal", format!("signal {}", sig)).map(|_| ())
}

pub fn kill_pid(pid: pid_t, sig: c_int) -> Result<()> {
    let rc = unsafe { kill(pid, sig) };
    chk(rc, "kill", format!("pid {} signal {}", pid, sig)).map(|_| ())
}

// ---------------------------------------------------------------------------
// wait
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ExitStatus {
    pub fn from_raw(status: c_int) -> ExitStatus {
        if wifexited(status) {
            ExitStatus {
                code: Some(wexitstatus(status)),
                signal: None,
            }
        } else if wifsignaled(status) {
            ExitStatus {
                code: None,
                signal: Some(wtermsig(status)),
            }
        } else {
            ExitStatus {
                code: None,
                signal: None,
            }
        }
    }

    /// Shell convention: a process killed by signal N reports 128+N.
    pub fn exit_code(&self) -> i32 {
        match (self.code, self.signal) {
            (Some(c), _) => c,
            (None, Some(s)) => 128 + s,
            _ => 255,
        }
    }

    pub fn describe(&self) -> String {
        match (self.code, self.signal) {
            (Some(c), _) => format!("exited with code {}", c),
            (None, Some(s)) => format!("killed by signal {} ({})", s, signal_name(s)),
            _ => "terminated for an unknown reason".into(),
        }
    }
}

pub fn signal_name(sig: c_int) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        _ => "SIG?",
    }
}

/// Parse a signal given as a name (`TERM`, `SIGTERM`) or number.
pub fn parse_signal(s: &str) -> Result<c_int> {
    let t = s.trim().to_ascii_uppercase();
    if let Ok(n) = t.parse::<i32>() {
        if (1..=64).contains(&n) {
            return Ok(n);
        }
        return Err(Error::cfg(format!("signal {} out of range", n)));
    }
    let t = t.strip_prefix("SIG").unwrap_or(&t);
    let n = match t {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "ABRT" => 6,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "CHLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "WINCH" => 28,
        _ => return Err(Error::cfg(format!("unknown signal {:?}", s))),
    };
    Ok(n)
}

/// `waitpid(2)`.  Returns `None` for `WNOHANG` with nothing to reap.
pub fn wait_pid(pid: pid_t, options: c_int) -> Result<Option<(pid_t, ExitStatus)>> {
    loop {
        let mut status: c_int = 0;
        let rc = unsafe { waitpid(pid, &mut status, options) };
        if rc < 0 {
            let e = errno();
            if e == EINTR {
                continue;
            }
            if e == ECHILD {
                return Ok(None);
            }
            return Err(Error::Syscall {
                call: "waitpid",
                errno: e,
                ctx: format!("pid {}", pid),
            });
        }
        if rc == 0 {
            return Ok(None); // WNOHANG, still running
        }
        if wifstopped(status) {
            continue;
        }
        return Ok(Some((rc as pid_t, ExitStatus::from_raw(status))));
    }
}

/// Reap every finished child.  Returns the statuses collected.
pub fn reap_all() -> Vec<(pid_t, ExitStatus)> {
    let mut out = Vec::new();
    loop {
        match wait_pid(-1, WNOHANG) {
            Ok(Some(x)) => out.push(x),
            _ => break,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// /proc introspection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProcStat {
    pub pid: pid_t,
    pub comm: String,
    pub state: char,
    pub ppid: pid_t,
    /// Field 22: process start time in clock ticks since boot.  Combined with
    /// the pid this uniquely identifies a process even across PID reuse.
    pub start_time: u64,
    pub utime: u64,
    pub stime: u64,
    pub num_threads: i64,
}

pub fn read_proc_stat(pid: pid_t) -> Result<ProcStat> {
    let path = format!("/proc/{}/stat", pid);
    let text =
        std::fs::read_to_string(&path).map_err(|e| Error::not_found(format!("{}: {}", path, e)))?;
    parse_proc_stat(&text)
}

pub fn parse_proc_stat(text: &str) -> Result<ProcStat> {
    // comm may contain spaces and parentheses, so split on the LAST ')'.
    let open = text
        .find('(')
        .ok_or_else(|| Error::parse("malformed /proc/<pid>/stat"))?;
    let close = text
        .rfind(')')
        .ok_or_else(|| Error::parse("malformed /proc/<pid>/stat"))?;
    let pid: pid_t = text[..open].trim().parse().unwrap_or(-1);
    let comm = text[open + 1..close].to_string();
    let rest: Vec<&str> = text[close + 1..].split_whitespace().collect();
    // rest[0] = state (field 3); field N maps to rest[N-3].
    let get = |n: usize| -> u64 { rest.get(n - 3).and_then(|s| s.parse().ok()).unwrap_or(0) };
    Ok(ProcStat {
        pid,
        comm,
        state: rest.first().and_then(|s| s.chars().next()).unwrap_or('?'),
        ppid: get(4) as pid_t,
        utime: get(14),
        stime: get(15),
        num_threads: get(20) as i64,
        start_time: get(22),
    })
}

/// Is this exact process still alive?
///
/// `start_time` guards against PID reuse: if the recorded start time no
/// longer matches, the PID belongs to somebody else and we must not signal it.
pub fn process_alive(pid: pid_t, start_time: Option<u64>) -> bool {
    match read_proc_stat(pid) {
        Ok(st) => {
            if st.state == 'Z' {
                return false;
            }
            match start_time {
                Some(t) => st.start_time == t,
                None => true,
            }
        }
        Err(_) => false,
    }
}

/// PIDs visible in a `/proc` mounted for the given pid's PID namespace.
pub fn list_pids_in_proc(proc_root: &str) -> Result<Vec<pid_t>> {
    let mut out = Vec::new();
    let rd =
        std::fs::read_dir(proc_root).map_err(|e| Error::io(format!("{}: {}", proc_root, e)))?;
    for e in rd.flatten() {
        if let Ok(p) = e.file_name().to_string_lossy().parse::<pid_t>() {
            out.push(p);
        }
    }
    out.sort_unstable();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_semantics() {
        let e = ExitStatus::from_raw(3 << 8);
        assert_eq!(e.code, Some(3));
        assert_eq!(e.exit_code(), 3);
        let k = ExitStatus::from_raw(9);
        assert_eq!(k.signal, Some(9));
        assert_eq!(k.exit_code(), 137);
        assert!(k.describe().contains("SIGKILL"));
    }

    #[test]
    fn signal_parsing() {
        assert_eq!(parse_signal("TERM").unwrap(), 15);
        assert_eq!(parse_signal("SIGKILL").unwrap(), 9);
        assert_eq!(parse_signal("9").unwrap(), 9);
        assert!(parse_signal("NOPE").is_err());
        assert!(parse_signal("999").is_err());
    }

    #[test]
    fn proc_stat_handles_weird_comm() {
        let line = "1234 ((weird) name) S 1 1234 1234 0 -1 4194304 100 0 0 0 \
                    11 22 0 0 20 0 3 0 987654 0 0";
        let st = parse_proc_stat(line).unwrap();
        assert_eq!(st.pid, 1234);
        assert_eq!(st.comm, "(weird) name");
        assert_eq!(st.state, 'S');
        assert_eq!(st.ppid, 1);
    }

    #[test]
    fn real_self_stat() {
        let me = super::super::getpid();
        let st = read_proc_stat(me).unwrap();
        assert_eq!(st.pid, me);
        assert!(st.start_time > 0);
        assert!(process_alive(me, Some(st.start_time)));
        assert!(
            !process_alive(me, Some(st.start_time + 1)),
            "start-time mismatch must be rejected"
        );
        assert!(!process_alive(0x7fff_fffe, None));
    }

    #[test]
    fn sealed_self_exe_works() {
        let (fd, sealed) = sealed_self_exe().unwrap();
        assert!(fd >= 0);
        if sealed {
            let seals = unsafe { fcntl(fd, F_GET_SEALS) };
            assert!(seals & F_SEAL_WRITE != 0, "memfd must be write-sealed");
        }
        super::super::close_fd(fd);
    }

    #[test]
    fn list_pids_sees_init() {
        let pids = list_pids_in_proc("/proc").unwrap();
        assert!(pids.contains(&1));
        assert!(pids.contains(&super::super::getpid()));
    }
}
