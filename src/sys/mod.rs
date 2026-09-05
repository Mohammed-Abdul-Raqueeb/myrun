//! Thin, safe-ish wrappers over [`ffi`].
//!
//! The rule in this module: every wrapper converts a `-1` return into
//! [`Error::Syscall`] carrying the real `errno` and a context string, so that
//! failures deep inside container setup stay debuggable.

pub mod caps;
pub mod ffi;
pub mod mount;
pub mod netlink;
pub mod process;
pub mod seccomp;
pub mod signal;

use crate::error::{Error, Result};
use ffi::*;
use std::ffi::CString;
use std::os::raw::{c_int, c_ulong};
use std::path::Path;

/// Build a NUL-terminated C string, rejecting embedded NULs.
pub fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::cfg(format!("string contains a NUL byte: {:?}", s)))
}

pub fn cpath(p: &Path) -> Result<CString> {
    let s = p
        .to_str()
        .ok_or_else(|| Error::cfg(format!("path is not valid UTF-8: {}", p.display())))?;
    cstr(s)
}

/// Turn a `-1` syscall return into an error.
pub fn chk(rc: c_int, call: &'static str, ctx: impl Into<String>) -> Result<c_int> {
    if rc < 0 {
        Err(Error::Syscall {
            call,
            errno: errno(),
            ctx: ctx.into(),
        })
    } else {
        Ok(rc)
    }
}

pub fn chk_long(rc: i64, call: &'static str, ctx: impl Into<String>) -> Result<i64> {
    if rc < 0 {
        // Raw syscall() also sets errno via glibc's wrapper.
        Err(Error::Syscall {
            call,
            errno: errno(),
            ctx: ctx.into(),
        })
    } else {
        Ok(rc)
    }
}

// ---------------------------------------------------------------------------
// identity / misc
// ---------------------------------------------------------------------------

pub fn getpid() -> i32 {
    unsafe { ffi::getpid() }
}

pub fn getppid() -> i32 {
    unsafe { ffi::getppid() }
}

pub fn geteuid() -> u32 {
    unsafe { ffi::geteuid() }
}

pub fn is_root() -> bool {
    geteuid() == 0
}

pub fn setsid() -> Result<i32> {
    let rc = unsafe { ffi::setsid() };
    chk(rc, "setsid", "").map(|v| v as i32)
}

pub fn clock_ticks_per_sec() -> u64 {
    let v = unsafe { sysconf(SC_CLK_TCK) };
    if v <= 0 {
        100
    } else {
        v as u64
    }
}

pub fn num_cpus() -> u64 {
    let v = unsafe { sysconf(SC_NPROCESSORS_ONLN) };
    if v <= 0 {
        1
    } else {
        v as u64
    }
}

pub fn page_size() -> u64 {
    let v = unsafe { sysconf(SC_PAGESIZE) };
    if v <= 0 {
        4096
    } else {
        v as u64
    }
}

/// Set the process name shown in `ps`/`/proc/<pid>/comm` (max 15 chars).
pub fn set_process_name(name: &str) {
    if let Ok(c) = cstr(&name.chars().take(15).collect::<String>()) {
        unsafe {
            prctl(PR_SET_NAME, c.as_ptr());
        }
    }
}

/// `prctl(PR_SET_PDEATHSIG, sig)` — deliver `sig` to this process when its
/// parent dies.  Used so that killing the shim never leaks a container.
pub fn set_pdeathsig(sig: c_int) -> Result<()> {
    let rc = unsafe { prctl(PR_SET_PDEATHSIG, sig as c_ulong) };
    chk(rc, "prctl", "PR_SET_PDEATHSIG").map(|_| ())
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)` — irreversible; blocks setuid/setcap
/// binaries inside the container from granting new privileges on exec.
pub fn set_no_new_privs() -> Result<()> {
    let rc = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
    chk(rc, "prctl", "PR_SET_NO_NEW_PRIVS").map(|_| ())
}

pub fn get_no_new_privs() -> bool {
    unsafe { prctl(PR_GET_NO_NEW_PRIVS, 0u64, 0u64, 0u64, 0u64) == 1 }
}

pub fn sethostname_str(name: &str) -> Result<()> {
    let c = cstr(name)?;
    let rc = unsafe { ffi::sethostname(c.as_ptr(), name.len()) };
    chk(rc, "sethostname", name).map(|_| ())
}

pub fn set_rlimit(resource: c_int, soft: u64, hard: u64) -> Result<()> {
    let rl = RLimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    let rc = unsafe { setrlimit(resource, &rl) };
    chk(rc, "setrlimit", format!("resource {}", resource)).map(|_| ())
}

// ---------------------------------------------------------------------------
// file descriptors
// ---------------------------------------------------------------------------

pub fn open_path(path: &Path, flags: c_int) -> Result<i32> {
    let c = cpath(path)?;
    let rc = unsafe { ffi::open(c.as_ptr(), flags) };
    chk(rc, "open", path.display().to_string())
}

pub fn close_fd(fd: i32) {
    if fd >= 0 {
        unsafe {
            ffi::close(fd);
        }
    }
}

pub fn set_cloexec(fd: i32, on: bool) -> Result<()> {
    let cur = unsafe { fcntl(fd, F_GETFD) };
    chk(cur, "fcntl", "F_GETFD")?;
    let new = if on {
        cur | FD_CLOEXEC
    } else {
        cur & !FD_CLOEXEC
    };
    chk(unsafe { fcntl(fd, F_SETFD, new) }, "fcntl", "F_SETFD").map(|_| ())
}

/// Advisory exclusive lock, used to serialise state-store and IPAM updates
/// across concurrent `myrun` invocations.
/// A file descriptor that is closed when it goes out of scope.
///
/// Used on paths where a descriptor is created and then several fallible
/// steps happen before it is consumed — an early `?` return would otherwise
/// leak it.
pub struct OwnedFd(i32);

impl OwnedFd {
    pub fn new(fd: i32) -> OwnedFd {
        OwnedFd(fd)
    }

    pub fn get(&self) -> i32 {
        self.0
    }

    /// Give up ownership; the caller must close it.
    pub fn into_raw(mut self) -> i32 {
        let fd = self.0;
        self.0 = -1;
        fd
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            close_fd(self.0);
        }
    }
}

pub struct FileLock {
    fd: i32,
}

impl FileLock {
    pub fn acquire(path: &Path) -> Result<FileLock> {
        let c = cpath(path)?;
        let fd = unsafe { ffi::open(c.as_ptr(), O_RDWR | O_CREAT | O_CLOEXEC, 0o600 as c_int) };
        let fd = chk(fd, "open", path.display().to_string())?;
        let rc = unsafe { flock(fd, LOCK_EX) };
        if rc < 0 {
            let e = errno();
            close_fd(fd);
            return Err(Error::Syscall {
                call: "flock",
                errno: e,
                ctx: path.display().to_string(),
            });
        }
        Ok(FileLock { fd })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        unsafe {
            flock(self.fd, LOCK_UN);
        }
        close_fd(self.fd);
    }
}

// ---------------------------------------------------------------------------
// namespaces
// ---------------------------------------------------------------------------

/// `setns(2)`: join an existing namespace referenced by `fd`.
/// `nstype` may be 0 (any) or a `CLONE_NEW*` constant for validation.
pub fn setns(fd: i32, nstype: c_int) -> Result<()> {
    let rc = unsafe { ffi::syscall(nr::SETNS, fd as i64, nstype as i64) };
    chk_long(rc, "setns", format!("fd {}", fd)).map(|_| ())
}

pub fn unshare_flags(flags: u64) -> Result<()> {
    let rc = unsafe { ffi::unshare(flags as c_int) };
    chk(rc, "unshare", format!("flags {:#x}", flags)).map(|_| ())
}

/// Read the inode number behind `/proc/<pid>/ns/<kind>`.
///
/// Two processes are in the same namespace iff these match.  This is exactly
/// how the integration tests prove isolation.
pub fn ns_inode(pid: i32, kind: &str) -> Result<u64> {
    let p = format!("/proc/{}/ns/{}", pid, kind);
    let link = std::fs::read_link(&p).map_err(|e| Error::io(format!("{}: {}", p, e)))?;
    let s = link.to_string_lossy().to_string();
    // Format is e.g. "pid:[4026532281]"
    let open = s
        .find('[')
        .ok_or_else(|| Error::parse(format!("unexpected ns link {:?}", s)))?;
    let close = s
        .find(']')
        .ok_or_else(|| Error::parse(format!("unexpected ns link {:?}", s)))?;
    s[open + 1..close]
        .parse::<u64>()
        .map_err(|e| Error::parse(format!("ns inode {:?}: {}", s, e)))
}

/// Run `f` while temporarily attached to another process's namespace.
///
/// Saves the current namespace fd, `setns`es into the target, runs the
/// closure, and always restores.  `myrun` is single threaded, which is what
/// makes this safe (setns on a multithreaded process only moves one thread).
pub fn with_namespace_of<T, F: FnOnce() -> Result<T>>(
    pid: i32,
    kind: &str,
    nstype: c_int,
    f: F,
) -> Result<T> {
    let self_ns = Path::new("/proc/self/ns").join(kind);
    let target = Path::new("/proc")
        .join(pid.to_string())
        .join("ns")
        .join(kind);
    let saved = open_path(&self_ns, O_RDONLY | O_CLOEXEC)?;
    let tfd = match open_path(&target, O_RDONLY | O_CLOEXEC) {
        Ok(fd) => fd,
        Err(e) => {
            close_fd(saved);
            return Err(e);
        }
    };
    let entered = setns(tfd, nstype);
    close_fd(tfd);
    if let Err(e) = entered {
        close_fd(saved);
        return Err(e);
    }
    let out = f();
    let restored = setns(saved, nstype);
    close_fd(saved);
    restored?;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstr_rejects_nul() {
        assert!(cstr("ok").is_ok());
        assert!(cstr("no\0pe").is_err());
    }

    #[test]
    fn ns_inode_of_self() {
        let a = ns_inode(getpid(), "pid").unwrap();
        let b = ns_inode(getpid(), "pid").unwrap();
        assert_eq!(a, b);
        assert!(a > 0);
        let m = ns_inode(getpid(), "mnt").unwrap();
        assert_ne!(a, m, "pid and mnt namespaces have distinct inodes");
    }

    #[test]
    fn sysconf_values_are_sane() {
        assert!(clock_ticks_per_sec() >= 1);
        assert!(num_cpus() >= 1);
        assert_eq!(page_size() % 1024, 0);
    }

    #[test]
    fn file_lock_is_exclusive_per_process_handle() {
        let p = std::env::temp_dir().join(format!("myrun-lock-{}", std::process::id()));
        let l = FileLock::acquire(&p).unwrap();
        drop(l);
        // Re-acquiring after drop must succeed.
        let l2 = FileLock::acquire(&p).unwrap();
        drop(l2);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn chk_maps_errno() {
        set_errno(0);
        let e = chk(-1, "test", "ctx");
        assert!(e.is_err());
    }
}
