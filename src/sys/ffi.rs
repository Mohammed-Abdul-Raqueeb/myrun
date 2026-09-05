//! Raw FFI surface.
//!
//! `myrun` has no third-party crates, so every kernel interface it uses is
//! declared here.  Two mechanisms are used:
//!
//! * Functions that glibc wraps well (`mount`, `prctl`, `poll`, ...) are
//!   declared directly.  glibc is already linked by the Rust std runtime, so
//!   this costs nothing.
//! * Functions glibc does not wrap, or wraps in a way that hides what we
//!   want (`clone3`, `pivot_root`, `capset`, `seccomp`, `pidfd_open`,
//!   `execveat`), go through the variadic `syscall(2)` entry point with the
//!   architecture's syscall number.
//!
//! Every constant below is annotated with the header it comes from so the
//! values can be checked against the kernel UAPI headers.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

pub use std::os::raw::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

pub type pid_t = i32;
pub type uid_t = u32;
pub type gid_t = u32;
pub type mode_t = u32;
pub type dev_t = u64;
pub type nfds_t = c_ulong;
pub type socklen_t = u32;

// ---------------------------------------------------------------------------
// Syscall numbers (arch specific) — asm/unistd_64.h
// ---------------------------------------------------------------------------
#[cfg(target_arch = "x86_64")]
pub mod nr {
    pub const CLONE: i64 = 56;
    pub const CLONE3: i64 = 435;
    pub const PIVOT_ROOT: i64 = 155;
    pub const SETNS: i64 = 308;
    pub const SECCOMP: i64 = 317;
    pub const MEMFD_CREATE: i64 = 319;
    pub const EXECVEAT: i64 = 322;
    pub const CAPGET: i64 = 125;
    pub const CAPSET: i64 = 126;
    pub const PIDFD_OPEN: i64 = 434;
    pub const PIDFD_SEND_SIGNAL: i64 = 424;
    pub const CLOSE_RANGE: i64 = 436;
}

#[cfg(target_arch = "aarch64")]
pub mod nr {
    pub const CLONE: i64 = 220;
    pub const CLONE3: i64 = 435;
    pub const PIVOT_ROOT: i64 = 41;
    pub const SETNS: i64 = 268;
    pub const SECCOMP: i64 = 277;
    pub const MEMFD_CREATE: i64 = 279;
    pub const EXECVEAT: i64 = 281;
    pub const CAPGET: i64 = 90;
    pub const CAPSET: i64 = 91;
    pub const PIDFD_OPEN: i64 = 434;
    pub const PIDFD_SEND_SIGNAL: i64 = 424;
    pub const CLOSE_RANGE: i64 = 436;
}

// ---------------------------------------------------------------------------
// clone(2) / clone3(2) — linux/sched.h
// ---------------------------------------------------------------------------
pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_PIDFD: u64 = 0x0000_1000;
pub const CLONE_PTRACE: u64 = 0x0000_2000;
pub const CLONE_VFORK: u64 = 0x0000_4000;
pub const CLONE_PARENT: u64 = 0x0000_8000;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// `struct clone_args` as of Linux 5.7 (CLONE_ARGS_SIZE_VER2).
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

// ---------------------------------------------------------------------------
// mount(2) — sys/mount.h
// ---------------------------------------------------------------------------
pub const MS_RDONLY: c_ulong = 1;
pub const MS_NOSUID: c_ulong = 2;
pub const MS_NODEV: c_ulong = 4;
pub const MS_NOEXEC: c_ulong = 8;
pub const MS_SYNCHRONOUS: c_ulong = 16;
pub const MS_REMOUNT: c_ulong = 32;
pub const MS_MANDLOCK: c_ulong = 64;
pub const MS_NOATIME: c_ulong = 1024;
pub const MS_NODIRATIME: c_ulong = 2048;
pub const MS_BIND: c_ulong = 4096;
pub const MS_MOVE: c_ulong = 8192;
pub const MS_REC: c_ulong = 16384;
pub const MS_SILENT: c_ulong = 32768;
pub const MS_UNBINDABLE: c_ulong = 1 << 17;
pub const MS_PRIVATE: c_ulong = 1 << 18;
pub const MS_SLAVE: c_ulong = 1 << 19;
pub const MS_SHARED: c_ulong = 1 << 20;
pub const MS_RELATIME: c_ulong = 1 << 21;
pub const MS_STRICTATIME: c_ulong = 1 << 24;
pub const MS_LAZYTIME: c_ulong = 1 << 25;

pub const MNT_FORCE: c_int = 1;
pub const MNT_DETACH: c_int = 2;
pub const MNT_EXPIRE: c_int = 4;
pub const UMOUNT_NOFOLLOW: c_int = 8;

// ---------------------------------------------------------------------------
// open(2) — fcntl.h
// ---------------------------------------------------------------------------
pub const O_RDONLY: c_int = 0;
pub const O_WRONLY: c_int = 1;
pub const O_RDWR: c_int = 2;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_TRUNC: c_int = 0o1000;
pub const O_APPEND: c_int = 0o2000;
pub const O_NONBLOCK: c_int = 0o4000;
pub const O_DIRECTORY: c_int = 0o200000;
pub const O_NOFOLLOW: c_int = 0o400000;
pub const O_CLOEXEC: c_int = 0o2000000;
pub const O_PATH: c_int = 0o10000000;

pub const AT_FDCWD: c_int = -100;
pub const AT_EMPTY_PATH: c_int = 0x1000;
pub const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

pub const F_GETFD: c_int = 1;
pub const F_SETFD: c_int = 2;
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;
pub const F_ADD_SEALS: c_int = 1033;
pub const F_GET_SEALS: c_int = 1034;
pub const FD_CLOEXEC: c_int = 1;

pub const F_SEAL_SEAL: c_int = 0x0001;
pub const F_SEAL_SHRINK: c_int = 0x0002;
pub const F_SEAL_GROW: c_int = 0x0004;
pub const F_SEAL_WRITE: c_int = 0x0008;

pub const MFD_CLOEXEC: c_uint = 0x0001;
pub const MFD_ALLOW_SEALING: c_uint = 0x0002;

pub const LOCK_SH: c_int = 1;
pub const LOCK_EX: c_int = 2;
pub const LOCK_NB: c_int = 4;
pub const LOCK_UN: c_int = 8;

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------
pub const SIGHUP: c_int = 1;
pub const SIGINT: c_int = 2;
pub const SIGQUIT: c_int = 3;
pub const SIGILL: c_int = 4;
pub const SIGABRT: c_int = 6;
pub const SIGKILL: c_int = 9;
pub const SIGUSR1: c_int = 10;
pub const SIGSEGV: c_int = 11;
pub const SIGUSR2: c_int = 12;
pub const SIGPIPE: c_int = 13;
pub const SIGALRM: c_int = 14;
pub const SIGTERM: c_int = 15;
pub const SIGCHLD: c_int = 17;
pub const SIGCONT: c_int = 18;
pub const SIGSTOP: c_int = 19;
pub const SIGTSTP: c_int = 20;
pub const SIGTTIN: c_int = 21;
pub const SIGTTOU: c_int = 22;
pub const SIGWINCH: c_int = 28;
pub const NSIG: c_int = 64;

pub const SIG_BLOCK: c_int = 0;
pub const SIG_UNBLOCK: c_int = 1;
pub const SIG_SETMASK: c_int = 2;

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

pub const SFD_CLOEXEC: c_int = 0o2000000;
pub const SFD_NONBLOCK: c_int = 0o4000;

/// glibc `sigset_t` is 1024 bits regardless of what the kernel uses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigSet {
    pub bits: [u64; 16],
}

impl Default for SigSet {
    fn default() -> Self {
        SigSet { bits: [0; 16] }
    }
}

impl SigSet {
    pub fn empty() -> SigSet {
        SigSet::default()
    }
    pub fn full() -> SigSet {
        SigSet { bits: [!0u64; 16] }
    }
    pub fn add(&mut self, sig: c_int) {
        if sig <= 0 {
            return;
        }
        let n = (sig - 1) as usize;
        self.bits[n / 64] |= 1u64 << (n % 64);
    }
    pub fn contains(&self, sig: c_int) -> bool {
        if sig <= 0 {
            return false;
        }
        let n = (sig - 1) as usize;
        self.bits[n / 64] & (1u64 << (n % 64)) != 0
    }
}

/// `struct signalfd_siginfo` (128 bytes, linux/signalfd.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalfdSiginfo {
    pub ssi_signo: u32,
    pub ssi_errno: i32,
    pub ssi_code: i32,
    pub ssi_pid: u32,
    pub ssi_uid: u32,
    pub ssi_fd: i32,
    pub ssi_tid: u32,
    pub ssi_band: u32,
    pub ssi_overrun: u32,
    pub ssi_trapno: u32,
    pub ssi_status: i32,
    pub ssi_int: i32,
    pub ssi_ptr: u64,
    pub ssi_utime: u64,
    pub ssi_stime: u64,
    pub ssi_addr: u64,
    pub ssi_addr_lsb: u16,
    pub __pad2: u16,
    pub ssi_syscall: i32,
    pub ssi_call_addr: u64,
    pub ssi_arch: u32,
    pub __pad: [u8; 28],
}

impl Default for SignalfdSiginfo {
    fn default() -> Self {
        // Safety: the struct is plain old data.
        unsafe { std::mem::zeroed() }
    }
}

// ---------------------------------------------------------------------------
// poll(2)
// ---------------------------------------------------------------------------
pub const POLLIN: i16 = 0x001;
pub const POLLPRI: i16 = 0x002;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;
pub const POLLNVAL: i16 = 0x020;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PollFd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

// ---------------------------------------------------------------------------
// wait(2) status decoding — bits/waitstatus.h
// ---------------------------------------------------------------------------
pub const WNOHANG: c_int = 1;
pub const WUNTRACED: c_int = 2;
pub const WCONTINUED: c_int = 8;

pub fn wifexited(status: c_int) -> bool {
    (status & 0x7f) == 0
}
pub fn wexitstatus(status: c_int) -> c_int {
    (status >> 8) & 0xff
}
pub fn wifsignaled(status: c_int) -> bool {
    ((status & 0x7f) + 1) >> 1 > 0
}
pub fn wtermsig(status: c_int) -> c_int {
    status & 0x7f
}
pub fn wcoredump(status: c_int) -> bool {
    status & 0x80 != 0
}
pub fn wifstopped(status: c_int) -> bool {
    (status & 0xff) == 0x7f
}

// ---------------------------------------------------------------------------
// prctl(2) — linux/prctl.h
// ---------------------------------------------------------------------------
pub const PR_SET_PDEATHSIG: c_int = 1;
pub const PR_GET_PDEATHSIG: c_int = 2;
pub const PR_SET_DUMPABLE: c_int = 4;
pub const PR_SET_KEEPCAPS: c_int = 8;
pub const PR_SET_NAME: c_int = 15;
pub const PR_CAPBSET_READ: c_int = 23;
pub const PR_CAPBSET_DROP: c_int = 24;
pub const PR_GET_SECUREBITS: c_int = 27;
pub const PR_SET_SECUREBITS: c_int = 28;
pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
pub const PR_GET_NO_NEW_PRIVS: c_int = 39;
pub const PR_CAP_AMBIENT: c_int = 47;
pub const PR_CAP_AMBIENT_IS_SET: c_ulong = 1;
pub const PR_CAP_AMBIENT_RAISE: c_ulong = 2;
pub const PR_CAP_AMBIENT_LOWER: c_ulong = 3;
pub const PR_CAP_AMBIENT_CLEAR_ALL: c_ulong = 4;

// ---------------------------------------------------------------------------
// capabilities — linux/capability.h
// ---------------------------------------------------------------------------
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct CapUserHeader {
    pub version: u32,
    pub pid: c_int,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct CapUserData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

// ---------------------------------------------------------------------------
// seccomp(2) — linux/seccomp.h, linux/filter.h
// ---------------------------------------------------------------------------
pub const SECCOMP_SET_MODE_STRICT: c_uint = 0;
pub const SECCOMP_SET_MODE_FILTER: c_uint = 1;
pub const SECCOMP_FILTER_FLAG_TSYNC: c_uint = 1;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

/// `struct sock_filter` — a single classic-BPF instruction.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

// classic BPF opcodes (linux/bpf_common.h)
pub const BPF_LD: u16 = 0x00;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_K: u16 = 0x00;

// ---------------------------------------------------------------------------
// Sockets / netlink
// ---------------------------------------------------------------------------
pub const AF_UNIX: c_int = 1;
pub const AF_INET: c_int = 2;
pub const AF_NETLINK: c_int = 16;
pub const AF_PACKET: c_int = 17;
pub const AF_UNSPEC: c_int = 0;

pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_SEQPACKET: c_int = 5;
pub const SOCK_CLOEXEC: c_int = 0o2000000;
pub const SOCK_NONBLOCK: c_int = 0o4000;

pub const NETLINK_ROUTE: c_int = 0;
pub const SOL_SOCKET: c_int = 1;
pub const SO_RCVBUF: c_int = 8;
pub const SO_SNDBUF: c_int = 7;
pub const SO_RCVTIMEO: c_int = 20;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrNl {
    pub nl_family: u16,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

impl Default for SockaddrNl {
    fn default() -> Self {
        SockaddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

// ---------------------------------------------------------------------------
// resource limits
// ---------------------------------------------------------------------------
pub const RLIMIT_NOFILE: c_int = 7;
pub const RLIMIT_NPROC: c_int = 6;
pub const RLIMIT_CORE: c_int = 4;
pub const RLIMIT_FSIZE: c_int = 1;
pub const RLIM_INFINITY: u64 = !0u64;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RLimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

// ---------------------------------------------------------------------------
// device node helpers
// ---------------------------------------------------------------------------
pub const S_IFCHR: mode_t = 0o020000;
pub const S_IFDIR: mode_t = 0o040000;
pub const S_IFREG: mode_t = 0o100000;

/// glibc `makedev` encoding.
pub fn makedev(major: u64, minor: u64) -> dev_t {
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

// ---------------------------------------------------------------------------
// sysconf
// ---------------------------------------------------------------------------
pub const SC_CLK_TCK: c_int = 2;
pub const SC_PAGESIZE: c_int = 30;
pub const SC_NPROCESSORS_ONLN: c_int = 84;

// ---------------------------------------------------------------------------
// extern declarations
// ---------------------------------------------------------------------------
extern "C" {
    pub fn syscall(num: c_long, ...) -> c_long;
    pub fn __errno_location() -> *mut c_int;

    pub fn fork() -> pid_t;
    pub fn _exit(status: c_int) -> !;
    pub fn execve(
        path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int;
    pub fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t;
    pub fn kill(pid: pid_t, sig: c_int) -> c_int;
    pub fn getpid() -> pid_t;
    pub fn getppid() -> pid_t;
    pub fn getuid() -> uid_t;
    pub fn geteuid() -> uid_t;
    pub fn getgid() -> gid_t;
    pub fn setsid() -> pid_t;
    pub fn setuid(uid: uid_t) -> c_int;
    pub fn setgid(gid: gid_t) -> c_int;
    pub fn setgroups(size: usize, list: *const gid_t) -> c_int;
    pub fn umask(mask: mode_t) -> mode_t;

    pub fn chdir(path: *const c_char) -> c_int;
    pub fn chroot(path: *const c_char) -> c_int;
    pub fn mkdir(path: *const c_char, mode: mode_t) -> c_int;
    pub fn rmdir(path: *const c_char) -> c_int;
    pub fn unlink(path: *const c_char) -> c_int;
    pub fn symlink(target: *const c_char, linkpath: *const c_char) -> c_int;
    pub fn mknod(path: *const c_char, mode: mode_t, dev: dev_t) -> c_int;
    pub fn readlink(path: *const c_char, buf: *mut c_char, bufsiz: usize) -> isize;

    pub fn mount(
        source: *const c_char,
        target: *const c_char,
        fstype: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    pub fn umount2(target: *const c_char, flags: c_int) -> c_int;
    pub fn sethostname(name: *const c_char, len: usize) -> c_int;
    pub fn unshare(flags: c_int) -> c_int;

    pub fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    pub fn close(fd: c_int) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    pub fn dup2(oldfd: c_int, newfd: c_int) -> c_int;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub fn ftruncate(fd: c_int, len: i64) -> c_int;
    pub fn flock(fd: c_int, operation: c_int) -> c_int;
    pub fn fsync(fd: c_int) -> c_int;
    pub fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    pub fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn bind(fd: c_int, addr: *const c_void, len: socklen_t) -> c_int;
    pub fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    pub fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
    pub fn setsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: socklen_t,
    ) -> c_int;
    pub fn poll(fds: *mut PollFd, nfds: nfds_t, timeout: c_int) -> c_int;

    pub fn sigprocmask(how: c_int, set: *const SigSet, oldset: *mut SigSet) -> c_int;
    pub fn signalfd(fd: c_int, mask: *const SigSet, flags: c_int) -> c_int;
    pub fn signal(sig: c_int, handler: usize) -> usize;

    pub fn prctl(option: c_int, ...) -> c_int;
    pub fn setrlimit(resource: c_int, rlim: *const RLimit) -> c_int;
    pub fn getrlimit(resource: c_int, rlim: *mut RLimit) -> c_int;
    pub fn sysconf(name: c_int) -> c_long;
    pub fn if_nametoindex(name: *const c_char) -> c_uint;
}

/// Current `errno`.
#[inline]
pub fn errno() -> c_int {
    unsafe { *__errno_location() }
}

#[inline]
pub fn set_errno(v: c_int) {
    unsafe {
        *__errno_location() = v;
    }
}

// Common errno values used for control flow.
pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const ESRCH: c_int = 3;
pub const EINTR: c_int = 4;
pub const EAGAIN: c_int = 11;
pub const EACCES: c_int = 13;
pub const EEXIST: c_int = 17;
pub const EINVAL: c_int = 22;
pub const ENOTDIR: c_int = 20;
pub const EBUSY: c_int = 16;
pub const ENOSYS: c_int = 38;
pub const ECHILD: c_int = 10;
pub const EOPNOTSUPP: c_int = 95;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_status_decoding() {
        // exit(7) => status 0x0700
        let s = 7 << 8;
        assert!(wifexited(s));
        assert_eq!(wexitstatus(s), 7);
        assert!(!wifsignaled(s));
        // killed by SIGKILL => low 7 bits = 9
        let s = 9;
        assert!(!wifexited(s));
        assert!(wifsignaled(s));
        assert_eq!(wtermsig(s), 9);
    }

    #[test]
    fn sigset_bits() {
        let mut s = SigSet::empty();
        s.add(SIGTERM);
        s.add(SIGCHLD);
        assert!(s.contains(SIGTERM));
        assert!(s.contains(SIGCHLD));
        assert!(!s.contains(SIGINT));
        assert_eq!(s.bits[0], (1u64 << 14) | (1u64 << 16));
    }

    #[test]
    fn dev_encoding() {
        // /dev/null is 1:3, /dev/urandom is 1:9
        assert_eq!(makedev(1, 3), 0x103);
        assert_eq!(makedev(1, 9), 0x109);
        assert_eq!(makedev(5, 0), 0x500);
    }

    #[test]
    fn syscall_works() {
        // getpid via raw syscall must equal std::process::id()
        #[cfg(target_arch = "x86_64")]
        const SYS_GETPID: i64 = 39;
        #[cfg(target_arch = "aarch64")]
        const SYS_GETPID: i64 = 172;
        let pid = unsafe { syscall(SYS_GETPID) };
        assert_eq!(pid as u32, std::process::id());
    }
}
