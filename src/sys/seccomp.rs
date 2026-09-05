//! seccomp-BPF.
//!
//! We hand-assemble a classic BPF program and install it with
//! `seccomp(SECCOMP_SET_MODE_FILTER)`.  The program the kernel runs for every
//! syscall looks like this (pseudo-assembly):
//!
//! ```text
//!   ld  [4]                     ; seccomp_data.arch
//!   jeq NATIVE_ARCH  -> next    ; foreign ABI (e.g. i386 on x86_64) is a
//!                    -> kill    ; classic filter-bypass, so refuse outright
//!   ld  [0]                     ; seccomp_data.nr
//!   jge 0x40000000   -> kill    ; x32 ABI numbers, x86_64 only
//!   jeq __NR_mount   -> deny
//!   jeq __NR_...     -> deny
//!   ret ALLOW
//! deny:
//!   ret ERRNO(EPERM)            ; or KILL_PROCESS in strict mode
//! kill:
//!   ret KILL_PROCESS
//! ```
//!
//! A deny-list (rather than an allow-list) is a deliberate trade-off: an
//! allow-list is strictly safer but needs per-workload tuning, and getting it
//! wrong makes ordinary programs die in confusing ways.  The limitation is
//! documented in `docs/security.md`.

use super::chk_long;
use super::ffi::*;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompMode {
    /// No filter installed.
    Unconfined,
    /// Deny-list, blocked calls return `EPERM`.
    Default,
    /// Deny-list plus extra entries; blocked calls kill the process.
    Strict,
}

impl SeccompMode {
    pub fn parse(s: &str) -> Result<SeccompMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "unconfined" | "off" | "none" => Ok(SeccompMode::Unconfined),
            "default" | "on" => Ok(SeccompMode::Default),
            "strict" => Ok(SeccompMode::Strict),
            other => Err(Error::cfg(format!(
                "unknown seccomp mode {:?} (expected unconfined|default|strict)",
                other
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SeccompMode::Unconfined => "unconfined",
            SeccompMode::Default => "default",
            SeccompMode::Strict => "strict",
        }
    }
}

/// (name, x86_64 nr, aarch64 nr).  `-1` means "not present on this arch".
const SYSCALLS: &[(&str, i32, i32)] = &[
    ("mount", 165, 40),
    ("umount2", 166, 39),
    ("pivot_root", 155, 41),
    ("chroot", 161, 51),
    ("swapon", 167, 224),
    ("swapoff", 168, 225),
    ("reboot", 169, 142),
    ("sethostname", 170, 161),
    ("setdomainname", 171, 162),
    ("init_module", 175, 105),
    ("finit_module", 313, 273),
    ("delete_module", 176, 106),
    ("kexec_load", 246, 104),
    ("kexec_file_load", 320, 294),
    ("open_by_handle_at", 304, 265),
    ("name_to_handle_at", 303, 264),
    ("add_key", 248, 217),
    ("request_key", 249, 218),
    ("keyctl", 250, 219),
    ("setns", 308, 268),
    ("unshare", 272, 97),
    ("bpf", 321, 280),
    ("perf_event_open", 298, 241),
    ("clock_settime", 227, 112),
    ("clock_adjtime", 305, 266),
    ("settimeofday", 164, 170),
    ("adjtimex", 159, 171),
    ("acct", 163, 89),
    ("quotactl", 179, 60),
    ("ioperm", 173, -1),
    ("iopl", 172, -1),
    ("uselib", 134, -1),
    ("nfsservctl", 180, -1),
    ("fsopen", 430, 430),
    ("fsconfig", 431, 431),
    ("fsmount", 432, 432),
    ("move_mount", 429, 429),
    ("open_tree", 428, 428),
    ("mount_setattr", 442, 442),
    // strict-only entries
    ("ptrace", 101, 117),
    ("process_vm_readv", 310, 270),
    ("process_vm_writev", 311, 271),
    ("syslog", 103, 116),
];

const DEFAULT_DENY: &[&str] = &[
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "swapon",
    "swapoff",
    "reboot",
    "sethostname",
    "setdomainname",
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "open_by_handle_at",
    "name_to_handle_at",
    "add_key",
    "request_key",
    "keyctl",
    "setns",
    "unshare",
    "bpf",
    "perf_event_open",
    "clock_settime",
    "clock_adjtime",
    "settimeofday",
    "adjtimex",
    "acct",
    "quotactl",
    "ioperm",
    "iopl",
    "uselib",
    "nfsservctl",
    "fsopen",
    "fsconfig",
    "fsmount",
    "move_mount",
    "open_tree",
    "mount_setattr",
];

const STRICT_EXTRA: &[&str] = &["ptrace", "process_vm_readv", "process_vm_writev", "syslog"];

pub fn syscall_nr(name: &str) -> Option<u32> {
    SYSCALLS.iter().find(|(n, _, _)| *n == name).and_then(|e| {
        #[cfg(target_arch = "x86_64")]
        let v = e.1;
        #[cfg(target_arch = "aarch64")]
        let v = e.2;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let v = -1;
        if v < 0 {
            None
        } else {
            Some(v as u32)
        }
    })
}

/// Which syscalls a mode blocks (names, in filter order).
pub fn denied_syscalls(mode: SeccompMode) -> Vec<&'static str> {
    match mode {
        SeccompMode::Unconfined => Vec::new(),
        SeccompMode::Default => DEFAULT_DENY.to_vec(),
        SeccompMode::Strict => {
            let mut v = DEFAULT_DENY.to_vec();
            v.extend_from_slice(STRICT_EXTRA);
            v
        }
    }
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Assemble the filter program.  Exposed separately from [`install`] so unit
/// tests can inspect it without needing privileges.
pub fn build_filter(mode: SeccompMode) -> Result<Vec<SockFilter>> {
    let names = denied_syscalls(mode);
    let nrs: Vec<u32> = names.iter().filter_map(|n| syscall_nr(n)).collect();
    let n = nrs.len();

    let has_x32_guard = cfg!(target_arch = "x86_64");
    let first_check = if has_x32_guard { 4 } else { 3 };
    let allow_idx = first_check + n;
    let deny_idx = allow_idx + 1;
    let kill_idx = allow_idx + 2;

    if kill_idx > 250 {
        return Err(Error::unsupported(
            "seccomp filter too large for 8-bit jump offsets",
        ));
    }

    let mut prog: Vec<SockFilter> = Vec::with_capacity(kill_idx + 1);
    // 0: load arch
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, 4));
    // 1: arch mismatch -> kill
    prog.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_NATIVE,
        0,
        (kill_idx - 2) as u8,
    ));
    // 2: load syscall number
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, 0));
    // 3 (x86_64 only): x32 ABI -> kill
    if has_x32_guard {
        prog.push(jump(
            BPF_JMP | BPF_JGE | BPF_K,
            0x4000_0000,
            (kill_idx - 4) as u8,
            0,
        ));
    }
    for (i, nr) in nrs.iter().enumerate() {
        let idx = first_check + i;
        prog.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            *nr,
            (deny_idx - idx - 1) as u8,
            0,
        ));
    }
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    let deny_action = if mode == SeccompMode::Strict {
        SECCOMP_RET_KILL_PROCESS
    } else {
        SECCOMP_RET_ERRNO | (EPERM as u32 & SECCOMP_RET_DATA)
    };
    prog.push(stmt(BPF_RET | BPF_K, deny_action));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    debug_assert_eq!(prog.len(), kill_idx + 1);
    Ok(prog)
}

/// Install the filter on the calling process (inherited by children).
///
/// Requires either `CAP_SYS_ADMIN` or `no_new_privs`; `myrun` always sets
/// `no_new_privs` first, so this works even after capabilities are dropped.
pub fn install(mode: SeccompMode) -> Result<usize> {
    if mode == SeccompMode::Unconfined {
        return Ok(0);
    }
    let prog = build_filter(mode)?;
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let rc = unsafe {
        syscall(
            nr::SECCOMP,
            SECCOMP_SET_MODE_FILTER as i64,
            0i64,
            &fprog as *const SockFprog as i64,
        )
    };
    chk_long(rc, "seccomp", format!("mode {}", mode.as_str()))?;
    Ok(prog.len())
}

/// Read `Seccomp:` from `/proc/<pid>/status` (0 = disabled, 2 = filter).
pub fn seccomp_mode_of(pid: i32) -> Option<u32> {
    let text = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Seccomp:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing() {
        assert_eq!(SeccompMode::parse("default").unwrap(), SeccompMode::Default);
        assert_eq!(
            SeccompMode::parse("UNCONFINED").unwrap(),
            SeccompMode::Unconfined
        );
        assert!(SeccompMode::parse("banana").is_err());
    }

    #[test]
    fn filter_shape_is_valid() {
        let prog = build_filter(SeccompMode::Default).unwrap();
        // First instruction always loads the arch field.
        assert_eq!(prog[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(prog[0].k, 4);
        // Last three: allow, deny, kill.
        let n = prog.len();
        assert_eq!(prog[n - 3].k, SECCOMP_RET_ALLOW);
        assert_eq!(prog[n - 2].k & 0xffff_0000, SECCOMP_RET_ERRNO);
        assert_eq!(prog[n - 2].k & 0xffff, EPERM as u32);
        assert_eq!(prog[n - 1].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn every_jump_lands_inside_the_program() {
        for mode in [SeccompMode::Default, SeccompMode::Strict] {
            let prog = build_filter(mode).unwrap();
            let n = prog.len();
            for (i, ins) in prog.iter().enumerate() {
                if ins.code & 0x07 == BPF_JMP {
                    assert!(i + 1 + ins.jt as usize <= n, "jt out of range at {}", i);
                    assert!(i + 1 + ins.jf as usize <= n, "jf out of range at {}", i);
                }
            }
        }
    }

    #[test]
    fn strict_blocks_more_and_kills() {
        let d = build_filter(SeccompMode::Default).unwrap();
        let s = build_filter(SeccompMode::Strict).unwrap();
        assert!(s.len() > d.len());
        assert_eq!(s[s.len() - 2].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn unconfined_is_empty() {
        assert!(denied_syscalls(SeccompMode::Unconfined).is_empty());
        assert_eq!(install(SeccompMode::Unconfined).unwrap(), 0);
    }

    #[test]
    fn known_syscall_numbers() {
        // mount(2) is 165 on x86_64, 40 on aarch64 — whichever we built for.
        let n = syscall_nr("mount").unwrap();
        assert!(n == 165 || n == 40);
        assert!(syscall_nr("definitely_not_a_syscall").is_none());
    }

    #[test]
    fn filter_contains_mount_and_reboot() {
        let prog = build_filter(SeccompMode::Default).unwrap();
        let mount_nr = syscall_nr("mount").unwrap();
        let reboot_nr = syscall_nr("reboot").unwrap();
        assert!(prog
            .iter()
            .any(|i| i.k == mount_nr && i.code & 0x07 == BPF_JMP));
        assert!(prog
            .iter()
            .any(|i| i.k == reboot_nr && i.code & 0x07 == BPF_JMP));
    }
}
