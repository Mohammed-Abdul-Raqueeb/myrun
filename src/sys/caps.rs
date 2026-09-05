//! Linux capabilities (`capset(2)`, `PR_CAPBSET_DROP`, ambient set).
//!
//! Running as uid 0 inside a container is only tolerable because the set of
//! things "root" may do has been cut down.  We manipulate four sets:
//!
//! | set          | meaning                                              |
//! |--------------|------------------------------------------------------|
//! | permitted    | the caps the process *may* raise into effective       |
//! | effective    | the caps checked by the kernel right now              |
//! | inheritable  | caps preserved across `execve` of a non-file-cap file |
//! | bounding     | ceiling: nothing can ever be added back above it      |
//! | ambient      | inheritable caps that actually survive a plain exec   |
//!
//! Dropping only permitted/effective is not enough: without dropping the
//! **bounding** set a setuid-root binary inside the container would regain
//! everything.  We therefore drop the bounding set first (which needs
//! `CAP_SETPCAP`), then narrow permitted/effective, and finally clear the
//! ambient set.

use super::ffi::*;
use super::{chk, chk_long};
use crate::error::{Error, Result};
use std::os::raw::{c_int, c_ulong};

/// (name without the `CAP_` prefix, value) — linux/capability.h
pub const CAP_TABLE: &[(&str, u8)] = &[
    ("CHOWN", 0),
    ("DAC_OVERRIDE", 1),
    ("DAC_READ_SEARCH", 2),
    ("FOWNER", 3),
    ("FSETID", 4),
    ("KILL", 5),
    ("SETGID", 6),
    ("SETUID", 7),
    ("SETPCAP", 8),
    ("LINUX_IMMUTABLE", 9),
    ("NET_BIND_SERVICE", 10),
    ("NET_BROADCAST", 11),
    ("NET_ADMIN", 12),
    ("NET_RAW", 13),
    ("IPC_LOCK", 14),
    ("IPC_OWNER", 15),
    ("SYS_MODULE", 16),
    ("SYS_RAWIO", 17),
    ("SYS_CHROOT", 18),
    ("SYS_PTRACE", 19),
    ("SYS_PACCT", 20),
    ("SYS_ADMIN", 21),
    ("SYS_BOOT", 22),
    ("SYS_NICE", 23),
    ("SYS_RESOURCE", 24),
    ("SYS_TIME", 25),
    ("SYS_TTY_CONFIG", 26),
    ("MKNOD", 27),
    ("LEASE", 28),
    ("AUDIT_WRITE", 29),
    ("AUDIT_CONTROL", 30),
    ("SETFCAP", 31),
    ("MAC_OVERRIDE", 32),
    ("MAC_ADMIN", 33),
    ("SYSLOG", 34),
    ("WAKE_ALARM", 35),
    ("BLOCK_SUSPEND", 36),
    ("AUDIT_READ", 37),
    ("PERFMON", 38),
    ("BPF", 39),
    ("CHECKPOINT_RESTORE", 40),
];

/// Default retained set — deliberately the same shape as Docker's default,
/// minus `CAP_NET_RAW` (ping still works via ping_group_range on modern
/// distros and NET_RAW enables ARP/DHCP spoofing from inside the container).
pub const DEFAULT_KEEP: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "NET_BIND_SERVICE",
    "SYS_CHROOT",
    "MKNOD",
    "AUDIT_WRITE",
];

pub fn parse_cap(name: &str) -> Result<u8> {
    let n = name.trim().to_ascii_uppercase();
    let n = n.strip_prefix("CAP_").unwrap_or(&n);
    CAP_TABLE
        .iter()
        .find(|(k, _)| *k == n)
        .map(|(_, v)| *v)
        .ok_or_else(|| Error::cfg(format!("unknown capability {:?}", name)))
}

pub fn cap_name(v: u8) -> String {
    CAP_TABLE
        .iter()
        .find(|(_, n)| *n == v)
        .map(|(k, _)| format!("CAP_{}", k))
        .unwrap_or_else(|| format!("CAP_{}", v))
}

/// Highest capability this kernel knows about.
pub fn last_cap() -> u8 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or(40)
}

/// Resolve a keep-list plus `--cap-add` / `--cap-drop` into a bitmask.
pub fn resolve_keep_set(base: &[String], add: &[String], drop: &[String]) -> Result<u64> {
    let mut mask: u64 = 0;
    let all = drop.iter().any(|d| d.eq_ignore_ascii_case("all"));
    if !all {
        for c in base {
            mask |= 1u64 << parse_cap(c)?;
        }
        for c in drop {
            mask &= !(1u64 << parse_cap(c)?);
        }
    }
    for c in add {
        if c.eq_ignore_ascii_case("all") {
            for (_, v) in CAP_TABLE {
                mask |= 1u64 << *v;
            }
        } else {
            mask |= 1u64 << parse_cap(c)?;
        }
    }
    Ok(mask)
}

pub fn describe_mask(mask: u64) -> Vec<String> {
    let mut v = Vec::new();
    for (name, bit) in CAP_TABLE {
        if mask & (1u64 << *bit) != 0 {
            v.push(format!("CAP_{}", name));
        }
    }
    v
}

/// Read the current permitted/effective/inheritable sets.
pub fn get_caps() -> Result<(u64, u64, u64)> {
    let hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData::default(); 2];
    let rc = unsafe {
        syscall(
            nr::CAPGET,
            &hdr as *const CapUserHeader as i64,
            data.as_mut_ptr() as i64,
        )
    };
    chk_long(rc, "capget", "")?;
    let join = |lo: u32, hi: u32| ((hi as u64) << 32) | lo as u64;
    Ok((
        join(data[0].effective, data[1].effective),
        join(data[0].permitted, data[1].permitted),
        join(data[0].inheritable, data[1].inheritable),
    ))
}

fn set_caps(effective: u64, permitted: u64, inheritable: u64) -> Result<()> {
    let hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapUserData {
            effective: effective as u32,
            permitted: permitted as u32,
            inheritable: inheritable as u32,
        },
        CapUserData {
            effective: (effective >> 32) as u32,
            permitted: (permitted >> 32) as u32,
            inheritable: (inheritable >> 32) as u32,
        },
    ];
    let rc = unsafe {
        syscall(
            nr::CAPSET,
            &hdr as *const CapUserHeader as i64,
            data.as_ptr() as i64,
        )
    };
    chk_long(rc, "capset", format!("keep mask {:#x}", permitted)).map(|_| ())
}

/// Apply the final capability configuration.
///
/// Must be called **after** every privileged setup step (mounts, network,
/// cgroup join) and **before** the workload is executed.
pub fn apply(keep_mask: u64) -> Result<()> {
    let last = last_cap();

    // 1. Ambient set first: it must be empty before we shrink permitted,
    //    otherwise capset(2) fails with EPERM (ambient must be a subset).
    let rc = unsafe { prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0u64, 0u64, 0u64) };
    if rc < 0 && errno() != EINVAL {
        return Err(Error::Syscall {
            call: "prctl",
            errno: errno(),
            ctx: "PR_CAP_AMBIENT_CLEAR_ALL".into(),
        });
    }

    // 2. Bounding set — needs CAP_SETPCAP, which we still hold here.
    for cap in 0..=last {
        if keep_mask & (1u64 << cap) != 0 {
            continue;
        }
        let rc = unsafe { prctl(PR_CAPBSET_DROP, cap as c_ulong, 0u64, 0u64, 0u64) };
        if rc < 0 {
            let e = errno();
            // EINVAL: capability unknown to this kernel — fine.
            if e == EINVAL {
                continue;
            }
            return Err(Error::Syscall {
                call: "prctl",
                errno: e,
                ctx: format!("PR_CAPBSET_DROP {}", cap_name(cap)),
            });
        }
    }

    // 3. Narrow permitted/effective; inheritable stays empty so that an
    //    exec inside the container cannot propagate privileges further.
    set_caps(keep_mask, keep_mask, 0)
}

/// After a `setuid()` away from root the kernel clears permitted caps for us.
/// This is a belt-and-braces assertion used by the security tests.
pub fn assert_dropped(expected_mask: u64) -> Result<()> {
    let (eff, perm, inh) = get_caps()?;
    if eff & !expected_mask != 0 || perm & !expected_mask != 0 || inh != 0 {
        return Err(Error::container(format!(
            "capability drop incomplete: effective={:#x} permitted={:#x} inheritable={:#x} expected<={:#x}",
            eff, perm, inh, expected_mask
        )));
    }
    Ok(())
}

/// Is a capability present in our bounding set?
pub fn in_bounding_set(cap: u8) -> bool {
    unsafe { prctl(PR_CAPBSET_READ, cap as c_ulong, 0u64, 0u64, 0u64) == 1 }
}

/// Set uid/gid (and clear supplementary groups).  Called in the workload
/// child, before exec, when `--user` was given.
pub fn switch_user(uid: u32, gid: u32) -> Result<()> {
    let rc = unsafe { setgroups(0, std::ptr::null()) };
    chk(rc, "setgroups", "clearing supplementary groups")?;
    let rc = unsafe { setgid(gid) };
    chk(rc, "setgid", format!("gid {}", gid))?;
    let rc = unsafe { setuid(uid) };
    chk(rc, "setuid", format!("uid {}", uid))?;
    Ok(())
}

/// `getrlimit`-friendly helper used by the init process.
pub fn nofile_limit() -> Option<(u64, u64)> {
    let mut rl = RLimit::default();
    let rc = unsafe { getrlimit(RLIMIT_NOFILE, &mut rl) };
    if rc == 0 {
        Some((rl.rlim_cur, rl.rlim_max))
    } else {
        None
    }
}

#[allow(dead_code)]
fn _unused(_: c_int) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_names() {
        assert_eq!(parse_cap("CAP_NET_ADMIN").unwrap(), 12);
        assert_eq!(parse_cap("net_admin").unwrap(), 12);
        assert_eq!(parse_cap("SYS_ADMIN").unwrap(), 21);
        assert!(parse_cap("NOT_A_CAP").is_err());
        assert_eq!(cap_name(21), "CAP_SYS_ADMIN");
    }

    #[test]
    fn keep_set_resolution() {
        let base: Vec<String> = DEFAULT_KEEP.iter().map(|s| s.to_string()).collect();
        let mask = resolve_keep_set(&base, &[], &[]).unwrap();
        assert!(mask & (1 << 0) != 0, "CHOWN kept by default");
        assert!(mask & (1 << 21) == 0, "SYS_ADMIN never default");

        let mask = resolve_keep_set(&base, &["NET_ADMIN".into()], &[]).unwrap();
        assert!(mask & (1 << 12) != 0);

        let mask = resolve_keep_set(&base, &[], &["all".into()]).unwrap();
        assert_eq!(mask, 0, "--cap-drop all clears everything");

        let mask = resolve_keep_set(&base, &["SYS_TIME".into()], &["all".into()]).unwrap();
        assert_eq!(mask, 1 << 25, "add is applied after drop-all");

        let mask = resolve_keep_set(&base, &[], &["CHOWN".into()]).unwrap();
        assert!(mask & 1 == 0);
    }

    #[test]
    fn describe_is_readable() {
        let d = describe_mask((1 << 0) | (1 << 12));
        assert_eq!(d, vec!["CAP_CHOWN", "CAP_NET_ADMIN"]);
    }

    #[test]
    fn can_read_own_caps() {
        let (eff, perm, _inh) = get_caps().unwrap();
        // Under root eff should be non-empty; unprivileged it may be 0.
        if super::super::is_root() {
            assert!(perm != 0);
            assert!(eff != 0);
            assert!(in_bounding_set(21));
        }
        assert!(last_cap() >= 30);
    }
}
