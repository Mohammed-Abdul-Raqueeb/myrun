//! Security hardening, applied by init immediately before the workload
//! starts.
//!
//! The order is not arbitrary:
//!
//! 1. **Capabilities.** Drop from the bounding, permitted, effective and
//!    ambient sets while we still have `CAP_SETPCAP`.
//! 2. **`no_new_privs`.** Once set it cannot be unset, and it is what makes
//!    a setuid binary inside the rootfs harmless. It must come *after* the
//!    capability work and *before* seccomp — the kernel requires either
//!    `no_new_privs` or `CAP_SYS_ADMIN` to install a filter, and we want the
//!    former, not the latter.
//! 3. **Seccomp.** Last, because everything above it uses syscalls the
//!    filter may deny.
//!
//! Getting this order wrong fails open, quietly, which is the worst kind of
//! security bug — hence the assertions in `verify`.

use crate::config::SecurityConfig;
use crate::error::{Error, Result};
use crate::sys::{caps, seccomp};

/// Validate a security configuration without applying it.
///
/// Split out from [`apply`] so the impossible combinations are caught in
/// the CLI process, before any capability has actually been dropped.
pub fn precheck(sec: &SecurityConfig) -> Result<()> {
    if sec.privileged {
        return Ok(());
    }
    let _ = sec.cap_mask()?;
    if !sec.no_new_privs && sec.seccomp != seccomp::SeccompMode::Unconfined {
        return Err(Error::cfg(
            "--no-new-privs=false cannot be combined with seccomp; the kernel \
             requires PR_SET_NO_NEW_PRIVS or CAP_SYS_ADMIN to install a filter",
        ));
    }
    Ok(())
}

/// Apply every hardening step. Called inside the container namespaces.
pub fn apply(sec: &SecurityConfig) -> Result<()> {
    precheck(sec)?;
    if sec.privileged {
        crate::log_warn!(
            "container is running privileged: capabilities, seccomp and path masking are all disabled"
        );
        return Ok(());
    }

    // 1. Capabilities.
    let keep = sec.cap_mask()?;
    caps::apply(keep)?;
    crate::log_debug!("capabilities: kept {}", caps::describe_mask(keep).join(","));

    // 2. no_new_privs.
    // Installing a filter without no_new_privs needs CAP_SYS_ADMIN, which we
    // have just dropped; precheck() has already rejected that combination.
    if sec.no_new_privs {
        crate::sys::set_no_new_privs()?;
    }

    // 3. Seccomp.
    seccomp::install(sec.seccomp)?;
    if sec.seccomp != seccomp::SeccompMode::Unconfined {
        crate::log_debug!("seccomp filter installed ({})", sec.seccomp.as_str());
    }

    Ok(())
}

/// Switch to an unprivileged user, if one was requested.
///
/// Must run *after* [`apply`] set up the capability sets but *before*
/// `execve`. `setgid` and the group list go first: after `setuid` we no
/// longer have the privilege to change them.
pub fn switch_user(sec: &SecurityConfig) -> Result<()> {
    if let Some((uid, gid)) = sec.user {
        caps::switch_user(uid, gid)?;
        crate::log_debug!("switched to uid={} gid={}", uid, gid);
    }
    Ok(())
}

/// Post-conditions, checked in tests and in `--verify` runs.
///
/// Returns a list of human-readable problems; empty means the sandbox is
/// as requested.
pub fn verify(sec: &SecurityConfig) -> Vec<String> {
    let mut problems = Vec::new();
    if sec.privileged {
        return problems;
    }

    let keep = match sec.cap_mask() {
        Ok(k) => k,
        Err(e) => {
            problems.push(format!("capability set is invalid: {}", e));
            return problems;
        }
    };
    if let Err(e) = caps::assert_dropped(keep) {
        problems.push(e.to_string());
    }
    // CAP_SYS_ADMIN in a container is close to being root on the host: it
    // allows mount, setns and cgroup manipulation. Call it out explicitly.
    if keep & (1u64 << 21) != 0 {
        problems.push("CAP_SYS_ADMIN is retained".to_string());
    }
    if sec.no_new_privs && !crate::sys::get_no_new_privs() {
        problems.push("no_new_privs was requested but is not set".to_string());
    }
    if sec.seccomp != seccomp::SeccompMode::Unconfined {
        let mode = seccomp::seccomp_mode_of(crate::sys::getpid()).unwrap_or(0);
        if mode == 0 {
            problems.push("seccomp was requested but no filter is active".to_string());
        }
    }
    problems
}

/// A short human-readable summary for `myrun inspect`.
pub fn summary(sec: &SecurityConfig) -> String {
    if sec.privileged {
        return "privileged (no confinement)".to_string();
    }
    let keep = sec.cap_mask().unwrap_or(0);
    let n = keep.count_ones();
    format!(
        "{} capabilit{}, no_new_privs={}, seccomp={}{}",
        n,
        if n == 1 { "y" } else { "ies" },
        sec.no_new_privs,
        sec.seccomp.as_str(),
        match sec.user {
            Some((u, g)) => format!(", user={}:{}", u, g),
            None => String::new(),
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::seccomp::SeccompMode;

    #[test]
    fn privileged_skips_everything() {
        let mut sec = SecurityConfig::default();
        sec.privileged = true;
        assert!(verify(&sec).is_empty());
        assert!(summary(&sec).contains("privileged"));
    }

    #[test]
    fn no_new_privs_false_with_seccomp_is_rejected() {
        // precheck() rather than apply(): apply() would drop this test
        // process's own capabilities as a side effect.
        let mut sec = SecurityConfig::default();
        sec.no_new_privs = false;
        sec.seccomp = SeccompMode::Default;
        let err = match precheck(&sec) {
            Err(e) => e.to_string(),
            Ok(()) => panic!("precheck should have rejected this combination"),
        };
        assert!(err.contains("no-new-privs"), "{}", err);

        // Without seccomp the same setting is legitimate.
        sec.seccomp = SeccompMode::Unconfined;
        precheck(&sec).unwrap();

        // Unknown capability names are caught here too.
        let mut bad = SecurityConfig::default();
        bad.cap_add = vec!["CAP_MADE_UP".into()];
        assert!(precheck(&bad).is_err());
    }

    #[test]
    fn summary_reports_the_shape_of_the_sandbox() {
        let sec = SecurityConfig::default();
        let s = summary(&sec);
        assert!(s.contains("no_new_privs=true"), "{}", s);
        assert!(s.contains("seccomp=default"), "{}", s);
        assert!(s.contains("capabilit"), "{}", s);
    }

    #[test]
    fn dropping_all_capabilities_is_representable() {
        let mut sec = SecurityConfig::default();
        sec.cap_drop = vec!["all".into()];
        assert_eq!(sec.cap_mask().unwrap(), 0);
        assert!(summary(&sec).starts_with("0 capabilities"));
    }

    #[test]
    fn user_switch_requires_setuid_capability() {
        let mut sec = SecurityConfig::default();
        sec.cap_drop = vec!["all".into()];
        sec.user = Some((1000, 1000));
        let mask = sec.cap_mask().unwrap();
        let setuid = 1u64 << crate::sys::caps::parse_cap("SETUID").unwrap();
        let setgid = 1u64 << crate::sys::caps::parse_cap("SETGID").unwrap();
        assert!(
            mask & setuid != 0 && mask & setgid != 0,
            "--user must keep SETUID/SETGID even with --cap-drop all"
        );
    }
}
