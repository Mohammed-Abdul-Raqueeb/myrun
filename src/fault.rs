//! Deterministic fault injection.
//!
//! Rollback code is the least-tested part of most runtimes because the
//! failures it handles are rare.  `myrun` therefore lets the test suite ask
//! for a specific failure at a specific point:
//!
//! ```sh
//! MYRUN_FAULT=after_veth_create myrun run --network bridge ./rootfs /bin/sh
//! ```
//!
//! Every injection point calls [`check`]; if the name matches, the call
//! returns `Error::Fault`, which propagates through the normal `?` path and
//! triggers exactly the same rollback a real kernel error would.
//!
//! Multiple points can be armed with a comma separated list.  The special
//! value `list` is handled by `myrun info`.

use crate::error::{Error, Result};

/// Every injection point that exists.  Kept as a constant so `myrun info`
/// can print them and the tests can assert none were renamed.
pub const POINTS: &[&str] = &[
    "before_state_create",
    "after_state_create",
    "after_cgroup_create",
    "after_cgroup_limits",
    "before_clone",
    "after_clone",
    "after_bridge_create",
    "after_veth_create",
    "after_veth_master",
    "after_ip_alloc",
    "after_netns_move",
    "after_nat_rules",
    "before_go_signal",
    "after_go_signal",
    "before_pivot_root",
    "after_pivot_root",
    "before_exec",
    "after_start",
    "before_teardown",
];

fn armed() -> Vec<String> {
    match std::env::var("MYRUN_FAULT") {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Returns `Err(Error::Fault)` when `point` is armed via `MYRUN_FAULT`.
pub fn check(point: &str) -> Result<()> {
    let a = armed();
    if a.is_empty() {
        return Ok(());
    }
    if a.iter().any(|p| p == point) {
        crate::log_warn!("injecting fault at {}", point);
        return Err(Error::Fault(point.to_string()));
    }
    Ok(())
}

/// True if the named point is armed (for points that need to simulate a
/// partial success rather than return an error).
pub fn is_armed(point: &str) -> bool {
    armed().iter().any(|p| p == point)
}

/// Validate that an armed fault name is real — a typo in a test would
/// otherwise silently mean "no fault injected" and the test would pass for
/// the wrong reason.
pub fn validate_env() -> Result<()> {
    for p in armed() {
        if !POINTS.contains(&p.as_str()) {
            return Err(Error::cfg(format!(
                "MYRUN_FAULT names unknown injection point {:?}; known points: {}",
                p,
                POINTS.join(", ")
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate a process-global env var, so they are run as one
    // test to avoid interference from cargo's test threads.
    #[test]
    fn injection_lifecycle() {
        std::env::remove_var("MYRUN_FAULT");
        assert!(check("before_clone").is_ok());
        assert!(validate_env().is_ok());

        std::env::set_var("MYRUN_FAULT", "before_clone");
        assert!(check("before_clone").is_err());
        assert!(check("after_clone").is_ok());
        assert!(is_armed("before_clone"));
        assert!(validate_env().is_ok());

        std::env::set_var("MYRUN_FAULT", "after_veth_create, after_nat_rules");
        assert!(check("after_veth_create").is_err());
        assert!(check("after_nat_rules").is_err());
        assert!(check("before_clone").is_ok());

        std::env::set_var("MYRUN_FAULT", "typo_here");
        assert!(validate_env().is_err());
        std::env::remove_var("MYRUN_FAULT");
    }

    #[test]
    fn points_are_unique() {
        let mut v = POINTS.to_vec();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(n, v.len(), "duplicate fault injection point names");
    }
}
