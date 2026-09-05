//! The runtime: everything that turns a [`crate::config::ContainerConfig`]
//! into a running, isolated process — and takes it apart again.
//!
//! Component map (see `README.md` for the diagram):
//!
//! ```text
//!   cli  ->  supervisor  ->  { cgroup, network, filesystem, security }
//!               |                     ^
//!               v                     |
//!             shim  <-- ipc -->  init (PID 1 inside the container)
//!               |
//!               v
//!             state  <-->  stats / lifecycle
//! ```

pub mod cgroup;
pub mod filesystem;
pub mod init;
pub mod ipam;
pub mod ipc;
pub mod lifecycle;
pub mod nat;
pub mod network;
pub mod security;
pub mod shim;
pub mod state;
pub mod stats;
pub mod supervisor;

use crate::error::Result;
use crate::util;
use std::path::PathBuf;

/// Root of the runtime's on-disk state.
///
/// `/run` is a tmpfs on every modern distro, which is exactly right for
/// container state: it must not survive a reboot, because the processes it
/// describes do not either.
pub fn runtime_root() -> PathBuf {
    if let Ok(p) = std::env::var("MYRUN_ROOT") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if crate::sys::is_root() && std::path::Path::new("/run").is_dir() {
        return PathBuf::from("/run/myrun");
    }
    if let Ok(x) = std::env::var("XDG_RUNTIME_DIR") {
        if !x.is_empty() {
            return PathBuf::from(x).join("myrun");
        }
    }
    PathBuf::from(format!("/tmp/myrun-{}", crate::sys::geteuid()))
}

pub fn containers_dir() -> PathBuf {
    runtime_root().join("containers")
}

pub fn ensure_root() -> Result<PathBuf> {
    let r = runtime_root();
    util::mkdir_p(r.join("containers"))?;
    Ok(r)
}

/// Name of the veth pair ends for a container.
///
/// Linux caps interface names at 15 characters (`IFNAMSIZ - 1`), so the
/// container id is hashed down to 8 hex digits.
pub fn veth_names(id: &str) -> (String, String) {
    let h = util::fnv1a(id.as_bytes());
    let suffix = format!("{:08x}", (h & 0xffff_ffff) as u32);
    (format!("mrv{}", suffix), format!("mrp{}", suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veth_names_fit_ifnamsiz_and_are_stable() {
        let (a, b) = veth_names("0123456789abcdef0123456789abcdef");
        assert!(a.len() <= 15 && b.len() <= 15, "{} {}", a, b);
        assert_ne!(a, b);
        let (a2, _) = veth_names("0123456789abcdef0123456789abcdef");
        assert_eq!(a, a2, "names must be deterministic");
        let (a3, _) = veth_names("different");
        assert_ne!(a, a3);
    }

    #[test]
    fn runtime_root_honours_env() {
        std::env::set_var("MYRUN_ROOT", "/tmp/some-root");
        assert_eq!(runtime_root(), PathBuf::from("/tmp/some-root"));
        assert_eq!(containers_dir(), PathBuf::from("/tmp/some-root/containers"));
        std::env::remove_var("MYRUN_ROOT");
    }
}
