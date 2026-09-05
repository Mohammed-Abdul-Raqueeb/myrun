//! cgroup v2 resource control.
//!
//! Layout:
//!
//! ```text
//!   <cgroup2 mount>/                 cgroup.subtree_control += memory cpu pids
//!   └── myrun/                       cgroup.subtree_control += memory cpu pids
//!       └── <container id>/          <- the container's processes live here
//!           ├── cgroup.procs
//!           ├── memory.max, memory.swap.max
//!           ├── cpu.max, cpu.weight
//!           ├── pids.max
//!           ├── cgroup.freeze         (pause / unpause)
//!           └── cgroup.kill           (atomic kill of the whole subtree)
//! ```
//!
//! Only the leaf holds processes, which keeps the kernel's "no internal
//! processes" rule satisfied and lets us enable controllers on `myrun/`.
//!
//! **v2 only, on purpose.** cgroup v1's split hierarchies make atomic
//! creation and teardown genuinely racy, and v1 has no `cgroup.kill` and no
//! `CLONE_INTO_CGROUP`. Rather than silently produce a container with no
//! effective limits on a v1/hybrid host, `create` fails with an explanatory
//! error unless the caller opts into a degraded run.

use crate::config::Resources;
use crate::error::{Error, Result};
use crate::sys::ffi;
use crate::sys::mount::find_cgroup2_mount;
use crate::util;
use std::path::{Path, PathBuf};

/// Controllers we ask for.  `memory` and `pids` are hard requirements for a
/// meaningful limit; `cpu` is needed for `--cpus` / `--cpu-weight`.
pub const WANTED: &[&str] = &["memory", "cpu", "pids"];

pub const BASE_NAME: &str = "myrun";

/// Escape hatch for hosts (CI containers, hybrid-cgroup systems) where the
/// controllers are not delegated to cgroup v2.
pub fn allow_missing_controllers() -> bool {
    matches!(
        std::env::var("MYRUN_ALLOW_MISSING_CONTROLLERS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CgroupStats {
    pub memory_current: Option<u64>,
    pub memory_peak: Option<u64>,
    pub memory_max: Option<u64>,
    pub oom_kills: u64,
    pub cpu_usage_usec: Option<u64>,
    pub cpu_user_usec: Option<u64>,
    pub cpu_system_usec: Option<u64>,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
    pub pids_current: Option<u64>,
    pub pids_max: Option<u64>,
}

/// A container's cgroup.
#[derive(Debug, Clone)]
pub struct Cgroup {
    /// Absolute path of the leaf directory.
    pub path: PathBuf,
    /// Controllers actually enabled for the leaf.
    pub enabled: Vec<String>,
}

/// Find the cgroup v2 mount point, or explain why we cannot proceed.
pub fn mount_point() -> Result<PathBuf> {
    match find_cgroup2_mount() {
        Some(m) => Ok(PathBuf::from(m)),
        None => Err(Error::unsupported(
            "no cgroup2 filesystem is mounted; myrun requires cgroup v2 \
             (mount one with: mount -t cgroup2 none /sys/fs/cgroup)",
        )),
    }
}

fn read_list(p: &Path) -> Vec<String> {
    util::read_trimmed(p)
        .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
        .unwrap_or_default()
}

/// Controllers available for delegation at `dir` (i.e. its
/// `cgroup.controllers`).
pub fn available_controllers(dir: &Path) -> Vec<String> {
    read_list(&dir.join("cgroup.controllers"))
}

/// Ask `dir` to delegate `wanted` to its children.
///
/// Writing each controller separately means one unavailable controller does
/// not silently discard the rest of the request.
fn enable_subtree(dir: &Path, wanted: &[String]) -> Vec<String> {
    let mut ok = Vec::new();
    let already = read_list(&dir.join("cgroup.subtree_control"));
    for c in wanted {
        if already.contains(c) {
            ok.push(c.clone());
            continue;
        }
        match util::write_file(dir.join("cgroup.subtree_control"), &format!("+{}", c)) {
            Ok(()) => ok.push(c.clone()),
            Err(e) => crate::log_debug!(
                "could not enable controller {} in {}: {}",
                c,
                dir.display(),
                e
            ),
        }
    }
    ok
}

/// Which controllers does this configuration actually need?
pub fn required_for(res: &Resources) -> Vec<&'static str> {
    let mut v = Vec::new();
    if res.memory.is_some() || res.memory_swap.is_some() {
        v.push("memory");
    }
    if res.cpus.is_some() || res.cpu_weight.is_some() {
        v.push("cpu");
    }
    if res.pids.is_some() {
        v.push("pids");
    }
    v
}

impl Cgroup {
    /// Create `<mount>/myrun/<id>` with as many controllers as the host
    /// will delegate.
    pub fn create(id: &str, res: &Resources) -> Result<Cgroup> {
        let mount = mount_point()?;
        let base = mount.join(BASE_NAME);

        let wanted: Vec<String> = WANTED.iter().map(|s| s.to_string()).collect();
        // Delegate from the root down to the leaf's parent.
        enable_subtree(&mount, &wanted);
        if !base.exists() {
            std::fs::create_dir(&base)
                .map_err(|e| Error::io(format!("creating cgroup {}: {}", base.display(), e)))?;
        }
        let enabled = enable_subtree(&base, &wanted);

        let required = required_for(res);
        let missing: Vec<&str> = required
            .iter()
            .copied()
            .filter(|c| !enabled.iter().any(|e| e == c))
            .collect();
        if !missing.is_empty() {
            let msg = format!(
                "cgroup v2 controller(s) {} are not available at {} \
                 (cgroup.controllers = [{}]). The requested limits cannot be \
                 enforced. This usually means the host is running cgroup v1 or \
                 hybrid mode, or the controllers are not delegated to this \
                 subtree. Boot with systemd.unified_cgroup_hierarchy=1, or set \
                 MYRUN_ALLOW_MISSING_CONTROLLERS=1 to run without enforcement.",
                missing.join(", "),
                mount.display(),
                available_controllers(&mount).join(" ")
            );
            if !allow_missing_controllers() {
                return Err(Error::unsupported(msg));
            }
            crate::log_warn!("{}", msg);
        }

        let path = base.join(id);
        if path.exists() {
            // Left over from a crashed run: reuse it only if it is empty.
            let _ = std::fs::remove_dir(&path);
        }
        std::fs::create_dir(&path)
            .map_err(|e| Error::io(format!("creating cgroup {}: {}", path.display(), e)))?;

        let cg = Cgroup { path, enabled };
        // Anything that fails from here on must not leave the directory
        // behind: the caller never receives the Cgroup, so it has nothing to
        // register with its rollback stack.
        let finish = || -> Result<()> {
            crate::fault::check("after_cgroup_create")?;
            cg.apply(res)?;
            crate::fault::check("after_cgroup_limits")?;
            Ok(())
        };
        if let Err(e) = finish() {
            let _ = std::fs::remove_dir(&cg.path);
            return Err(e);
        }
        Ok(cg)
    }

    /// Attach to an existing cgroup directory (used by the shim and by
    /// `stats`, which must not create anything).
    pub fn attach(path: &Path) -> Result<Cgroup> {
        if !path.is_dir() {
            return Err(Error::not_found(format!("cgroup {}", path.display())));
        }
        Ok(Cgroup {
            path: path.to_path_buf(),
            enabled: available_controllers(path),
        })
    }

    pub fn has(&self, controller: &str) -> bool {
        self.enabled.iter().any(|c| c == controller)
    }

    fn write(&self, file: &str, value: &str) -> Result<()> {
        util::write_file(self.path.join(file), value).map_err(|e| {
            Error::io(format!(
                "writing {:?} to {}/{}: {}",
                value,
                self.path.display(),
                file,
                e
            ))
        })
    }

    fn write_if(&self, controller: &str, file: &str, value: &str) -> Result<()> {
        if !self.has(controller) {
            crate::log_warn!(
                "controller {} unavailable; not writing {} = {}",
                controller,
                file,
                value
            );
            return Ok(());
        }
        self.write(file, value)
    }

    fn read(&self, file: &str) -> Option<String> {
        util::read_trimmed(self.path.join(file)).ok()
    }

    fn read_u64(&self, file: &str) -> Option<u64> {
        match self.read(file)?.as_str() {
            "max" => None,
            s => s.parse().ok(),
        }
    }

    /// Parse a flat keyed file (`cpu.stat`, `memory.events`).
    fn read_keyed(&self, file: &str) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        if let Some(text) = self.read(file) {
            for line in text.lines() {
                let mut it = line.split_whitespace();
                if let (Some(k), Some(v)) = (it.next(), it.next()) {
                    if let Ok(n) = v.parse::<u64>() {
                        out.push((k.to_string(), n));
                    }
                }
            }
        }
        out
    }

    fn keyed_value(&self, file: &str, key: &str) -> Option<u64> {
        self.read_keyed(file)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Write the configured limits.
    pub fn apply(&self, res: &Resources) -> Result<()> {
        if let Some(m) = res.memory {
            self.write_if("memory", "memory.max", &m.to_string())?;
        }
        match res.memory_swap {
            Some(s) => {
                // cgroup v2 counts swap separately from memory, unlike v1's
                // combined memsw limit. `--memory-swap` is specified as the
                // combined total, so subtract the memory limit.
                let swap_only = match res.memory {
                    Some(m) => s.saturating_sub(m),
                    None => s,
                };
                self.write_if("memory", "memory.swap.max", &swap_only.to_string())?;
            }
            None => {
                if res.memory.is_some() {
                    // A memory limit with unbounded swap is not a limit at
                    // all: the workload just swaps. Default to no swap.
                    let _ = self.write_if("memory", "memory.swap.max", "0");
                }
            }
        }
        if let Some(v) = res.cpu_max_value() {
            self.write_if("cpu", "cpu.max", &v)?;
        }
        if let Some(w) = res.cpu_weight {
            self.write_if("cpu", "cpu.weight", &w.to_string())?;
        }
        if let Some(p) = res.pids {
            self.write_if("pids", "pids.max", &p.to_string())?;
        }
        Ok(())
    }

    /// An `O_DIRECTORY` fd suitable for `clone3(CLONE_INTO_CGROUP)`.
    ///
    /// Placing the child in its cgroup *at creation time* closes the window
    /// in which the process exists outside the limits — with the write-to-
    /// `cgroup.procs` approach a fork bomb can escape before the move lands.
    pub fn open_fd(&self) -> Result<i32> {
        crate::sys::open_path(
            &self.path,
            ffi::O_RDONLY | ffi::O_DIRECTORY | ffi::O_CLOEXEC,
        )
    }

    pub fn add_pid(&self, pid: i32) -> Result<()> {
        self.write("cgroup.procs", &pid.to_string())
    }

    pub fn pids(&self) -> Vec<i32> {
        self.read("cgroup.procs")
            .map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect())
            .unwrap_or_default()
    }

    pub fn is_populated(&self) -> bool {
        self.keyed_value("cgroup.events", "populated").unwrap_or(0) == 1
    }

    /// `cgroup.freeze` — SIGSTOP for a whole subtree, without the workload
    /// being able to observe or block it.
    pub fn freeze(&self) -> Result<()> {
        self.write("cgroup.freeze", "1")
    }

    pub fn thaw(&self) -> Result<()> {
        self.write("cgroup.freeze", "0")
    }

    pub fn frozen(&self) -> bool {
        self.read("cgroup.freeze").as_deref() == Some("1")
    }

    /// `cgroup.kill` — atomically SIGKILL every process in the subtree.
    /// Nothing can fork away from it, which a `kill(-pid)` loop cannot
    /// promise.
    pub fn kill_all(&self) -> Result<()> {
        if self.path.join("cgroup.kill").exists() {
            return self.write("cgroup.kill", "1");
        }
        // Kernels older than 5.14 have no cgroup.kill; fall back to a
        // best-effort sweep.
        for pid in self.pids() {
            let _ = crate::sys::process::kill_pid(pid, ffi::SIGKILL);
        }
        Ok(())
    }

    pub fn stats(&self) -> CgroupStats {
        CgroupStats {
            memory_current: self.read_u64("memory.current"),
            memory_peak: self.read_u64("memory.peak"),
            memory_max: self.read_u64("memory.max"),
            oom_kills: self.keyed_value("memory.events", "oom_kill").unwrap_or(0),
            cpu_usage_usec: self.keyed_value("cpu.stat", "usage_usec"),
            cpu_user_usec: self.keyed_value("cpu.stat", "user_usec"),
            cpu_system_usec: self.keyed_value("cpu.stat", "system_usec"),
            nr_throttled: self.keyed_value("cpu.stat", "nr_throttled").unwrap_or(0),
            throttled_usec: self.keyed_value("cpu.stat", "throttled_usec").unwrap_or(0),
            pids_current: self.read_u64("pids.current"),
            pids_max: self.read_u64("pids.max"),
        }
    }

    /// True if the kernel OOM-killed something in this cgroup.
    pub fn was_oom_killed(&self) -> bool {
        self.stats().oom_kills > 0
    }

    /// Remove the cgroup.  `rmdir` only succeeds once every process is gone,
    /// so retry briefly to let exiting processes be reaped.
    pub fn remove(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        for attempt in 0..50 {
            match std::fs::remove_dir(&self.path) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let busy = e.raw_os_error() == Some(ffi::EBUSY);
                    if !busy && !self.path.exists() {
                        return Ok(());
                    }
                    if attempt == 0 && busy {
                        let _ = self.kill_all();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
        Err(Error::io(format!(
            "cgroup {} is still busy after 1s; processes may be unkillable (D state)",
            self.path.display()
        )))
    }
}

/// Remove any leftover container cgroups that have no processes.
pub fn gc_empty(live_ids: &[String]) -> usize {
    let base = match mount_point() {
        Ok(m) => m.join(BASE_NAME),
        Err(_) => return 0,
    };
    let mut removed = 0;
    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        if live_ids.contains(&name) {
            continue;
        }
        if let Ok(cg) = Cgroup::attach(&p) {
            if cg.pids().is_empty() && cg.remove().is_ok() {
                crate::log_info!("removed orphaned cgroup {}", p.display());
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_controllers_track_the_request() {
        let mut r = Resources::default();
        assert!(required_for(&r).is_empty());
        r.memory = Some(1 << 20);
        assert_eq!(required_for(&r), vec!["memory"]);
        r.cpus = Some(1.0);
        r.pids = Some(10);
        assert_eq!(required_for(&r), vec!["memory", "cpu", "pids"]);
    }

    #[test]
    fn detects_or_explains_cgroup2() {
        // Either the host has cgroup2 or we produce a useful error; both are
        // acceptable, an unhelpful failure is not.
        match mount_point() {
            Ok(p) => assert!(p.is_dir()),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("cgroup2"), "unhelpful error: {}", msg);
            }
        }
    }

    #[test]
    fn keyed_file_parsing() {
        let dir = std::env::temp_dir().join(format!("myrun-cg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("cpu.stat"),
            "usage_usec 12345\nuser_usec 100\nsystem_usec 200\nnr_throttled 3\nthrottled_usec 999\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("memory.events"),
            "low 0\nhigh 0\noom 2\noom_kill 1\n",
        )
        .unwrap();
        std::fs::write(dir.join("memory.current"), "4096\n").unwrap();
        std::fs::write(dir.join("memory.max"), "max\n").unwrap();
        std::fs::write(dir.join("pids.current"), "7\n").unwrap();

        let cg = Cgroup::attach(&dir).unwrap();
        let s = cg.stats();
        assert_eq!(s.cpu_usage_usec, Some(12345));
        assert_eq!(s.nr_throttled, 3);
        assert_eq!(s.throttled_usec, 999);
        assert_eq!(s.oom_kills, 1);
        assert_eq!(s.memory_current, Some(4096));
        assert_eq!(s.memory_max, None, "\"max\" means unlimited, not an error");
        assert_eq!(s.pids_current, Some(7));
        assert!(cg.was_oom_killed());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn swap_limit_is_converted_to_v2_semantics() {
        // v1 memsw = memory + swap; v2 memory.swap.max is swap alone.
        let mut r = Resources::default();
        r.memory = Some(100 * 1024 * 1024);
        r.memory_swap = Some(150 * 1024 * 1024);
        let dir = std::env::temp_dir().join(format!("myrun-cgswap-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        for f in ["memory.max", "memory.swap.max"] {
            std::fs::write(dir.join(f), "").unwrap();
        }
        let mut cg = Cgroup::attach(&dir).unwrap();
        cg.enabled = vec!["memory".into()];
        cg.apply(&r).unwrap();
        assert_eq!(
            util::read_trimmed(dir.join("memory.swap.max")).unwrap(),
            (50 * 1024 * 1024).to_string()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
