//! Shared helpers for the integration tests.
//!
//! Two things matter here:
//!
//! * **Privileged tests must skip, not fail.** Creating namespaces, cgroups
//!   and veth pairs needs root. A developer running `cargo test` as an
//!   ordinary user should get a clear "skipped, needs root" line rather than
//!   a wall of permission errors that hides the real failures.
//! * **Every test gets its own state root.** Tests run in parallel; sharing
//!   `/run/myrun` would mean one test's `gc` deleting another's container.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Path to the built `myrun` binary.
pub fn binary() -> PathBuf {
    // CARGO_BIN_EXE_ is set by cargo for integration tests.
    if let Some(p) = option_env!("CARGO_BIN_EXE_myrun") {
        return PathBuf::from(p);
    }
    // Fall back to the sibling of the test executable.
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("myrun")
}

/// True when this process can actually create containers.
pub fn is_root() -> bool {
    unsafe { libc_geteuid() == 0 }
}

extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Privileged tests are opt-in: `MYRUN_PRIVILEGED_TESTS=1 cargo test`.
///
/// They create real bridges and iptables rules on the host, so running them
/// by accident on a developer workstation would be rude.
pub fn privileged_enabled() -> bool {
    matches!(
        std::env::var("MYRUN_PRIVILEGED_TESTS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Guard for a privileged test. Returns `false` (after printing why) when
/// the test cannot run here.
#[macro_export]
macro_rules! require_privileged {
    ($name:expr) => {
        if !$crate::common::is_root() {
            eprintln!("SKIP {}: needs root", $name);
            return;
        }
        if !$crate::common::privileged_enabled() {
            eprintln!(
                "SKIP {}: set MYRUN_PRIVILEGED_TESTS=1 to run tests that \
                 create namespaces, cgroups and network interfaces",
                $name
            );
            return;
        }
        if !$crate::common::rootfs_available() {
            eprintln!(
                "SKIP {}: no test rootfs; run scripts/setup-rootfs.sh first",
                $name
            );
            return;
        }
    };
}

/// Guard for a test that needs working cgroup v2 controllers.
#[macro_export]
macro_rules! require_controllers {
    ($name:expr, $($c:expr),+) => {
        $(
            if !$crate::common::controller_available($c) {
                eprintln!(
                    "SKIP {}: cgroup v2 controller {:?} is not delegated on this host \
                     (hybrid or v1 cgroups); boot with systemd.unified_cgroup_hierarchy=1",
                    $name, $c
                );
                return;
            }
        )+
    };
}

pub fn rootfs() -> PathBuf {
    PathBuf::from(
        std::env::var("MYRUN_TEST_ROOTFS").unwrap_or_else(|_| "/tmp/myrun-rootfs".to_string()),
    )
}

pub fn rootfs_available() -> bool {
    rootfs().join("bin/sh").exists()
}

/// Is a cgroup v2 controller actually usable here?
pub fn controller_available(name: &str) -> bool {
    let mount = match myrun::sys::mount::find_cgroup2_mount() {
        Some(m) => PathBuf::from(m),
        None => return false,
    };
    myrun::runtime::cgroup::available_controllers(&mount)
        .iter()
        .any(|c| c == name)
}

/// An isolated runtime root that is torn down with the test.
pub struct Sandbox {
    pub root: PathBuf,
    pub name_prefix: String,
}

impl Sandbox {
    pub fn new(tag: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "myrun-it-{}-{}-{}",
            std::process::id(),
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("containers")).unwrap();
        Sandbox {
            root,
            name_prefix: format!("it{}", tag),
        }
    }

    /// Run `myrun` with this sandbox's state root.
    pub fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(binary());
        cmd.env("MYRUN_ROOT", &self.root)
            // Most CI machines and this development environment run hybrid
            // cgroups; resource tests check the controllers explicitly, so
            // the rest should not be blocked by their absence.
            .env("MYRUN_ALLOW_MISSING_CONTROLLERS", "1")
            .args(args);
        cmd.output().expect("failed to execute myrun")
    }

    /// Run with an extra environment variable (used for fault injection).
    pub fn run_env(&self, env: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = Command::new(binary());
        cmd.env("MYRUN_ROOT", &self.root)
            .env("MYRUN_ALLOW_MISSING_CONTROLLERS", "1");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.args(args);
        cmd.output().expect("failed to execute myrun")
    }

    /// Convenience: `myrun run <rootfs> /bin/sh -c <script>`, captured.
    pub fn sh(&self, script: &str) -> Output {
        let rootfs = rootfs();
        self.run(&["run", rootfs.to_str().unwrap(), "/bin/sh", "-c", script])
    }

    pub fn sh_with(&self, extra: &[&str], script: &str) -> Output {
        let rootfs = rootfs();
        let mut args: Vec<&str> = vec!["run"];
        args.extend_from_slice(extra);
        let r = rootfs.to_str().unwrap().to_string();
        args.push(&r);
        args.push("/bin/sh");
        args.push("-c");
        args.push(script);
        self.run(&args)
    }

    pub fn container_ids(&self) -> Vec<String> {
        let d = self.root.join("containers");
        let mut v = Vec::new();
        if let Ok(entries) = std::fs::read_dir(d) {
            for e in entries.flatten() {
                v.push(e.file_name().to_string_lossy().to_string());
            }
        }
        v
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // Kill anything still running, then clean up host resources.
        let _ = self.run(&["gc"]);
        for id in self.container_ids() {
            let _ = self.run(&["rm", "-f", &id]);
        }
        let _ = self.run(&["gc"]);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub fn stdout_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

pub fn stderr_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

pub fn combined(o: &Output) -> String {
    format!("{}{}", stdout_of(o), stderr_of(o))
}

pub fn code_of(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

/// Assert a command succeeded, printing everything useful when it did not.
pub fn assert_ok(o: &Output, what: &str) {
    assert!(
        o.status.success(),
        "{} failed with {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        what,
        o.status.code(),
        stdout_of(o),
        stderr_of(o)
    );
}

/// Count host veth interfaces created by myrun.
pub fn myrun_veth_count() -> usize {
    match myrun::sys::netlink::Netlink::open() {
        Ok(mut nl) => nl
            .list_links()
            .map(|l| l.iter().filter(|n| n.starts_with("mrv")).count())
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Count container cgroups under the runtime's base cgroup.
pub fn myrun_cgroup_count() -> usize {
    let mount = match myrun::sys::mount::find_cgroup2_mount() {
        Some(m) => PathBuf::from(m),
        None => return 0,
    };
    let base = mount.join(myrun::runtime::cgroup::BASE_NAME);
    match std::fs::read_dir(base) {
        Ok(entries) => entries.flatten().filter(|e| e.path().is_dir()).count(),
        Err(_) => 0,
    }
}

/// Number of iptables rules tagged for a container id.
pub fn iptables_rule_count(id: &str) -> usize {
    myrun::runtime::nat::rule_count(id)
}

/// Wait for a predicate, polling. Returns false on timeout.
pub fn wait_until(timeout_ms: u64, mut f: impl FnMut() -> bool) -> bool {
    let step = 50;
    let mut waited = 0;
    loop {
        if f() {
            return true;
        }
        if waited >= timeout_ms {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(step));
        waited += step;
    }
}

/// Read a container's recorded state as JSON.
pub fn state_json(sb: &Sandbox, id: &str) -> myrun::util::json::Json {
    let p = sb.root.join("containers").join(id).join("state.json");
    let text =
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {}", p.display(), e));
    myrun::util::json::parse(&text).expect("state.json should be valid JSON")
}

pub fn path_exists(p: &Path) -> bool {
    p.exists()
}
