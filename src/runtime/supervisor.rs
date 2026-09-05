//! Parent-side orchestration: turn a validated config into a running
//! container, or leave the host exactly as it was found.
//!
//! The launch sequence, and why it is in this order:
//!
//! ```text
//!   1. cgroup created           (needs to exist before the process does,
//!                                so CLONE_INTO_CGROUP can use it)
//!   2. binary sealed into memfd (CVE-2019-5736: the child must not be able
//!                                to rewrite /proc/self/exe)
//!   3. clone3(CLONE_NEW*)       (namespaces + cgroup placement, atomically)
//!   4. wait for READY           (namespaces now exist and are enterable)
//!   5. network set up by pid    (veth peer moved into the child's netns)
//!   6. netstate.json written    (init reads it before it pivots away)
//!   7. send GO                  (init does mounts/pivot/security)
//!   8. wait for STARTED         (or a typed error from inside)
//! ```
//!
//! Every resource created between 1 and 7 is registered with a
//! [`Rollback`], so a failure at step 7 removes the veth, the lease, the
//! iptables rules and the cgroup before returning.

use crate::error::{Error, Result};
use crate::rollback::Rollback;
use crate::runtime::cgroup::Cgroup;
use crate::runtime::ipc::{Channel, TAG_STARTED};
use crate::runtime::state::{ContainerState, Status, Store};
use crate::runtime::{network, state};
use crate::sys::ffi;
use crate::sys::process::{self, Child, CloneRequest, ExecPlan, ExitStatus};
use crate::util;
use crate::util::json::Json;
use std::path::Path;

/// A container that has been started and not yet waited on.
pub struct Running {
    pub child: Child,
    pub chan: Channel,
    pub cgroup: Option<Cgroup>,
}

impl Running {
    pub fn pid(&self) -> i32 {
        self.child.pid
    }
}

/// Create the container's state directory without starting anything.
pub fn create(store: &Store, mut st: ContainerState) -> Result<ContainerState> {
    crate::fault::check("before_state_create")?;
    store.create(&st)?;
    crate::fault::check("after_state_create")?;
    st.transition(Status::Created)?;
    store.save(&st)?;
    Ok(st)
}

fn write_netstate(store: &Store, st: &ContainerState) -> Result<()> {
    let mut j = Json::obj();
    j.set("mode", Json::Str(st.network.mode.clone()));
    let os = |v: &Option<String>| v.clone().map(Json::Str).unwrap_or(Json::Null);
    j.set("ip", os(&st.network.ip));
    j.set("gateway", os(&st.network.gateway));
    j.set("container_veth", os(&st.network.container_veth));
    j.set("prefix", Json::Int(st.network.prefix as i64));
    util::write_atomic(
        store.dir(&st.id).join("netstate.json"),
        &j.to_string_pretty(),
    )
}

/// Start a container that is in the `Created` state.
///
/// On success `st` is updated to `Running` and saved. On failure the host is
/// returned to its prior condition and `st` is left describing a stopped
/// container.
pub fn launch(store: &Store, st: &mut ContainerState) -> Result<Running> {
    if st.status != Status::Created {
        return Err(Error::state(format!(
            "container {} is {}, not created; cannot start it",
            util::short_id(&st.id),
            st.status.as_str()
        )));
    }
    let cfg = st.config.clone();
    let mut rb = Rollback::new();

    // --- 1. cgroup -------------------------------------------------------
    let cgroup = match Cgroup::create(&st.id, &cfg.resources) {
        Ok(cg) => {
            let path = cg.path.clone();
            rb.push("cgroup", move || {
                Cgroup::attach(&path).and_then(|c| c.remove())
            });
            st.cgroup_path = Some(cg.path.display().to_string());
            Some(cg)
        }
        Err(e) if cfg.resources.is_empty() && e.exit_code() == crate::error::exit::UNSUPPORTED => {
            // No limits were asked for, so a missing cgroup2 hierarchy is
            // survivable — the container just has no accounting.
            crate::log_warn!("running without a cgroup: {}", e);
            None
        }
        Err(e) => return Err(e),
    };

    // --- 2. sealed copy of ourselves -------------------------------------
    // Held in an OwnedFd so that any `?` between here and the clone closes
    // it instead of leaking a descriptor (and, for the memfd, its memory).
    let (exe_fd_raw, sealed) = process::sealed_self_exe()?;
    let exe_fd = crate::sys::OwnedFd::new(exe_fd_raw);
    if !sealed {
        crate::log_warn!(
            "could not seal the runtime binary in memory; \
             a malicious container image could in principle overwrite it"
        );
    }

    // --- 3. clone --------------------------------------------------------
    let (parent_chan, child_chan) = Channel::pair()?;
    let state_dir = store.dir(&st.id);
    let argv = vec![
        "myrun-init".to_string(),
        "__init".to_string(),
        state_dir.display().to_string(),
    ];
    let envp = init_environment();
    let plan = ExecPlan::new(exe_fd.get(), &argv, &envp)?;

    let cgroup_fd = match &cgroup {
        Some(cg) => cg.open_fd().ok().map(crate::sys::OwnedFd::new),
        None => None,
    };
    let placed_by_clone = cgroup_fd.is_some();

    crate::fault::check("before_clone")?;
    let req = CloneRequest {
        flags: cfg.namespaces.clone_flags(),
        cgroup_fd: cgroup_fd.as_ref().map(|f| f.get()),
        sync_fd: child_chan.fd(),
        exit_signal: ffi::SIGCHLD,
        // If we die unexpectedly, init dies too rather than becoming an
        // orphaned container nobody is tracking.
        pdeathsig: Some(ffi::SIGKILL),
        plan: &plan,
    };
    let child = process::clone_child(&req)?;
    crate::fault::check("after_clone")?;

    // The child owns its end now; keeping it open in the parent would stop
    // us from ever seeing EOF. The two OwnedFds close themselves here.
    drop(child_chan);
    drop(cgroup_fd);
    drop(exe_fd);

    let pid = child.pid;
    {
        // From here on a failure must kill the child.
        rb.push("container process", move || {
            let _ = process::kill_pid(pid, ffi::SIGKILL);
            let _ = process::wait_pid(pid, 0);
            Ok(())
        });
    }

    // If CLONE_INTO_CGROUP was unavailable, move the process now. This is
    // the racy path, which is exactly why it is the fallback.
    if let Some(cg) = &cgroup {
        if !placed_by_clone {
            cg.add_pid(pid)?;
        }
    }

    st.init_pid = pid;
    st.init_start_time = match process::read_proc_stat(pid) {
        Ok(s) => s.start_time,
        Err(e) => {
            // Not fatal: liveness checks fall back to a pid-only test. Worth
            // saying out loud, because it means PID reuse is no longer
            // detectable for this container.
            crate::log_warn!("could not read the start time of pid {}: {}", pid, e);
            0
        }
    };

    // --- 4. wait for the namespaces --------------------------------------
    parent_chan.expect(crate::runtime::ipc::TAG_READY)?;

    // --- 5. network ------------------------------------------------------
    let netstate = network::setup_host(&cfg, pid, &mut rb)?;
    st.network = netstate;
    {
        let id = st.id.clone();
        let ns = st.network.clone();
        rb.push("container network", move || {
            network::teardown(&id, &ns);
            Ok(())
        });
    }

    // --- 6. hand the network details to init -----------------------------
    write_netstate(store, st)?;

    // --- 7/8. go, and wait for confirmation ------------------------------
    parent_chan.send_tag(crate::runtime::ipc::TAG_GO)?;
    parent_chan.expect(TAG_STARTED)?;

    st.transition(Status::Running)?;
    st.error = None;
    store.save(st)?;
    crate::fault::check("after_start")?;

    rb.commit();
    Ok(Running {
        child,
        chan: parent_chan,
        cgroup,
    })
}

/// The environment handed to `myrun __init`.
///
/// Deliberately minimal: the container's own environment comes from
/// `config.json`, and inheriting the caller's would leak host details into
/// PID 1.
fn init_environment() -> Vec<String> {
    let mut env = vec![format!("PATH={}", crate::config::DEFAULT_PATH)];
    for key in ["MYRUN_LOG", "MYRUN_FAULT"] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                env.push(format!("{}={}", key, v));
            }
        }
    }
    env
}

/// Block until the container exits, then record the result.
///
/// Prefers the exit frame from init (which knows the workload's status)
/// and falls back to `waitpid` (which only knows init's).
pub fn wait_for_exit(
    store: &Store,
    st: &mut ContainerState,
    running: &mut Running,
) -> Result<ExitStatus> {
    let mut from_init: Option<ExitStatus> = None;
    loop {
        match running.chan.recv() {
            Ok(Some((crate::runtime::ipc::TAG_EXIT, payload))) => {
                if let Some((code, signal)) = Channel::parse_exit(&payload) {
                    from_init = Some(ExitStatus {
                        code: if code >= 0 { Some(code) } else { None },
                        signal: if signal > 0 { Some(signal) } else { None },
                    });
                }
            }
            Ok(Some((tag, payload))) => {
                if tag == crate::runtime::ipc::TAG_ERROR {
                    st.error = Some(String::from_utf8_lossy(&payload).to_string());
                }
            }
            // EOF: init is gone.
            Ok(None) => break,
            Err(e) => {
                crate::log_debug!("sync channel error while waiting: {}", e);
                break;
            }
        }
    }

    let waited = process::wait_pid(running.child.pid, 0)?;
    let status = from_init
        .or_else(|| waited.map(|(_, s)| s))
        .unwrap_or(ExitStatus {
            code: Some(-1),
            signal: None,
        });

    if let Some(cg) = &running.cgroup {
        if cg.was_oom_killed() {
            st.oom_killed = true;
            crate::log_info!("container {} was OOM-killed", util::short_id(&st.id));
        }
    }

    st.record_exit(status);
    let _ = st.transition(Status::Stopped);
    store.save(st)?;
    Ok(status)
}

/// Release everything a running container owns. Idempotent and best effort:
/// this is the path taken after a crash as well as after a clean exit.
pub fn teardown(store: &Store, st: &mut ContainerState) {
    crate::fault::check("before_teardown").ok();

    if st.init_pid > 0 && st.init_is_alive() {
        let _ = process::kill_pid(st.init_pid, ffi::SIGKILL);
        let _ = process::wait_pid(st.init_pid, ffi::WNOHANG);
    }

    if let Some(path) = &st.cgroup_path {
        match Cgroup::attach(Path::new(path)) {
            Ok(cg) => {
                if cg.was_oom_killed() {
                    st.oom_killed = true;
                }
                let _ = cg.kill_all();
                if let Err(e) = cg.remove() {
                    crate::log_warn!("removing cgroup: {}", e);
                }
            }
            Err(_) => { /* already gone */ }
        }
    }

    network::teardown(&st.id, &st.network);

    if st.status.is_live() {
        st.status = Status::Stopped;
        if st.finished_at == 0 {
            st.finished_at = util::now_ms();
        }
    }
    let _ = store.save(st);
}

/// Reconcile every container's recorded state with reality and clean up
/// anything orphaned. Returns a human-readable list of what was collected.
pub fn gc(store: &Store) -> Result<Vec<String>> {
    let mut report = Vec::new();
    let mut live_ids = Vec::new();

    for mut st in store.list()? {
        let corrected = store.reconcile(&mut st)?;
        if corrected {
            report.push(format!(
                "{}: marked stopped (init process was gone)",
                util::short_id(&st.id)
            ));
            teardown(store, &mut st);
        }
        if st.status.is_live() {
            live_ids.push(st.id.clone());
        }
    }

    let n = crate::runtime::cgroup::gc_empty(&live_ids);
    if n > 0 {
        report.push(format!("removed {} orphaned cgroup(s)", n));
    }

    match crate::runtime::ipam::gc(&live_ids) {
        Ok(n) if n > 0 => report.push(format!("released {} stale IP lease(s)", n)),
        Ok(_) => {}
        Err(e) => crate::log_warn!("ipam gc: {}", e),
    }

    match network::orphaned_veths(&live_ids) {
        Ok(veths) => {
            for v in veths {
                match crate::sys::netlink::Netlink::open().and_then(|mut nl| {
                    let idx = nl.link_index_required(&v)?;
                    nl.delete_link(idx)
                }) {
                    Ok(()) => report.push(format!("deleted orphaned interface {}", v)),
                    Err(e) => crate::log_warn!("deleting {}: {}", v, e),
                }
            }
        }
        Err(e) => crate::log_debug!("listing veths: {}", e),
    }

    if live_ids.is_empty() {
        if let Ok(true) = network::remove_bridge_if_unused(crate::config::DEFAULT_BRIDGE) {
            report.push(format!(
                "removed unused bridge {}",
                crate::config::DEFAULT_BRIDGE
            ));
        }
        // The shared MASQUERADE/FORWARD rules and our chains only make sense
        // while at least one container exists. Removing them here is what
        // makes `gc` leave the host's packet filter exactly as it found it.
        let base_rules = crate::runtime::nat::rule_count("base");
        if base_rules > 0 {
            crate::runtime::nat::teardown_base();
            report.push(format!("removed {} shared iptables rule(s)", base_rules));
        }
    }

    Ok(report)
}

/// Convenience used by `myrun list`: load, reconcile, return.
pub fn load_reconciled(store: &Store, id: &str) -> Result<ContainerState> {
    let mut st = store.load(id)?;
    store.reconcile(&mut st)?;
    Ok(st)
}

pub type StateStore = state::Store;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContainerConfig;

    fn store_in(tag: &str) -> (crate::testutil::TempRoot, Store) {
        let root = crate::testutil::TempRoot::new(tag);
        let store = Store::open().unwrap();
        (root, store)
    }

    fn cfg() -> ContainerConfig {
        let mut c = ContainerConfig::default();
        c.rootfs = "/tmp".into();
        c.command = vec!["/bin/true".into()];
        c.network.mode = crate::config::NetworkMode::None;
        c.finalize_and_validate(true).unwrap();
        c
    }

    #[test]
    fn create_moves_to_created_and_persists() {
        let (_root, store) = store_in("create");
        let st = create(&store, ContainerState::new(cfg())).unwrap();
        assert_eq!(st.status, Status::Created);
        let back = store.load(&st.id).unwrap();
        assert_eq!(back.status, Status::Created);
        assert!(store.config_path(&st.id).exists());
    }

    #[test]
    fn launching_a_non_created_container_is_rejected() {
        let (_root, store) = store_in("badstate");
        let mut st = ContainerState::new(cfg());
        store.create(&st).unwrap();
        // Still in Creating.
        let err = match launch(&store, &mut st) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("launch should have refused a container in Creating"),
        };
        assert!(err.contains("not created"), "{}", err);
    }

    #[test]
    fn init_environment_is_minimal() {
        std::env::set_var("MYRUN_LOG", "debug");
        std::env::set_var("SOME_HOST_SECRET", "leak-me");
        let env = init_environment();
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
        assert!(env.iter().any(|e| e == "MYRUN_LOG=debug"));
        assert!(
            !env.iter().any(|e| e.contains("SOME_HOST_SECRET")),
            "host environment must not leak into init: {:?}",
            env
        );
        std::env::remove_var("MYRUN_LOG");
        std::env::remove_var("SOME_HOST_SECRET");
    }

    #[test]
    fn netstate_is_written_for_init() {
        let (_root, store) = store_in("netstate");
        let mut st = ContainerState::new(cfg());
        store.create(&st).unwrap();
        st.network.mode = "bridge".into();
        st.network.ip = Some("10.87.0.9".into());
        st.network.gateway = Some("10.87.0.1".into());
        st.network.prefix = 24;
        write_netstate(&store, &st).unwrap();
        let p = store.dir(&st.id).join("netstate.json");
        let text = util::read_to_string(&p).unwrap();
        assert!(text.contains("10.87.0.9"));
    }
}
