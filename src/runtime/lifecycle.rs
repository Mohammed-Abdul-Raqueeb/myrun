//! Lifecycle operations.
//!
//! These are the verbs the CLI exposes. They all follow the same shape:
//! take the container lock, load and reconcile the state, act, save.
//!
//! Operations act on the container **directly** — by signalling init's pid
//! and by writing to the cgroup — rather than by asking the shim to do it
//! over a socket. That means `myrun stop` still works if the shim has been
//! killed, which is exactly the situation in which you most want it to.

use crate::error::{Error, Result};
use crate::runtime::cgroup::Cgroup;
use crate::runtime::state::{ContainerState, Status, Store};
use crate::runtime::{shim, supervisor};
use crate::sys::ffi;
use crate::sys::process::{self, ExitStatus};
use crate::util;
use std::path::Path;
use std::time::{Duration, Instant};

/// Default grace period between SIGTERM and SIGKILL, in seconds.
pub const DEFAULT_STOP_TIMEOUT: u64 = 10;

fn cgroup_of(st: &ContainerState) -> Option<Cgroup> {
    st.cgroup_path
        .as_ref()
        .and_then(|p| Cgroup::attach(Path::new(p)).ok())
}

/// Start a created container, detached, via a shim.
pub fn start(store: &Store, id: &str) -> Result<ContainerState> {
    let _lock = store.lock(id)?;
    let mut st = supervisor::load_reconciled(store, id)?;
    match st.status {
        Status::Created => {}
        Status::Running | Status::Paused => {
            return Err(Error::state(format!(
                "container {} is already running",
                util::short_id(id)
            )))
        }
        other => {
            return Err(Error::state(format!(
                "container {} is {} and cannot be started again; create a new one",
                util::short_id(id),
                other.as_str()
            )))
        }
    }
    let spawned = shim::spawn(store, &st)?;
    // The shim owns the state file from here; re-read what it wrote.
    st = store.load(id)?;
    st.shim_pid = spawned.shim_pid;
    store.save(&st)?;
    Ok(st)
}

/// Send a signal to the container's init process.
///
/// `all` sends to every process in the cgroup instead, which is what you
/// want for SIGKILL — init could be stuck, and `cgroup.kill` cannot be
/// blocked or ignored.
pub fn kill(store: &Store, id: &str, signal: i32, all: bool) -> Result<()> {
    let _lock = store.lock(id)?;
    let mut st = supervisor::load_reconciled(store, id)?;
    if !st.status.is_live() {
        return Err(Error::state(format!(
            "container {} is {}",
            util::short_id(id),
            st.status.as_str()
        )));
    }
    // A frozen container cannot act on a signal; thaw it or the signal just
    // queues up and `myrun stop` appears to hang.
    if st.status == Status::Paused {
        if let Some(cg) = cgroup_of(&st) {
            let _ = cg.thaw();
        }
        st.transition(Status::Running)?;
    }

    if all && signal == ffi::SIGKILL {
        if let Some(cg) = cgroup_of(&st) {
            cg.kill_all()?;
            store.save(&st)?;
            return Ok(());
        }
    }
    process::kill_pid(st.init_pid, signal).map_err(|e| {
        Error::container(format!(
            "signalling container {}: {}",
            util::short_id(id),
            e
        ))
    })?;
    store.save(&st)?;
    Ok(())
}

/// Graceful stop: SIGTERM, wait, then SIGKILL the whole cgroup.
pub fn stop(store: &Store, id: &str, timeout_secs: u64) -> Result<ExitStatus> {
    {
        let _lock = store.lock(id)?;
        let mut st = supervisor::load_reconciled(store, id)?;
        if !st.status.is_live() {
            return Ok(ExitStatus {
                code: st.exit_code,
                signal: st.exit_signal,
            });
        }
        if st.status == Status::Paused {
            if let Some(cg) = cgroup_of(&st) {
                let _ = cg.thaw();
            }
            st.transition(Status::Running)?;
        }
        st.transition(Status::Stopping)?;
        store.save(&st)?;
        let _ = process::kill_pid(st.init_pid, ffi::SIGTERM);
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        let st = store.load(id)?;
        if !st.init_is_alive() {
            return finalize_stopped(store, id);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    crate::log_info!(
        "container {} did not exit within {}s; killing it",
        util::short_id(id),
        timeout_secs
    );
    {
        let _lock = store.lock(id)?;
        let st = store.load(id)?;
        match cgroup_of(&st) {
            Some(cg) => cg.kill_all()?,
            None => {
                let _ = process::kill_pid(st.init_pid, ffi::SIGKILL);
            }
        }
    }
    // SIGKILL is not instantaneous; give the kernel a moment.
    for _ in 0..100 {
        if !store.load(id)?.init_is_alive() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    finalize_stopped(store, id)
}

/// After the process is gone, make sure the state and resources agree.
fn finalize_stopped(store: &Store, id: &str) -> Result<ExitStatus> {
    let _lock = store.lock(id)?;
    let mut st = store.load(id)?;
    if st.init_is_alive() {
        return Err(Error::container(format!(
            "container {} is still alive after being killed",
            util::short_id(id)
        )));
    }
    // A shim, if there is one, records the exit status itself. Wait briefly
    // for it rather than racing it into the state file.
    if st.shim_pid > 0 && process::process_alive(st.shim_pid, None) {
        drop(_lock);
        for _ in 0..100 {
            let cur = store.load(id)?;
            if cur.status == Status::Stopped && cur.exit_code.is_some() {
                return Ok(ExitStatus {
                    code: cur.exit_code,
                    signal: cur.exit_signal,
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut cur = store.load(id)?;
        supervisor::teardown(store, &mut cur);
        return Ok(ExitStatus {
            code: cur.exit_code,
            signal: cur.exit_signal,
        });
    }

    supervisor::teardown(store, &mut st);
    Ok(ExitStatus {
        code: st.exit_code,
        signal: st.exit_signal,
    })
}

pub fn pause(store: &Store, id: &str) -> Result<()> {
    let _lock = store.lock(id)?;
    let mut st = supervisor::load_reconciled(store, id)?;
    if st.status != Status::Running {
        return Err(Error::state(format!(
            "container {} is {}, not running",
            util::short_id(id),
            st.status.as_str()
        )));
    }
    let cg = cgroup_of(&st).ok_or_else(|| {
        Error::unsupported("pausing needs a cgroup; this container was started without one")
    })?;
    cg.freeze()?;
    st.transition(Status::Paused)?;
    store.save(&st)?;
    Ok(())
}

pub fn unpause(store: &Store, id: &str) -> Result<()> {
    let _lock = store.lock(id)?;
    let mut st = supervisor::load_reconciled(store, id)?;
    if st.status != Status::Paused {
        return Err(Error::state(format!(
            "container {} is {}, not paused",
            util::short_id(id),
            st.status.as_str()
        )));
    }
    let cg = cgroup_of(&st)
        .ok_or_else(|| Error::unsupported("this container has no cgroup to unfreeze"))?;
    cg.thaw()?;
    st.transition(Status::Running)?;
    store.save(&st)?;
    Ok(())
}

/// Remove a container. Running containers need `force`.
pub fn delete(store: &Store, id: &str, force: bool) -> Result<()> {
    let mut st = {
        let _lock = store.lock(id)?;
        supervisor::load_reconciled(store, id)?
    };

    if st.status.is_live() {
        if !force {
            return Err(Error::state(format!(
                "container {} is {}; stop it first or use --force",
                util::short_id(id),
                st.status.as_str()
            )));
        }
        stop(store, id, 5)?;
        st = store.load(id)?;
    }

    let _lock = store.lock(id)?;
    supervisor::teardown(store, &mut st);
    drop(_lock);
    store.remove(id)?;
    crate::log_info!("removed container {}", util::short_id(id));
    Ok(())
}

/// Block until the container is no longer running and return its status.
pub fn wait(store: &Store, id: &str, timeout_secs: Option<u64>) -> Result<ExitStatus> {
    let deadline = timeout_secs.map(|t| Instant::now() + Duration::from_secs(t));
    loop {
        let mut st = store.load(id)?;
        store.reconcile(&mut st)?;
        if !st.status.is_live() {
            return Ok(ExitStatus {
                code: st.exit_code,
                signal: st.exit_signal,
            });
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                return Err(Error::container(format!(
                    "timed out waiting for container {}",
                    util::short_id(id)
                )));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Read the captured output of a container.
pub fn logs(store: &Store, id: &str, tail: Option<usize>) -> Result<String> {
    let p = store.log_path(id);
    if !p.exists() {
        return Ok(String::new());
    }
    let text = util::read_to_string(&p)?;
    match tail {
        Some(n) => {
            let lines: Vec<&str> = text.lines().collect();
            let start = lines.len().saturating_sub(n);
            Ok(lines[start..].join("\n"))
        }
        None => Ok(text),
    }
}

/// Follow a container's log, printing new data as it appears.
pub fn follow_logs(store: &Store, id: &str, mut sink: impl std::io::Write) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let p = store.log_path(id);
    let mut f = std::fs::File::open(&p)
        .map_err(|e| Error::io(format!("opening {}: {}", p.display(), e)))?;
    let mut pos = 0u64;
    let mut buf = [0u8; 8192];
    loop {
        f.seek(SeekFrom::Start(pos))
            .map_err(|e| Error::io(e.to_string()))?;
        loop {
            let n = f.read(&mut buf).map_err(|e| Error::io(e.to_string()))?;
            if n == 0 {
                break;
            }
            pos += n as u64;
            sink.write_all(&buf[..n])
                .map_err(|e| Error::io(e.to_string()))?;
        }
        let _ = sink.flush();
        let st = store.load(id)?;
        if !st.status.is_live() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContainerConfig;

    fn store_in(tag: &str) -> (crate::testutil::TempRoot, Store) {
        let root = crate::testutil::TempRoot::new(tag);
        let store = Store::open().unwrap();
        (root, store)
    }

    fn created(store: &Store, name: &str) -> ContainerState {
        let mut c = ContainerConfig::default();
        c.rootfs = "/tmp".into();
        c.command = vec!["/bin/true".into()];
        c.name = Some(name.to_string());
        c.network.mode = crate::config::NetworkMode::None;
        c.finalize_and_validate(true).unwrap();
        let mut st = ContainerState::new(c);
        store.create(&st).unwrap();
        st.transition(Status::Created).unwrap();
        store.save(&st).unwrap();
        st
    }

    #[test]
    fn operations_reject_wrong_states() {
        let (_root, store) = store_in("states");
        let st = created(&store, "c1");

        // Not running yet.
        assert!(pause(&store, &st.id).is_err());
        assert!(unpause(&store, &st.id).is_err());
        assert!(kill(&store, &st.id, ffi::SIGTERM, false).is_err());

        // Stopping a created container is a no-op, not an error.
        let r = stop(&store, &st.id, 1).unwrap();
        assert!(r.code.is_none());

        // Delete works from Created.
        delete(&store, &st.id, false).unwrap();
        assert!(!store.exists(&st.id));
    }

    #[test]
    fn delete_refuses_a_live_container_without_force() {
        let (_root, store) = store_in("delforce");
        let mut st = created(&store, "c2");
        st.transition(Status::Running).unwrap();
        // A pid that is alive: our own test process.
        st.init_pid = crate::sys::getpid();
        st.init_start_time = process::read_proc_stat(st.init_pid).unwrap().start_time;
        store.save(&st).unwrap();

        let err = delete(&store, &st.id, false).unwrap_err();
        assert!(err.to_string().contains("--force"), "{}", err);
    }

    #[test]
    fn wait_returns_immediately_for_stopped_containers() {
        let (_root, store) = store_in("wait");
        let mut st = created(&store, "c3");
        st.transition(Status::Stopped).unwrap();
        st.exit_code = Some(3);
        store.save(&st).unwrap();
        let r = wait(&store, &st.id, Some(1)).unwrap();
        assert_eq!(r.code, Some(3));
    }

    #[test]
    fn logs_tail() {
        let (_root, store) = store_in("logs");
        let st = created(&store, "c4");
        std::fs::write(store.log_path(&st.id), "a\nb\nc\nd\n").unwrap();
        assert_eq!(logs(&store, &st.id, Some(2)).unwrap(), "c\nd");
        assert_eq!(logs(&store, &st.id, None).unwrap(), "a\nb\nc\nd\n");
    }

    #[test]
    fn missing_log_is_empty_not_an_error() {
        let (_root, store) = store_in("nolog");
        let st = created(&store, "c5");
        assert_eq!(logs(&store, &st.id, None).unwrap(), "");
    }

    #[test]
    fn a_dead_running_container_is_reconciled_before_acting() {
        let (_root, store) = store_in("reconcile");
        let mut st = created(&store, "c6");
        st.transition(Status::Running).unwrap();
        st.init_pid = 0x7fff_fffe;
        st.init_start_time = 1;
        store.save(&st).unwrap();
        // delete without force succeeds because reconcile marks it stopped.
        delete(&store, &st.id, false).unwrap();
        assert!(!store.exists(&st.id));
    }
}
