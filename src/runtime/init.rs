//! Container init — PID 1 inside the container.
//!
//! Reached by re-executing the myrun binary as `myrun __init <state-dir>`
//! inside the freshly cloned namespaces. It is a real init, not a wrapper:
//!
//! * **It must reap.** PID 1 inherits every orphan in its namespace. Without
//!   a reaping loop the container fills up with zombies and eventually hits
//!   `pids.max`.
//! * **It must forward signals.** `myrun stop` signals init; the workload is
//!   init's child and would otherwise never see it.
//! * **It must not let the kernel's PID-1 signal semantics fool it.** PID 1
//!   does not get default signal dispositions, so an unhandled SIGTERM is
//!   simply discarded. Signals are therefore blocked and drained from a
//!   `signalfd` rather than handled.
//! * **It must exit with the workload's status**, so `myrun run` can be used
//!   in a shell pipeline like any other command.

use crate::config::ContainerConfig;
use crate::error::{Error, Result};
use crate::runtime::ipc::{Channel, TAG_GO, TAG_READY, TAG_STARTED};
use crate::runtime::state::NetworkState;
use crate::runtime::{filesystem, network, security};
use crate::sys::ffi::{self, c_char, c_int, pid_t};
use crate::sys::process::{self, ExitStatus};
use crate::sys::signal as sig;
use crate::util;
use crate::util::json;
use std::ffi::CString;
use std::path::{Path, PathBuf};

/// The descriptor the parent hands init the sync channel on.
pub const SYNC_FD: c_int = 3;

/// Entry point for `myrun __init <state-dir>`.
///
/// Never returns: it always ends in `_exit`, because unwinding out of PID 1
/// would run destructors in a process whose filesystem has been pivoted
/// away underneath it.
pub fn main(state_dir: &Path) -> ! {
    crate::logging::set_role(crate::logging::ROLE_INIT);
    crate::sys::set_process_name("myrun-init");
    let chan = Channel::from_raw(SYNC_FD);

    match run(state_dir, &chan) {
        Ok(status) => {
            let code = status.code.unwrap_or(-1);
            let signal = status.signal.unwrap_or(0);
            let _ = chan.send_exit(code, signal);
            unsafe { ffi::_exit(status.exit_code()) }
        }
        Err(e) => {
            crate::log_error!("{}", e);
            let _ = chan.send_error(&e.to_string());
            unsafe { ffi::_exit(e.exit_code()) }
        }
    }
}

fn read_config(state_dir: &Path) -> Result<ContainerConfig> {
    let p = state_dir.join("config.json");
    let text = util::read_to_string(&p)?;
    ContainerConfig::from_json(&json::parse(&text)?)
}

fn read_network_state(state_dir: &Path) -> NetworkState {
    let p = state_dir.join("netstate.json");
    match util::read_to_string(&p)
        .ok()
        .and_then(|t| json::parse(&t).ok())
    {
        Some(j) => {
            let mut st = NetworkState::default();
            let s = |k: &str| j.get(k).and_then(|v| v.as_str()).map(|x| x.to_string());
            st.mode = s("mode").unwrap_or_else(|| "none".into());
            st.container_veth = s("container_veth");
            st.ip = s("ip");
            st.gateway = s("gateway");
            st.prefix = j.get("prefix").and_then(|v| v.as_u64()).unwrap_or(24) as u8;
            st
        }
        None => NetworkState::default(),
    }
}

fn run(state_dir: &Path, chan: &Channel) -> Result<ExitStatus> {
    let cfg = read_config(state_dir)?;
    crate::log_debug!("init running for container {}", util::short_id(&cfg.id));

    // Tell the parent the namespaces exist, then wait for it to finish the
    // host-side work (cgroup membership, veth peer).
    chan.send_tag(TAG_READY)?;
    crate::fault::check("before_go_signal")?;
    chan.expect(TAG_GO)?;
    crate::fault::check("after_go_signal")?;

    // Read the network state the parent just wrote — must happen before the
    // pivot, while the state directory is still reachable.
    let netstate = read_network_state(state_dir);

    setup(&cfg, &netstate)?;

    // Signals are blocked *before* the fork so neither we nor the child can
    // miss one in the window between fork and the supervision loop. The
    // child unblocks them itself.
    let blocked = sig::block(sig::FORWARDED)?;
    let sfd = sig::SignalFd::new(sig::FORWARDED)?;

    crate::fault::check("before_exec")?;
    let child = spawn_workload(&cfg, &blocked)?;
    crate::log_debug!("workload started as pid {} inside the container", child);

    chan.send_tag(TAG_STARTED)?;

    let status = supervise(child, &sfd);
    crate::log_debug!("workload exited: {}", status.describe());

    // Give anything else in the namespace a chance to shut down, then make
    // sure nothing is left: exiting PID 1 kills the namespace anyway, but
    // doing it deliberately means the exit is orderly.
    shutdown_remaining();
    Ok(status)
}

/// Everything between the go signal and the fork.
fn setup(cfg: &ContainerConfig, netstate: &NetworkState) -> Result<()> {
    // Hostname: needs the UTS namespace, which we are already in.
    if cfg.namespaces.uts {
        crate::sys::sethostname_str(&cfg.hostname)?;
    }

    // Filesystem, including pivot_root. After this call the host root is
    // detached and paths mean container paths.
    filesystem::setup(cfg)?;

    // Interfaces inside the network namespace.
    if cfg.namespaces.net {
        network::configure_inside(netstate)
            .map_err(|e| Error::container(format!("configuring container network: {}", e)))?;
    }
    network::write_resolver_files(cfg, netstate);

    filesystem::enter_cwd(&cfg.cwd)?;

    // Capabilities, no_new_privs, seccomp — last, because everything above
    // needs privileges this removes.
    security::apply(&cfg.security)?;
    Ok(())
}

/// Resolve `argv[0]` against `PATH` the way `execvp` would.
pub fn resolve_exe(cmd: &str, path_env: Option<&str>) -> Result<PathBuf> {
    let is_executable = |p: &Path| -> bool {
        match std::fs::metadata(p) {
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                m.is_file() && m.permissions().mode() & 0o111 != 0
            }
            Err(_) => false,
        }
    };

    if cmd.contains('/') {
        let p = PathBuf::from(cmd);
        if is_executable(&p) {
            return Ok(p);
        }
        return Err(Error::not_found(format!(
            "{} is not an executable file in the container",
            cmd
        )));
    }
    let path = path_env.unwrap_or(crate::config::DEFAULT_PATH);
    for dir in path.split(':').filter(|d| !d.is_empty()) {
        let candidate = Path::new(dir).join(cmd);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::not_found(format!(
        "executable {:?} not found in the container's PATH ({})",
        cmd, path
    )))
}

/// Fork the workload. The child never returns.
fn spawn_workload(cfg: &ContainerConfig, blocked: &ffi::SigSet) -> Result<pid_t> {
    let exe = resolve_exe(&cfg.command[0], cfg.env_value("PATH"))?;

    // Build the C strings before forking: allocation after fork in a
    // process with threads is not async-signal-safe, and more importantly a
    // failure here is far easier to report from the parent.
    let c_exe = CString::new(exe.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::cfg("command path contains a NUL byte"))?;
    let argv: Vec<CString> = cfg
        .command
        .iter()
        .map(|a| CString::new(a.as_str()).map_err(|_| Error::cfg("argument contains a NUL byte")))
        .collect::<Result<_>>()?;
    let envp: Vec<CString> = cfg
        .env
        .iter()
        .map(|a| {
            CString::new(a.as_str()).map_err(|_| Error::cfg("environment contains a NUL byte"))
        })
        .collect::<Result<_>>()?;
    let mut argv_ptrs: Vec<*const c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const c_char> = envp.iter().map(|c| c.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let uid_gid = cfg.security.user;

    let pid = process::fork_process()?;
    if pid == 0 {
        // ---- child: async-signal-safe territory, no allocation ----
        // Default dispositions and an empty signal mask: the workload must
        // behave exactly as if the shell had started it.
        sig::reset_handlers();
        let _ = sig::unblock_all();

        if let Some((uid, gid)) = uid_gid {
            if crate::sys::caps::switch_user(uid, gid).is_err() {
                unsafe { ffi::_exit(126) }
            }
        }
        unsafe {
            ffi::execve(c_exe.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            // Only reached if execve failed. 127 is the shell's convention
            // for "command not found", 126 for "found but not executable".
            ffi::_exit(127)
        }
    }
    let _ = blocked; // the mask is already installed in this process
    Ok(pid)
}

/// The supervision loop: forward signals, reap orphans, return the
/// workload's exit status.
fn supervise(workload: pid_t, sfd: &sig::SignalFd) -> ExitStatus {
    let mut result: Option<ExitStatus> = None;
    let mut fds = [ffi::PollFd {
        fd: sfd.fd(),
        events: ffi::POLLIN,
        revents: 0,
    }];

    loop {
        // Reap first: SIGCHLD may have arrived before we got here, and a
        // waitpid before the poll avoids a lost-wakeup hang.
        for (pid, status) in process::reap_all() {
            if pid == workload {
                crate::log_debug!("workload {} exited: {}", pid, status.describe());
                result = Some(status);
            } else {
                crate::log_trace!("reaped orphan {}: {}", pid, status.describe());
            }
        }
        if let Some(status) = result {
            return status;
        }

        // 200ms cap so a missed SIGCHLD cannot wedge init forever.
        match sig::poll_fds(&mut fds, 200) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(e) => {
                crate::log_warn!("poll failed in init: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        }

        while let Ok(Some(info)) = sfd.next_signal() {
            let signo = info.ssi_signo as c_int;
            if signo == ffi::SIGCHLD {
                continue; // handled by the reap loop above
            }
            crate::log_debug!(
                "forwarding {} to workload {}",
                process::signal_name(signo),
                workload
            );
            if let Err(e) = process::kill_pid(workload, signo) {
                crate::log_debug!("could not forward signal: {}", e);
            }
        }
    }
}

/// Terminate anything still running in the namespace.
///
/// Exiting PID 1 makes the kernel SIGKILL the rest of the PID namespace, so
/// this is about giving them a chance to exit cleanly first.
fn shutdown_remaining() {
    let remaining = process::list_pids_in_proc("/proc").unwrap_or_default();
    let others: Vec<pid_t> = remaining.into_iter().filter(|p| *p != 1).collect();
    if others.is_empty() {
        return;
    }
    crate::log_debug!(
        "{} process(es) still running; sending SIGTERM",
        others.len()
    );
    for p in &others {
        let _ = process::kill_pid(*p, ffi::SIGTERM);
    }
    // Brief grace period, reaping as they go.
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(25));
        process::reap_all();
        let left = process::list_pids_in_proc("/proc")
            .unwrap_or_default()
            .into_iter()
            .filter(|p| *p != 1)
            .count();
        if left == 0 {
            return;
        }
    }
    for p in others {
        let _ = process::kill_pid(p, ffi::SIGKILL);
    }
    process::reap_all();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_absolute_paths() {
        let sh = resolve_exe("/bin/sh", None).unwrap();
        assert_eq!(sh, PathBuf::from("/bin/sh"));
        assert!(resolve_exe("/bin/definitely-not-here", None).is_err());
        // A directory is not an executable.
        assert!(resolve_exe("/tmp", None).is_err());
    }

    #[test]
    fn resolves_via_path() {
        let sh = resolve_exe("sh", Some("/nonexistent:/bin:/usr/bin")).unwrap();
        assert!(sh.ends_with("sh"), "{:?}", sh);
        let err = resolve_exe("sh", Some("/nonexistent")).unwrap_err();
        assert!(err.to_string().contains("not found"), "{}", err);
    }

    #[test]
    fn empty_path_segments_are_skipped() {
        // "::" in PATH means the current directory to some shells; we
        // deliberately do not honour that inside a container.
        let r = resolve_exe("sh", Some("::/bin"));
        assert!(r.is_ok());
    }

    #[test]
    fn network_state_missing_file_is_a_default() {
        let dir = std::env::temp_dir().join(format!("myrun-init-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let st = read_network_state(&dir);
        assert_eq!(st.mode, "none");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn network_state_is_read_back() {
        let dir = std::env::temp_dir().join(format!("myrun-init2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let mut j = json::Json::obj();
        j.set("mode", json::Json::Str("bridge".into()));
        j.set("ip", json::Json::Str("10.87.0.4".into()));
        j.set("gateway", json::Json::Str("10.87.0.1".into()));
        j.set("prefix", json::Json::Int(24));
        j.set("container_veth", json::Json::Str("eth0".into()));
        std::fs::write(dir.join("netstate.json"), j.to_string()).unwrap();
        let st = read_network_state(&dir);
        assert_eq!(st.mode, "bridge");
        assert_eq!(st.ip.as_deref(), Some("10.87.0.4"));
        assert_eq!(st.prefix, 24);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
