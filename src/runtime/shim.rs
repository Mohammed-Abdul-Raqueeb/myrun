//! The shim: the process that owns a detached container.
//!
//! `myrun run -d` cannot simply start a container and exit — something has
//! to stay alive to reap init, record the exit status, and tear down the
//! cgroup, veth and iptables rules afterwards. That something is the shim:
//! a forked, `setsid`-detached copy of myrun that holds the container and
//! nothing else.
//!
//! ```text
//!   myrun run -d
//!     │ fork
//!     ├──────────────► shim (setsid, new session, stdio -> container.log)
//!     │                  │ launch()
//!     │                  ├──────────► init (PID 1) ──► workload
//!     │  <── notify ─────┤ "container is up" / "it failed because ..."
//!     └─ prints id,      │
//!        exits           │ wait_for_exit(), teardown()
//!                        └─ exits
//! ```
//!
//! The notify pipe is what makes `myrun run -d` able to report a *startup*
//! failure with a real message and a non-zero exit code, instead of the
//! usual "detached fine, silently died a millisecond later".

use crate::error::{Error, Result};
use crate::runtime::state::{ContainerState, Status, Store};
use crate::runtime::supervisor;
use crate::sys::ffi::{self, c_int, c_void};
use crate::sys::{close_fd, open_path};
use crate::util;
use std::path::{Path, PathBuf};

/// Reply written to the notify pipe: one byte of status, then a message.
const NOTIFY_OK: u8 = b'+';
const NOTIFY_ERR: u8 = b'-';

/// Run as the shim. Never returns.
pub fn main(state_dir: &Path, notify_fd: c_int) -> ! {
    crate::logging::set_role(crate::logging::ROLE_SHIM);
    crate::sys::set_process_name("myrun-shim");

    let code = match run(state_dir, notify_fd) {
        Ok(c) => c,
        Err(e) => {
            crate::log_error!("shim: {}", e);
            notify(notify_fd, NOTIFY_ERR, &e.to_string());
            e.exit_code()
        }
    };
    unsafe { ffi::_exit(code) }
}

fn notify(fd: c_int, status: u8, msg: &str) {
    if fd < 0 {
        return;
    }
    let mut buf = vec![status];
    buf.extend_from_slice(msg.as_bytes());
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe { ffi::write(fd, buf[off..].as_ptr() as *const c_void, buf.len() - off) };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
    close_fd(fd);
}

/// Point stdout/stderr at the container log so the workload's output is
/// captured rather than written to whatever terminal happened to start it.
fn redirect_output(log_path: &Path) -> Result<()> {
    let fd = open_path(
        log_path,
        ffi::O_WRONLY | ffi::O_CREAT | ffi::O_APPEND | ffi::O_CLOEXEC,
    )?;
    unsafe {
        ffi::dup2(fd, 1);
        ffi::dup2(fd, 2);
    }
    close_fd(fd);
    // stdin becomes /dev/null: a detached container has no terminal, and a
    // workload that reads stdin should see EOF, not block forever.
    if let Ok(null) = open_path(Path::new("/dev/null"), ffi::O_RDONLY) {
        unsafe {
            ffi::dup2(null, 0);
        }
        close_fd(null);
    }
    Ok(())
}

fn run(state_dir: &Path, notify_fd: c_int) -> Result<i32> {
    // A new session detaches us from the caller's terminal, so a Ctrl-C in
    // the shell that started the container does not kill it.
    let _ = crate::sys::setsid();

    let id = state_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .ok_or_else(|| Error::usage("shim needs a container state directory"))?;

    let store = Store::open()?;
    let mut st = store.load(&id)?;
    redirect_output(&store.log_path(&id))?;

    let mut running = match supervisor::launch(&store, &mut st) {
        Ok(r) => r,
        Err(e) => {
            // launch() already rolled back; record why and let the caller
            // see the message.
            st.error = Some(e.to_string());
            st.status = Status::Stopped;
            st.finished_at = util::now_ms();
            let _ = store.save(&st);
            return Err(e);
        }
    };

    st.shim_pid = crate::sys::getpid();
    store.save(&st)?;
    notify(
        notify_fd,
        NOTIFY_OK,
        &format!("{} {}", st.id, running.child.pid),
    );

    crate::log_info!(
        "container {} running as pid {}",
        util::short_id(&st.id),
        running.child.pid
    );

    let status = supervisor::wait_for_exit(&store, &mut st, &mut running)?;
    crate::log_info!(
        "container {} exited: {}",
        util::short_id(&st.id),
        status.describe()
    );

    supervisor::teardown(&store, &mut st);

    if st.config.auto_remove {
        if let Err(e) = store.remove(&st.id) {
            crate::log_warn!("auto-remove failed: {}", e);
        }
    }
    Ok(status.exit_code())
}

/// Result of asking a shim to start a container.
pub struct Spawned {
    pub shim_pid: i32,
    pub container_pid: i32,
}

/// Fork a shim for `st` and wait until it reports success or failure.
///
/// Runs in the CLI process. The fork-without-exec is deliberate: the child
/// is a copy of a single-threaded process that immediately re-roles itself,
/// so there is no exec needed, no window where the binary path matters, and
/// no dependence on argv[0] being resolvable.
pub fn spawn(store: &Store, st: &ContainerState) -> Result<Spawned> {
    let mut fds = [0 as c_int; 2];
    crate::sys::chk(
        unsafe { ffi::pipe2(fds.as_mut_ptr(), ffi::O_CLOEXEC) },
        "pipe2",
        "shim notify pipe",
    )?;
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let state_dir: PathBuf = store.dir(&st.id);

    let pid = crate::sys::process::fork_process()?;
    if pid == 0 {
        close_fd(read_fd);
        // The write end must survive exec-less re-roling; clear CLOEXEC so
        // it is still there if a future version does exec.
        let _ = crate::sys::set_cloexec(write_fd, false);
        main(&state_dir, write_fd);
    }
    close_fd(write_fd);

    // Read the shim's verdict. EOF without a byte means it died before it
    // could tell us anything.
    let mut buf = [0u8; 4096];
    let mut got = 0usize;
    loop {
        let n = unsafe {
            ffi::read(
                read_fd,
                buf[got..].as_mut_ptr() as *mut c_void,
                buf.len() - got,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(ffi::EINTR) {
                continue;
            }
            close_fd(read_fd);
            return Err(Error::io(format!("reading shim status: {}", e)));
        }
        if n == 0 {
            break;
        }
        got += n as usize;
        if got == buf.len() {
            break;
        }
    }
    close_fd(read_fd);

    if got == 0 {
        // Reap it so it does not linger as a zombie, then report.
        let _ = crate::sys::process::wait_pid(pid, ffi::WNOHANG);
        return Err(Error::container(
            "the container shim exited without reporting a status; \
             check the container log for details",
        ));
    }

    let msg = String::from_utf8_lossy(&buf[1..got]).to_string();
    if buf[0] == NOTIFY_ERR {
        let _ = crate::sys::process::wait_pid(pid, ffi::WNOHANG);
        return Err(Error::container(msg));
    }

    let container_pid = msg
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(Spawned {
        shim_pid: pid,
        container_pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_encoding_roundtrip() {
        let mut fds = [0 as c_int; 2];
        crate::sys::chk(unsafe { ffi::pipe2(fds.as_mut_ptr(), 0) }, "pipe2", "test").unwrap();
        notify(fds[1], NOTIFY_OK, "abc123 4242");
        let mut buf = [0u8; 128];
        let n = unsafe { ffi::read(fds[0], buf.as_mut_ptr() as *mut c_void, buf.len()) };
        assert!(n > 0);
        let got = &buf[..n as usize];
        assert_eq!(got[0], NOTIFY_OK);
        assert_eq!(String::from_utf8_lossy(&got[1..]), "abc123 4242");
        close_fd(fds[0]);
    }

    #[test]
    fn error_notifications_are_distinguishable() {
        let mut fds = [0 as c_int; 2];
        crate::sys::chk(unsafe { ffi::pipe2(fds.as_mut_ptr(), 0) }, "pipe2", "test").unwrap();
        notify(fds[1], NOTIFY_ERR, "pivot_root failed");
        let mut buf = [0u8; 128];
        let n = unsafe { ffi::read(fds[0], buf.as_mut_ptr() as *mut c_void, buf.len()) };
        let got = &buf[..n as usize];
        assert_eq!(got[0], NOTIFY_ERR);
        assert!(String::from_utf8_lossy(&got[1..]).contains("pivot_root"));
        close_fd(fds[0]);
    }
}
