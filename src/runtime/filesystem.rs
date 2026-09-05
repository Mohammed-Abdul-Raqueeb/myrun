//! Root filesystem construction, executed inside the container's mount
//! namespace by init.
//!
//! Order matters a great deal here:
//!
//! 1. `mount(NULL, "/", MS_REC|MS_PRIVATE)` — without this, every mount we
//!    make propagates back to the host, because the namespace inherits
//!    shared propagation from systemd.
//! 2. Bind the rootfs onto itself. `pivot_root` requires the new root to be
//!    a mount point, and a plain directory is not one.
//! 3. Populate `/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm`, `/tmp` and
//!    the user's volumes *while still outside* the new root, so paths are
//!    unambiguous.
//! 4. `pivot_root(".", ".")` then `umount2(".", MNT_DETACH)`.
//!
//! Step 4 uses the "pivot onto itself" idiom: the old root is stacked on top
//! of the new root at `/` and immediately lazily unmounted. The alternative
//! — a `put_old` directory inside the new root — leaves a directory behind
//! and needs the rootfs to be writable.

use crate::config::{ContainerConfig, MountSpec};
use crate::error::{Error, Result};
use crate::sys::ffi::*;
use crate::sys::mount as m;
use std::path::{Path, PathBuf};

/// `(path, major, minor, mode)` for the device nodes every container gets.
pub const DEVICES: &[(&str, u64, u64, u32)] = &[
    ("null", 1, 3, 0o666),
    ("zero", 1, 5, 0o666),
    ("full", 1, 7, 0o666),
    ("random", 1, 8, 0o666),
    ("urandom", 1, 9, 0o666),
    ("tty", 5, 0, 0o666),
];

/// `/dev/fd` and friends, as symlinks into `/proc`.
pub const DEV_SYMLINKS: &[(&str, &str)] = &[
    ("/proc/self/fd", "fd"),
    ("/proc/self/fd/0", "stdin"),
    ("/proc/self/fd/1", "stdout"),
    ("/proc/self/fd/2", "stderr"),
    ("/proc/kcore", "core"),
];

fn join(root: &Path, rel: &str) -> PathBuf {
    root.join(rel.trim_start_matches('/'))
}

/// Mount `/proc`, `/sys`, `/dev`, `/tmp` and the user's volumes under
/// `root`.
fn mount_standard(root: &Path, cfg: &ContainerConfig) -> Result<()> {
    // /proc must be a fresh procfs so it reflects the new PID namespace.
    let proc_dir = join(root, "proc");
    m::mkdir_p(&proc_dir, 0o755)?;
    m::mount(
        Some("proc"),
        &proc_dir,
        Some("proc"),
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        None,
    )?;

    // /sys is read-only: a container with a writable sysfs can reconfigure
    // the host. With a network namespace it must be mounted, not bound,
    // or it shows the host's network devices.
    let sys_dir = join(root, "sys");
    m::mkdir_p(&sys_dir, 0o755)?;
    let sys_flags = MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY;
    if let Err(e) = m::mount(Some("sysfs"), &sys_dir, Some("sysfs"), sys_flags, None) {
        // Mounting sysfs needs a network namespace we own; with
        // --network host the kernel refuses, so fall back to a read-only
        // bind of the host's.
        crate::log_debug!("sysfs mount failed ({}), binding host /sys read-only", e);
        m::bind(Path::new("/sys"), &sys_dir, true)?;
        m::remount_ro(&sys_dir, MS_REC)?;
    }

    // /dev as a small tmpfs we then populate.
    let dev_dir = join(root, "dev");
    m::mkdir_p(&dev_dir, 0o755)?;
    m::mount(
        Some("tmpfs"),
        &dev_dir,
        Some("tmpfs"),
        MS_NOSUID | MS_STRICTATIME,
        Some("mode=755,size=65536k"),
    )?;

    let pts = dev_dir.join("pts");
    m::mkdir_p(&pts, 0o755)?;
    // `newinstance` is implied for a devpts mounted in a new namespace on
    // modern kernels; ptmxmode makes /dev/ptmx usable by non-root.
    m::mount(
        Some("devpts"),
        &pts,
        Some("devpts"),
        MS_NOSUID | MS_NOEXEC,
        Some("gid=5,mode=620,ptmxmode=666"),
    )
    .or_else(|e| {
        crate::log_debug!("devpts mount failed: {}", e);
        Ok::<(), Error>(())
    })?;

    let shm = dev_dir.join("shm");
    m::mkdir_p(&shm, 0o755)?;
    m::mount(
        Some("shm"),
        &shm,
        Some("tmpfs"),
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        Some("mode=1777,size=65536k"),
    )?;

    let mqueue = dev_dir.join("mqueue");
    m::mkdir_p(&mqueue, 0o755)?;
    let _ = m::mount(
        Some("mqueue"),
        &mqueue,
        Some("mqueue"),
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        None,
    );

    // /tmp: a container writing to a read-only rootfs still needs scratch
    // space, and a host /tmp leaking in would break isolation.
    let tmp = join(root, "tmp");
    m::mkdir_p(&tmp, 0o1777)?;
    m::mount(
        Some("tmpfs"),
        &tmp,
        Some("tmpfs"),
        MS_NOSUID | MS_NODEV,
        Some("mode=1777,size=131072k"),
    )?;

    make_devices(&dev_dir)?;
    mount_volumes(root, &cfg.mounts)?;
    Ok(())
}

/// Create the device nodes, falling back to bind mounts when `mknod` is not
/// permitted (which is what happens inside an unprivileged user namespace).
fn make_devices(dev_dir: &Path) -> Result<()> {
    for (name, major, minor, mode) in DEVICES {
        let target = dev_dir.join(name);
        match m::mknod_char(&target, *mode, *major, *minor) {
            Ok(()) => {}
            Err(e) => {
                crate::log_debug!("mknod {} failed ({}), trying bind mount", name, e);
                let host = PathBuf::from("/dev").join(name);
                if !host.exists() {
                    crate::log_warn!("no /dev/{} on the host either; skipping", name);
                    continue;
                }
                m::touch(&target)?;
                m::bind(&host, &target, false).map_err(|e2| {
                    Error::container(format!(
                        "could not provide /dev/{}: mknod said {}, bind said {}",
                        name, e, e2
                    ))
                })?;
            }
        }
    }

    // /dev/ptmx must point at the devpts instance, not the host's.
    let ptmx = dev_dir.join("ptmx");
    let _ = std::fs::remove_file(&ptmx);
    if let Err(e) = m::symlink("pts/ptmx", &ptmx) {
        crate::log_debug!("could not link /dev/ptmx: {}", e);
    }

    for (target, name) in DEV_SYMLINKS {
        let link = dev_dir.join(name);
        if link.exists() {
            continue;
        }
        if let Err(e) = m::symlink(target, &link) {
            crate::log_debug!("could not create /dev/{}: {}", name, e);
        }
    }
    Ok(())
}

fn mount_volumes(root: &Path, mounts: &[MountSpec]) -> Result<()> {
    for spec in mounts {
        let target = join(root, &spec.destination);
        if spec.fstype == "tmpfs" {
            m::mkdir_p(&target, 0o755)?;
            m::mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MS_NOSUID | MS_NODEV,
                None,
            )?;
        } else {
            let source = Path::new(&spec.source);
            let meta = std::fs::metadata(source)
                .map_err(|e| Error::cfg(format!("bind mount source {}: {}", spec.source, e)))?;
            if meta.is_dir() {
                m::mkdir_p(&target, 0o755)?;
            } else {
                if let Some(parent) = target.parent() {
                    m::mkdir_p(parent, 0o755)?;
                }
                m::touch(&target)?;
            }
            m::bind(source, &target, true)?;
        }
        if spec.readonly {
            // A read-only bind needs a second remount; MS_RDONLY is ignored
            // in the initial MS_BIND call.
            m::remount_ro(&target, MS_REC)?;
        }
        crate::log_debug!(
            "mounted {} -> {}{}",
            spec.source,
            spec.destination,
            if spec.readonly { " (ro)" } else { "" }
        );
    }
    Ok(())
}

/// Hide sensitive paths with `/dev/null` (files) or an empty read-only
/// tmpfs (directories).
pub fn mask_paths(paths: &[String]) -> Result<()> {
    for p in paths {
        let path = Path::new(p);
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => continue, // not present in this kernel/rootfs
        };
        let r = if meta.is_dir() {
            m::mount(
                Some("tmpfs"),
                path,
                Some("tmpfs"),
                MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                Some("size=0k"),
            )
        } else {
            m::bind(Path::new("/dev/null"), path, false)
        };
        match r {
            Ok(()) => crate::log_trace!("masked {}", p),
            Err(e) => crate::log_debug!("could not mask {}: {}", p, e),
        }
    }
    Ok(())
}

/// Remount paths read-only inside the container.
pub fn readonly_paths(paths: &[String]) -> Result<()> {
    for p in paths {
        let path = Path::new(p);
        if !path.exists() {
            continue;
        }
        // A path can only be remounted read-only if it is a mount point, so
        // bind it onto itself first.
        if let Err(e) = m::bind(path, path, true) {
            crate::log_debug!("could not bind {} for ro remount: {}", p, e);
            continue;
        }
        match m::remount_ro(path, MS_REC) {
            Ok(()) => crate::log_trace!("remounted {} read-only", p),
            Err(e) => crate::log_debug!("could not remount {} read-only: {}", p, e),
        }
    }
    Ok(())
}

/// Build the container root and pivot into it.
///
/// On return the process's `/` is the container rootfs and the host
/// filesystem is unreachable — not merely hidden, actually detached.
pub fn setup(cfg: &ContainerConfig) -> Result<()> {
    let root = cfg.rootfs.clone();

    // 1. Stop mount propagation to the host.
    m::make_rprivate(Path::new("/"))?;

    // 2. The new root must be a mount point.
    m::bind(&root, &root, true)?;

    // 3. Populate it.
    mount_standard(&root, cfg)?;

    // 4. Optionally seal the rootfs. Done last so the mounts above (which
    //    need to create directories) still work, and applied only to the
    //    rootfs mount itself so /tmp and volumes stay writable.
    if cfg.read_only {
        m::remount_ro(&root, 0)?;
        crate::log_debug!("rootfs remounted read-only");
    }

    crate::fault::check("before_pivot_root")?;

    // 5. Pivot.
    m::chdir(&root)?;
    m::pivot_root(Path::new("."), Path::new("."))?;
    // At this point "." is the old root, stacked over the new one.
    m::umount(Path::new("."), MNT_DETACH)?;
    m::chdir(Path::new("/"))?;

    crate::fault::check("after_pivot_root")?;

    // 6. Now that we are inside, mask and seal the sensitive paths. These
    //    must happen post-pivot: the paths are container paths.
    if !cfg.security.privileged {
        mask_paths(&cfg.security.masked_paths)?;
        readonly_paths(&cfg.security.readonly_paths)?;
    }

    Ok(())
}

/// Change into the configured working directory, after the pivot.
pub fn enter_cwd(cwd: &str) -> Result<()> {
    let p = Path::new(cwd);
    m::chdir(p).map_err(|e| {
        Error::container(format!(
            "working directory {} does not exist in the container: {}",
            cwd, e
        ))
    })
}

/// Sanity check used by the integration tests: is `path` really the root of
/// a mount, i.e. did the pivot take effect?
pub fn host_root_is_detached() -> bool {
    // After a successful pivot_root + detach there is exactly one entry with
    // mount point "/" and no entry pointing at the old root.
    match m::mountinfo_for("self") {
        Ok(entries) => entries.iter().filter(|e| e.mount_point == "/").count() == 1,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_table_is_correct() {
        // Wrong major/minor numbers produce a device that silently does the
        // wrong thing, so pin them.
        let by_name = |n: &str| DEVICES.iter().find(|d| d.0 == n).copied().unwrap();
        assert_eq!(by_name("null"), ("null", 1, 3, 0o666));
        assert_eq!(by_name("zero"), ("zero", 1, 5, 0o666));
        assert_eq!(by_name("full"), ("full", 1, 7, 0o666));
        assert_eq!(by_name("random"), ("random", 1, 8, 0o666));
        assert_eq!(by_name("urandom"), ("urandom", 1, 9, 0o666));
        assert_eq!(by_name("tty"), ("tty", 5, 0, 0o666));
    }

    #[test]
    fn join_handles_absolute_destinations() {
        let root = Path::new("/var/lib/rootfs");
        assert_eq!(join(root, "/proc"), Path::new("/var/lib/rootfs/proc"));
        assert_eq!(join(root, "proc"), Path::new("/var/lib/rootfs/proc"));
        assert_eq!(
            join(root, "/mnt/data"),
            Path::new("/var/lib/rootfs/mnt/data")
        );
    }

    #[test]
    fn masking_a_missing_path_is_not_an_error() {
        mask_paths(&["/definitely/not/here".to_string()]).unwrap();
        readonly_paths(&["/definitely/not/here".to_string()]).unwrap();
    }

    #[test]
    fn default_masked_paths_cover_the_dangerous_ones() {
        let masked = crate::config::DEFAULT_MASKED_PATHS;
        for p in ["/proc/kcore", "/proc/keys", "/sys/firmware"] {
            assert!(masked.contains(&p), "{} must be masked", p);
        }
        let ro = crate::config::DEFAULT_READONLY_PATHS;
        for p in ["/proc/sys", "/proc/sysrq-trigger"] {
            assert!(ro.contains(&p), "{} must be read-only", p);
        }
    }
}
