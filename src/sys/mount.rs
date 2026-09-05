//! `mount(2)`, `umount2(2)`, `pivot_root(2)` and `/proc/self/mountinfo`.

use super::ffi::*;
use super::{chk, chk_long, cpath, cstr};
use crate::error::{Error, Result};
use std::os::raw::{c_char, c_int, c_ulong, c_void};
use std::path::Path;

/// Raw `mount(2)`.
///
/// `source` and `fstype` are optional because the same syscall is used for
/// four very different operations:
///   * new filesystem      — source=device/name, fstype=Some
///   * bind mount          — source=path,        flags=MS_BIND
///   * remount             — flags=MS_REMOUNT
///   * propagation change  — flags=MS_PRIVATE/MS_SLAVE/...
pub fn mount(
    source: Option<&str>,
    target: &Path,
    fstype: Option<&str>,
    flags: c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let c_src = match source {
        Some(s) => Some(cstr(s)?),
        None => None,
    };
    let c_tgt = cpath(target)?;
    let c_fs = match fstype {
        Some(s) => Some(cstr(s)?),
        None => None,
    };
    let c_data = match data {
        Some(s) => Some(cstr(s)?),
        None => None,
    };
    let rc = unsafe {
        super::ffi::mount(
            c_src
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null()),
            c_tgt.as_ptr(),
            c_fs.as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null()),
            flags,
            c_data
                .as_ref()
                .map(|c| c.as_ptr() as *const c_void)
                .unwrap_or(std::ptr::null()),
        )
    };
    chk(
        rc,
        "mount",
        format!(
            "source={:?} target={} fstype={:?} flags={:#x} data={:?}",
            source.unwrap_or("-"),
            target.display(),
            fstype.unwrap_or("-"),
            flags,
            data.unwrap_or("-")
        ),
    )
    .map(|_| ())
}

pub fn umount(target: &Path, flags: c_int) -> Result<()> {
    let c = cpath(target)?;
    let rc = unsafe { umount2(c.as_ptr(), flags) };
    chk(rc, "umount2", target.display().to_string()).map(|_| ())
}

/// Make the whole mount tree private so that mounts we perform inside the
/// container's mount namespace never propagate back to the host.
///
/// Without this, systemd hosts (which mount `/` as MS_SHARED) would see every
/// container mount, and `pivot_root` would fail with `EINVAL`.
pub fn make_rprivate(path: &Path) -> Result<()> {
    mount(None, path, None, MS_REC | MS_PRIVATE, None)
}

/// Bind mount, optionally recursive.
pub fn bind(source: &Path, target: &Path, recursive: bool) -> Result<()> {
    let src = source
        .to_str()
        .ok_or_else(|| Error::cfg("non-UTF-8 bind source"))?;
    let flags = if recursive { MS_BIND | MS_REC } else { MS_BIND };
    mount(Some(src), target, None, flags, None)
}

/// Remount an existing mount read-only.
///
/// A bind mount cannot be made read-only in the initial `mount(MS_BIND)`
/// call: the kernel ignores other flags for the first bind.  A second
/// `MS_REMOUNT|MS_BIND|MS_RDONLY` call is required, and the original
/// per-mount flags must be preserved or they are silently dropped.
pub fn remount_ro(target: &Path, extra_flags: c_ulong) -> Result<()> {
    mount(
        None,
        target,
        None,
        MS_REMOUNT | MS_BIND | MS_RDONLY | extra_flags,
        None,
    )
}

/// `pivot_root(2)`.
///
/// We use the `pivot_root(".", ".")` idiom: both arguments point at the new
/// root (as the current working directory), which lets us avoid creating a
/// `put_old` directory inside the container's filesystem.  The old root ends
/// up stacked on top of the new root's mount point and is then detached with
/// `umount2(".", MNT_DETACH)`.
pub fn pivot_root(new_root: &Path, put_old: &Path) -> Result<()> {
    let a = cpath(new_root)?;
    let b = cpath(put_old)?;
    let rc = unsafe { syscall(nr::PIVOT_ROOT, a.as_ptr() as i64, b.as_ptr() as i64) };
    chk_long(
        rc,
        "pivot_root",
        format!(
            "new_root={} put_old={}",
            new_root.display(),
            put_old.display()
        ),
    )
    .map(|_| ())
}

pub fn chdir(path: &Path) -> Result<()> {
    let c = cpath(path)?;
    let rc = unsafe { super::ffi::chdir(c.as_ptr()) };
    chk(rc, "chdir", path.display().to_string()).map(|_| ())
}

pub fn mkdir(path: &Path, mode: mode_t) -> Result<()> {
    let c = cpath(path)?;
    let rc = unsafe { super::ffi::mkdir(c.as_ptr(), mode) };
    if rc < 0 && errno() == EEXIST {
        return Ok(());
    }
    chk(rc, "mkdir", path.display().to_string()).map(|_| ())
}

/// `mkdir -p` implemented with the raw syscall so it works after
/// `pivot_root`, where std's path handling is still fine but we want
/// consistent error reporting.
pub fn mkdir_p(path: &Path, mode: mode_t) -> Result<()> {
    let mut cur = std::path::PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if cur.as_os_str().is_empty() || cur == Path::new("/") {
            continue;
        }
        mkdir(&cur, mode)?;
    }
    Ok(())
}

pub fn symlink(target: &str, linkpath: &Path) -> Result<()> {
    let t = cstr(target)?;
    let l = cpath(linkpath)?;
    let rc = unsafe { super::ffi::symlink(t.as_ptr(), l.as_ptr()) };
    if rc < 0 && errno() == EEXIST {
        return Ok(());
    }
    chk(
        rc,
        "symlink",
        format!("{} -> {}", linkpath.display(), target),
    )
    .map(|_| ())
}

/// Create a character device node (needs CAP_MKNOD).
pub fn mknod_char(path: &Path, mode: mode_t, major: u64, minor: u64) -> Result<()> {
    let c = cpath(path)?;
    let rc = unsafe { mknod(c.as_ptr(), S_IFCHR | mode, makedev(major, minor)) };
    if rc < 0 && errno() == EEXIST {
        return Ok(());
    }
    chk(
        rc,
        "mknod",
        format!("{} c {}:{}", path.display(), major, minor),
    )
    .map(|_| ())
}

/// Create an empty regular file (bind-mount target for masked paths).
pub fn touch(path: &Path) -> Result<()> {
    let c = cpath(path)?;
    let fd = unsafe {
        super::ffi::open(
            c.as_ptr(),
            O_WRONLY | O_CREAT | O_CLOEXEC,
            0o644 as std::os::raw::c_int,
        )
    };
    if fd < 0 && errno() == EEXIST {
        return Ok(());
    }
    let fd = chk(fd, "open", path.display().to_string())?;
    unsafe {
        super::ffi::close(fd);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// /proc/self/mountinfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct MountEntry {
    pub mount_id: i32,
    pub parent_id: i32,
    pub root: String,
    pub mount_point: String,
    pub options: String,
    pub fstype: String,
    pub source: String,
    pub super_options: String,
}

impl MountEntry {
    pub fn is_readonly(&self) -> bool {
        self.options.split(',').any(|o| o == "ro")
    }
}

/// Parse `/proc/<pid>/mountinfo`.
///
/// Format (fs/proc_namespace.c):
///   36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
///   [0][1] [2]  [3]   [4]     [5]        [6..]  ^ separator
pub fn mountinfo_for(pid: &str) -> Result<Vec<MountEntry>> {
    let path = format!("/proc/{}/mountinfo", pid);
    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(format!("{}: {}", path, e)))?;
    parse_mountinfo(&text)
}

pub fn parse_mountinfo(text: &str) -> Result<Vec<MountEntry>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let sep = match fields.iter().position(|f| *f == "-") {
            Some(i) => i,
            None => continue,
        };
        if fields.len() < sep + 3 {
            continue;
        }
        out.push(MountEntry {
            mount_id: fields[0].parse().unwrap_or(-1),
            parent_id: fields[1].parse().unwrap_or(-1),
            root: unescape_octal(fields[3]),
            mount_point: unescape_octal(fields[4]),
            options: fields[5].to_string(),
            fstype: fields[sep + 1].to_string(),
            source: unescape_octal(fields[sep + 2]),
            super_options: fields.get(sep + 3).copied().unwrap_or("").to_string(),
        });
    }
    Ok(out)
}

/// mountinfo escapes space, tab, newline and backslash as `\0NN`.
fn unescape_octal(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let oct = &s[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(oct, 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

pub fn is_mount_point(path: &Path) -> bool {
    let p = path.to_string_lossy().to_string();
    mountinfo_for("self")
        .map(|v| v.iter().any(|m| m.mount_point == p))
        .unwrap_or(false)
}

/// Locate the cgroup v2 (unified) mount point, if any.
pub fn find_cgroup2_mount() -> Option<String> {
    let mounts = mountinfo_for("self").ok()?;
    // Prefer /sys/fs/cgroup itself, otherwise the first cgroup2 mount
    // (hybrid hosts usually expose it under /sys/fs/cgroup/unified).
    let mut best: Option<String> = None;
    for m in mounts {
        if m.fstype == "cgroup2" {
            if m.mount_point == "/sys/fs/cgroup" {
                return Some(m.mount_point);
            }
            if best.is_none() {
                best = Some(m.mount_point);
            }
        }
    }
    best
}

/// Used by `readlink()` based helpers.
pub fn readlink_str(path: &Path) -> Result<String> {
    let c = cpath(path)?;
    let mut buf = vec![0u8; 4096];
    let n = unsafe { readlink(c.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if n < 0 {
        return Err(Error::Syscall {
            call: "readlink",
            errno: errno(),
            ctx: path.display().to_string(),
        });
    }
    buf.truncate(n as usize);
    Ok(String::from_utf8_lossy(&buf).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
23 28 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
24 28 0:22 / /sys ro,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs ro
41 24 0:36 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:16 - cgroup2 cgroup2 rw,nsdelegate
77 28 8:1 /var/lib/myrun/x\\040y /mnt rw,relatime - ext4 /dev/sda1 rw
";

    #[test]
    fn parses_mountinfo() {
        let v = parse_mountinfo(SAMPLE).unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v[0].fstype, "proc");
        assert_eq!(v[0].mount_point, "/proc");
        assert!(!v[0].is_readonly());
        assert!(v[1].is_readonly());
        assert_eq!(v[2].fstype, "cgroup2");
        assert_eq!(v[3].root, "/var/lib/myrun/x y", "octal escapes decoded");
    }

    #[test]
    fn finds_cgroup2_in_sample() {
        // Direct check of the selection logic, independent of the host.
        let mounts = parse_mountinfo(SAMPLE).unwrap();
        let found = mounts.iter().find(|m| m.fstype == "cgroup2").unwrap();
        assert_eq!(found.mount_point, "/sys/fs/cgroup/unified");
    }

    #[test]
    fn real_host_has_proc_mounted() {
        let v = mountinfo_for("self").unwrap();
        assert!(v.iter().any(|m| m.mount_point == "/proc"));
        assert!(is_mount_point(Path::new("/proc")));
        assert!(!is_mount_point(Path::new("/definitely/not/mounted")));
    }

    #[test]
    fn mkdir_p_and_symlink() {
        let base = std::env::temp_dir().join(format!("myrun-mnt-{}", std::process::id()));
        let deep = base.join("a/b/c");
        mkdir_p(&deep, 0o755).unwrap();
        assert!(deep.is_dir());
        // Idempotent.
        mkdir_p(&deep, 0o755).unwrap();
        let link = base.join("link");
        symlink("a/b/c", &link).unwrap();
        symlink("a/b/c", &link).unwrap(); // EEXIST tolerated
        let _ = std::fs::remove_dir_all(&base);
    }
}
