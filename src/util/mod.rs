//! Small shared helpers: atomic file writes, human size parsing, ids, time.

pub mod json;
pub mod toml;

use crate::error::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Read a file to a `String`, attaching the path to any error.
pub fn read_to_string<P: AsRef<Path>>(p: P) -> Result<String> {
    let p = p.as_ref();
    fs::read_to_string(p).map_err(|e| match e.raw_os_error() {
        Some(errno) => Error::Syscall {
            call: "read",
            errno,
            ctx: p.display().to_string(),
        },
        None => Error::io(format!("{}: {}", p.display(), e)),
    })
}

/// Read a sysfs/procfs file and trim it.  These pseudo-files always end in a
/// newline and are the primary interface to cgroup v2.
pub fn read_trimmed<P: AsRef<Path>>(p: P) -> Result<String> {
    Ok(read_to_string(p)?.trim().to_string())
}

pub fn write_file<P: AsRef<Path>>(p: P, data: &str) -> Result<()> {
    let p = p.as_ref();
    fs::write(p, data).map_err(|e| match e.raw_os_error() {
        Some(errno) => Error::Syscall {
            call: "write",
            errno,
            ctx: p.display().to_string(),
        },
        None => Error::io(format!("{}: {}", p.display(), e)),
    })
}

/// Write a file atomically: create `<path>.tmp.<pid>`, fsync, rename.
///
/// The state store depends on this — a half-written `state.json` observed by
/// a concurrent `myrun list` would be a real bug, and `rename(2)` within the
/// same directory is atomic.
pub fn write_atomic<P: AsRef<Path>>(path: P, data: &str) -> Result<()> {
    let path = path.as_ref();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "f".into()),
        std::process::id()
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        Error::io(format!(
            "rename {} -> {}: {}",
            tmp.display(),
            path.display(),
            e
        ))
    })
}

pub fn mkdir_p<P: AsRef<Path>>(p: P) -> Result<()> {
    let p = p.as_ref();
    fs::create_dir_all(p).map_err(|e| match e.raw_os_error() {
        Some(errno) => Error::Syscall {
            call: "mkdir",
            errno,
            ctx: p.display().to_string(),
        },
        None => Error::io(format!("{}: {}", p.display(), e)),
    })
}

pub fn exists<P: AsRef<Path>>(p: P) -> bool {
    p.as_ref().exists()
}

/// Milliseconds since the UNIX epoch.  Used for created/started/finished
/// timestamps in the state store.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Render a millisecond epoch stamp as RFC3339-ish UTC for humans.
pub fn format_time(ms: u64) -> String {
    if ms == 0 {
        return "-".into();
    }
    let secs = (ms / 1000) as i64;
    let (y, mo, d, h, mi, s) = civil_from_epoch(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

/// Days-from-civil algorithm (Howard Hinnant), no chrono dependency.
fn civil_from_epoch(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

/// Human duration, e.g. "3m21s".
pub fn format_duration_ms(ms: u64) -> String {
    let s = ms / 1000;
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m{}s", s / 60, s % 60)
    } else if s < 86400 {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d{}h", s / 86400, (s % 86400) / 3600)
    }
}

/// Parse a memory size such as `256m`, `1g`, `512kb`, `1048576`.
/// Returns bytes.  `-1` / `max` / `unlimited` map to `None`.
pub fn parse_size(s: &str) -> Result<Option<u64>> {
    let t = s.trim().to_ascii_lowercase();
    if t.is_empty() {
        return Err(Error::cfg("empty size value"));
    }
    if t == "-1" || t == "max" || t == "unlimited" {
        return Ok(None);
    }
    let (num_part, mult) = if let Some(p) = t.strip_suffix("kib") {
        (p, 1024u64)
    } else if let Some(p) = t.strip_suffix("mib") {
        (p, 1024 * 1024)
    } else if let Some(p) = t.strip_suffix("gib") {
        (p, 1024 * 1024 * 1024)
    } else if let Some(p) = t.strip_suffix("kb") {
        (p, 1024)
    } else if let Some(p) = t.strip_suffix("mb") {
        (p, 1024 * 1024)
    } else if let Some(p) = t.strip_suffix("gb") {
        (p, 1024 * 1024 * 1024)
    } else if let Some(p) = t.strip_suffix('k') {
        (p, 1024)
    } else if let Some(p) = t.strip_suffix('m') {
        (p, 1024 * 1024)
    } else if let Some(p) = t.strip_suffix('g') {
        (p, 1024 * 1024 * 1024)
    } else if let Some(p) = t.strip_suffix('b') {
        (p, 1)
    } else {
        (t.as_str(), 1)
    };
    let n: f64 = num_part
        .trim()
        .parse()
        .map_err(|_| Error::cfg(format!("cannot parse size {:?}", s)))?;
    if n < 0.0 {
        return Err(Error::cfg(format!("negative size {:?}", s)));
    }
    Ok(Some((n * mult as f64) as u64))
}

/// Format bytes for humans (`stats` output).
pub fn format_bytes(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f < K {
        format!("{}B", b)
    } else if f < K * K {
        format!("{:.1}KiB", f / K)
    } else if f < K * K * K {
        format!("{:.1}MiB", f / (K * K))
    } else {
        format!("{:.2}GiB", f / (K * K * K))
    }
}

/// 64-bit non-cryptographic hash (FNV-1a).  Used for deterministic interface
/// name suffixes; never used for anything security relevant.
pub fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

/// Generate a 32-hex-character container id.
///
/// Entropy comes from `/dev/urandom`; if that is unavailable we fall back to
/// mixing pid + nanosecond clock, which is good enough because ids are also
/// checked for collision against the state directory.
pub fn generate_id() -> String {
    let mut bytes = [0u8; 16];
    // NOTE: /dev/urandom never reaches EOF, so a plain fs::read() would spin
    // forever allocating.  Read exactly the number of bytes we need.
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    }
    if bytes.iter().all(|b| *b == 0) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mix = fnv1a(&nanos.to_le_bytes()) ^ fnv1a(&(std::process::id() as u64).to_le_bytes());
        bytes[..8].copy_from_slice(&mix.to_le_bytes());
        bytes[8..].copy_from_slice(&fnv1a(&mix.to_be_bytes()).to_le_bytes());
    }
    hex(&bytes)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Validate a user-supplied container id / name.
pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 {
        return Err(Error::cfg(
            "container id must be between 1 and 64 characters",
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Error::cfg(format!(
            "container id {:?} may only contain [A-Za-z0-9._-]",
            id
        )));
    }
    if id.starts_with('.') {
        return Err(Error::cfg("container id may not start with '.'"));
    }
    Ok(())
}

/// Canonicalise a path, producing a friendly error if it does not exist.
pub fn canonicalize<P: AsRef<Path>>(p: P) -> Result<PathBuf> {
    let p = p.as_ref();
    fs::canonicalize(p).map_err(|e| Error::cfg(format!("{}: {}", p.display(), e)))
}

/// Truncate an id for display in `myrun list`.
pub fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("256m").unwrap(), Some(268_435_456));
        assert_eq!(parse_size("1g").unwrap(), Some(1_073_741_824));
        assert_eq!(parse_size("512k").unwrap(), Some(524_288));
        assert_eq!(parse_size("1024").unwrap(), Some(1024));
        assert_eq!(parse_size("1.5m").unwrap(), Some(1_572_864));
        assert_eq!(parse_size("max").unwrap(), None);
        assert_eq!(parse_size("-1").unwrap(), None);
        assert!(parse_size("abc").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn ids() {
        let a = generate_id();
        let b = generate_id();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "ids must not repeat");
        assert!(validate_id("web-1").is_ok());
        assert!(validate_id("a/b").is_err());
        assert!(validate_id("").is_err());
        assert!(validate_id(".hidden").is_err());
    }

    #[test]
    fn time_formatting() {
        assert_eq!(format_time(0), "-");
        // 2021-01-01T00:00:00Z == 1609459200
        assert_eq!(format_time(1_609_459_200_000), "2021-01-01T00:00:00Z");
        assert_eq!(format_duration_ms(90_000), "1m30s");
    }

    #[test]
    fn bytes_formatting() {
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(2048), "2.0KiB");
        assert!(format_bytes(5 * 1024 * 1024).starts_with("5.0MiB"));
    }

    #[test]
    fn atomic_write_roundtrip() {
        let dir = std::env::temp_dir().join(format!("myrun-util-{}", std::process::id()));
        mkdir_p(&dir).unwrap();
        let f = dir.join("state.json");
        write_atomic(&f, "{\"a\":1}").unwrap();
        assert_eq!(read_to_string(&f).unwrap(), "{\"a\":1}");
        write_atomic(&f, "{\"a\":2}").unwrap();
        assert_eq!(read_to_string(&f).unwrap(), "{\"a\":2}");
        // No temp files left behind.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp files leaked: {:?}", leftovers);
        let _ = fs::remove_dir_all(&dir);
    }
}
