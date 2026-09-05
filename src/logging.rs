//! A tiny stderr logger.
//!
//! Level is taken from `MYRUN_LOG` (`error|warn|info|debug|trace`, default
//! `warn`).  Every line is prefixed with the process role and pid, which
//! matters a lot here: a single `myrun run` produces output from the CLI, the
//! shim and the container's init, and untangling them without the prefix is
//! painful.

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

pub const ERROR: u8 = 1;
pub const WARN: u8 = 2;
pub const INFO: u8 = 3;
pub const DEBUG: u8 = 4;
pub const TRACE: u8 = 5;

static LEVEL: AtomicU8 = AtomicU8::new(WARN);
static ROLE: AtomicU8 = AtomicU8::new(0);

const ROLES: [&str; 4] = ["cli", "shim", "init", "test"];

pub const ROLE_CLI: u8 = 0;
pub const ROLE_SHIM: u8 = 1;
pub const ROLE_INIT: u8 = 2;
pub const ROLE_TEST: u8 = 3;

pub fn init_from_env() {
    let lvl = std::env::var("MYRUN_LOG").unwrap_or_default();
    let l = match lvl.trim().to_ascii_lowercase().as_str() {
        "error" => ERROR,
        "warn" | "warning" => WARN,
        "info" => INFO,
        "debug" => DEBUG,
        "trace" => TRACE,
        _ => WARN,
    };
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn set_level(l: u8) {
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn level() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

pub fn set_role(idx: u8) {
    ROLE.store(idx.min(3), Ordering::Relaxed);
}

pub fn enabled(l: u8) -> bool {
    l <= LEVEL.load(Ordering::Relaxed)
}

pub fn log(l: u8, args: std::fmt::Arguments<'_>) {
    if !enabled(l) {
        return;
    }
    let tag = match l {
        ERROR => "ERROR",
        WARN => "WARN ",
        INFO => "INFO ",
        DEBUG => "DEBUG",
        _ => "TRACE",
    };
    let role = ROLES[ROLE.load(Ordering::Relaxed) as usize];
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "[myrun {} {} {}] {}",
        tag,
        role,
        std::process::id(),
        args
    );
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::ERROR, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::WARN, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::INFO, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::DEBUG, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::TRACE, format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_gating() {
        set_level(WARN);
        assert!(enabled(ERROR));
        assert!(enabled(WARN));
        assert!(!enabled(INFO));
        set_level(TRACE);
        assert!(enabled(TRACE));
        set_level(WARN);
    }
}
