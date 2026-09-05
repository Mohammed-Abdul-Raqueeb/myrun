//! Central error type.
//!
//! Every fallible operation in `myrun` funnels into [`Error`].  The
//! `Syscall` variant carries the raw `errno` so that callers can make
//! decisions (`ENOSYS` -> fall back, `EBUSY` -> retry, `ENOENT` -> feature
//! not present in this kernel) instead of matching on strings.

use std::fmt;

/// Exit codes used by the CLI.  Chosen so scripts can distinguish classes of
/// failure; container exit codes (0-255) are passed through untouched by
/// `myrun run`, which is why we start at 64 (sysexits.h `EX_USAGE`).
pub mod exit {
    pub const USAGE: i32 = 64;
    pub const CONFIG: i32 = 65;
    pub const NOT_FOUND: i32 = 66;
    pub const STATE: i32 = 67;
    pub const SYSCALL: i32 = 70;
    pub const UNSUPPORTED: i32 = 71;
    pub const FAULT: i32 = 72;
    pub const GENERIC: i32 = 1;
}

#[derive(Debug)]
pub enum Error {
    /// Bad command line.
    Usage(String),
    /// Bad configuration file / flag value combination.
    Config(String),
    /// Container (or other object) does not exist.
    NotFound(String),
    /// Container already exists.
    AlreadyExists(String),
    /// Operation is illegal for the container's current lifecycle state.
    InvalidState(String),
    /// A syscall returned -1.
    Syscall {
        call: &'static str,
        errno: i32,
        ctx: String,
    },
    /// Filesystem / IO problem that is not a direct syscall wrapper.
    Io(String),
    /// JSON / TOML / integer parse failure.
    Parse(String),
    /// The container reported a failure from inside its namespaces.
    Container(String),
    /// A deliberately injected fault (see `src/fault.rs`).
    Fault(String),
    /// Kernel or host lacks a required feature.
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => exit::USAGE,
            Error::Config(_) | Error::Parse(_) => exit::CONFIG,
            Error::NotFound(_) => exit::NOT_FOUND,
            Error::AlreadyExists(_) | Error::InvalidState(_) => exit::STATE,
            Error::Syscall { .. } => exit::SYSCALL,
            Error::Unsupported(_) => exit::UNSUPPORTED,
            Error::Fault(_) => exit::FAULT,
            Error::Io(_) | Error::Container(_) => exit::GENERIC,
        }
    }

    /// The raw `errno`, when this error came from a syscall.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Syscall { errno, .. } => Some(*errno),
            _ => None,
        }
    }

    pub fn is_errno(&self, e: i32) -> bool {
        self.errno() == Some(e)
    }

    pub fn io<S: Into<String>>(s: S) -> Error {
        Error::Io(s.into())
    }
    pub fn cfg<S: Into<String>>(s: S) -> Error {
        Error::Config(s.into())
    }
    pub fn usage<S: Into<String>>(s: S) -> Error {
        Error::Usage(s.into())
    }
    pub fn parse<S: Into<String>>(s: S) -> Error {
        Error::Parse(s.into())
    }
    pub fn unsupported<S: Into<String>>(s: S) -> Error {
        Error::Unsupported(s.into())
    }
    pub fn state<S: Into<String>>(s: S) -> Error {
        Error::InvalidState(s.into())
    }
    pub fn container<S: Into<String>>(s: S) -> Error {
        Error::Container(s.into())
    }
    pub fn not_found<S: Into<String>>(s: S) -> Error {
        Error::NotFound(s.into())
    }
}

/// Human readable `errno` name; used everywhere in diagnostics because
/// "mount(2) failed: EPERM" is far more debuggable than "mount failed: 1".
pub fn errno_name(e: i32) -> &'static str {
    match e {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        9 => "EBADF",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        28 => "ENOSPC",
        32 => "EPIPE",
        36 => "ENAMETOOLONG",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        61 => "ENODATA",
        62 => "ETIME",
        95 => "EOPNOTSUPP",
        98 => "EADDRINUSE",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        _ => "E?",
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(m) => write!(f, "{}", m),
            Error::Config(m) => write!(f, "invalid configuration: {}", m),
            Error::NotFound(m) => write!(f, "not found: {}", m),
            Error::AlreadyExists(m) => write!(f, "already exists: {}", m),
            Error::InvalidState(m) => write!(f, "invalid state: {}", m),
            Error::Syscall { call, errno, ctx } => {
                if ctx.is_empty() {
                    write!(f, "{}(2) failed: {} ({})", call, errno_name(*errno), errno)
                } else {
                    write!(
                        f,
                        "{}(2) failed: {} ({}): {}",
                        call,
                        errno_name(*errno),
                        errno,
                        ctx
                    )
                }
            }
            Error::Io(m) => write!(f, "io error: {}", m),
            Error::Parse(m) => write!(f, "parse error: {}", m),
            Error::Container(m) => write!(f, "container error: {}", m),
            Error::Fault(m) => write!(f, "injected fault: {}", m),
            Error::Unsupported(m) => write!(f, "unsupported: {}", m),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        match e.raw_os_error() {
            Some(errno) => Error::Syscall {
                call: "io",
                errno,
                ctx: e.to_string(),
            },
            None => Error::Io(e.to_string()),
        }
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Error {
        Error::Parse(e.to_string())
    }
}

impl From<std::num::ParseFloatError> for Error {
    fn from(e: std::num::ParseFloatError) -> Error {
        Error::Parse(e.to_string())
    }
}
