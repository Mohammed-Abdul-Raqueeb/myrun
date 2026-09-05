//! Test-only helpers.
//!
//! Several modules resolve their state directory through the `MYRUN_ROOT`
//! environment variable, which is process-global. cargo runs unit tests in
//! parallel threads, so any test that sets it must hold this lock for the
//! duration — without it, one test's temporary root silently becomes
//! another's and the failures look like phantom bugs in the allocator.

use std::sync::{Mutex, MutexGuard, OnceLock};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Serialise access to process-global environment state.
pub fn env_guard() -> MutexGuard<'static, ()> {
    let m = ENV_LOCK.get_or_init(|| Mutex::new(()));
    // A panicking test poisons the mutex; the data is `()`, so recovering is
    // always safe and keeps one failure from cascading into all the others.
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A unique temporary directory installed as `MYRUN_ROOT` for as long as the
/// returned value is alive.
pub struct TempRoot {
    pub path: std::path::PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl TempRoot {
    pub fn new(tag: &str) -> TempRoot {
        let guard = env_guard();
        let path = std::env::temp_dir().join(format!(
            "myrun-test-{}-{}-{}",
            std::process::id(),
            tag,
            crate::util::now_ms()
        ));
        let _ = std::fs::create_dir_all(path.join("containers"));
        std::env::set_var("MYRUN_ROOT", &path);
        TempRoot {
            path,
            _guard: guard,
        }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        std::env::remove_var("MYRUN_ROOT");
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
