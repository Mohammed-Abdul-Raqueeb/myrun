//! Container state machine and state store.
//!
//! ```text
//!                 create                start
//!    (nothing) ───────────> Created ─────────────> Running
//!        ^                    │                   │  │  ^
//!        │                    │ delete            │  │  │ resume
//!        │                    v                   │  │  │
//!        └──────────────── (deleted) <────────┐   │  └──┴── Paused
//!                                  delete     │   │           │
//!                             ┌───────────────┘   │ stop/kill │ stop/kill
//!                             │                   v           v
//!                          Stopped <────────── Stopping ──────┘
//! ```
//!
//! The state lives in `<root>/containers/<id>/state.json`, written
//! atomically and guarded by `flock` on `<root>/containers/<id>/lock`, so
//! concurrent `myrun` invocations cannot interleave a read-modify-write.

use crate::config::{ContainerConfig, NetworkMode, PortMapping};
use crate::error::{Error, Result};
use crate::sys::process::ExitStatus;
use crate::sys::FileLock;
use crate::util::json::{self, Json};
use crate::util::{self, now_ms};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Creating,
    Created,
    Running,
    Paused,
    Stopping,
    Stopped,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Creating => "creating",
            Status::Created => "created",
            Status::Running => "running",
            Status::Paused => "paused",
            Status::Stopping => "stopping",
            Status::Stopped => "stopped",
        }
    }

    pub fn parse(s: &str) -> Result<Status> {
        Ok(match s {
            "creating" => Status::Creating,
            "created" => Status::Created,
            "running" => Status::Running,
            "paused" => Status::Paused,
            "stopping" => Status::Stopping,
            "stopped" => Status::Stopped,
            other => {
                return Err(Error::parse(format!(
                    "unknown container status {:?}",
                    other
                )))
            }
        })
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Status::Running | Status::Paused | Status::Stopping)
    }

    /// Legal transitions.  Every state change goes through
    /// [`ContainerState::transition`], so an illegal transition is a hard
    /// error rather than a silently corrupt state file.
    pub fn can_transition_to(&self, next: Status) -> bool {
        use Status::*;
        matches!(
            (self, next),
            (Creating, Created)
                | (Creating, Stopped)
                | (Created, Running)
                | (Created, Stopped)
                | (Running, Paused)
                | (Running, Stopping)
                | (Running, Stopped)
                | (Paused, Running)
                | (Paused, Stopping)
                | (Paused, Stopped)
                | (Stopping, Stopped)
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkState {
    pub mode: String,
    pub bridge: Option<String>,
    pub host_veth: Option<String>,
    pub container_veth: Option<String>,
    pub ip: Option<String>,
    pub prefix: u8,
    pub gateway: Option<String>,
    pub published: Vec<PortMapping>,
}

impl Default for NetworkState {
    fn default() -> Self {
        NetworkState {
            mode: "none".to_string(),
            bridge: None,
            host_veth: None,
            container_veth: None,
            ip: None,
            prefix: 24,
            gateway: None,
            published: Vec::new(),
        }
    }
}

impl NetworkState {
    fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("mode", Json::Str(self.mode.clone()));
        let os = |v: &Option<String>| v.clone().map(Json::Str).unwrap_or(Json::Null);
        o.set("bridge", os(&self.bridge));
        o.set("host_veth", os(&self.host_veth));
        o.set("container_veth", os(&self.container_veth));
        o.set("ip", os(&self.ip));
        o.set("prefix", Json::Int(self.prefix as i64));
        o.set("gateway", os(&self.gateway));
        o.set(
            "published",
            Json::Arr(self.published.iter().map(|p| p.to_json()).collect()),
        );
        o
    }

    fn from_json(j: &Json) -> NetworkState {
        let s = |k: &str| j.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
        let mut published = Vec::new();
        if let Some(a) = j.get("published").and_then(|v| v.as_array()) {
            for p in a {
                let host = p.get("host_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let cport = p
                    .get("container_port")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16;
                let proto = p
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tcp")
                    .to_string();
                published.push(PortMapping {
                    host_port: host,
                    container_port: cport,
                    protocol: proto,
                });
            }
        }
        NetworkState {
            mode: s("mode").unwrap_or_else(|| "none".into()),
            bridge: s("bridge"),
            host_veth: s("host_veth"),
            container_veth: s("container_veth"),
            ip: s("ip"),
            prefix: j.get("prefix").and_then(|v| v.as_u64()).unwrap_or(24) as u8,
            gateway: s("gateway"),
            published,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContainerState {
    pub id: String,
    pub name: Option<String>,
    pub status: Status,
    /// PID of the container's init process **as seen from the host**.
    pub init_pid: i32,
    /// `/proc/<pid>/stat` field 22, used to detect PID reuse.
    pub init_start_time: u64,
    pub shim_pid: i32,
    pub created_at: u64,
    pub started_at: u64,
    pub finished_at: u64,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub oom_killed: bool,
    pub error: Option<String>,
    pub cgroup_path: Option<String>,
    pub network: NetworkState,
    pub config: ContainerConfig,
}

impl ContainerState {
    pub fn new(config: ContainerConfig) -> ContainerState {
        ContainerState {
            id: config.id.clone(),
            name: config.name.clone(),
            status: Status::Creating,
            init_pid: 0,
            init_start_time: 0,
            shim_pid: 0,
            created_at: now_ms(),
            started_at: 0,
            finished_at: 0,
            exit_code: None,
            exit_signal: None,
            oom_killed: false,
            error: None,
            cgroup_path: None,
            network: NetworkState {
                mode: config.network.mode.as_str().to_string(),
                ..Default::default()
            },
            config,
        }
    }

    pub fn transition(&mut self, next: Status) -> Result<()> {
        if self.status == next {
            return Ok(());
        }
        if !self.status.can_transition_to(next) {
            return Err(Error::state(format!(
                "container {} cannot go from {} to {}",
                util::short_id(&self.id),
                self.status.as_str(),
                next.as_str()
            )));
        }
        crate::log_debug!(
            "container {}: {} -> {}",
            util::short_id(&self.id),
            self.status.as_str(),
            next.as_str()
        );
        self.status = next;
        match next {
            Status::Running => {
                if self.started_at == 0 {
                    self.started_at = now_ms();
                }
            }
            Status::Stopped => {
                if self.finished_at == 0 {
                    self.finished_at = now_ms();
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn record_exit(&mut self, st: ExitStatus) {
        self.exit_code = st.code;
        self.exit_signal = st.signal;
        if self.finished_at == 0 {
            self.finished_at = now_ms();
        }
    }

    /// Exit code in shell convention (128+signal when killed).
    pub fn effective_exit_code(&self) -> i32 {
        ExitStatus {
            code: self.exit_code,
            signal: self.exit_signal,
        }
        .exit_code()
    }

    /// Is the recorded init process actually still there?
    ///
    /// The state file can lie: the shim may have been `SIGKILL`ed before it
    /// could write the final status.  `myrun list`/`inspect` reconcile with
    /// reality using this.
    pub fn init_is_alive(&self) -> bool {
        if self.init_pid <= 0 {
            return false;
        }
        // A recorded start time of 0 means we never managed to read
        // /proc/<pid>/stat. Passing Some(0) would compare against a start
        // time no process can have, so a perfectly healthy container would
        // look dead and be reconciled away. Fall back to a pid-only check.
        let start = if self.init_start_time == 0 {
            None
        } else {
            Some(self.init_start_time)
        };
        crate::sys::process::process_alive(self.init_pid, start)
    }

    pub fn uptime_ms(&self) -> u64 {
        if self.started_at == 0 {
            return 0;
        }
        let end = if self.finished_at > 0 {
            self.finished_at
        } else {
            now_ms()
        };
        end.saturating_sub(self.started_at)
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("id", Json::Str(self.id.clone()));
        o.set(
            "name",
            self.name.clone().map(Json::Str).unwrap_or(Json::Null),
        );
        o.set("status", Json::Str(self.status.as_str().into()));
        o.set("init_pid", Json::Int(self.init_pid as i64));
        o.set("init_start_time", Json::Int(self.init_start_time as i64));
        o.set("shim_pid", Json::Int(self.shim_pid as i64));
        o.set("created_at", Json::Int(self.created_at as i64));
        o.set("started_at", Json::Int(self.started_at as i64));
        o.set("finished_at", Json::Int(self.finished_at as i64));
        o.set(
            "exit_code",
            self.exit_code
                .map(|c| Json::Int(c as i64))
                .unwrap_or(Json::Null),
        );
        o.set(
            "exit_signal",
            self.exit_signal
                .map(|c| Json::Int(c as i64))
                .unwrap_or(Json::Null),
        );
        o.set("oom_killed", Json::Bool(self.oom_killed));
        o.set(
            "error",
            self.error.clone().map(Json::Str).unwrap_or(Json::Null),
        );
        o.set(
            "cgroup_path",
            self.cgroup_path
                .clone()
                .map(Json::Str)
                .unwrap_or(Json::Null),
        );
        o.set("network", self.network.to_json());
        o.set("config", self.config.to_json());
        o
    }

    pub fn from_json(j: &Json) -> Result<ContainerState> {
        let cfg_json = j
            .get("config")
            .ok_or_else(|| Error::parse("state file has no config section"))?;
        let config = ContainerConfig::from_json(cfg_json)?;
        let i = |k: &str| j.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        let u = |k: &str| j.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(ContainerState {
            id: j
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::parse("state file has no id"))?
                .to_string(),
            name: j.get("name").and_then(|v| v.as_str()).map(|s| s.into()),
            status: Status::parse(
                j.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("stopped"),
            )?,
            init_pid: i("init_pid") as i32,
            init_start_time: u("init_start_time"),
            shim_pid: i("shim_pid") as i32,
            created_at: u("created_at"),
            started_at: u("started_at"),
            finished_at: u("finished_at"),
            exit_code: j
                .get("exit_code")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32),
            exit_signal: j
                .get("exit_signal")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32),
            oom_killed: j
                .get("oom_killed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            error: j.get("error").and_then(|v| v.as_str()).map(|s| s.into()),
            cgroup_path: j
                .get("cgroup_path")
                .and_then(|v| v.as_str())
                .map(|s| s.into()),
            network: j
                .get("network")
                .map(NetworkState::from_json)
                .unwrap_or_default(),
            config,
        })
    }

    pub fn network_mode(&self) -> NetworkMode {
        NetworkMode::parse(&self.network.mode).unwrap_or(NetworkMode::None)
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open() -> Result<Store> {
        let root = super::ensure_root()?;
        Ok(Store { root })
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    pub fn containers_dir(&self) -> PathBuf {
        self.root.join("containers")
    }

    pub fn dir(&self, id: &str) -> PathBuf {
        self.containers_dir().join(id)
    }

    pub fn state_path(&self, id: &str) -> PathBuf {
        self.dir(id).join("state.json")
    }

    pub fn config_path(&self, id: &str) -> PathBuf {
        self.dir(id).join("config.json")
    }

    pub fn log_path(&self, id: &str) -> PathBuf {
        self.dir(id).join("container.log")
    }

    pub fn shim_socket_path(&self, id: &str) -> PathBuf {
        self.dir(id).join("shim.sock")
    }

    pub fn exists(&self, id: &str) -> bool {
        self.state_path(id).exists()
    }

    /// Lock a container for read-modify-write.
    pub fn lock(&self, id: &str) -> Result<FileLock> {
        util::mkdir_p(self.dir(id))?;
        FileLock::acquire(&self.dir(id).join("lock"))
    }

    pub fn ids(&self) -> Result<Vec<String>> {
        let d = self.containers_dir();
        let mut out = Vec::new();
        if !d.exists() {
            return Ok(out);
        }
        for e in std::fs::read_dir(&d).map_err(|e| Error::io(format!("{}: {}", d.display(), e)))? {
            let e = match e {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = e.file_name().to_string_lossy().to_string();
            if self.exists(&name) {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Resolve a full id, a name, or an unambiguous id prefix.
    pub fn resolve(&self, needle: &str) -> Result<String> {
        if needle.is_empty() {
            return Err(Error::usage("no container specified"));
        }
        if self.exists(needle) {
            return Ok(needle.to_string());
        }
        let mut matches = Vec::new();
        for id in self.ids()? {
            if id.starts_with(needle) {
                matches.push(id.clone());
                continue;
            }
            if let Ok(st) = self.load(&id) {
                if st.name.as_deref() == Some(needle) {
                    return Ok(id);
                }
            }
        }
        match matches.len() {
            0 => Err(Error::not_found(format!("container {:?}", needle))),
            1 => Ok(matches.remove(0)),
            _ => Err(Error::usage(format!(
                "container id prefix {:?} is ambiguous: {}",
                needle,
                matches
                    .iter()
                    .map(|m| util::short_id(m))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    pub fn load(&self, id: &str) -> Result<ContainerState> {
        let p = self.state_path(id);
        if !p.exists() {
            return Err(Error::not_found(format!(
                "container {}",
                util::short_id(id)
            )));
        }
        let text = util::read_to_string(&p)?;
        let j = json::parse(&text).map_err(|e| Error::parse(format!("{}: {}", p.display(), e)))?;
        ContainerState::from_json(&j)
    }

    pub fn save(&self, st: &ContainerState) -> Result<()> {
        util::mkdir_p(self.dir(&st.id))?;
        util::write_atomic(self.state_path(&st.id), &st.to_json().to_string_pretty())
    }

    /// Create a brand new container directory; fails if the id is taken.
    pub fn create(&self, st: &ContainerState) -> Result<()> {
        if self.exists(&st.id) {
            return Err(Error::AlreadyExists(format!(
                "container {}",
                util::short_id(&st.id)
            )));
        }
        if let Some(name) = &st.name {
            for id in self.ids()? {
                if let Ok(other) = self.load(&id) {
                    if other.name.as_deref() == Some(name.as_str()) {
                        return Err(Error::AlreadyExists(format!(
                            "container name {:?} (used by {})",
                            name,
                            util::short_id(&id)
                        )));
                    }
                }
            }
        }
        util::mkdir_p(self.dir(&st.id))?;
        // config.json is what `myrun __init` reads inside the namespaces.
        util::write_atomic(
            self.config_path(&st.id),
            &st.config.to_json().to_string_pretty(),
        )?;
        self.save(st)
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        let d = self.dir(id);
        if d.exists() {
            std::fs::remove_dir_all(&d)
                .map_err(|e| Error::io(format!("removing {}: {}", d.display(), e)))?;
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<ContainerState>> {
        let mut out = Vec::new();
        for id in self.ids()? {
            match self.load(&id) {
                Ok(s) => out.push(s),
                Err(e) => crate::log_warn!("skipping unreadable container {}: {}", id, e),
            }
        }
        out.sort_by_key(|s| s.created_at);
        Ok(out)
    }

    /// Reconcile a state file with reality.
    ///
    /// Returns `true` when the state was corrected and re-saved.
    pub fn reconcile(&self, st: &mut ContainerState) -> Result<bool> {
        if !st.status.is_live() {
            return Ok(false);
        }
        if st.init_is_alive() {
            return Ok(false);
        }
        crate::log_warn!(
            "container {} was marked {} but its init process is gone; marking stopped",
            util::short_id(&st.id),
            st.status.as_str()
        );
        st.status = Status::Stopped;
        if st.finished_at == 0 {
            st.finished_at = now_ms();
        }
        if st.error.is_none() {
            st.error = Some("init process disappeared without recording an exit status".into());
        }
        self.save(st)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContainerConfig;
    use std::path::Path;

    fn temp_store(tag: &str) -> Store {
        let root = std::env::temp_dir().join(format!(
            "myrun-store-{}-{}-{}",
            std::process::id(),
            tag,
            util::now_ms()
        ));
        util::mkdir_p(root.join("containers")).unwrap();
        Store { root }
    }

    fn sample_config(id: &str) -> ContainerConfig {
        let mut c = ContainerConfig::default();
        c.id = id.to_string();
        c.rootfs = PathBuf::from("/tmp");
        c.command = vec!["/bin/true".into()];
        c.finalize_and_validate(false).unwrap();
        c
    }

    #[test]
    fn transitions_are_enforced() {
        let mut st = ContainerState::new(sample_config("aaa"));
        assert_eq!(st.status, Status::Creating);
        st.transition(Status::Created).unwrap();
        assert!(st.transition(Status::Paused).is_err(), "created -> paused");
        st.transition(Status::Running).unwrap();
        assert!(st.started_at > 0);
        st.transition(Status::Paused).unwrap();
        st.transition(Status::Running).unwrap();
        st.transition(Status::Stopping).unwrap();
        st.transition(Status::Stopped).unwrap();
        assert!(st.finished_at > 0);
        assert!(st.transition(Status::Running).is_err(), "stopped is final");
    }

    #[test]
    fn status_liveness() {
        assert!(Status::Running.is_live());
        assert!(Status::Paused.is_live());
        assert!(!Status::Created.is_live());
        assert!(!Status::Stopped.is_live());
    }

    #[test]
    fn exit_code_conventions() {
        let mut st = ContainerState::new(sample_config("bbb"));
        st.record_exit(ExitStatus {
            code: Some(42),
            signal: None,
        });
        assert_eq!(st.effective_exit_code(), 42);
        st.record_exit(ExitStatus {
            code: None,
            signal: Some(9),
        });
        assert_eq!(st.effective_exit_code(), 137);
    }

    #[test]
    fn store_crud_and_resolution() {
        let s = temp_store("crud");
        let mut cfg = sample_config("");
        cfg.id = "1234567890abcdef".into();
        cfg.name = Some("web".into());
        let mut st = ContainerState::new(cfg);
        s.create(&st).unwrap();
        assert!(s.exists("1234567890abcdef"));
        assert!(Path::new(&s.config_path("1234567890abcdef")).exists());

        // Duplicate id and duplicate name are both rejected.
        assert!(s.create(&st).is_err());
        let mut other = ContainerState::new(sample_config("ffff"));
        other.name = Some("web".into());
        assert!(s.create(&other).is_err());

        st.transition(Status::Created).unwrap();
        st.init_pid = 4242;
        s.save(&st).unwrap();

        let back = s.load("1234567890abcdef").unwrap();
        assert_eq!(back.init_pid, 4242);
        assert_eq!(back.status, Status::Created);
        assert_eq!(back.name.as_deref(), Some("web"));
        assert_eq!(back.config.command, vec!["/bin/true".to_string()]);

        assert_eq!(s.resolve("12345").unwrap(), "1234567890abcdef");
        assert_eq!(s.resolve("web").unwrap(), "1234567890abcdef");
        assert!(s.resolve("nope").is_err());

        assert_eq!(s.list().unwrap().len(), 1);
        s.remove("1234567890abcdef").unwrap();
        assert!(!s.exists("1234567890abcdef"));
        let _ = std::fs::remove_dir_all(s.root());
    }

    #[test]
    fn ambiguous_prefix_is_an_error() {
        let s = temp_store("ambig");
        for id in ["abc111", "abc222"] {
            let st = ContainerState::new(sample_config(id));
            s.create(&st).unwrap();
        }
        assert!(s.resolve("abc").is_err());
        assert!(s.resolve("abc1").is_ok());
        let _ = std::fs::remove_dir_all(s.root());
    }

    #[test]
    fn reconcile_marks_dead_containers_stopped() {
        let s = temp_store("reconcile");
        let mut st = ContainerState::new(sample_config("dead1"));
        st.transition(Status::Created).unwrap();
        st.transition(Status::Running).unwrap();
        // A pid that certainly is not ours, with a bogus start time.
        st.init_pid = 0x7fff_fffe;
        st.init_start_time = 1;
        s.create(&st).unwrap();
        assert!(s.reconcile(&mut st).unwrap());
        assert_eq!(st.status, Status::Stopped);
        assert!(st.error.is_some());
        // Second call is a no-op.
        assert!(!s.reconcile(&mut st).unwrap());
        let _ = std::fs::remove_dir_all(s.root());
    }

    #[test]
    fn state_json_roundtrip() {
        let mut st = ContainerState::new(sample_config("rt"));
        st.network = NetworkState {
            mode: "bridge".into(),
            bridge: Some("myrun0".into()),
            host_veth: Some("mrv0000".into()),
            container_veth: Some("eth0".into()),
            ip: Some("10.87.0.5".into()),
            prefix: 24,
            gateway: Some("10.87.0.1".into()),
            published: vec![PortMapping::parse("8080:80").unwrap()],
        };
        st.oom_killed = true;
        st.cgroup_path = Some("/sys/fs/cgroup/myrun/rt".into());
        let text = st.to_json().to_string_pretty();
        let back = ContainerState::from_json(&json::parse(&text).unwrap()).unwrap();
        assert_eq!(back.network, st.network);
        assert!(back.oom_killed);
        assert_eq!(back.cgroup_path, st.cgroup_path);
        assert_eq!(back.status, st.status);
    }
}
