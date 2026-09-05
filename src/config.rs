//! The container configuration model.
//!
//! One `ContainerConfig` fully describes a container.  It is produced by
//! merging (in increasing priority):
//!
//!   1. built-in defaults
//!   2. a config file (`--config foo.toml` / `foo.json`)
//!   3. command line flags
//!
//! It is then serialised into `<state-dir>/<id>/config.json`, which is what
//! the re-exec'd `myrun __init` reads inside the new namespaces.  Passing the
//! config through a file rather than argv keeps the command line short and
//! means `myrun inspect` shows exactly what init acted on.

use crate::error::{Error, Result};
use crate::sys::caps;
use crate::sys::netlink::{format_ipv4, parse_cidr, parse_ipv4};
use crate::sys::seccomp::SeccompMode;
use crate::util::json::Json;
use crate::util::{self, parse_size};
use std::path::{Path, PathBuf};

pub const DEFAULT_BRIDGE: &str = "myrun0";
pub const DEFAULT_SUBNET: &str = "10.87.0.0/24";
pub const DEFAULT_MTU: u32 = 1500;
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// `/proc` entries that leak host information or allow host manipulation.
/// They are covered with a bind mount of `/dev/null` (files) or an empty
/// read-only tmpfs (directories).
pub const DEFAULT_MASKED_PATHS: &[&str] = &[
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

/// Paths remounted read-only inside the container.
pub const DEFAULT_READONLY_PATHS: &[&str] = &[
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network namespace configuration beyond an isolated `lo`.
    None,
    /// veth pair into a host bridge, with NAT to the outside world.
    Bridge,
    /// Share the host's network namespace (no `CLONE_NEWNET`).
    Host,
}

impl NetworkMode {
    pub fn parse(s: &str) -> Result<NetworkMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(NetworkMode::None),
            "bridge" => Ok(NetworkMode::Bridge),
            "host" => Ok(NetworkMode::Host),
            other => Err(Error::cfg(format!(
                "unknown network mode {:?} (expected none|bridge|host)",
                other
            ))),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkMode::None => "none",
            NetworkMode::Bridge => "bridge",
            NetworkMode::Host => "host",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

impl PortMapping {
    /// Parse `8080:80`, `8080:80/udp` or `80` (same port both sides).
    pub fn parse(s: &str) -> Result<PortMapping> {
        let (spec, protocol) = match s.split_once('/') {
            Some((a, p)) => (a, p.to_ascii_lowercase()),
            None => (s, "tcp".to_string()),
        };
        if protocol != "tcp" && protocol != "udp" {
            return Err(Error::cfg(format!(
                "unsupported protocol {:?} in port mapping {:?}",
                protocol, s
            )));
        }
        let (h, c) = match spec.split_once(':') {
            Some((a, b)) => (a, b),
            None => (spec, spec),
        };
        let host_port: u16 = h
            .trim()
            .parse()
            .map_err(|_| Error::cfg(format!("invalid host port in {:?}", s)))?;
        let container_port: u16 = c
            .trim()
            .parse()
            .map_err(|_| Error::cfg(format!("invalid container port in {:?}", s)))?;
        if host_port == 0 || container_port == 0 {
            return Err(Error::cfg("port 0 is not valid in a mapping"));
        }
        Ok(PortMapping {
            host_port,
            container_port,
            protocol,
        })
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("host_port", Json::Int(self.host_port as i64));
        o.set("container_port", Json::Int(self.container_port as i64));
        o.set("protocol", Json::Str(self.protocol.clone()));
        o
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpec {
    pub source: String,
    pub destination: String,
    pub fstype: String,
    pub readonly: bool,
}

impl MountSpec {
    /// Parse `src:dst[:ro]` (bind) or `tmpfs:dst[:ro]`.
    pub fn parse(s: &str) -> Result<MountSpec> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(Error::cfg(format!(
                "invalid mount {:?}; expected source:destination[:ro]",
                s
            )));
        }
        let readonly = match parts.get(2) {
            None => false,
            Some(&"ro") => true,
            Some(&"rw") => false,
            Some(other) => {
                return Err(Error::cfg(format!(
                    "invalid mount option {:?} (expected ro or rw)",
                    other
                )))
            }
        };
        let fstype = if parts[0] == "tmpfs" { "tmpfs" } else { "bind" };
        if !parts[1].starts_with('/') {
            return Err(Error::cfg(format!(
                "mount destination {:?} must be absolute",
                parts[1]
            )));
        }
        Ok(MountSpec {
            source: parts[0].to_string(),
            destination: parts[1].to_string(),
            fstype: fstype.to_string(),
            readonly,
        })
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("source", Json::Str(self.source.clone()));
        o.set("destination", Json::Str(self.destination.clone()));
        o.set("type", Json::Str(self.fstype.clone()));
        o.set("readonly", Json::Bool(self.readonly));
        o
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Resources {
    /// `memory.max`, bytes.
    pub memory: Option<u64>,
    /// `memory.swap.max`, bytes.
    pub memory_swap: Option<u64>,
    /// Fractional CPUs; becomes `cpu.max = <quota> <period>`.
    pub cpus: Option<f64>,
    /// `cpu.weight` (1..10000, default 100).
    pub cpu_weight: Option<u64>,
    /// `pids.max`.
    pub pids: Option<u64>,
}

impl Default for Resources {
    fn default() -> Self {
        Resources {
            memory: None,
            memory_swap: None,
            cpus: None,
            cpu_weight: None,
            pids: None,
        }
    }
}

impl Resources {
    pub const CPU_PERIOD_US: u64 = 100_000;

    /// The exact string written to `cpu.max`.
    pub fn cpu_max_value(&self) -> Option<String> {
        self.cpus.map(|c| {
            let quota = (c * Self::CPU_PERIOD_US as f64).round() as u64;
            format!("{} {}", quota.max(1000), Self::CPU_PERIOD_US)
        })
    }

    pub fn is_empty(&self) -> bool {
        self.memory.is_none()
            && self.memory_swap.is_none()
            && self.cpus.is_none()
            && self.cpu_weight.is_none()
            && self.pids.is_none()
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set(
            "memory",
            self.memory
                .map(|v| Json::Int(v as i64))
                .unwrap_or(Json::Null),
        );
        o.set(
            "memory_swap",
            self.memory_swap
                .map(|v| Json::Int(v as i64))
                .unwrap_or(Json::Null),
        );
        o.set("cpus", self.cpus.map(Json::Float).unwrap_or(Json::Null));
        o.set(
            "cpu_weight",
            self.cpu_weight
                .map(|v| Json::Int(v as i64))
                .unwrap_or(Json::Null),
        );
        o.set(
            "pids",
            self.pids.map(|v| Json::Int(v as i64)).unwrap_or(Json::Null),
        );
        o
    }

    fn from_json(j: &Json) -> Result<Resources> {
        let num_or_size = |key: &str| -> Result<Option<u64>> {
            match j.get(key) {
                None | Some(Json::Null) => Ok(None),
                Some(Json::Str(s)) => parse_size(s),
                Some(v) => Ok(v.as_u64()),
            }
        };
        Ok(Resources {
            memory: num_or_size("memory")?,
            memory_swap: num_or_size("memory_swap")?,
            cpus: j.get("cpus").and_then(|v| v.as_f64()),
            cpu_weight: j.get("cpu_weight").and_then(|v| v.as_u64()),
            pids: j.get("pids").and_then(|v| v.as_u64()),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkConfig {
    pub mode: NetworkMode,
    pub bridge: String,
    pub subnet: String,
    /// Explicit container address; allocated from the subnet when `None`.
    pub ip: Option<String>,
    pub gateway: Option<String>,
    pub mtu: u32,
    pub publish: Vec<PortMapping>,
    /// Install MASQUERADE so the container can reach the outside world.
    pub nat: bool,
    pub dns: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            mode: NetworkMode::None,
            bridge: DEFAULT_BRIDGE.to_string(),
            subnet: DEFAULT_SUBNET.to_string(),
            ip: None,
            gateway: None,
            mtu: DEFAULT_MTU,
            publish: Vec::new(),
            nat: true,
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
        }
    }
}

impl NetworkConfig {
    /// Gateway address: explicit, or the first usable address of the subnet.
    pub fn gateway_addr(&self) -> Result<[u8; 4]> {
        if let Some(g) = &self.gateway {
            return parse_ipv4(g);
        }
        let (net, prefix) = parse_cidr(&self.subnet)?;
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix as u32)
        };
        let base = u32::from_be_bytes(net) & mask;
        Ok((base + 1).to_be_bytes())
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("mode", Json::Str(self.mode.as_str().into()));
        o.set("bridge", Json::Str(self.bridge.clone()));
        o.set("subnet", Json::Str(self.subnet.clone()));
        o.set("ip", self.ip.clone().map(Json::Str).unwrap_or(Json::Null));
        o.set(
            "gateway",
            self.gateway.clone().map(Json::Str).unwrap_or(Json::Null),
        );
        o.set("mtu", Json::Int(self.mtu as i64));
        o.set(
            "publish",
            Json::Arr(self.publish.iter().map(|p| p.to_json()).collect()),
        );
        o.set("nat", Json::Bool(self.nat));
        o.set("dns", Json::strings(self.dns.clone()));
        o
    }

    fn from_json(j: &Json) -> Result<NetworkConfig> {
        let mut n = NetworkConfig::default();
        if let Some(m) = j.get("mode").and_then(|v| v.as_str()) {
            n.mode = NetworkMode::parse(m)?;
        }
        if let Some(v) = j.get("bridge").and_then(|v| v.as_str()) {
            n.bridge = v.to_string();
        }
        if let Some(v) = j.get("subnet").and_then(|v| v.as_str()) {
            n.subnet = v.to_string();
        }
        n.ip = j.get("ip").and_then(|v| v.as_str()).map(|s| s.to_string());
        n.gateway = j
            .get("gateway")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(v) = j.get("mtu").and_then(|v| v.as_u64()) {
            n.mtu = v as u32;
        }
        if let Some(v) = j.get("nat").and_then(|v| v.as_bool()) {
            n.nat = v;
        }
        if let Some(arr) = j.get("dns").and_then(|v| v.as_array()) {
            n.dns = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(arr) = j.get("publish").and_then(|v| v.as_array()) {
            n.publish.clear();
            for p in arr {
                if let Some(s) = p.as_str() {
                    n.publish.push(PortMapping::parse(s)?);
                } else {
                    let host = p
                        .get("host")
                        .or_else(|| p.get("host_port"))
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| Error::cfg("publish entry needs a host port"))?;
                    let cport = p
                        .get("container")
                        .or_else(|| p.get("container_port"))
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| Error::cfg("publish entry needs a container port"))?;
                    let proto = p
                        .get("protocol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("tcp")
                        .to_string();
                    n.publish.push(PortMapping {
                        host_port: host as u16,
                        container_port: cport as u16,
                        protocol: proto,
                    });
                }
            }
        }
        Ok(n)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityConfig {
    pub no_new_privs: bool,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub seccomp: SeccompMode,
    pub masked_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    /// `--user uid[:gid]`
    pub user: Option<(u32, u32)>,
    /// Skip capability drops, seccomp and path masking.  Never the default.
    pub privileged: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            no_new_privs: true,
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
            seccomp: SeccompMode::Default,
            masked_paths: DEFAULT_MASKED_PATHS.iter().map(|s| s.to_string()).collect(),
            readonly_paths: DEFAULT_READONLY_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            user: None,
            privileged: false,
        }
    }
}

impl SecurityConfig {
    /// Effective capability bitmask.
    pub fn cap_mask(&self) -> Result<u64> {
        if self.privileged {
            let mut m = 0u64;
            for (_, bit) in caps::CAP_TABLE {
                m |= 1u64 << *bit;
            }
            return Ok(m);
        }
        let base: Vec<String> = caps::DEFAULT_KEEP.iter().map(|s| s.to_string()).collect();
        let mut mask = caps::resolve_keep_set(&base, &self.cap_add, &self.cap_drop)?;
        // Switching user needs SETUID/SETGID in the effective set at the
        // moment of the switch; the kernel clears them for us afterwards.
        if self.user.is_some() {
            mask |= 1u64 << caps::parse_cap("SETUID")?;
            mask |= 1u64 << caps::parse_cap("SETGID")?;
        }
        Ok(mask)
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("no_new_privs", Json::Bool(self.no_new_privs));
        o.set("cap_add", Json::strings(self.cap_add.clone()));
        o.set("cap_drop", Json::strings(self.cap_drop.clone()));
        o.set("seccomp", Json::Str(self.seccomp.as_str().into()));
        o.set("masked_paths", Json::strings(self.masked_paths.clone()));
        o.set("readonly_paths", Json::strings(self.readonly_paths.clone()));
        o.set(
            "user",
            match self.user {
                Some((u, g)) => Json::Str(format!("{}:{}", u, g)),
                None => Json::Null,
            },
        );
        o.set("privileged", Json::Bool(self.privileged));
        o
    }

    fn from_json(j: &Json) -> Result<SecurityConfig> {
        let mut s = SecurityConfig::default();
        if let Some(v) = j.get("no_new_privs").and_then(|v| v.as_bool()) {
            s.no_new_privs = v;
        }
        if let Some(v) = j.get("privileged").and_then(|v| v.as_bool()) {
            s.privileged = v;
        }
        if let Some(v) = j.get("seccomp").and_then(|v| v.as_str()) {
            s.seccomp = SeccompMode::parse(v)?;
        }
        let strings = |key: &str| -> Option<Vec<String>> {
            j.get(key).and_then(|v| v.as_array()).map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
        };
        if let Some(v) = strings("cap_add") {
            s.cap_add = v;
        }
        if let Some(v) = strings("cap_drop") {
            s.cap_drop = v;
        }
        if let Some(v) = strings("masked_paths") {
            s.masked_paths = v;
        }
        if let Some(v) = strings("readonly_paths") {
            s.readonly_paths = v;
        }
        if let Some(v) = j.get("user").and_then(|v| v.as_str()) {
            s.user = Some(parse_user(v)?);
        }
        Ok(s)
    }
}

pub fn parse_user(s: &str) -> Result<(u32, u32)> {
    let (u, g) = match s.split_once(':') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let uid: u32 = u
        .trim()
        .parse()
        .map_err(|_| Error::cfg(format!("--user expects numeric uid[:gid], got {:?}", s)))?;
    let gid: u32 = match g {
        Some(g) => g
            .trim()
            .parse()
            .map_err(|_| Error::cfg(format!("--user expects numeric uid[:gid], got {:?}", s)))?,
        None => uid,
    };
    Ok((uid, gid))
}

/// Which namespaces to unshare.  `user` is deliberately absent — see
/// `docs/security.md` for why user namespaces are listed as future work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Namespaces {
    pub pid: bool,
    pub mount: bool,
    pub uts: bool,
    pub ipc: bool,
    pub net: bool,
    pub cgroup: bool,
}

impl Default for Namespaces {
    fn default() -> Self {
        Namespaces {
            pid: true,
            mount: true,
            uts: true,
            ipc: true,
            net: true,
            cgroup: true,
        }
    }
}

impl Namespaces {
    pub fn clone_flags(&self) -> u64 {
        use crate::sys::ffi::*;
        let mut f = 0u64;
        if self.pid {
            f |= CLONE_NEWPID;
        }
        if self.mount {
            f |= CLONE_NEWNS;
        }
        if self.uts {
            f |= CLONE_NEWUTS;
        }
        if self.ipc {
            f |= CLONE_NEWIPC;
        }
        if self.net {
            f |= CLONE_NEWNET;
        }
        if self.cgroup {
            f |= CLONE_NEWCGROUP;
        }
        f
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("pid", Json::Bool(self.pid));
        o.set("mount", Json::Bool(self.mount));
        o.set("uts", Json::Bool(self.uts));
        o.set("ipc", Json::Bool(self.ipc));
        o.set("net", Json::Bool(self.net));
        o.set("cgroup", Json::Bool(self.cgroup));
        o
    }

    fn from_json(j: &Json) -> Namespaces {
        let mut n = Namespaces::default();
        let b = |k: &str, cur: bool| j.get(k).and_then(|v| v.as_bool()).unwrap_or(cur);
        n.pid = b("pid", n.pid);
        n.mount = b("mount", n.mount);
        n.uts = b("uts", n.uts);
        n.ipc = b("ipc", n.ipc);
        n.net = b("net", n.net);
        n.cgroup = b("cgroup", n.cgroup);
        n
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContainerConfig {
    pub id: String,
    pub name: Option<String>,
    pub rootfs: PathBuf,
    pub command: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub hostname: String,
    pub read_only: bool,
    pub mounts: Vec<MountSpec>,
    pub resources: Resources,
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub namespaces: Namespaces,
    pub detach: bool,
    /// Remove the container's state and resources as soon as it exits.
    pub auto_remove: bool,
    pub labels: Vec<(String, String)>,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        ContainerConfig {
            id: String::new(),
            name: None,
            rootfs: PathBuf::new(),
            command: Vec::new(),
            env: vec![format!("PATH={}", DEFAULT_PATH), "TERM=xterm".to_string()],
            cwd: "/".to_string(),
            hostname: String::new(),
            read_only: false,
            mounts: Vec::new(),
            resources: Resources::default(),
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            namespaces: Namespaces::default(),
            detach: false,
            auto_remove: false,
            labels: Vec::new(),
        }
    }
}

impl ContainerConfig {
    /// Load defaults overridden by a TOML or JSON file.
    pub fn from_file(path: &Path) -> Result<ContainerConfig> {
        let text = util::read_to_string(path)?;
        let is_json = path.extension().map(|e| e == "json").unwrap_or(false)
            || text.trim_start().starts_with('{');
        let doc = if is_json {
            crate::util::json::parse(&text)?
        } else {
            crate::util::toml::parse(&text)?
        };
        ContainerConfig::from_json(&doc)
    }

    pub fn from_json(j: &Json) -> Result<ContainerConfig> {
        let mut c = ContainerConfig::default();
        if let Some(v) = j.get("id").and_then(|v| v.as_str()) {
            c.id = v.to_string();
        }
        c.name = j.get("name").and_then(|v| v.as_str()).map(|s| s.into());
        if let Some(v) = j.get("rootfs").and_then(|v| v.as_str()) {
            c.rootfs = PathBuf::from(v);
        }
        if let Some(a) = j.get("command").and_then(|v| v.as_array()) {
            c.command = a
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        } else if let Some(s) = j.get("command").and_then(|v| v.as_str()) {
            // A bare string is treated as a single argv[0], not shell-split:
            // splitting would silently do the wrong thing for quoted args.
            c.command = vec![s.to_string()];
        }
        if let Some(a) = j.get("env").and_then(|v| v.as_array()) {
            for e in a {
                if let Some(s) = e.as_str() {
                    c.set_env(s);
                }
            }
        }
        if let Some(Json::Obj(pairs)) = j.get("environment") {
            for (k, v) in pairs {
                if let Some(val) = v.as_str() {
                    c.set_env(&format!("{}={}", k, val));
                }
            }
        }
        if let Some(v) = j.get("cwd").or_else(|| j.get("workdir")) {
            if let Some(s) = v.as_str() {
                c.cwd = s.to_string();
            }
        }
        if let Some(v) = j.get("hostname").and_then(|v| v.as_str()) {
            c.hostname = v.to_string();
        }
        if let Some(v) = j.get("read_only").and_then(|v| v.as_bool()) {
            c.read_only = v;
        }
        if let Some(v) = j.get("auto_remove").and_then(|v| v.as_bool()) {
            c.auto_remove = v;
        }
        if let Some(a) = j.get("mounts").and_then(|v| v.as_array()) {
            for m in a {
                if let Some(s) = m.as_str() {
                    c.mounts.push(MountSpec::parse(s)?);
                } else {
                    let src = m
                        .get("source")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::cfg("mount entry needs a source"))?;
                    let dst = m
                        .get("destination")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::cfg("mount entry needs a destination"))?;
                    c.mounts.push(MountSpec {
                        source: src.to_string(),
                        destination: dst.to_string(),
                        fstype: m
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("bind")
                            .to_string(),
                        readonly: m.get("readonly").and_then(|v| v.as_bool()).unwrap_or(false),
                    });
                }
            }
        }
        if let Some(r) = j.get("resources") {
            c.resources = Resources::from_json(r)?;
        }
        if let Some(n) = j.get("network") {
            c.network = NetworkConfig::from_json(n)?;
        }
        if let Some(s) = j.get("security") {
            c.security = SecurityConfig::from_json(s)?;
        }
        if let Some(n) = j.get("namespaces") {
            c.namespaces = Namespaces::from_json(n);
        }
        if let Some(Json::Obj(pairs)) = j.get("labels") {
            for (k, v) in pairs {
                if let Some(val) = v.as_str() {
                    c.labels.push((k.clone(), val.to_string()));
                }
            }
        }
        Ok(c)
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("id", Json::Str(self.id.clone()));
        o.set(
            "name",
            self.name.clone().map(Json::Str).unwrap_or(Json::Null),
        );
        o.set("rootfs", Json::Str(self.rootfs.display().to_string()));
        o.set("command", Json::strings(self.command.clone()));
        o.set("env", Json::strings(self.env.clone()));
        o.set("cwd", Json::Str(self.cwd.clone()));
        o.set("hostname", Json::Str(self.hostname.clone()));
        o.set("read_only", Json::Bool(self.read_only));
        o.set("auto_remove", Json::Bool(self.auto_remove));
        o.set(
            "mounts",
            Json::Arr(self.mounts.iter().map(|m| m.to_json()).collect()),
        );
        o.set("resources", self.resources.to_json());
        o.set("network", self.network.to_json());
        o.set("security", self.security.to_json());
        o.set("namespaces", self.namespaces.to_json());
        let mut labels = Json::obj();
        for (k, v) in &self.labels {
            labels.set(k.clone(), Json::Str(v.clone()));
        }
        o.set("labels", labels);
        o
    }

    /// Set or replace `KEY=VALUE`.
    pub fn set_env(&mut self, kv: &str) {
        let key = match kv.split_once('=') {
            Some((k, _)) => k.to_string(),
            None => kv.to_string(),
        };
        let prefix = format!("{}=", key);
        self.env.retain(|e| !e.starts_with(&prefix));
        self.env.push(kv.to_string());
    }

    pub fn env_value(&self, key: &str) -> Option<&str> {
        let prefix = format!("{}=", key);
        self.env
            .iter()
            .find(|e| e.starts_with(&prefix))
            .map(|e| &e[prefix.len()..])
    }

    /// Fill in derived defaults and reject impossible combinations.
    ///
    /// Called once, in the CLI process, before anything is created — a bad
    /// config should never get as far as making a cgroup.
    pub fn finalize_and_validate(&mut self, require_rootfs: bool) -> Result<()> {
        if self.id.is_empty() {
            self.id = util::generate_id();
        }
        util::validate_id(&self.id)?;
        if let Some(n) = &self.name {
            util::validate_id(n)?;
        }

        if self.hostname.is_empty() {
            self.hostname = self
                .name
                .clone()
                .unwrap_or_else(|| util::short_id(&self.id));
        }
        if self.hostname.len() > 64 {
            return Err(Error::cfg("hostname must be at most 64 characters"));
        }
        if !self
            .hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(Error::cfg(format!(
                "hostname {:?} contains invalid characters",
                self.hostname
            )));
        }
        self.set_env(&format!("HOSTNAME={}", self.hostname));

        if self.command.is_empty() {
            return Err(Error::cfg("no command given for the container"));
        }
        if self.command[0].is_empty() {
            return Err(Error::cfg("container command is empty"));
        }
        if !self.cwd.starts_with('/') {
            return Err(Error::cfg(format!(
                "working directory {:?} must be absolute",
                self.cwd
            )));
        }

        if require_rootfs {
            if self.rootfs.as_os_str().is_empty() {
                return Err(Error::cfg("no rootfs given"));
            }
            let canon = util::canonicalize(&self.rootfs)?;
            if !canon.is_dir() {
                return Err(Error::cfg(format!(
                    "rootfs {} is not a directory",
                    canon.display()
                )));
            }
            if canon == Path::new("/") {
                return Err(Error::cfg(
                    "refusing to use / as a container rootfs; pivot_root would detach the host",
                ));
            }
            self.rootfs = canon;
        }

        for m in &self.mounts {
            if m.fstype == "bind" && !Path::new(&m.source).exists() {
                return Err(Error::cfg(format!(
                    "bind mount source {} does not exist",
                    m.source
                )));
            }
        }

        if let Some(mem) = self.resources.memory {
            if mem < 512 * 1024 {
                return Err(Error::cfg(
                    "memory limit must be at least 512k; smaller values make the kernel OOM-kill the container immediately",
                ));
            }
        }
        if let Some(sw) = self.resources.memory_swap {
            if let Some(mem) = self.resources.memory {
                if sw < mem {
                    return Err(Error::cfg(
                        "memory-swap must be greater than or equal to memory",
                    ));
                }
            }
        }
        if let Some(c) = self.resources.cpus {
            if !(c.is_finite() && c > 0.0) {
                return Err(Error::cfg("--cpus must be a positive number"));
            }
            if c > 1024.0 {
                return Err(Error::cfg("--cpus is absurdly large (max 1024)"));
            }
        }
        if let Some(w) = self.resources.cpu_weight {
            if !(1..=10_000).contains(&w) {
                return Err(Error::cfg("--cpu-weight must be between 1 and 10000"));
            }
        }
        if let Some(p) = self.resources.pids {
            if p < 1 {
                return Err(Error::cfg("--pids must be at least 1"));
            }
        }

        // Network consistency.
        match self.network.mode {
            NetworkMode::Host => {
                self.namespaces.net = false;
                if !self.network.publish.is_empty() {
                    return Err(Error::cfg(
                        "--publish is meaningless with --network host; the container already shares host ports",
                    ));
                }
            }
            NetworkMode::None => {
                if !self.network.publish.is_empty() {
                    return Err(Error::cfg("--publish requires --network bridge"));
                }
            }
            NetworkMode::Bridge => {
                if !self.namespaces.net {
                    return Err(Error::cfg("--network bridge requires a network namespace"));
                }
                let (net, prefix) = parse_cidr(&self.network.subnet)?;
                if prefix > 30 {
                    return Err(Error::cfg(
                        "bridge subnet must be /30 or larger to hold a gateway and a container",
                    ));
                }
                let gw = self.network.gateway_addr()?;
                if let Some(ip) = &self.network.ip {
                    let addr = parse_ipv4(ip)?;
                    if !in_subnet(addr, net, prefix) {
                        return Err(Error::cfg(format!(
                            "--ip {} is outside subnet {}",
                            format_ipv4(addr),
                            self.network.subnet
                        )));
                    }
                    if addr == gw {
                        return Err(Error::cfg(format!(
                            "--ip {} collides with the bridge gateway address",
                            format_ipv4(addr)
                        )));
                    }
                }
                let mut seen = Vec::new();
                for p in &self.network.publish {
                    let key = (p.host_port, p.protocol.clone());
                    if seen.contains(&key) {
                        return Err(Error::cfg(format!(
                            "host port {}/{} is published twice",
                            p.host_port, p.protocol
                        )));
                    }
                    seen.push(key);
                }
            }
        }
        if self.network.mtu < 68 || self.network.mtu > 65535 {
            return Err(Error::cfg("--mtu must be between 68 and 65535"));
        }

        // Security: this both validates names and pre-computes the mask, so
        // an unknown capability is rejected here rather than inside init.
        let _ = self.security.cap_mask()?;
        if self.security.privileged && self.security.seccomp != SeccompMode::Unconfined {
            // Privileged means "no confinement"; make that explicit rather
            // than half-applying it.
            self.security.seccomp = SeccompMode::Unconfined;
        }

        Ok(())
    }

    /// Where the container's writable runtime state lives.
    pub fn short_id(&self) -> String {
        util::short_id(&self.id)
    }
}

pub fn in_subnet(addr: [u8; 4], net: [u8; 4], prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    (u32::from_be_bytes(addr) & mask) == (u32::from_be_bytes(net) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ContainerConfig {
        let mut c = ContainerConfig::default();
        c.rootfs = PathBuf::from("/tmp");
        c.command = vec!["/bin/sh".into()];
        c
    }

    #[test]
    fn port_mapping_forms() {
        assert_eq!(
            PortMapping::parse("8080:80").unwrap(),
            PortMapping {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".into()
            }
        );
        assert_eq!(PortMapping::parse("53:53/udp").unwrap().protocol, "udp");
        let p = PortMapping::parse("443").unwrap();
        assert_eq!((p.host_port, p.container_port), (443, 443));
        assert!(PortMapping::parse("0:80").is_err());
        assert!(PortMapping::parse("8080:80/sctp").is_err());
        assert!(PortMapping::parse("abc:80").is_err());
    }

    #[test]
    fn mount_spec_forms() {
        let m = MountSpec::parse("/data:/mnt/data:ro").unwrap();
        assert_eq!(m.source, "/data");
        assert_eq!(m.destination, "/mnt/data");
        assert!(m.readonly);
        assert_eq!(m.fstype, "bind");
        assert_eq!(MountSpec::parse("tmpfs:/scratch").unwrap().fstype, "tmpfs");
        assert!(MountSpec::parse("/data").is_err());
        assert!(MountSpec::parse("/data:relative").is_err());
        assert!(MountSpec::parse("/a:/b:xx").is_err());
    }

    #[test]
    fn cpu_max_encoding() {
        let mut r = Resources::default();
        r.cpus = Some(1.0);
        assert_eq!(r.cpu_max_value().unwrap(), "100000 100000");
        r.cpus = Some(0.5);
        assert_eq!(r.cpu_max_value().unwrap(), "50000 100000");
        r.cpus = Some(2.5);
        assert_eq!(r.cpu_max_value().unwrap(), "250000 100000");
    }

    #[test]
    fn gateway_defaults_to_first_host_address() {
        let n = NetworkConfig::default();
        assert_eq!(n.gateway_addr().unwrap(), [10, 87, 0, 1]);
        let mut n2 = NetworkConfig::default();
        n2.subnet = "192.168.44.0/24".into();
        assert_eq!(n2.gateway_addr().unwrap(), [192, 168, 44, 1]);
        n2.gateway = Some("192.168.44.254".into());
        assert_eq!(n2.gateway_addr().unwrap(), [192, 168, 44, 254]);
    }

    #[test]
    fn clone_flags_match_requested_namespaces() {
        use crate::sys::ffi::*;
        let all = Namespaces::default().clone_flags();
        assert!(all & CLONE_NEWPID != 0);
        assert!(all & CLONE_NEWNET != 0);
        let mut n = Namespaces::default();
        n.net = false;
        assert!(n.clone_flags() & CLONE_NEWNET == 0);
        assert!(n.clone_flags() & CLONE_NEWNS != 0);
    }

    #[test]
    fn env_replacement() {
        let mut c = base();
        c.set_env("FOO=1");
        c.set_env("FOO=2");
        assert_eq!(c.env_value("FOO"), Some("2"));
        assert_eq!(c.env.iter().filter(|e| e.starts_with("FOO=")).count(), 1);
        assert!(c.env_value("PATH").is_some());
    }

    #[test]
    fn validation_fills_defaults() {
        let mut c = base();
        c.finalize_and_validate(true).unwrap();
        assert_eq!(c.id.len(), 32);
        assert!(!c.hostname.is_empty());
        assert_eq!(c.env_value("HOSTNAME"), Some(c.hostname.as_str()));
        assert_eq!(c.rootfs, PathBuf::from("/tmp"));
    }

    #[test]
    fn validation_rejects_bad_input() {
        let mut c = base();
        c.command.clear();
        assert!(c.finalize_and_validate(true).is_err());

        let mut c = base();
        c.rootfs = PathBuf::from("/");
        assert!(c.finalize_and_validate(true).is_err(), "/ as rootfs");

        let mut c = base();
        c.rootfs = PathBuf::from("/no/such/path/here");
        assert!(c.finalize_and_validate(true).is_err());

        let mut c = base();
        c.resources.memory = Some(1024);
        assert!(c.finalize_and_validate(true).is_err(), "tiny memory limit");

        let mut c = base();
        c.resources.cpus = Some(0.0);
        assert!(c.finalize_and_validate(true).is_err());

        let mut c = base();
        c.cwd = "relative".into();
        assert!(c.finalize_and_validate(true).is_err());

        let mut c = base();
        c.hostname = "bad host!".into();
        assert!(c.finalize_and_validate(true).is_err());

        let mut c = base();
        c.security.cap_add = vec!["CAP_NOT_REAL".into()];
        assert!(c.finalize_and_validate(true).is_err());
    }

    #[test]
    fn network_validation() {
        let mut c = base();
        c.network.mode = NetworkMode::None;
        c.network.publish = vec![PortMapping::parse("80:80").unwrap()];
        assert!(
            c.finalize_and_validate(true).is_err(),
            "publish needs bridge"
        );

        let mut c = base();
        c.network.mode = NetworkMode::Bridge;
        c.network.ip = Some("192.168.99.5".into());
        assert!(c.finalize_and_validate(true).is_err(), "ip outside subnet");

        let mut c = base();
        c.network.mode = NetworkMode::Bridge;
        c.network.ip = Some("10.87.0.1".into());
        assert!(c.finalize_and_validate(true).is_err(), "ip == gateway");

        let mut c = base();
        c.network.mode = NetworkMode::Bridge;
        c.network.ip = Some("10.87.0.7".into());
        c.network.publish = vec![
            PortMapping::parse("80:80").unwrap(),
            PortMapping::parse("80:8080").unwrap(),
        ];
        assert!(
            c.finalize_and_validate(true).is_err(),
            "duplicate host port"
        );

        let mut c = base();
        c.network.mode = NetworkMode::Host;
        c.finalize_and_validate(true).unwrap();
        assert!(!c.namespaces.net, "host networking disables netns");
    }

    #[test]
    fn json_roundtrip() {
        let mut c = base();
        c.network.mode = NetworkMode::Bridge;
        c.network.publish = vec![PortMapping::parse("8080:80").unwrap()];
        c.resources.memory = Some(256 * 1024 * 1024);
        c.resources.cpus = Some(1.5);
        c.mounts = vec![MountSpec::parse("/tmp:/host-tmp:ro").unwrap()];
        c.security.cap_add = vec!["NET_ADMIN".into()];
        c.finalize_and_validate(true).unwrap();

        let text = c.to_json().to_string_pretty();
        let back = ContainerConfig::from_json(&crate::util::json::parse(&text).unwrap()).unwrap();
        assert_eq!(back.id, c.id);
        assert_eq!(back.command, c.command);
        assert_eq!(back.resources, c.resources);
        assert_eq!(back.network, c.network);
        assert_eq!(back.security.cap_add, c.security.cap_add);
        assert_eq!(back.mounts, c.mounts);
        assert_eq!(back.namespaces, c.namespaces);
    }

    #[test]
    fn loads_toml_config() {
        let toml = r#"
rootfs = "/tmp"
command = ["/bin/sh", "-c", "echo hi"]
hostname = "demo"
read_only = true

[resources]
memory = "256m"
cpus = 2
pids = 64

[network]
mode = "bridge"
ip = "10.87.0.9"

[[network.publish]]
host = 8080
container = 80

[security]
seccomp = "strict"
cap_drop = ["all"]
"#;
        let dir = std::env::temp_dir().join(format!("myrun-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("c.toml");
        std::fs::write(&p, toml).unwrap();
        let mut c = ContainerConfig::from_file(&p).unwrap();
        c.finalize_and_validate(true).unwrap();
        assert_eq!(c.hostname, "demo");
        assert!(c.read_only);
        assert_eq!(c.resources.memory, Some(268_435_456));
        assert_eq!(c.resources.cpus, Some(2.0));
        assert_eq!(c.resources.pids, Some(64));
        assert_eq!(c.network.mode, NetworkMode::Bridge);
        assert_eq!(c.network.publish.len(), 1);
        assert_eq!(c.network.publish[0].host_port, 8080);
        assert_eq!(c.security.seccomp, SeccompMode::Strict);
        assert_eq!(c.security.cap_mask().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn subnet_membership() {
        assert!(in_subnet([10, 87, 0, 5], [10, 87, 0, 0], 24));
        assert!(!in_subnet([10, 88, 0, 5], [10, 87, 0, 0], 24));
        assert!(in_subnet([10, 88, 0, 5], [10, 0, 0, 0], 8));
    }

    #[test]
    fn privileged_disables_seccomp() {
        let mut c = base();
        c.security.privileged = true;
        c.finalize_and_validate(true).unwrap();
        assert_eq!(c.security.seccomp, SeccompMode::Unconfined);
        let mask = c.security.cap_mask().unwrap();
        assert!(mask & (1 << 21) != 0, "privileged keeps CAP_SYS_ADMIN");
    }
}
