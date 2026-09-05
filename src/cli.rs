//! Command line parsing.
//!
//! Hand-written, because the project takes no external dependencies. The
//! parser is deliberately strict: an unknown flag is an error rather than a
//! positional argument, and `--` ends option parsing. Silently accepting a
//! misspelled `--memroy 256m` and running an unlimited container is the
//! kind of failure a container runtime cannot afford.

use crate::config::{ContainerConfig, MountSpec, NetworkMode, PortMapping};
use crate::error::{Error, Result};
use crate::sys::process::parse_signal;
use crate::sys::seccomp::SeccompMode;
use crate::util::parse_size;
use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct RunArgs {
    pub config: ContainerConfig,
    pub detach: bool,
}

#[derive(Debug)]
pub enum Command {
    Run(Box<RunArgs>),
    Create(Box<RunArgs>),
    Start {
        id: String,
        attach: bool,
    },
    Stop {
        ids: Vec<String>,
        timeout: u64,
    },
    Kill {
        ids: Vec<String>,
        signal: i32,
    },
    Delete {
        ids: Vec<String>,
        force: bool,
    },
    List {
        all: bool,
        json: bool,
        quiet: bool,
    },
    Inspect {
        ids: Vec<String>,
    },
    Stats {
        ids: Vec<String>,
        json: bool,
        follow: bool,
        interval_ms: u64,
    },
    Pause {
        ids: Vec<String>,
    },
    Unpause {
        ids: Vec<String>,
    },
    Logs {
        id: String,
        follow: bool,
        tail: Option<usize>,
    },
    Wait {
        ids: Vec<String>,
        timeout: Option<u64>,
    },
    Gc,
    Info,
    Help {
        topic: Option<String>,
    },
    Version,
    /// Internal: `myrun __init <state-dir>`.
    Init {
        state_dir: PathBuf,
    },
    /// Internal: `myrun __shim <state-dir> <notify-fd>`.
    Shim {
        state_dir: PathBuf,
        notify_fd: i32,
    },
}

/// A cursor over the argument list.
struct Args {
    items: Vec<String>,
    pos: usize,
}

impl Args {
    fn new(items: &[String]) -> Args {
        Args {
            items: items.to_vec(),
            pos: 0,
        }
    }
    fn peek(&self) -> Option<&str> {
        self.items.get(self.pos).map(|s| s.as_str())
    }
    fn next(&mut self) -> Option<String> {
        let v = self.items.get(self.pos).cloned();
        if v.is_some() {
            self.pos += 1;
        }
        v
    }
    fn rest(&mut self) -> Vec<String> {
        let v = self.items[self.pos..].to_vec();
        self.pos = self.items.len();
        v
    }
    /// Value for a flag that requires one, supporting `--flag=value`.
    fn value(&mut self, flag: &str, inline: Option<&str>) -> Result<String> {
        if let Some(v) = inline {
            return Ok(v.to_string());
        }
        self.next()
            .ok_or_else(|| Error::usage(format!("{} requires a value", flag)))
    }
}

/// Split `--flag=value` into its parts.
fn split_flag(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((f, v)) if f.starts_with('-') => (f, Some(v)),
        _ => (arg, None),
    }
}

fn parse_bool(flag: &str, v: &str) -> Result<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(Error::usage(format!(
            "{} expects true or false, got {:?}",
            flag, other
        ))),
    }
}

pub fn parse(argv: &[String]) -> Result<Command> {
    let mut args = Args::new(argv);

    // Global flags may appear before the subcommand.
    let mut sub: Option<String> = None;
    while let Some(a) = args.peek().map(|s| s.to_string()) {
        let (flag, inline) = split_flag(&a);
        let inline = inline.map(|s| s.to_string());
        let inline = inline.as_deref();
        match flag {
            "-h" | "--help" => {
                args.next();
                let topic = args.next();
                return Ok(Command::Help { topic });
            }
            "-V" | "--version" => return Ok(Command::Version),
            "--log" => {
                args.next();
                let v = args.value("--log", inline)?;
                std::env::set_var("MYRUN_LOG", v);
            }
            "--root" => {
                args.next();
                let v = args.value("--root", inline)?;
                std::env::set_var("MYRUN_ROOT", v);
            }
            "--debug" => {
                args.next();
                std::env::set_var("MYRUN_LOG", "debug");
            }
            other if other.starts_with('-') => {
                return Err(Error::usage(format!(
                    "unknown global option {:?}; run `myrun --help`",
                    other
                )))
            }
            _ => {
                sub = args.next();
                break;
            }
        }
    }

    let sub = match sub {
        Some(s) => s,
        None => return Ok(Command::Help { topic: None }),
    };

    match sub.as_str() {
        "run" => Ok(Command::Run(Box::new(parse_run(&mut args, true)?))),
        "create" => Ok(Command::Create(Box::new(parse_run(&mut args, false)?))),
        "start" => parse_start(&mut args),
        "stop" => parse_stop(&mut args),
        "kill" => parse_kill(&mut args),
        "rm" | "delete" | "remove" => parse_delete(&mut args),
        "ls" | "list" | "ps" => parse_list(&mut args),
        "inspect" => Ok(Command::Inspect {
            ids: require_ids(&mut args, "inspect")?,
        }),
        "stats" => parse_stats(&mut args),
        "pause" => Ok(Command::Pause {
            ids: require_ids(&mut args, "pause")?,
        }),
        "unpause" | "resume" => Ok(Command::Unpause {
            ids: require_ids(&mut args, "unpause")?,
        }),
        "logs" => parse_logs(&mut args),
        "wait" => parse_wait(&mut args),
        "gc" | "prune" => Ok(Command::Gc),
        "info" => Ok(Command::Info),
        "help" => Ok(Command::Help { topic: args.next() }),
        "version" => Ok(Command::Version),
        "__init" => {
            let d = args
                .next()
                .ok_or_else(|| Error::usage("__init needs a state directory"))?;
            Ok(Command::Init {
                state_dir: PathBuf::from(d),
            })
        }
        "__shim" => {
            let d = args
                .next()
                .ok_or_else(|| Error::usage("__shim needs a state directory"))?;
            let fd: i32 = args
                .next()
                .ok_or_else(|| Error::usage("__shim needs a notify fd"))?
                .parse()
                .map_err(|_| Error::usage("__shim notify fd must be a number"))?;
            Ok(Command::Shim {
                state_dir: PathBuf::from(d),
                notify_fd: fd,
            })
        }
        other => Err(Error::usage(format!(
            "unknown command {:?}; run `myrun --help` for the list",
            other
        ))),
    }
}

fn require_ids(args: &mut Args, cmd: &str) -> Result<Vec<String>> {
    let ids: Vec<String> = args
        .rest()
        .into_iter()
        .filter(|a| !a.starts_with('-'))
        .collect();
    if ids.is_empty() {
        return Err(Error::usage(format!(
            "{} needs at least one container",
            cmd
        )));
    }
    Ok(ids)
}

/// Parse `run`/`create`.
///
/// Two passes over the same tokens. The first discovers `--config` (and
/// throws everything else away); the file is then loaded and the second pass
/// applies the flags on top of it.
///
/// A single pass cannot get this right: merging the file at the point where
/// `--config` appears makes precedence depend on argument order, so
/// `--name a --config f.toml` and `--config f.toml --name a` would mean
/// different things. Flags override the file, wherever they sit.
fn parse_run(args: &mut Args, run: bool) -> Result<RunArgs> {
    let mut probe = Args {
        items: args.items[args.pos..].to_vec(),
        pos: 0,
    };
    let (_, config_path) = parse_run_pass(&mut probe, run, ContainerConfig::default())?;
    let base = match &config_path {
        Some(p) => ContainerConfig::from_file(std::path::Path::new(p))?,
        None => ContainerConfig::default(),
    };
    let (parsed, _) = parse_run_pass(args, run, base)?;
    Ok(parsed)
}

fn parse_run_pass(
    args: &mut Args,
    run: bool,
    base: ContainerConfig,
) -> Result<(RunArgs, Option<String>)> {
    let mut cfg = base;
    let mut config_path: Option<String> = None;
    let mut detach = false;
    let mut positional: Vec<String> = Vec::new();
    let mut end_of_flags = false;

    while let Some(raw) = args.next() {
        if end_of_flags || !raw.starts_with('-') || raw == "-" {
            positional.push(raw);
            // Everything after the command name belongs to the command.
            if positional.len() >= 2 {
                positional.extend(args.rest());
                break;
            }
            continue;
        }
        let (flag, inline) = split_flag(&raw);
        match flag {
            "--" => {
                end_of_flags = true;
            }
            "-h" | "--help" => {
                return Err(Error::usage(help_text(Some(if run {
                    "run"
                } else {
                    "create"
                }))));
            }
            // Recorded, not applied: the caller loads it between the passes.
            "--config" | "-c" => config_path = Some(args.value(flag, inline)?),
            "--name" => cfg.name = Some(args.value(flag, inline)?),
            "--rootfs" => cfg.rootfs = PathBuf::from(args.value(flag, inline)?),
            "-e" | "--env" => cfg.set_env(&args.value(flag, inline)?),
            "-w" | "--workdir" | "--cwd" => cfg.cwd = args.value(flag, inline)?,
            "--hostname" => cfg.hostname = args.value(flag, inline)?,
            "-d" | "--detach" => detach = true,
            "--rm" => cfg.auto_remove = true,
            "--read-only" => cfg.read_only = true,
            "-v" | "--volume" | "--mount" => cfg
                .mounts
                .push(MountSpec::parse(&args.value(flag, inline)?)?),
            "--label" => {
                let kv = args.value(flag, inline)?;
                match kv.split_once('=') {
                    Some((k, v)) => cfg.labels.push((k.to_string(), v.to_string())),
                    None => return Err(Error::usage("--label expects key=value")),
                }
            }

            // Resources
            "-m" | "--memory" => cfg.resources.memory = parse_size(&args.value(flag, inline)?)?,
            "--memory-swap" => cfg.resources.memory_swap = parse_size(&args.value(flag, inline)?)?,
            "--cpus" => {
                cfg.resources.cpus = Some(
                    args.value(flag, inline)?
                        .parse()
                        .map_err(|_| Error::usage("--cpus expects a number, e.g. 1.5"))?,
                )
            }
            "--cpu-weight" | "--cpu-shares" => {
                cfg.resources.cpu_weight = Some(
                    args.value(flag, inline)?
                        .parse()
                        .map_err(|_| Error::usage("--cpu-weight expects an integer"))?,
                )
            }
            "--pids" | "--pids-limit" => {
                cfg.resources.pids = Some(
                    args.value(flag, inline)?
                        .parse()
                        .map_err(|_| Error::usage("--pids expects an integer"))?,
                )
            }

            // Networking
            "--network" | "--net" => {
                cfg.network.mode = NetworkMode::parse(&args.value(flag, inline)?)?
            }
            "--bridge" => cfg.network.bridge = args.value(flag, inline)?,
            "--subnet" => cfg.network.subnet = args.value(flag, inline)?,
            "--ip" => cfg.network.ip = Some(args.value(flag, inline)?),
            "--gateway" => cfg.network.gateway = Some(args.value(flag, inline)?),
            "--mtu" => {
                cfg.network.mtu = args
                    .value(flag, inline)?
                    .parse()
                    .map_err(|_| Error::usage("--mtu expects an integer"))?
            }
            "-p" | "--publish" => cfg
                .network
                .publish
                .push(PortMapping::parse(&args.value(flag, inline)?)?),
            "--no-nat" => cfg.network.nat = false,
            "--dns" => {
                let v = args.value(flag, inline)?;
                cfg.network.dns = v.split(',').map(|s| s.trim().to_string()).collect();
            }

            // Security
            "--cap-add" => cfg.security.cap_add.push(args.value(flag, inline)?),
            "--cap-drop" => cfg.security.cap_drop.push(args.value(flag, inline)?),
            "--seccomp" => cfg.security.seccomp = SeccompMode::parse(&args.value(flag, inline)?)?,
            "--privileged" => cfg.security.privileged = true,
            "--no-new-privs" => {
                cfg.security.no_new_privs = match inline {
                    Some(v) => parse_bool(flag, v)?,
                    None => true,
                }
            }
            "--user" | "-u" => {
                cfg.security.user = Some(crate::config::parse_user(&args.value(flag, inline)?)?)
            }

            // Namespaces
            "--no-pid-ns" => cfg.namespaces.pid = false,
            "--no-ipc-ns" => cfg.namespaces.ipc = false,
            "--no-uts-ns" => cfg.namespaces.uts = false,
            "--no-cgroup-ns" => cfg.namespaces.cgroup = false,

            other => {
                return Err(Error::usage(format!(
                    "unknown option {:?} for `myrun {}`",
                    other,
                    if run { "run" } else { "create" }
                )))
            }
        }
    }

    // Positional form: <rootfs> <command> [args...]
    if !positional.is_empty() {
        if cfg.rootfs.as_os_str().is_empty() {
            cfg.rootfs = PathBuf::from(positional.remove(0));
        }
        if !positional.is_empty() {
            cfg.command = positional;
        }
    }

    cfg.detach = detach;
    Ok((
        RunArgs {
            config: cfg,
            detach,
        },
        config_path,
    ))
}

fn parse_start(args: &mut Args) -> Result<Command> {
    let mut attach = false;
    let mut id = None;
    while let Some(raw) = args.next() {
        let (flag, _) = split_flag(&raw);
        match flag {
            "-a" | "--attach" => attach = true,
            other if other.starts_with('-') => {
                return Err(Error::usage(format!(
                    "unknown option {:?} for start",
                    other
                )))
            }
            _ => id = Some(raw),
        }
    }
    Ok(Command::Start {
        id: id.ok_or_else(|| Error::usage("start needs a container"))?,
        attach,
    })
}

fn parse_stop(args: &mut Args) -> Result<Command> {
    let mut timeout = crate::runtime::lifecycle::DEFAULT_STOP_TIMEOUT;
    let mut ids = Vec::new();
    while let Some(raw) = args.next() {
        let (flag, inline) = split_flag(&raw);
        match flag {
            "-t" | "--timeout" | "--time" => {
                timeout = args
                    .value(flag, inline)?
                    .parse()
                    .map_err(|_| Error::usage("--timeout expects seconds"))?
            }
            other if other.starts_with('-') => {
                return Err(Error::usage(format!("unknown option {:?} for stop", other)))
            }
            _ => ids.push(raw),
        }
    }
    if ids.is_empty() {
        return Err(Error::usage("stop needs at least one container"));
    }
    Ok(Command::Stop { ids, timeout })
}

fn parse_kill(args: &mut Args) -> Result<Command> {
    let mut signal = crate::sys::ffi::SIGTERM;
    let mut ids = Vec::new();
    while let Some(raw) = args.next() {
        let (flag, inline) = split_flag(&raw);
        match flag {
            "-s" | "--signal" => signal = parse_signal(&args.value(flag, inline)?)?,
            other if other.starts_with('-') => {
                return Err(Error::usage(format!("unknown option {:?} for kill", other)))
            }
            _ => ids.push(raw),
        }
    }
    if ids.is_empty() {
        return Err(Error::usage("kill needs at least one container"));
    }
    Ok(Command::Kill { ids, signal })
}

fn parse_delete(args: &mut Args) -> Result<Command> {
    let mut force = false;
    let mut ids = Vec::new();
    while let Some(raw) = args.next() {
        let (flag, _) = split_flag(&raw);
        match flag {
            "-f" | "--force" => force = true,
            other if other.starts_with('-') => {
                return Err(Error::usage(format!("unknown option {:?} for rm", other)))
            }
            _ => ids.push(raw),
        }
    }
    if ids.is_empty() {
        return Err(Error::usage("rm needs at least one container"));
    }
    Ok(Command::Delete { ids, force })
}

fn parse_list(args: &mut Args) -> Result<Command> {
    let (mut all, mut json, mut quiet) = (false, false, false);
    while let Some(raw) = args.next() {
        let (flag, _) = split_flag(&raw);
        match flag {
            "-a" | "--all" => all = true,
            "--json" => json = true,
            "-q" | "--quiet" => quiet = true,
            other => return Err(Error::usage(format!("unknown option {:?} for list", other))),
        }
    }
    Ok(Command::List { all, json, quiet })
}

fn parse_stats(args: &mut Args) -> Result<Command> {
    let (mut json, mut follow) = (false, false);
    let mut interval_ms = 1000;
    let mut ids = Vec::new();
    while let Some(raw) = args.next() {
        let (flag, inline) = split_flag(&raw);
        match flag {
            "--json" => json = true,
            "-f" | "--follow" => follow = true,
            "-i" | "--interval" => {
                let secs: f64 = args
                    .value(flag, inline)?
                    .parse()
                    .map_err(|_| Error::usage("--interval expects seconds"))?;
                if secs <= 0.0 {
                    return Err(Error::usage("--interval must be positive"));
                }
                interval_ms = (secs * 1000.0) as u64;
            }
            other if other.starts_with('-') => {
                return Err(Error::usage(format!(
                    "unknown option {:?} for stats",
                    other
                )))
            }
            _ => ids.push(raw),
        }
    }
    Ok(Command::Stats {
        ids,
        json,
        follow,
        interval_ms,
    })
}

fn parse_logs(args: &mut Args) -> Result<Command> {
    let mut follow = false;
    let mut tail = None;
    let mut id = None;
    while let Some(raw) = args.next() {
        let (flag, inline) = split_flag(&raw);
        match flag {
            "-f" | "--follow" => follow = true,
            "-n" | "--tail" => {
                let v = args.value(flag, inline)?;
                if v != "all" {
                    tail = Some(
                        v.parse()
                            .map_err(|_| Error::usage("--tail expects a number or 'all'"))?,
                    );
                }
            }
            other if other.starts_with('-') => {
                return Err(Error::usage(format!("unknown option {:?} for logs", other)))
            }
            _ => id = Some(raw),
        }
    }
    Ok(Command::Logs {
        id: id.ok_or_else(|| Error::usage("logs needs a container"))?,
        follow,
        tail,
    })
}

fn parse_wait(args: &mut Args) -> Result<Command> {
    let mut timeout = None;
    let mut ids = Vec::new();
    while let Some(raw) = args.next() {
        let (flag, inline) = split_flag(&raw);
        match flag {
            "-t" | "--timeout" => {
                timeout = Some(
                    args.value(flag, inline)?
                        .parse()
                        .map_err(|_| Error::usage("--timeout expects seconds"))?,
                )
            }
            other if other.starts_with('-') => {
                return Err(Error::usage(format!("unknown option {:?} for wait", other)))
            }
            _ => ids.push(raw),
        }
    }
    if ids.is_empty() {
        return Err(Error::usage("wait needs at least one container"));
    }
    Ok(Command::Wait { ids, timeout })
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

pub fn help_text(topic: Option<&str>) -> String {
    match topic {
        Some("run") | Some("create") => RUN_HELP.to_string(),
        Some("network") => NETWORK_HELP.to_string(),
        Some("security") => SECURITY_HELP.to_string(),
        Some(other) => format!("no help topic {:?}\n\n{}", other, MAIN_HELP),
        None => MAIN_HELP.to_string(),
    }
}

pub const MAIN_HELP: &str = r#"myrun - a container runtime

USAGE:
    myrun [global options] <command> [options]

COMMANDS:
    run <rootfs> <cmd>...   Create and start a container
    create <rootfs> <cmd>.. Create a container without starting it
    start <container>       Start a created container
    stop <container>...     SIGTERM, then SIGKILL after a grace period
    kill <container>...     Send a signal (default TERM)
    pause / unpause <c>...  Freeze / thaw via the cgroup freezer
    rm <container>...       Delete a container and its resources
    ls                      List containers
    inspect <container>...  Full JSON state
    stats [container]...    Live resource usage
    logs <container>        Show captured output
    wait <container>...     Block until a container exits
    gc                      Reconcile state and clean up orphans
    info                    Runtime and host capability report

GLOBAL OPTIONS:
    --root <dir>            State directory (default /run/myrun)
    --log <level>           error|warn|info|debug|trace
    --debug                 Shorthand for --log debug
    -h, --help [topic]      Help; topics: run, network, security
    -V, --version

EXAMPLES:
    myrun run ./rootfs /bin/sh
    myrun run -d --name web -m 256m --cpus 1.5 -p 8080:80 ./rootfs /srv/httpd
    myrun ls -a
    myrun stats --follow
"#;

pub const RUN_HELP: &str = r#"myrun run [options] <rootfs> <command> [args...]

CONTAINER:
    --name <name>           Human-readable name (must be unique)
    --rootfs <dir>          Root filesystem (alternative to the positional)
    -e, --env KEY=VALUE     Set an environment variable (repeatable)
    -w, --workdir <dir>     Working directory inside the container
    --hostname <name>       UTS hostname (default: the short container id)
    -v, --volume SRC:DST[:ro]   Bind mount, or tmpfs:DST for a tmpfs
    --read-only             Mount the rootfs read-only
    --label key=value       Attach metadata (repeatable)
    -d, --detach            Run in the background and print the id
    --rm                    Delete the container once it exits
    -c, --config <file>     Load defaults from a TOML or JSON file

RESOURCES:
    -m, --memory <size>     Memory limit, e.g. 512m, 2g
    --memory-swap <size>    Memory + swap limit
    --cpus <n>              Fractional CPU limit, e.g. 1.5
    --cpu-weight <n>        Relative weight, 1-10000 (default 100)
    --pids <n>              Maximum number of processes

NETWORK:            (see `myrun --help network`)
    --network none|bridge|host
    -p, --publish H:C[/tcp|udp]

SECURITY:           (see `myrun --help security`)
    --cap-add / --cap-drop <CAP>
    --seccomp unconfined|default|strict
    -u, --user <uid[:gid]>
    --privileged
"#;

pub const NETWORK_HELP: &str = r#"myrun networking

MODES:
    --network none      Isolated network namespace with only a loopback
                        interface. The default.
    --network bridge    A veth pair into a host bridge, an address from the
                        runtime's IPAM, NAT to the outside world.
    --network host      Share the host's network namespace. No isolation.

OPTIONS:
    --bridge <name>     Bridge to attach to (default myrun0, created on demand)
    --subnet <cidr>     Address pool (default 10.87.0.0/24)
    --ip <addr>         Request a specific address from the pool
    --gateway <addr>    Bridge address (default: first host address)
    --mtu <n>           MTU for both ends of the veth pair
    -p, --publish H:C   Publish a container port on the host (DNAT)
    --no-nat            Skip the MASQUERADE rule
    --dns a,b           Nameservers written to /etc/resolv.conf

NOTES:
    Published ports require --network bridge.
    Packet filtering is done by shelling out to iptables; every rule is
    tagged with the container id so teardown removes exactly its own rules.
"#;

pub const SECURITY_HELP: &str = r#"myrun security

By default a container gets:
  * a Docker-like capability set, minus CAP_NET_RAW
  * PR_SET_NO_NEW_PRIVS
  * a seccomp filter denying ~39 syscalls (mount, pivot_root, kexec, bpf, ...)
  * /proc/kcore and friends masked, /proc/sys and friends read-only
  * a read-only /sys

OPTIONS:
    --cap-add <CAP>       Add a capability (name with or without CAP_)
    --cap-drop <CAP>      Drop one; --cap-drop all clears the set first
    --seccomp <mode>      unconfined | default | strict
    --no-new-privs=false  Disable no_new_privs (incompatible with seccomp)
    -u, --user uid[:gid]  Run the workload as an unprivileged user
    --privileged          Disable all of the above. Use only for debugging.

ORDER OF OPERATIONS (inside the container, after pivot_root):
    capabilities -> no_new_privs -> seccomp -> setgid/setuid -> execve
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Command> {
        let v: Vec<String> = s.split_whitespace().map(|x| x.to_string()).collect();
        parse(&v)
    }

    #[test]
    fn positional_rootfs_and_command() {
        match p("run /tmp/rootfs /bin/sh -c echo").unwrap() {
            Command::Run(a) => {
                assert_eq!(a.config.rootfs, PathBuf::from("/tmp/rootfs"));
                assert_eq!(a.config.command, vec!["/bin/sh", "-c", "echo"]);
                assert!(!a.detach);
            }
            other => panic!("wrong command: {:?}", other),
        }
    }

    #[test]
    fn flags_before_and_after_positionals() {
        match p("run -d --name web -m 256m --cpus 1.5 /tmp /bin/sh").unwrap() {
            Command::Run(a) => {
                assert!(a.detach);
                assert_eq!(a.config.name.as_deref(), Some("web"));
                assert_eq!(a.config.resources.memory, Some(268_435_456));
                assert_eq!(a.config.resources.cpus, Some(1.5));
                assert_eq!(a.config.command, vec!["/bin/sh"]);
            }
            other => panic!("wrong command: {:?}", other),
        }
    }

    #[test]
    fn command_arguments_are_not_parsed_as_flags() {
        // This is the property that matters most: `-c` here belongs to sh.
        match p("run /tmp /bin/sh -c ls --json").unwrap() {
            Command::Run(a) => {
                assert_eq!(a.config.command, vec!["/bin/sh", "-c", "ls", "--json"]);
            }
            other => panic!("wrong command: {:?}", other),
        }
    }

    #[test]
    fn inline_values_work() {
        match p("run --name=api --memory=1g --network=bridge /tmp /bin/true").unwrap() {
            Command::Run(a) => {
                assert_eq!(a.config.name.as_deref(), Some("api"));
                assert_eq!(a.config.resources.memory, Some(1024 * 1024 * 1024));
                assert_eq!(a.config.network.mode, NetworkMode::Bridge);
            }
            other => panic!("wrong command: {:?}", other),
        }
    }

    #[test]
    fn unknown_flags_are_rejected() {
        // A typo must never be silently ignored.
        let e = p("run --memroy 256m /tmp /bin/sh").unwrap_err();
        assert!(e.to_string().contains("unknown option"), "{}", e);
        assert!(p("frobnicate").is_err());
        assert!(p("--nope run").is_err());
    }

    #[test]
    fn repeatable_flags_accumulate() {
        match p("run -e A=1 -e B=2 -v /a:/b -v /c:/d:ro -p 80:80 -p 443:443 /tmp /bin/true")
            .unwrap()
        {
            Command::Run(a) => {
                assert_eq!(a.config.env_value("A"), Some("1"));
                assert_eq!(a.config.env_value("B"), Some("2"));
                assert_eq!(a.config.mounts.len(), 2);
                assert!(a.config.mounts[1].readonly);
                assert_eq!(a.config.network.publish.len(), 2);
            }
            other => panic!("wrong command: {:?}", other),
        }
    }

    #[test]
    fn double_dash_ends_option_parsing() {
        match p("run --rootfs /tmp -- /bin/sh --detach").unwrap() {
            Command::Run(a) => {
                assert_eq!(a.config.command, vec!["/bin/sh", "--detach"]);
                assert!(!a.detach, "--detach after -- belongs to the workload");
            }
            other => panic!("wrong command: {:?}", other),
        }
    }

    #[test]
    fn lifecycle_commands() {
        match p("stop -t 30 abc def").unwrap() {
            Command::Stop { ids, timeout } => {
                assert_eq!(ids, vec!["abc", "def"]);
                assert_eq!(timeout, 30);
            }
            other => panic!("{:?}", other),
        }
        match p("kill -s KILL abc").unwrap() {
            Command::Kill { signal, .. } => assert_eq!(signal, crate::sys::ffi::SIGKILL),
            other => panic!("{:?}", other),
        }
        match p("rm -f abc").unwrap() {
            Command::Delete { force, .. } => assert!(force),
            other => panic!("{:?}", other),
        }
        match p("ls -a --json").unwrap() {
            Command::List { all, json, .. } => assert!(all && json),
            other => panic!("{:?}", other),
        }
        match p("logs -f -n 20 abc").unwrap() {
            Command::Logs { follow, tail, .. } => {
                assert!(follow);
                assert_eq!(tail, Some(20));
            }
            other => panic!("{:?}", other),
        }
        assert!(matches!(p("gc").unwrap(), Command::Gc));
        assert!(matches!(p("info").unwrap(), Command::Info));
    }

    #[test]
    fn missing_operands_are_errors() {
        assert!(p("stop").is_err());
        assert!(p("kill").is_err());
        assert!(p("logs").is_err());
        assert!(p("inspect").is_err());
        assert!(p("start").is_err());
        assert!(p("run --name").is_err(), "--name with no value");
    }

    #[test]
    fn internal_subcommands() {
        match p("__init /run/myrun/containers/abc").unwrap() {
            Command::Init { state_dir } => {
                assert_eq!(state_dir, PathBuf::from("/run/myrun/containers/abc"))
            }
            other => panic!("{:?}", other),
        }
        match p("__shim /run/myrun/containers/abc 7").unwrap() {
            Command::Shim { notify_fd, .. } => assert_eq!(notify_fd, 7),
            other => panic!("{:?}", other),
        }
        assert!(p("__shim /x notanumber").is_err());
    }

    #[test]
    fn help_and_version() {
        assert!(matches!(p("").unwrap(), Command::Help { .. }));
        assert!(matches!(p("--version").unwrap(), Command::Version));
        assert!(matches!(p("help run").unwrap(), Command::Help { .. }));
        assert!(help_text(Some("network")).contains("bridge"));
        assert!(help_text(Some("security")).contains("no_new_privs"));
        assert!(help_text(None).contains("USAGE"));
    }

    #[test]
    fn security_flags() {
        match p(
            "run --cap-add NET_ADMIN --cap-drop all --seccomp strict -u 1000:1000 /tmp /bin/true",
        )
        .unwrap()
        {
            Command::Run(a) => {
                assert_eq!(a.config.security.cap_add, vec!["NET_ADMIN"]);
                assert_eq!(a.config.security.cap_drop, vec!["all"]);
                assert_eq!(a.config.security.seccomp, SeccompMode::Strict);
                assert_eq!(a.config.security.user, Some((1000, 1000)));
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn stats_interval_parsing() {
        match p("stats -i 0.5 --json").unwrap() {
            Command::Stats {
                interval_ms, json, ..
            } => {
                assert_eq!(interval_ms, 500);
                assert!(json);
            }
            other => panic!("{:?}", other),
        }
        assert!(p("stats -i 0").is_err());
    }

    #[test]
    fn flags_override_the_config_file_regardless_of_order() {
        let dir = std::env::temp_dir().join(format!("myrun-cliorder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        std::fs::write(
            &path,
            "rootfs = \"/tmp\"\ncommand = [\"/bin/true\"]\nname = \"from-file\"\nhostname = \"file-host\"\n",
        )
        .unwrap();
        let p = path.to_str().unwrap().to_string();

        for argv in [
            vec!["run", "--name", "from-flag", "--config", &p],
            vec!["run", "--config", &p, "--name", "from-flag"],
        ] {
            let v: Vec<String> = argv.iter().map(|x| x.to_string()).collect();
            match parse(&v).unwrap() {
                Command::Run(a) => {
                    assert_eq!(
                        a.config.name.as_deref(),
                        Some("from-flag"),
                        "flag lost for {:?}",
                        argv
                    );
                    // Values the flags did not touch still come from the file.
                    assert_eq!(a.config.hostname, "file-host");
                    assert_eq!(a.config.command, vec!["/bin/true".to_string()]);
                    assert_eq!(a.config.rootfs, PathBuf::from("/tmp"));
                }
                other => panic!("{:?}", other),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn positional_command_overrides_the_config_file() {
        let dir = std::env::temp_dir().join(format!("myrun-clipos-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        std::fs::write(&path, "rootfs = \"/tmp\"\ncommand = [\"/bin/true\"]\n").unwrap();
        let p = path.to_str().unwrap().to_string();
        let v: Vec<String> = ["run", "--config", &p, "/bin/echo", "hi"]
            .iter()
            .map(|x| x.to_string())
            .collect();
        match parse(&v).unwrap() {
            Command::Run(a) => {
                assert_eq!(a.config.command, vec!["/bin/echo", "hi"]);
                assert_eq!(a.config.rootfs, PathBuf::from("/tmp"), "rootfs from file");
            }
            other => panic!("{:?}", other),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
