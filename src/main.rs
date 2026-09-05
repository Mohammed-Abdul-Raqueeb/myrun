//! `myrun` entry point.

use myrun::cli::{self, Command};
use myrun::config::ContainerConfig;
use myrun::error::{exit, Error, Result};
use myrun::runtime::state::{ContainerState, Status, Store};
use myrun::runtime::{init, lifecycle, shim, stats, supervisor};
use myrun::sys::ffi;
use myrun::sys::process::ExitStatus;
use myrun::sys::signal as sig;
use myrun::util;
use myrun::util::json::Json;
use std::io::Write;

fn main() {
    myrun::logging::init_from_env();
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let code = match real_main(&argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("myrun: {}", e);
            e.exit_code()
        }
    };
    std::process::exit(code);
}

fn real_main(argv: &[String]) -> Result<i32> {
    let cmd = cli::parse(argv)?;

    // The two internal subcommands never return.
    match cmd {
        Command::Init { ref state_dir } => init::main(state_dir),
        Command::Shim {
            ref state_dir,
            notify_fd,
        } => shim::main(state_dir, notify_fd),
        _ => {}
    }

    // Fault injection is opt-in via MYRUN_FAULT; validate it once, here, so
    // a typo in a point name is reported instead of silently never firing.
    myrun::fault::validate_env()?;

    match cmd {
        Command::Help { topic } => {
            println!("{}", cli::help_text(topic.as_deref()));
            Ok(0)
        }
        Command::Version => {
            println!("myrun {}", cli::VERSION);
            Ok(0)
        }
        Command::Info => cmd_info(),
        Command::Run(args) => cmd_run(*args),
        Command::Create(args) => cmd_create(*args),
        Command::Start { id, attach } => cmd_start(&id, attach),
        Command::Stop { ids, timeout } => cmd_stop(&ids, timeout),
        Command::Kill { ids, signal } => cmd_kill(&ids, signal),
        Command::Delete { ids, force } => cmd_delete(&ids, force),
        Command::List { all, json, quiet } => cmd_list(all, json, quiet),
        Command::Inspect { ids } => cmd_inspect(&ids),
        Command::Stats {
            ids,
            json,
            follow,
            interval_ms,
        } => cmd_stats(&ids, json, follow, interval_ms),
        Command::Pause { ids } => cmd_simple(&ids, lifecycle::pause, "paused"),
        Command::Unpause { ids } => cmd_simple(&ids, lifecycle::unpause, "unpaused"),
        Command::Logs { id, follow, tail } => cmd_logs(&id, follow, tail),
        Command::Wait { ids, timeout } => cmd_wait(&ids, timeout),
        Command::Gc => cmd_gc(),
        // Both diverge in the match above; this arm only satisfies
        // exhaustiveness. An error beats `unreachable!()`: if a future
        // refactor ever lets one fall through, the user gets a message
        // instead of a panic.
        Command::Init { .. } | Command::Shim { .. } => Err(Error::usage(
            "internal subcommands are not invoked directly",
        )),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn store() -> Result<Store> {
    Store::open()
}

/// Print a left-aligned table.
fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(c.len());
            }
        }
    }
    let line = |cells: &[String]| {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                s.push_str(&format!("{:width$}   ", c, width = widths[i]));
            }
        }
        s.trim_end().to_string()
    };
    let head: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    println!("{}", line(&head));
    for r in rows {
        println!("{}", line(r));
    }
}

fn resolve(store: &Store, needle: &str) -> Result<String> {
    store.resolve(needle)
}

fn require_root(action: &str) -> Result<()> {
    if myrun::sys::is_root() {
        return Ok(());
    }
    Err(Error::unsupported(format!(
        "{} needs root: creating namespaces, cgroups and veth pairs are all \
         privileged operations. Re-run with sudo. (Rootless containers would \
         need user namespaces and a setuid helper for networking; see \
         docs/security.md.)",
        action
    )))
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_info() -> Result<i32> {
    let mut out = String::new();
    out.push_str(&format!("myrun {}\n", cli::VERSION));
    out.push_str(&format!(
        "kernel:            {}\n",
        util::read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|_| "unknown".into())
    ));
    out.push_str(&format!("running as uid:    {}\n", myrun::sys::geteuid()));
    out.push_str(&format!(
        "state root:        {}\n",
        myrun::runtime::runtime_root().display()
    ));
    out.push_str(&format!("cpus:              {}\n", myrun::sys::num_cpus()));

    match myrun::runtime::cgroup::mount_point() {
        Ok(m) => {
            let avail = myrun::runtime::cgroup::available_controllers(&m);
            out.push_str(&format!("cgroup v2:         {}\n", m.display()));
            out.push_str(&format!(
                "  controllers:     {}\n",
                if avail.is_empty() {
                    "(none delegated)".to_string()
                } else {
                    avail.join(" ")
                }
            ));
            for c in myrun::runtime::cgroup::WANTED {
                let ok = avail.iter().any(|a| a == c);
                out.push_str(&format!(
                    "  {:<14} {}\n",
                    format!("{}:", c),
                    if ok { "available" } else { "MISSING" }
                ));
            }
        }
        Err(e) => out.push_str(&format!("cgroup v2:         unavailable ({})\n", e)),
    }

    out.push_str(&format!(
        "iptables:          {}\n",
        if myrun::runtime::nat::available() {
            "available"
        } else {
            "unavailable (bridge networking will not work)"
        }
    ));
    out.push_str(&format!(
        "seccomp:           {}\n",
        if std::path::Path::new("/proc/sys/kernel/seccomp/actions_avail").exists() {
            "supported"
        } else {
            "unknown"
        }
    ));
    out.push_str(&format!(
        "ip_forward:        {}\n",
        util::read_trimmed("/proc/sys/net/ipv4/ip_forward").unwrap_or_else(|_| "?".into())
    ));

    out.push_str("\nfault injection points (MYRUN_FAULT=<point>):\n");
    for p in myrun::fault::POINTS {
        out.push_str(&format!("  {}\n", p));
    }
    print!("{}", out);
    Ok(0)
}

fn build_state(mut cfg: ContainerConfig, detach: bool) -> Result<ContainerState> {
    cfg.finalize_and_validate(true)?;
    myrun::runtime::security::precheck(&cfg.security)?;
    cfg.detach = detach;
    Ok(ContainerState::new(cfg))
}

fn cmd_create(args: cli::RunArgs) -> Result<i32> {
    require_root("creating a container")?;
    let store = store()?;
    let st = build_state(args.config, args.detach)?;
    let st = supervisor::create(&store, st)?;
    println!("{}", st.id);
    Ok(0)
}

fn cmd_run(args: cli::RunArgs) -> Result<i32> {
    require_root("running a container")?;
    let store = store()?;
    let detach = args.detach;
    let st = build_state(args.config, detach)?;
    let st = supervisor::create(&store, st)?;

    if detach {
        match shim::spawn(&store, &st) {
            Ok(_) => {
                println!("{}", st.id);
                Ok(0)
            }
            Err(e) => {
                // The shim already rolled back; remove the state directory so
                // a failed `run -d` does not leave a phantom container.
                let _ = store.remove(&st.id);
                Err(e)
            }
        }
    } else {
        run_attached(&store, st)
    }
}

/// Run in the foreground: the CLI process itself supervises the container.
///
/// Documented limitation: if this process is SIGKILLed, init dies with it
/// (PDEATHSIG) but the cgroup, veth and iptables rules survive until the
/// next `myrun gc`.
fn run_attached(store: &Store, mut st: ContainerState) -> Result<i32> {
    let mut running = match supervisor::launch(store, &mut st) {
        Ok(r) => r,
        Err(e) => {
            let _ = store.remove(&st.id);
            return Err(e);
        }
    };

    // Forward terminal signals to the container instead of dying and
    // orphaning it.
    let forwarded = [ffi::SIGINT, ffi::SIGTERM, ffi::SIGQUIT, ffi::SIGHUP];
    let _blocked = sig::block(&forwarded)?;
    let sfd = sig::SignalFd::new(&forwarded)?;

    let mut fds = [
        ffi::PollFd {
            fd: sfd.fd(),
            events: ffi::POLLIN,
            revents: 0,
        },
        ffi::PollFd {
            fd: running.chan.fd(),
            events: ffi::POLLIN,
            revents: 0,
        },
    ];

    loop {
        match sig::poll_fds(&mut fds, 500) {
            Ok(0) => {
                if !st.init_is_alive() {
                    break;
                }
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                myrun::log_warn!("poll: {}", e);
                continue;
            }
        }
        if fds[0].revents != 0 {
            while let Ok(Some(info)) = sfd.next_signal() {
                let signo = info.ssi_signo as i32;
                myrun::log_debug!("forwarding {} to the container", signo);
                let _ = myrun::sys::process::kill_pid(st.init_pid, signo);
            }
        }
        if fds[1].revents != 0 {
            break;
        }
    }

    let status = supervisor::wait_for_exit(store, &mut st, &mut running)?;
    supervisor::teardown(store, &mut st);
    if st.config.auto_remove {
        let _ = store.remove(&st.id);
    }
    report_exit(&st, status);
    Ok(status.exit_code())
}

fn report_exit(st: &ContainerState, status: ExitStatus) {
    if st.oom_killed {
        eprintln!(
            "myrun: container {} was killed by the kernel OOM killer",
            util::short_id(&st.id)
        );
    } else if status.signal.is_some() {
        myrun::log_info!("container exited: {}", status.describe());
    }
}

fn cmd_start(id: &str, attach: bool) -> Result<i32> {
    require_root("starting a container")?;
    let store = store()?;
    let id = resolve(&store, id)?;
    if attach {
        let mut st = store.load(&id)?;
        if st.status != Status::Created {
            return Err(Error::state(format!(
                "container {} is {}, not created",
                util::short_id(&id),
                st.status.as_str()
            )));
        }
        st.config.detach = false;
        return run_attached(&store, st);
    }
    let st = lifecycle::start(&store, &id)?;
    println!("{}", st.id);
    Ok(0)
}

fn for_each<F>(ids: &[String], mut f: F) -> Result<i32>
where
    F: FnMut(&Store, &str) -> Result<String>,
{
    let store = store()?;
    let mut failures = 0;
    for needle in ids {
        match resolve(&store, needle).and_then(|id| f(&store, &id)) {
            Ok(out) => println!("{}", out),
            Err(e) => {
                eprintln!("myrun: {}: {}", needle, e);
                failures += 1;
            }
        }
    }
    Ok(if failures > 0 { exit::GENERIC } else { 0 })
}

fn cmd_stop(ids: &[String], timeout: u64) -> Result<i32> {
    for_each(ids, |store, id| {
        lifecycle::stop(store, id, timeout)?;
        Ok(id.to_string())
    })
}

fn cmd_kill(ids: &[String], signal: i32) -> Result<i32> {
    let all = signal == ffi::SIGKILL;
    for_each(ids, move |store, id| {
        lifecycle::kill(store, id, signal, all)?;
        Ok(id.to_string())
    })
}

fn cmd_delete(ids: &[String], force: bool) -> Result<i32> {
    for_each(ids, move |store, id| {
        lifecycle::delete(store, id, force)?;
        Ok(id.to_string())
    })
}

fn cmd_simple(ids: &[String], op: fn(&Store, &str) -> Result<()>, verb: &str) -> Result<i32> {
    let verb = verb.to_string();
    for_each(ids, move |store, id| {
        op(store, id)?;
        myrun::log_info!("{} {}", verb, util::short_id(id));
        Ok(id.to_string())
    })
}

fn cmd_list(all: bool, json: bool, quiet: bool) -> Result<i32> {
    let store = store()?;
    let mut states = Vec::new();
    for mut st in store.list()? {
        let _ = store.reconcile(&mut st);
        if all || st.status.is_live() || st.status == Status::Created {
            states.push(st);
        }
    }

    if json {
        let arr = Json::Arr(states.iter().map(|s| s.to_json()).collect());
        println!("{}", arr.to_string_pretty());
        return Ok(0);
    }
    if quiet {
        for s in &states {
            println!("{}", s.id);
        }
        return Ok(0);
    }

    let rows: Vec<Vec<String>> = states
        .iter()
        .map(|s| {
            vec![
                util::short_id(&s.id),
                s.name.clone().unwrap_or_else(|| "-".into()),
                s.status.as_str().to_string(),
                if s.init_pid > 0 && s.status.is_live() {
                    s.init_pid.to_string()
                } else {
                    "-".into()
                },
                s.config
                    .command
                    .join(" ")
                    .chars()
                    .take(30)
                    .collect::<String>(),
                s.network.ip.clone().unwrap_or_else(|| "-".into()),
                if s.started_at > 0 {
                    util::format_duration_ms(s.uptime_ms())
                } else {
                    "-".into()
                },
                match (s.status, s.exit_code, s.exit_signal) {
                    (Status::Stopped, Some(c), _) => format!("exited({})", c),
                    (Status::Stopped, _, Some(sg)) => {
                        format!("signal({})", myrun::sys::process::signal_name(sg))
                    }
                    _ => "-".into(),
                },
            ]
        })
        .collect();
    print_table(
        &[
            "CONTAINER",
            "NAME",
            "STATUS",
            "PID",
            "COMMAND",
            "IP",
            "UPTIME",
            "EXIT",
        ],
        &rows,
    );
    Ok(0)
}

fn cmd_inspect(ids: &[String]) -> Result<i32> {
    let store = store()?;
    let mut out = Vec::new();
    for needle in ids {
        let id = resolve(&store, needle)?;
        let mut st = store.load(&id)?;
        let _ = store.reconcile(&mut st);
        let mut j = st.to_json();
        j.set(
            "security_summary",
            Json::Str(myrun::runtime::security::summary(&st.config.security)),
        );
        j.set("uptime_ms", Json::Int(st.uptime_ms() as i64));
        j.set("created", Json::Str(util::format_time(st.created_at)));
        if st.finished_at > 0 {
            j.set("finished", Json::Str(util::format_time(st.finished_at)));
        }
        out.push(j);
    }
    println!("{}", Json::Arr(out).to_string_pretty());
    Ok(0)
}

fn cmd_stats(ids: &[String], json: bool, follow: bool, interval_ms: u64) -> Result<i32> {
    let store = store()?;

    let collect_all = || -> Result<Vec<stats::Stats>> {
        let targets: Vec<String> = if ids.is_empty() {
            store
                .list()?
                .into_iter()
                .filter(|s| s.status.is_live())
                .map(|s| s.id)
                .collect()
        } else {
            ids.iter()
                .map(|n| resolve(&store, n))
                .collect::<Result<Vec<_>>>()?
        };
        let mut out = Vec::new();
        for id in targets {
            let mut st = store.load(&id)?;
            let _ = store.reconcile(&mut st);
            out.push(stats::collect(&st)?);
        }
        Ok(out)
    };

    if !follow {
        let all = collect_all()?;
        if json {
            println!(
                "{}",
                Json::Arr(all.iter().map(|s| s.to_json()).collect()).to_string_pretty()
            );
        } else if all.is_empty() {
            println!("no running containers");
        } else {
            let rows: Vec<Vec<String>> = all.iter().map(|s| s.table_row()).collect();
            print_table(stats::Stats::HEADERS, &rows);
        }
        return Ok(0);
    }

    let mut previous: Vec<stats::Stats> = Vec::new();
    loop {
        let current = collect_all()?;
        if current.is_empty() {
            println!("no running containers");
            return Ok(0);
        }
        if json {
            println!(
                "{}",
                Json::Arr(current.iter().map(|s| s.to_json()).collect()).to_string()
            );
        } else {
            // Clear the screen so `stats -f` behaves like `top`.
            print!("\x1b[2J\x1b[H");
            let rows: Vec<Vec<String>> = current
                .iter()
                .map(|s| {
                    let mut row = s.table_row();
                    if let Some(p) = previous.iter().find(|p| p.id == s.id) {
                        if let Some(pct) = stats::cpu_delta_percent(p, s, interval_ms) {
                            row[3] = format!("{:.2}%", pct);
                        }
                    }
                    row
                })
                .collect();
            print_table(stats::Stats::HEADERS, &rows);
            let _ = std::io::stdout().flush();
        }
        previous = current;
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
    }
}

fn cmd_logs(id: &str, follow: bool, tail: Option<usize>) -> Result<i32> {
    let store = store()?;
    let id = resolve(&store, id)?;
    if follow {
        let stdout = std::io::stdout();
        lifecycle::follow_logs(&store, &id, stdout.lock())?;
    } else {
        let text = lifecycle::logs(&store, &id, tail)?;
        print!("{}", text);
        if !text.is_empty() && !text.ends_with('\n') {
            println!();
        }
    }
    Ok(0)
}

/// Print each container's exit code and exit 0.
///
/// `wait` exits non-zero only when the wait itself fails (unknown container,
/// timeout). Propagating the container's code instead would make "the
/// container exited 1" indistinguishable from "wait could not find it".
fn cmd_wait(ids: &[String], timeout: Option<u64>) -> Result<i32> {
    let store = store()?;
    for needle in ids {
        let id = resolve(&store, needle)?;
        let status = lifecycle::wait(&store, &id, timeout)?;
        println!("{}", status.exit_code());
    }
    Ok(0)
}

fn cmd_gc() -> Result<i32> {
    require_root("garbage collection")?;
    let store = store()?;
    let report = supervisor::gc(&store)?;
    if report.is_empty() {
        println!("nothing to clean up");
    } else {
        for line in report {
            println!("{}", line);
        }
    }
    Ok(0)
}
