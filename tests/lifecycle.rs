//! Container lifecycle and isolation, exercised against real containers.
//!
//! Every test here needs root and `MYRUN_PRIVILEGED_TESTS=1`; without those
//! they print a skip line and pass, so `cargo test` stays useful for
//! unprivileged developers.

mod common;

use common::*;

#[test]
fn runs_a_command_and_propagates_its_exit_code() {
    require_privileged!("runs_a_command_and_propagates_its_exit_code");
    let sb = Sandbox::new("exit");

    let o = sb.sh("echo hello-container");
    assert_ok(&o, "run");
    assert!(
        stdout_of(&o).contains("hello-container"),
        "{}",
        stdout_of(&o)
    );

    // Exit codes must survive the init -> shim -> CLI chain intact.
    for code in [0, 1, 42, 127] {
        let o = sb.sh(&format!("exit {}", code));
        assert_eq!(
            code_of(&o),
            code,
            "exit {} was reported as {}",
            code,
            code_of(&o)
        );
    }
}

#[test]
fn a_missing_executable_is_reported_not_silently_zero() {
    require_privileged!("a_missing_executable_is_reported_not_silently_zero");
    let sb = Sandbox::new("noexe");
    let rootfs = rootfs();
    let o = sb.run(&["run", rootfs.to_str().unwrap(), "/bin/does-not-exist"]);
    assert!(!o.status.success(), "should not succeed");
    assert!(
        combined(&o).to_lowercase().contains("not"),
        "unhelpful error: {}",
        combined(&o)
    );
}

#[test]
fn pid_namespace_makes_the_workload_pid_two() {
    require_privileged!("pid_namespace_makes_the_workload_pid_two");
    let sb = Sandbox::new("pidns");
    // init is PID 1; the workload it forks is PID 2.
    let o = sb.sh("echo pid=$$");
    assert_ok(&o, "run");
    assert!(stdout_of(&o).contains("pid=2"), "{}", stdout_of(&o));

    // And the container cannot see the host's process table.
    let o = sb.sh("ls /proc | grep -c '^[0-9]*$'");
    assert_ok(&o, "run");
    let n: usize = stdout_of(&o).trim().parse().unwrap_or(9999);
    assert!(n < 10, "container sees {} host processes", n);
}

#[test]
fn uts_namespace_isolates_the_hostname() {
    require_privileged!("uts_namespace_isolates_the_hostname");
    let sb = Sandbox::new("uts");
    let o = sb.sh_with(&["--hostname", "isolated-box"], "hostname");
    assert_ok(&o, "run");
    assert_eq!(stdout_of(&o).trim(), "isolated-box");

    // The host's hostname must be unchanged.
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    assert_ne!(
        host.trim(),
        "isolated-box",
        "container changed the host hostname"
    );
}

#[test]
fn mount_namespace_and_pivot_root_detach_the_host() {
    require_privileged!("mount_namespace_and_pivot_root_detach_the_host");
    let sb = Sandbox::new("mountns");

    // A marker that exists on the host but not in the rootfs.
    let marker = "/tmp/myrun-host-marker-should-not-be-visible";
    std::fs::write(marker, "host").unwrap();

    let o = sb.sh(&format!(
        "test -e {} && echo LEAKED || echo isolated",
        marker
    ));
    assert_ok(&o, "run");
    assert!(
        stdout_of(&o).contains("isolated"),
        "host filesystem leaked into the container: {}",
        stdout_of(&o)
    );

    // Exactly one entry whose *mount point* (field 5) is "/" means the old
    // root really was detached, not merely hidden. Field 4 is "/" for almost
    // every entry, so this has to be an exact field match, not a grep.
    let o = sb.sh("awk '$5 == \"/\"' /proc/self/mountinfo | wc -l");
    assert_ok(&o, "run");
    assert_eq!(stdout_of(&o).trim(), "1", "old root still mounted");

    let _ = std::fs::remove_file(marker);
}

#[test]
fn standard_mounts_and_devices_are_present() {
    require_privileged!("standard_mounts_and_devices_are_present");
    let sb = Sandbox::new("devices");

    let o = sb.sh("for d in null zero full random urandom tty; do test -c /dev/$d || echo MISSING:$d; done; echo done");
    assert_ok(&o, "run");
    assert!(
        !stdout_of(&o).contains("MISSING"),
        "device nodes missing: {}",
        stdout_of(&o)
    );

    // /dev/null and /dev/zero must actually behave correctly, not just exist.
    let o =
        sb.sh("echo discarded > /dev/null && dd if=/dev/zero bs=16 count=1 2>/dev/null | wc -c");
    assert_ok(&o, "run");
    assert_eq!(stdout_of(&o).trim(), "16");

    let o = sb.sh("mount | grep -c -E '^(proc|sysfs|tmpfs|devpts|shm) '");
    assert_ok(&o, "run");
    let n: usize = stdout_of(&o).trim().parse().unwrap_or(0);
    assert!(n >= 4, "expected the standard mounts, got {}", n);
}

#[test]
fn sys_is_read_only() {
    require_privileged!("sys_is_read_only");
    let sb = Sandbox::new("sysro");
    let o = sb.sh("mount | grep ' /sys ' | grep -c ro");
    assert_ok(&o, "run");
    assert_eq!(
        stdout_of(&o).trim(),
        "1",
        "/sys should be mounted read-only"
    );
}

#[test]
fn read_only_rootfs_still_has_a_writable_tmp() {
    require_privileged!("read_only_rootfs_still_has_a_writable_tmp");
    let sb = Sandbox::new("rorootfs");
    let o = sb.sh_with(
        &["--read-only"],
        "touch /should-fail 2>/dev/null && echo WRITABLE || echo sealed; \
         touch /tmp/ok && echo tmp-writable",
    );
    assert_ok(&o, "run");
    let out = stdout_of(&o);
    assert!(out.contains("sealed"), "rootfs was writable: {}", out);
    assert!(
        out.contains("tmp-writable"),
        "/tmp should stay writable: {}",
        out
    );
}

#[test]
fn bind_mounts_honour_read_only() {
    require_privileged!("bind_mounts_honour_read_only");
    let sb = Sandbox::new("volumes");
    let dir = sb.root.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), "from-the-host\n").unwrap();

    let ro = format!("{}:/mnt/data:ro", dir.display());
    let o = sb.sh_with(
        &["-v", &ro],
        "cat /mnt/data/payload.txt; touch /mnt/data/new 2>/dev/null && echo WRITABLE || echo readonly",
    );
    assert_ok(&o, "run");
    let out = stdout_of(&o);
    assert!(out.contains("from-the-host"), "{}", out);
    assert!(
        out.contains("readonly"),
        "ro bind mount was writable: {}",
        out
    );

    // A writable bind mount must actually propagate back to the host.
    let rw = format!("{}:/mnt/data", dir.display());
    let o = sb.sh_with(&["-v", &rw], "echo from-container > /mnt/data/written.txt");
    assert_ok(&o, "run");
    let back = std::fs::read_to_string(dir.join("written.txt")).unwrap_or_default();
    assert!(
        back.contains("from-container"),
        "rw bind mount did not persist"
    );
}

#[test]
fn environment_and_working_directory_are_applied() {
    require_privileged!("environment_and_working_directory_are_applied");
    let sb = Sandbox::new("env");
    let o = sb.sh_with(
        &["-e", "GREETING=hi", "-e", "COUNT=7", "-w", "/tmp"],
        "echo $GREETING-$COUNT; pwd",
    );
    assert_ok(&o, "run");
    let out = stdout_of(&o);
    assert!(out.contains("hi-7"), "{}", out);
    assert!(out.contains("/tmp"), "{}", out);

    // A nonexistent working directory is an error, not a silent fallback.
    let o = sb.sh_with(&["-w", "/no/such/dir"], "pwd");
    assert!(!o.status.success());
    assert!(
        combined(&o).contains("working directory"),
        "{}",
        combined(&o)
    );
}

#[test]
fn detached_lifecycle_start_list_logs_stop_remove() {
    require_privileged!("detached_lifecycle_start_list_logs_stop_remove");
    let sb = Sandbox::new("detached");
    let rootfs = rootfs();

    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "lifecycle",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "i=0; while true; do echo tick-$i; i=$((i+1)); sleep 1; done",
    ]);
    assert_ok(&o, "run -d");
    let id = stdout_of(&o).trim().to_string();
    assert_eq!(id.len(), 32, "run -d should print the container id");

    assert!(
        wait_until(5000, || {
            let o = sb.run(&["ls"]);
            stdout_of(&o).contains("running")
        }),
        "container never reached running"
    );

    // Logs are captured by the shim.
    assert!(
        wait_until(5000, || sb
            .run(&["logs", "lifecycle"])
            .stdout
            .windows(6)
            .any(|w| w == b"tick-0")),
        "no output captured"
    );

    // Name resolution, prefix resolution and full id all work.
    for needle in [&id[..], "lifecycle", &id[..8]] {
        let o = sb.run(&["inspect", needle]);
        assert_ok(&o, "inspect");
        assert!(
            stdout_of(&o).contains(&id),
            "inspect {} lost the id",
            needle
        );
    }

    let o = sb.run(&["stop", "-t", "5", "lifecycle"]);
    assert_ok(&o, "stop");

    let j = state_json(&sb, &id);
    assert_eq!(j.get("status").and_then(|v| v.as_str()), Some("stopped"));

    let o = sb.run(&["rm", "lifecycle"]);
    assert_ok(&o, "rm");
    assert!(!sb.root.join("containers").join(&id).exists());
}

#[test]
fn create_then_start_is_equivalent_to_run() {
    require_privileged!("create_then_start_is_equivalent_to_run");
    let sb = Sandbox::new("createstart");
    let rootfs = rootfs();

    let o = sb.run(&[
        "create",
        "--name",
        "staged",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "sleep 30",
    ]);
    assert_ok(&o, "create");
    let id = stdout_of(&o).trim().to_string();

    let j = state_json(&sb, &id);
    assert_eq!(j.get("status").and_then(|v| v.as_str()), Some("created"));
    assert_eq!(j.get("init_pid").and_then(|v| v.as_i64()), Some(0));

    // A created container is not running, so stop/pause must refuse.
    assert!(!sb.run(&["pause", "staged"]).status.success());

    assert_ok(&sb.run(&["start", "staged"]), "start");
    assert!(wait_until(5000, || {
        state_json(&sb, &id).get("status").and_then(|v| v.as_str()) == Some("running")
    }));

    // Starting twice is an error, not a second container.
    let o = sb.run(&["start", "staged"]);
    assert!(!o.status.success());
    assert!(combined(&o).contains("already running"), "{}", combined(&o));

    assert_ok(&sb.run(&["rm", "-f", "staged"]), "rm -f");
}

#[test]
fn pause_freezes_the_workload() {
    require_privileged!("pause_freezes_the_workload");
    let sb = Sandbox::new("pause");
    let rootfs = rootfs();

    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "frozen",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "while true; do echo x; sleep 0.2; done",
    ]);
    assert_ok(&o, "run -d");
    let id = stdout_of(&o).trim().to_string();

    assert!(wait_until(5000, || !sb
        .run(&["logs", &id])
        .stdout
        .is_empty()));

    assert_ok(&sb.run(&["pause", "frozen"]), "pause");
    assert_eq!(
        state_json(&sb, &id).get("status").and_then(|v| v.as_str()),
        Some("paused")
    );

    let before = sb.run(&["logs", &id]).stdout.len();
    std::thread::sleep(std::time::Duration::from_millis(800));
    let during = sb.run(&["logs", &id]).stdout.len();
    assert_eq!(before, during, "a frozen container kept producing output");

    assert_ok(&sb.run(&["unpause", "frozen"]), "unpause");
    assert!(
        wait_until(3000, || sb.run(&["logs", &id]).stdout.len() > during),
        "container did not resume after unpause"
    );

    assert_ok(&sb.run(&["rm", "-f", "frozen"]), "rm -f");
}

#[test]
fn kill_records_the_signal() {
    require_privileged!("kill_records_the_signal");
    let sb = Sandbox::new("kill");
    let rootfs = rootfs();

    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "victim",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "sleep 300",
    ]);
    assert_ok(&o, "run -d");
    let id = stdout_of(&o).trim().to_string();
    assert!(wait_until(5000, || state_json(&sb, &id)
        .get("status")
        .and_then(|v| v.as_str())
        == Some("running")));

    assert_ok(&sb.run(&["kill", "-s", "KILL", "victim"]), "kill");
    assert!(
        wait_until(5000, || state_json(&sb, &id)
            .get("status")
            .and_then(|v| v.as_str())
            == Some("stopped")),
        "container did not die"
    );
    let j = state_json(&sb, &id);
    assert_eq!(j.get("exit_signal").and_then(|v| v.as_i64()), Some(9));

    assert_ok(&sb.run(&["rm", "victim"]), "rm");
}

#[test]
fn delete_refuses_running_containers_without_force() {
    require_privileged!("delete_refuses_running_containers_without_force");
    let sb = Sandbox::new("delforce");
    let rootfs = rootfs();

    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "busy",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "sleep 300",
    ]);
    assert_ok(&o, "run -d");
    let id = stdout_of(&o).trim().to_string();
    assert!(wait_until(5000, || state_json(&sb, &id)
        .get("status")
        .and_then(|v| v.as_str())
        == Some("running")));

    let o = sb.run(&["rm", "busy"]);
    assert!(!o.status.success(), "rm should refuse a running container");
    assert!(combined(&o).contains("force"), "{}", combined(&o));

    assert_ok(&sb.run(&["rm", "-f", "busy"]), "rm -f");
    assert!(!sb.root.join("containers").join(&id).exists());
}

#[test]
fn auto_remove_cleans_up_after_exit() {
    require_privileged!("auto_remove_cleans_up_after_exit");
    let sb = Sandbox::new("autorm");
    let o = sb.sh_with(&["--rm"], "true");
    assert_ok(&o, "run --rm");
    assert!(
        sb.container_ids().is_empty(),
        "--rm left state behind: {:?}",
        sb.container_ids()
    );
}

#[test]
fn duplicate_names_are_rejected() {
    require_privileged!("duplicate_names_are_rejected");
    let sb = Sandbox::new("dupname");
    let rootfs = rootfs();
    let args = vec![
        "create",
        "--name",
        "unique",
        rootfs.to_str().unwrap(),
        "/bin/true",
    ];
    assert_ok(&sb.run(&args), "first create");
    let o = sb.run(&args);
    assert!(!o.status.success(), "duplicate name should be rejected");
    assert!(combined(&o).contains("unique"), "{}", combined(&o));
}

#[test]
fn stats_and_inspect_report_real_values() {
    require_privileged!("stats_and_inspect_report_real_values");
    let sb = Sandbox::new("stats");
    let rootfs = rootfs();

    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "measured",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "while true; do :; done",
    ]);
    assert_ok(&o, "run -d");
    let id = stdout_of(&o).trim().to_string();
    assert!(wait_until(5000, || state_json(&sb, &id)
        .get("status")
        .and_then(|v| v.as_str())
        == Some("running")));

    let o = sb.run(&["stats", "--json", "measured"]);
    assert_ok(&o, "stats --json");
    let j = myrun::util::json::parse(&stdout_of(&o)).expect("stats json");
    let entry = &j.as_array().expect("array")[0];
    for key in ["memory", "cpu", "pids", "network", "uptime_ms"] {
        assert!(entry.get(key).is_some(), "stats missing {}", key);
    }

    let o = sb.run(&["inspect", "measured"]);
    assert_ok(&o, "inspect");
    let j = myrun::util::json::parse(&stdout_of(&o)).expect("inspect json");
    let entry = &j.as_array().expect("array")[0];
    assert!(entry.get("config").is_some());
    assert!(entry.get("security_summary").is_some());
    assert!(entry.get("created").is_some());

    assert_ok(&sb.run(&["rm", "-f", "measured"]), "rm -f");
}

#[test]
fn signals_are_forwarded_to_the_workload() {
    require_privileged!("signals_are_forwarded_to_the_workload");
    let sb = Sandbox::new("signals");
    let rootfs = rootfs();

    // The workload traps SIGTERM and exits 17; if init failed to forward the
    // signal it would be SIGKILLed after the grace period instead.
    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "trapper",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "trap 'exit 17' TERM; echo ready; while true; do sleep 0.1; done",
    ]);
    assert_ok(&o, "run -d");
    let id = stdout_of(&o).trim().to_string();
    assert!(wait_until(5000, || sb
        .run(&["logs", &id])
        .stdout
        .windows(5)
        .any(|w| w == b"ready")));

    assert_ok(&sb.run(&["stop", "-t", "5", "trapper"]), "stop");
    let j = state_json(&sb, &id);
    assert_eq!(
        j.get("exit_code").and_then(|v| v.as_i64()),
        Some(17),
        "the workload's SIGTERM handler did not run, so the signal was not forwarded"
    );
    assert_ok(&sb.run(&["rm", "trapper"]), "rm");
}

#[test]
fn init_reaps_orphaned_children() {
    require_privileged!("init_reaps_orphaned_children");
    let sb = Sandbox::new("reap");
    // Spawn children that outlive their parent shell; PID 1 inherits them and
    // must reap them rather than accumulating zombies.
    let o = sb.sh("for i in 1 2 3 4 5; do (sleep 0.1 &) ; done; sleep 1; \
         ps -o stat 2>/dev/null | grep -c Z || echo 0");
    assert_ok(&o, "run");
    let zombies: usize = stdout_of(&o)
        .trim()
        .lines()
        .last()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    assert_eq!(zombies, 0, "init left zombies behind:\n{}", stdout_of(&o));
}

#[test]
fn wait_returns_the_exit_code() {
    require_privileged!("wait_returns_the_exit_code");
    let sb = Sandbox::new("wait");
    let rootfs = rootfs();
    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "shortlived",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "sleep 0.5; exit 23",
    ]);
    assert_ok(&o, "run -d");
    // `wait` prints the container's exit code and itself exits 0, the same
    // convention `docker wait` uses: a non-zero exit would be indistinguishable
    // from `wait` itself having failed.
    let o = sb.run(&["wait", "shortlived"]);
    assert_ok(&o, "wait");
    assert_eq!(stdout_of(&o).trim(), "23");
    assert_ok(&sb.run(&["rm", "shortlived"]), "rm");
}
