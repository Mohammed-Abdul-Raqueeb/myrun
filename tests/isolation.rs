//! Security hardening, networking, resource limits, and failure handling.

mod common;

use common::*;

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

#[test]
fn default_sandbox_drops_privileges() {
    require_privileged!("default_sandbox_drops_privileges");
    let sb = Sandbox::new("secdefault");

    let o = sb.sh("grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status");
    assert_ok(&o, "run");
    let out = stdout_of(&o);

    assert!(
        out.contains("NoNewPrivs:\t1"),
        "no_new_privs not set:\n{}",
        out
    );
    assert!(
        out.contains("Seccomp:\t2"),
        "seccomp filter mode not active:\n{}",
        out
    );

    // CAP_SYS_ADMIN (bit 21) must not be in the effective set: with it a
    // container can mount, setns and manipulate cgroups.
    let eff = out
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .expect("CapEff");
    assert_eq!(eff & (1 << 21), 0, "CAP_SYS_ADMIN retained: {:016x}", eff);
    // CAP_NET_RAW (bit 13) is dropped by default too.
    assert_eq!(eff & (1 << 13), 0, "CAP_NET_RAW retained: {:016x}", eff);
    // But the container is not stripped of everything by accident.
    assert!(eff != 0, "the default set should not be empty");
}

#[test]
fn seccomp_denies_dangerous_syscalls() {
    require_privileged!("seccomp_denies_dangerous_syscalls");
    let sb = Sandbox::new("seccomp");

    // mount(2) is on the deny list; with CAP_SYS_ADMIN also gone this is
    // belt and braces, which is the point.
    let o = sb.sh("mount -t tmpfs none /tmp 2>&1; echo rc=$?");
    assert_ok(&o, "run");
    assert!(
        !stdout_of(&o).contains("rc=0"),
        "mount succeeded inside the container: {}",
        stdout_of(&o)
    );

    // Unconfined must actually turn the filter off, or the flag is a lie.
    let o = sb.sh_with(
        &["--seccomp", "unconfined"],
        "grep '^Seccomp:' /proc/self/status",
    );
    assert_ok(&o, "run");
    assert!(
        stdout_of(&o).contains("Seccomp:\t0"),
        "--seccomp unconfined still installed a filter: {}",
        stdout_of(&o)
    );
}

#[test]
fn capability_flags_take_effect() {
    require_privileged!("capability_flags_take_effect");
    let sb = Sandbox::new("caps");

    let eff = |o: &std::process::Output| -> u64 {
        stdout_of(o)
            .lines()
            .find(|l| l.starts_with("CapEff:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .unwrap_or(u64::MAX)
    };

    let base = sb.sh("grep '^CapEff:' /proc/self/status");
    assert_ok(&base, "run");

    let added = sb.sh_with(
        &["--cap-add", "NET_RAW"],
        "grep '^CapEff:' /proc/self/status",
    );
    assert_ok(&added, "run --cap-add");
    assert_ne!(
        eff(&added) & (1 << 13),
        0,
        "--cap-add NET_RAW had no effect"
    );

    let dropped = sb.sh_with(&["--cap-drop", "all"], "grep '^CapEff:' /proc/self/status");
    assert_ok(&dropped, "run --cap-drop all");
    assert_eq!(eff(&dropped), 0, "--cap-drop all left capabilities behind");

    assert!(eff(&base) != 0 && eff(&base) != eff(&dropped));
}

#[test]
fn masked_and_readonly_paths_are_enforced() {
    require_privileged!("masked_and_readonly_paths_are_enforced");
    let sb = Sandbox::new("masked");

    // /proc/kcore is a full image of kernel memory.
    let o = sb.sh("dd if=/proc/kcore bs=1 count=1 2>/dev/null | wc -c");
    assert_ok(&o, "run");
    assert_eq!(stdout_of(&o).trim(), "0", "/proc/kcore was readable");

    let o = sb.sh("echo 1 > /proc/sysrq-trigger 2>&1; echo rc=$?");
    assert_ok(&o, "run");
    assert!(
        !stdout_of(&o).contains("rc=0"),
        "/proc/sysrq-trigger was writable, which can reboot the host"
    );
}

#[test]
fn user_switching_drops_to_an_unprivileged_uid() {
    require_privileged!("user_switching_drops_to_an_unprivileged_uid");
    let sb = Sandbox::new("user");
    let o = sb.sh_with(&["--user", "65534:65534"], "id -u; id -g");
    assert_ok(&o, "run");
    let out = stdout_of(&o);
    assert!(out.contains("65534"), "--user was not applied: {}", out);

    // And the unprivileged user cannot write to a root-owned directory.
    let o = sb.sh_with(&["--user", "65534"], "touch /root/x 2>&1; echo rc=$?");
    assert_ok(&o, "run");
    assert!(!stdout_of(&o).contains("rc=0"), "uid 65534 wrote to /root");
}

#[test]
fn privileged_mode_is_actually_privileged() {
    require_privileged!("privileged_mode_is_actually_privileged");
    let sb = Sandbox::new("priv");
    let o = sb.sh_with(
        &["--privileged"],
        "grep -E '^(CapEff|Seccomp):' /proc/self/status",
    );
    assert_ok(&o, "run --privileged");
    let out = stdout_of(&o);
    assert!(out.contains("Seccomp:\t0"), "seccomp still on: {}", out);
    let eff = out
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .unwrap();
    assert_ne!(eff & (1 << 21), 0, "--privileged should keep CAP_SYS_ADMIN");
}

// ---------------------------------------------------------------------------
// Networking
// ---------------------------------------------------------------------------

#[test]
fn network_none_gives_only_loopback() {
    require_privileged!("network_none_gives_only_loopback");
    let sb = Sandbox::new("netnone");
    let o = sb.sh("ip -o link | wc -l");
    assert_ok(&o, "run");
    assert_eq!(
        stdout_of(&o).trim(),
        "1",
        "an isolated container should see only lo"
    );
}

#[test]
fn bridge_networking_configures_the_container() {
    require_privileged!("bridge_networking_configures_the_container");
    let sb = Sandbox::new("netbridge");

    let o = sb.sh_with(
        &["--network", "bridge"],
        "ip -4 -o addr show eth0; ip route | grep default",
    );
    assert_ok(&o, "run --network bridge");
    let out = stdout_of(&o);
    assert!(out.contains("10.87.0."), "no address on eth0:\n{}", out);
    assert!(
        out.contains("default via 10.87.0.1"),
        "no default route:\n{}",
        out
    );
}

#[test]
fn the_container_can_reach_the_gateway() {
    require_privileged!("the_container_can_reach_the_gateway");
    let sb = Sandbox::new("netping");
    // ICMP needs CAP_NET_RAW, which the default profile drops on purpose.
    let o = sb.sh_with(
        &["--network", "bridge", "--cap-add", "NET_RAW"],
        "ping -c 2 -W 2 10.87.0.1 | tail -2",
    );
    assert_ok(&o, "run");
    assert!(
        stdout_of(&o).contains("0% packet loss"),
        "container could not reach the bridge:\n{}",
        stdout_of(&o)
    );
}

#[test]
fn addresses_are_unique_across_containers() {
    require_privileged!("addresses_are_unique_across_containers");
    let sb = Sandbox::new("ipam");
    let rootfs = rootfs();

    let mut ids = Vec::new();
    for i in 0..3 {
        let name = format!("ipam{}", i);
        let o = sb.run(&[
            "run",
            "-d",
            "--name",
            &name,
            "--network",
            "bridge",
            rootfs.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "sleep 30",
        ]);
        assert_ok(&o, "run -d");
        ids.push(stdout_of(&o).trim().to_string());
    }
    for id in &ids {
        assert!(wait_until(5000, || state_json(&sb, id)
            .get("status")
            .and_then(|v| v.as_str())
            == Some("running")));
    }

    let mut addrs: Vec<String> = ids
        .iter()
        .map(|id| {
            state_json(&sb, id)
                .get("network")
                .and_then(|n| n.get("ip"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect();
    addrs.sort();
    addrs.dedup();
    assert_eq!(
        addrs.len(),
        3,
        "IPAM handed out duplicate addresses: {:?}",
        addrs
    );

    for id in &ids {
        assert_ok(&sb.run(&["rm", "-f", id]), "rm -f");
    }
}

#[test]
fn published_ports_reach_the_container_and_are_cleaned_up() {
    require_privileged!("published_ports_reach_the_container_and_are_cleaned_up");
    let sb = Sandbox::new("publish");
    let rootfs = rootfs();

    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "listener",
        "--network",
        "bridge",
        "-p",
        "19555:9555",
        rootfs.to_str().unwrap(),
        "/bin/sh",
        "-c",
        "nc -l -p 9555 > /tmp/received; echo GOT; cat /tmp/received",
    ]);
    assert_ok(&o, "run -d");
    let id = stdout_of(&o).trim().to_string();
    assert!(wait_until(5000, || state_json(&sb, &id)
        .get("status")
        .and_then(|v| v.as_str())
        == Some("running")));

    assert!(
        iptables_rule_count(&id) > 0,
        "publishing installed no iptables rules"
    );

    // Give the listener a moment to bind, then connect from the host.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let ok = wait_until(5000, || {
        use std::io::Write;
        match std::net::TcpStream::connect("127.0.0.1:19555") {
            Ok(mut s) => {
                let _ = s.write_all(b"payload-through-dnat\n");
                true
            }
            Err(_) => false,
        }
    });
    assert!(ok, "could not connect to the published port");

    assert!(
        wait_until(5000, || sb
            .run(&["logs", &id])
            .stdout
            .windows(20)
            .any(|w| w == b"payload-through-dnat")),
        "the payload never reached the container: {}",
        stdout_of(&sb.run(&["logs", &id]))
    );

    assert_ok(&sb.run(&["rm", "-f", &id]), "rm -f");
    assert_eq!(
        iptables_rule_count(&id),
        0,
        "iptables rules survived container removal"
    );
}

#[test]
fn host_networking_shares_the_host_namespace() {
    require_privileged!("host_networking_shares_the_host_namespace");
    let sb = Sandbox::new("nethost");
    let o = sb.sh_with(&["--network", "host"], "ip -o link | wc -l");
    assert_ok(&o, "run --network host");
    let n: usize = stdout_of(&o).trim().parse().unwrap_or(0);
    assert!(
        n > 1,
        "--network host should show the host's interfaces, saw {}",
        n
    );
}

// ---------------------------------------------------------------------------
// cgroups
// ---------------------------------------------------------------------------

#[test]
fn memory_limit_is_enforced() {
    require_privileged!("memory_limit_is_enforced");
    require_controllers!("memory_limit_is_enforced", "memory");
    let sb = Sandbox::new("cgmem");

    let o = sb.sh_with(&["--memory", "32m"], "cat /sys/fs/cgroup/memory.max");
    assert_ok(&o, "run");
    assert_eq!(
        stdout_of(&o).trim(),
        (32 * 1024 * 1024).to_string(),
        "memory.max was not applied"
    );

    // Allocating well past the limit must be stopped by the kernel.
    let o = sb.sh_with(
        &["--memory", "32m"],
        "dd if=/dev/zero of=/dev/shm/balloon bs=1M count=256 2>/dev/null; echo rc=$?",
    );
    let id = sb.container_ids().pop().unwrap_or_default();
    let oom = state_json(&sb, &id)
        .get("oom_killed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(
        oom || !stdout_of(&o).contains("rc=0"),
        "a 256MiB allocation succeeded inside a 32MiB container"
    );
}

#[test]
fn pids_limit_is_enforced() {
    require_privileged!("pids_limit_is_enforced");
    require_controllers!("pids_limit_is_enforced", "pids");
    let sb = Sandbox::new("cgpids");

    let o = sb.sh_with(&["--pids", "16"], "cat /sys/fs/cgroup/pids.max");
    assert_ok(&o, "run");
    assert_eq!(stdout_of(&o).trim(), "16", "pids.max was not applied");

    // A fork bomb must hit the wall rather than take the host down.
    let o = sb.sh_with(
        &["--pids", "16"],
        "i=0; while [ $i -lt 64 ]; do (sleep 5 &) 2>/dev/null || break; i=$((i+1)); done; echo spawned=$i",
    );
    let spawned: usize = stdout_of(&o)
        .lines()
        .find_map(|l| l.strip_prefix("spawned="))
        .and_then(|n| n.parse().ok())
        .unwrap_or(64);
    assert!(spawned < 64, "the pids limit did not stop the fork loop");
}

#[test]
fn cpu_limit_is_applied() {
    require_privileged!("cpu_limit_is_applied");
    require_controllers!("cpu_limit_is_applied", "cpu");
    let sb = Sandbox::new("cgcpu");
    let o = sb.sh_with(&["--cpus", "0.5"], "cat /sys/fs/cgroup/cpu.max");
    assert_ok(&o, "run");
    assert_eq!(
        stdout_of(&o).trim(),
        "50000 100000",
        "cpu.max was not applied"
    );
}

#[test]
fn missing_controllers_produce_a_clear_error_by_default() {
    require_privileged!("missing_controllers_produce_a_clear_error_by_default");
    if controller_available("memory") {
        eprintln!("SKIP missing_controllers_...: this host does delegate memory");
        return;
    }
    let sb = Sandbox::new("cgmissing");
    let rootfs = rootfs();
    // Without the escape hatch, a limit that cannot be enforced must fail
    // loudly rather than run unlimited.
    let o = std::process::Command::new(binary())
        .env("MYRUN_ROOT", &sb.root)
        .args([
            "run",
            "--memory",
            "64m",
            rootfs.to_str().unwrap(),
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert!(!o.status.success(), "should have refused to run");
    let msg = combined(&o);
    assert!(msg.contains("memory"), "{}", msg);
    assert!(
        msg.contains("MYRUN_ALLOW_MISSING_CONTROLLERS"),
        "the error should name the escape hatch: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// Failure handling and rollback
// ---------------------------------------------------------------------------

#[test]
fn every_fault_point_rolls_back_cleanly() {
    require_privileged!("every_fault_point_rolls_back_cleanly");
    let sb = Sandbox::new("faults");
    let rootfs = rootfs();

    let veths_before = myrun_veth_count();
    let cgroups_before = myrun_cgroup_count();

    // Points that can fire during a bridged container start. Points after
    // the container is already up are covered separately.
    let points = [
        "before_state_create",
        "after_state_create",
        "after_cgroup_create",
        "after_cgroup_limits",
        "before_clone",
        "after_clone",
        "after_ip_alloc",
        "after_veth_create",
        "after_veth_master",
        "after_netns_move",
        "after_nat_rules",
        "before_go_signal",
        "after_go_signal",
        "before_pivot_root",
        "after_pivot_root",
        "before_exec",
        "after_start",
    ];

    for point in points {
        let o = sb.run_env(
            &[("MYRUN_FAULT", point)],
            &[
                "run",
                "--network",
                "bridge",
                rootfs.to_str().unwrap(),
                "/bin/true",
            ],
        );
        assert!(
            !o.status.success(),
            "fault {} did not cause a failure",
            point
        );
        assert!(
            combined(&o).contains(point),
            "fault {} produced an unrelated error: {}",
            point,
            combined(&o)
        );
        assert!(
            !combined(&o).contains("panicked"),
            "fault {} panicked instead of unwinding: {}",
            point,
            combined(&o)
        );
    }

    // Give teardown a moment, then confirm nothing accumulated.
    assert!(
        wait_until(5000, || myrun_veth_count() <= veths_before),
        "fault injection leaked veth interfaces: {} -> {}",
        veths_before,
        myrun_veth_count()
    );
    assert!(
        wait_until(5000, || myrun_cgroup_count() <= cgroups_before),
        "fault injection leaked cgroups: {} -> {}",
        cgroups_before,
        myrun_cgroup_count()
    );

    // No IP leases should be outstanding either.
    let leases = myrun::runtime::ipam::all_leases().unwrap_or_default();
    assert!(
        leases.is_empty(),
        "fault injection leaked IP leases: {:?}",
        leases
    );
}

#[test]
fn repeated_failures_do_not_accumulate_state() {
    require_privileged!("repeated_failures_do_not_accumulate_state");
    let sb = Sandbox::new("repeatfail");
    let rootfs = rootfs();

    for _ in 0..5 {
        let o = sb.run_env(
            &[("MYRUN_FAULT", "after_veth_create")],
            &[
                "run",
                "--network",
                "bridge",
                rootfs.to_str().unwrap(),
                "/bin/true",
            ],
        );
        assert!(!o.status.success());
    }
    assert!(
        wait_until(5000, || myrun_veth_count() == 0),
        "five failed starts left {} veth interfaces behind",
        myrun_veth_count()
    );
}

#[test]
fn gc_reclaims_a_crashed_containers_resources() {
    require_privileged!("gc_reclaims_a_crashed_containers_resources");
    let sb = Sandbox::new("gccrash");
    let rootfs = rootfs();

    let o = sb.run(&[
        "run",
        "-d",
        "--name",
        "doomed",
        "--network",
        "bridge",
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

    // Simulate a hard crash: kill the shim and init without letting either
    // record an exit status or tear anything down.
    let j = state_json(&sb, &id);
    let shim = j.get("shim_pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let init = j.get("init_pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    assert!(shim > 0 && init > 0);
    let _ = myrun::sys::process::kill_pid(shim, myrun::sys::ffi::SIGKILL);
    let _ = myrun::sys::process::kill_pid(init, myrun::sys::ffi::SIGKILL);
    assert!(wait_until(5000, || !myrun::sys::process::process_alive(
        init, None
    )));

    // The state file still claims the container is running; gc must notice.
    let o = sb.run(&["gc"]);
    assert_ok(&o, "gc");
    let j = state_json(&sb, &id);
    assert_eq!(
        j.get("status").and_then(|v| v.as_str()),
        Some("stopped"),
        "gc did not reconcile the crashed container"
    );
    assert_eq!(iptables_rule_count(&id), 0, "gc left iptables rules behind");

    assert_ok(&sb.run(&["rm", "doomed"]), "rm");
}

#[test]
fn a_failed_start_leaves_no_phantom_container() {
    require_privileged!("a_failed_start_leaves_no_phantom_container");
    let sb = Sandbox::new("phantom");
    let rootfs = rootfs();

    let before = sb.container_ids().len();
    let o = sb.run(&[
        "run",
        "-d",
        rootfs.to_str().unwrap(),
        "/bin/definitely-not-here",
    ]);
    assert!(!o.status.success(), "should have failed");
    assert_eq!(
        sb.container_ids().len(),
        before,
        "a failed `run -d` left a container behind: {:?}",
        sb.container_ids()
    );
}
