//! CLI behaviour that does not need root.
//!
//! These run everywhere, including CI containers with no privileges, and
//! cover the parts of the runtime that are pure logic: argument parsing,
//! validation, state handling, help and error messages.

mod common;

use common::*;

#[test]
fn version_and_help() {
    let sb = Sandbox::new("help");

    let o = sb.run(&["--version"]);
    assert_ok(&o, "--version");
    assert!(stdout_of(&o).starts_with("myrun "), "{}", stdout_of(&o));

    let o = sb.run(&["--help"]);
    assert_ok(&o, "--help");
    let text = stdout_of(&o);
    for cmd in [
        "run", "create", "stop", "kill", "rm", "ls", "inspect", "stats", "gc",
    ] {
        assert!(text.contains(cmd), "help should mention {}", cmd);
    }

    for topic in ["run", "network", "security"] {
        let o = sb.run(&["--help", topic]);
        assert_ok(&o, "help topic");
        assert!(stdout_of(&o).len() > 100, "topic {} is too thin", topic);
    }
}

#[test]
fn info_reports_host_capabilities() {
    let sb = Sandbox::new("info");
    let o = sb.run(&["info"]);
    assert_ok(&o, "info");
    let text = stdout_of(&o);
    for key in [
        "kernel:",
        "cgroup v2:",
        "iptables:",
        "fault injection points",
    ] {
        assert!(text.contains(key), "info is missing {:?}:\n{}", key, text);
    }
    // Every fault point the binary knows about should be listed, so the
    // documentation cannot drift from the code.
    for p in myrun::fault::POINTS {
        assert!(text.contains(p), "info omits fault point {}", p);
    }
}

#[test]
fn unknown_commands_and_flags_are_rejected() {
    let sb = Sandbox::new("badargs");

    let o = sb.run(&["frobnicate"]);
    assert!(!o.status.success());
    assert!(combined(&o).contains("unknown command"), "{}", combined(&o));
    assert_eq!(code_of(&o), myrun::error::exit::USAGE);

    // A typo in a resource flag must not silently produce an unlimited
    // container.
    let o = sb.run(&["run", "--memroy", "256m", "/tmp", "/bin/true"]);
    assert!(!o.status.success());
    assert!(combined(&o).contains("unknown option"), "{}", combined(&o));
}

#[test]
fn validation_rejects_impossible_configs() {
    let sb = Sandbox::new("validate");
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec!["run", "/nonexistent-rootfs-xyz", "/bin/true"],
            "rootfs",
        ),
        (vec!["run", "/", "/bin/true"], "/"),
        (vec!["run", "--memory", "1k", "/tmp", "/bin/true"], "memory"),
        (vec!["run", "--cpus", "0", "/tmp", "/bin/true"], "cpus"),
        (
            vec!["run", "--publish", "80:80", "/tmp", "/bin/true"],
            "publish",
        ),
        (
            vec!["run", "--cap-add", "CAP_NOT_A_THING", "/tmp", "/bin/true"],
            "capab",
        ),
        (
            vec![
                "run",
                "--ip",
                "192.168.99.9",
                "--network",
                "bridge",
                "/tmp",
                "/bin/true",
            ],
            "subnet",
        ),
        (
            vec!["run", "--workdir", "relative", "/tmp", "/bin/true"],
            "absolute",
        ),
    ];
    for (args, needle) in cases {
        let o = sb.run(&args);
        assert!(
            !o.status.success(),
            "expected {:?} to be rejected, but it succeeded",
            args
        );
        let msg = combined(&o).to_lowercase();
        assert!(
            msg.contains(&needle.to_lowercase()),
            "error for {:?} should mention {:?}, got: {}",
            args,
            needle,
            msg
        );
    }
}

#[test]
fn empty_list_is_not_an_error() {
    let sb = Sandbox::new("emptylist");
    let o = sb.run(&["ls"]);
    assert_ok(&o, "ls");
    assert!(stdout_of(&o).contains("CONTAINER"), "header should print");

    let o = sb.run(&["ls", "--json"]);
    assert_ok(&o, "ls --json");
    let j = myrun::util::json::parse(&stdout_of(&o)).expect("valid json");
    assert_eq!(j.as_array().map(|a| a.len()), Some(0));
}

#[test]
fn operations_on_unknown_containers_fail_cleanly() {
    let sb = Sandbox::new("unknown");
    for args in [
        vec!["inspect", "nope"],
        vec!["logs", "nope"],
        vec!["stop", "nope"],
        vec!["rm", "nope"],
    ] {
        let o = sb.run(&args);
        assert!(!o.status.success(), "{:?} should fail", args);
        let msg = combined(&o);
        assert!(
            msg.contains("nope") || msg.to_lowercase().contains("not found"),
            "{:?} produced an unhelpful error: {}",
            args,
            msg
        );
        // Never a panic.
        assert!(!msg.contains("panicked"), "{:?} panicked: {}", args, msg);
    }
}

#[test]
fn bad_fault_point_names_are_caught_early() {
    let sb = Sandbox::new("faultname");
    let o = sb.run_env(&[("MYRUN_FAULT", "not_a_real_point")], &["ls"]);
    assert!(!o.status.success());
    assert!(
        combined(&o).contains("not_a_real_point"),
        "{}",
        combined(&o)
    );
}

#[test]
fn config_files_are_loaded_and_validated() {
    let sb = Sandbox::new("configfile");
    let path = sb.root.join("container.toml");
    std::fs::write(
        &path,
        r#"
rootfs = "/tmp"
command = ["/bin/true"]
hostname = "from-file"

[resources]
memory = "1k"
"#,
    )
    .unwrap();
    // The invalid memory limit inside the file must be caught the same way
    // as one given on the command line.
    let o = sb.run(&["run", "--config", path.to_str().unwrap()]);
    assert!(!o.status.success());
    assert!(combined(&o).contains("memory"), "{}", combined(&o));

    // A malformed file produces a parse error, not a panic.
    std::fs::write(&path, "this is not = valid = toml [[[").unwrap();
    let o = sb.run(&["run", "--config", path.to_str().unwrap()]);
    assert!(!o.status.success());
    assert!(!combined(&o).contains("panicked"), "{}", combined(&o));
}

#[test]
fn non_root_gets_an_actionable_error() {
    if is_root() {
        eprintln!("SKIP non_root_gets_an_actionable_error: running as root");
        return;
    }
    let sb = Sandbox::new("nonroot");
    let o = sb.run(&["run", "/tmp", "/bin/true"]);
    assert!(!o.status.success());
    let msg = combined(&o);
    assert!(
        msg.contains("root") && msg.contains("sudo"),
        "error should explain the privilege requirement: {}",
        msg
    );
}
