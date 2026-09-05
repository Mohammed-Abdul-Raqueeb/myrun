//! NAT, forwarding and port publishing.
//!
//! **This is the one place myrun shells out to an external tool.** Every
//! other kernel interaction in this codebase is a direct syscall or a
//! hand-built netlink message, but packet filtering is not: the modern
//! interface is nftables' netlink protocol, whose expression bytecode
//! (immediate/cmp/payload/meta/nat expressions, set descriptors, batch
//! transactions) is a serialisation project in its own right and well
//! outside the scope of a container runtime exercise. Emitting `iptables`
//! commands is the honest, reviewable choice; `docs/networking.md` records
//! this as known technical debt.
//!
//! Every rule we install carries an iptables comment of the form
//! `myrun:<container id>` (or `myrun:base`). Teardown then works by parsing
//! `iptables-save`, finding the tagged rules and deleting exactly those —
//! no line-number arithmetic, no guessing, and rules belonging to other
//! tools are never touched.

use crate::config::PortMapping;
use crate::error::{Error, Result};
use crate::sys::netlink::format_ipv4;
use crate::util;
use std::process::Command;

pub const NAT_TABLE: &str = "nat";
pub const FILTER_TABLE: &str = "filter";
/// Our own chains, so a flush of ours never disturbs anyone else's rules.
pub const CHAIN_PRE: &str = "MYRUN-PRE";
pub const CHAIN_POST: &str = "MYRUN-POST";
pub const CHAIN_FWD: &str = "MYRUN-FWD";

fn iptables_bin() -> String {
    std::env::var("MYRUN_IPTABLES").unwrap_or_else(|_| "iptables".to_string())
}

/// Is iptables usable at all?  Checked once before we start building a
/// network so the failure is reported before anything is created.
pub fn available() -> bool {
    Command::new(iptables_bin())
        .args(["-t", "nat", "-S"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(args: &[&str]) -> Result<String> {
    let out = Command::new(iptables_bin())
        .args(args)
        .output()
        .map_err(|e| Error::io(format!("running iptables: {}", e)))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(Error::container(format!(
            "iptables {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    crate::log_trace!("iptables {}", args.join(" "));
    Ok(stdout)
}

/// Run a command whose failure is acceptable (used during teardown).
fn run_ok(args: &[&str]) -> bool {
    match run(args) {
        Ok(_) => true,
        Err(e) => {
            crate::log_debug!("{}", e);
            false
        }
    }
}

fn tag(id: &str) -> String {
    format!("myrun:{}", id)
}

fn chain_exists(table: &str, chain: &str) -> bool {
    run(&["-t", table, "-S", chain]).is_ok()
}

fn rule_exists(table: &str, args: &[&str]) -> bool {
    let mut v = vec!["-t", table, "-C"];
    v.extend_from_slice(args);
    run(&v).is_ok()
}

fn append_unique(table: &str, args: &[&str]) -> Result<()> {
    if rule_exists(table, args) {
        return Ok(());
    }
    let mut v = vec!["-t", table, "-A"];
    v.extend_from_slice(args);
    run(&v).map(|_| ())
}

fn insert_unique(table: &str, args: &[&str]) -> Result<()> {
    if rule_exists(table, args) {
        return Ok(());
    }
    let mut v = vec!["-t", table, "-I"];
    v.extend_from_slice(args);
    run(&v).map(|_| ())
}

/// Enable IPv4 forwarding, without which a bridged container can talk to
/// the host but nothing beyond it.
pub fn enable_ip_forwarding() -> Result<()> {
    let p = "/proc/sys/net/ipv4/ip_forward";
    if util::read_trimmed(p).unwrap_or_default() == "1" {
        return Ok(());
    }
    util::write_file(p, "1")
        .map_err(|e| Error::container(format!("enabling IPv4 forwarding: {}", e)))
}

/// Allow the host to reach published ports via `127.0.0.1`.
///
/// A DNAT from a loopback source to a non-loopback destination is dropped by
/// the kernel's martian-source check unless `route_localnet` is set. Docker
/// sets the same knob for the same reason. It is not free: with it enabled,
/// packets arriving from outside claiming a 127/8 destination would be
/// routed, so `ensure_chains` also installs a guard rule dropping exactly
/// those on non-loopback interfaces.
pub fn enable_route_localnet() -> Result<()> {
    let p = "/proc/sys/net/ipv4/conf/all/route_localnet";
    if util::read_trimmed(p).unwrap_or_default() == "1" {
        return Ok(());
    }
    util::write_file(p, "1")
        .map_err(|e| Error::container(format!("enabling route_localnet: {}", e)))
}

/// Create our chains and hook them into the built-in ones.  Idempotent.
pub fn ensure_chains() -> Result<()> {
    for (table, chain) in [
        (NAT_TABLE, CHAIN_PRE),
        (NAT_TABLE, CHAIN_POST),
        (FILTER_TABLE, CHAIN_FWD),
    ] {
        if !chain_exists(table, chain) {
            run(&["-t", table, "-N", chain])?;
        }
    }
    // PREROUTING and OUTPUT both jump to MYRUN-PRE so published ports work
    // from other hosts *and* from the host itself.
    insert_unique(NAT_TABLE, &["PREROUTING", "-j", CHAIN_PRE])?;
    insert_unique(NAT_TABLE, &["OUTPUT", "-j", CHAIN_PRE])?;
    insert_unique(NAT_TABLE, &["POSTROUTING", "-j", CHAIN_POST])?;
    insert_unique(FILTER_TABLE, &["FORWARD", "-j", CHAIN_FWD])?;

    // Guard for route_localnet: never accept a *new* connection claiming a
    // 127/8 destination that did not come in on the loopback interface.
    //
    // The ctstate match is load-bearing. Without it this rule also drops the
    // return traffic of our own published ports: a connection to
    // 127.0.0.1:<published> is DNATed out to the container, and the reply
    // arrives on the bridge and is un-NATed back to a 127.0.0.1 destination
    // before it reaches INPUT. Dropping that breaks exactly the feature
    // route_localnet was enabled for.
    let comment = tag("base");
    insert_unique(
        FILTER_TABLE,
        &[
            "INPUT",
            "!",
            "-i",
            "lo",
            "-d",
            "127.0.0.0/8",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-j",
            "DROP",
            "-m",
            "comment",
            "--comment",
            &comment,
        ],
    )?;
    Ok(())
}

/// Per-bridge rules: masquerade outbound traffic and allow forwarding.
pub fn setup_bridge(bridge: &str, subnet: &str, nat: bool) -> Result<()> {
    enable_ip_forwarding()?;
    if let Err(e) = enable_route_localnet() {
        // Not fatal: published ports still work via the host's real address.
        crate::log_warn!("{}; publishing to 127.0.0.1 will not work", e);
    }
    ensure_chains()?;
    let comment = tag("base");

    if nat {
        // Traffic from the container subnet leaving via any other interface
        // gets the host's address. `! -o <bridge>` keeps container-to-
        // container traffic un-NATed.
        append_unique(
            NAT_TABLE,
            &[
                CHAIN_POST,
                "-s",
                subnet,
                "!",
                "-o",
                bridge,
                "-j",
                "MASQUERADE",
                "-m",
                "comment",
                "--comment",
                &comment,
            ],
        )?;
    }
    // Host-originated traffic to a published port arrives at the container
    // still carrying a 127.0.0.1 source, which the container cannot reply
    // to. Rewrite it to the bridge address.
    append_unique(
        NAT_TABLE,
        &[
            CHAIN_POST,
            "-s",
            "127.0.0.0/8",
            "-o",
            bridge,
            "-j",
            "MASQUERADE",
            "-m",
            "comment",
            "--comment",
            &comment,
        ],
    )?;

    // Container -> world, and established replies back.
    append_unique(
        FILTER_TABLE,
        &[
            CHAIN_FWD,
            "-i",
            bridge,
            "!",
            "-o",
            bridge,
            "-j",
            "ACCEPT",
            "-m",
            "comment",
            "--comment",
            &comment,
        ],
    )?;
    append_unique(
        FILTER_TABLE,
        &[
            CHAIN_FWD,
            "-o",
            bridge,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
            "-m",
            "comment",
            "--comment",
            &comment,
        ],
    )?;
    // Container <-> container on the same bridge.
    append_unique(
        FILTER_TABLE,
        &[
            CHAIN_FWD,
            "-i",
            bridge,
            "-o",
            bridge,
            "-j",
            "ACCEPT",
            "-m",
            "comment",
            "--comment",
            &comment,
        ],
    )?;
    crate::fault::check("after_nat_rules")?;
    Ok(())
}

/// Publish `host_port -> container_ip:container_port`.
pub fn publish(id: &str, bridge: &str, container_ip: [u8; 4], m: &PortMapping) -> Result<()> {
    ensure_chains()?;
    let comment = tag(id);
    let ip = format_ipv4(container_ip);
    let dest = format!("{}:{}", ip, m.container_port);
    let hp = m.host_port.to_string();
    let cp = m.container_port.to_string();

    append_unique(
        NAT_TABLE,
        &[
            CHAIN_PRE,
            "-p",
            &m.protocol,
            "--dport",
            &hp,
            "-j",
            "DNAT",
            "--to-destination",
            &dest,
            "-m",
            "comment",
            "--comment",
            &comment,
        ],
    )?;
    // Hairpin: a container reaching its own published port via the host
    // address needs the reply to come back through the host.
    append_unique(
        NAT_TABLE,
        &[
            CHAIN_POST,
            "-s",
            &ip,
            "-d",
            &ip,
            "-p",
            &m.protocol,
            "--dport",
            &cp,
            "-j",
            "MASQUERADE",
            "-m",
            "comment",
            "--comment",
            &comment,
        ],
    )?;
    append_unique(
        FILTER_TABLE,
        &[
            CHAIN_FWD,
            "-o",
            bridge,
            "-d",
            &ip,
            "-p",
            &m.protocol,
            "--dport",
            &cp,
            "-j",
            "ACCEPT",
            "-m",
            "comment",
            "--comment",
            &comment,
        ],
    )?;
    crate::log_debug!(
        "published {}:{}/{} -> {}",
        "host",
        m.host_port,
        m.protocol,
        dest
    );
    Ok(())
}

/// Every rule tagged for `id`, as `(table, args-after-the-chain-name)`.
fn tagged_rules(id: &str) -> Vec<(String, Vec<String>)> {
    let needle = format!("--comment {}", tag(id));
    let needle_quoted = format!("--comment \"{}\"", tag(id));
    let mut out = Vec::new();
    for table in [NAT_TABLE, FILTER_TABLE] {
        let dump = match run(&["-t", table, "-S"]) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for line in dump.lines() {
            if !line.starts_with("-A ") {
                continue;
            }
            if !line.contains(&needle) && !line.contains(&needle_quoted) {
                continue;
            }
            let args = split_rule(&line[3..]);
            if !args.is_empty() {
                out.push((table.to_string(), args));
            }
        }
    }
    out
}

/// Split an `iptables -S` line into argv, honouring the double quotes
/// iptables puts around comments.
pub fn split_rule(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Delete every rule tagged for this container.  Best effort: teardown must
/// never fail loudly enough to leave the rest of the cleanup undone.
pub fn cleanup(id: &str) -> usize {
    let rules = tagged_rules(id);
    let mut removed = 0;
    for (table, args) in rules {
        let mut v: Vec<&str> = vec!["-t", &table, "-D"];
        v.extend(args.iter().map(|s| s.as_str()));
        if run_ok(&v) {
            removed += 1;
        }
    }
    if removed > 0 {
        crate::log_debug!(
            "removed {} iptables rule(s) for {}",
            removed,
            util::short_id(id)
        );
    }
    removed
}

/// Remove the shared base rules and our chains.  Only safe once no
/// containers are left, so `myrun gc` calls it and nothing else does.
pub fn teardown_base() {
    cleanup("base");
    run_ok(&[
        "-t",
        FILTER_TABLE,
        "-D",
        "INPUT",
        "!",
        "-i",
        "lo",
        "-d",
        "127.0.0.0/8",
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-j",
        "DROP",
        "-m",
        "comment",
        "--comment",
        &tag("base"),
    ]);
    for (table, chain, parent) in [
        (NAT_TABLE, CHAIN_PRE, "PREROUTING"),
        (NAT_TABLE, CHAIN_PRE, "OUTPUT"),
        (NAT_TABLE, CHAIN_POST, "POSTROUTING"),
        (FILTER_TABLE, CHAIN_FWD, "FORWARD"),
    ] {
        run_ok(&["-t", table, "-D", parent, "-j", chain]);
    }
    for (table, chain) in [
        (NAT_TABLE, CHAIN_PRE),
        (NAT_TABLE, CHAIN_POST),
        (FILTER_TABLE, CHAIN_FWD),
    ] {
        run_ok(&["-t", table, "-F", chain]);
        run_ok(&["-t", table, "-X", chain]);
    }
}

/// Count the rules currently tagged for a container — used by the leak
/// checker and the integration tests.
pub fn rule_count(id: &str) -> usize {
    tagged_rules(id).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_splitting_handles_quoted_comments() {
        let line = "MYRUN-PRE -p tcp -m tcp --dport 8080 -m comment --comment \"myrun:abc123\" -j DNAT --to-destination 10.87.0.2:80";
        let args = split_rule(line);
        assert_eq!(args[0], "MYRUN-PRE");
        assert!(
            args.contains(&"myrun:abc123".to_string()),
            "comment must survive as one argument: {:?}",
            args
        );
        assert_eq!(args.last().unwrap(), "10.87.0.2:80");
        assert!(!args.iter().any(|a| a.contains('"')));
    }

    #[test]
    fn split_rule_ignores_extra_whitespace() {
        assert_eq!(
            split_rule("  A   -j  ACCEPT "),
            vec!["A".to_string(), "-j".into(), "ACCEPT".into()]
        );
        assert!(split_rule("   ").is_empty());
    }

    #[test]
    fn tags_are_namespaced() {
        assert_eq!(tag("abc"), "myrun:abc");
        assert_eq!(tag("base"), "myrun:base");
    }
}
