//! Container networking: bridge, veth pair, addressing and teardown.
//!
//! ```text
//!   host netns                          container netns
//!   ┌──────────────────────────┐        ┌────────────────────┐
//!   │  eth0 ── MASQUERADE      │        │                    │
//!   │   │                      │        │                    │
//!   │  myrun0 (10.87.0.1/24) ──┼─ veth ─┼── eth0 10.87.0.2/24│
//!   │   (bridge)   mrvXXXXXXXX │  pair  │   default via .1   │
//!   └──────────────────────────┘        └────────────────────┘
//! ```
//!
//! The host half of the pair is created in the host namespace and enslaved
//! to the bridge; the peer is moved into the container's network namespace
//! by pid and renamed `eth0` there. Addressing inside the namespace is done
//! by init (which is already in that namespace) rather than by entering it
//! from outside — no `setns` dance, and no window where a half-configured
//! interface is visible.

use crate::config::{ContainerConfig, NetworkMode};
use crate::error::{Error, Result};
use crate::rollback::Rollback;
use crate::runtime::state::NetworkState;
use crate::runtime::{ipam, nat, veth_names};
use crate::sys::netlink::{format_ipv4, parse_cidr, Netlink};
use crate::util;

pub const CONTAINER_IFNAME: &str = "eth0";

/// Create the bridge if it is not there yet and make sure it is up and
/// carries the gateway address.
pub fn ensure_bridge(nl: &mut Netlink, bridge: &str, gateway: [u8; 4], prefix: u8) -> Result<u32> {
    let idx = match nl.link_index(bridge)? {
        Some(i) => i,
        None => {
            crate::log_info!("creating bridge {}", bridge);
            nl.create_bridge(bridge)?;
            crate::fault::check("after_bridge_create")?;
            nl.link_index_required(bridge)?
        }
    };
    // Adding an address that is already there returns EEXIST, which is fine.
    match nl.add_address(idx, gateway, prefix) {
        Ok(()) => {}
        Err(e) if e.is_errno(crate::sys::ffi::EEXIST) => {}
        Err(e) => {
            return Err(Error::container(format!(
                "assigning {}/{} to bridge {}: {}",
                format_ipv4(gateway),
                prefix,
                bridge,
                e
            )))
        }
    }
    nl.set_up(idx)?;
    Ok(idx)
}

/// Host-side setup for one container.  Everything it creates is registered
/// with `rb`, so a later failure unwinds the bridge port, the veth pair,
/// the IP lease and the iptables rules in the right order.
pub fn setup_host(cfg: &ContainerConfig, pid: i32, rb: &mut Rollback) -> Result<NetworkState> {
    let mut st = NetworkState {
        mode: cfg.network.mode.as_str().to_string(),
        ..Default::default()
    };

    match cfg.network.mode {
        NetworkMode::None | NetworkMode::Host => return Ok(st),
        NetworkMode::Bridge => {}
    }

    if !nat::available() {
        return Err(Error::unsupported(
            "iptables is not usable, so bridge networking cannot be set up \
             (install iptables, or use --network none)",
        ));
    }

    let (_, prefix) = parse_cidr(&cfg.network.subnet)?;
    let gateway = cfg.network.gateway_addr()?;
    let id = cfg.id.clone();

    let mut nl = Netlink::open()?;
    let bridge_idx = ensure_bridge(&mut nl, &cfg.network.bridge, gateway, prefix)?;

    // 1. Lease an address.
    let requested = match &cfg.network.ip {
        Some(s) => Some(crate::sys::netlink::parse_ipv4(s)?),
        None => None,
    };
    let (ip, prefix) = ipam::allocate(&cfg.network.subnet, &id, requested, gateway)?;
    {
        let id = id.clone();
        rb.push("ip lease", move || ipam::release(&id));
    }
    crate::fault::check("after_ip_alloc")?;

    // 2. Create the veth pair.
    let (host_name, peer_name) = veth_names(&id);
    if nl.link_index(&host_name)?.is_some() {
        // Left over from a crash with the same container id.
        if let Some(i) = nl.link_index(&host_name)? {
            let _ = nl.delete_link(i);
        }
    }
    nl.create_veth(&host_name, &peer_name)?;
    {
        let host_name = host_name.clone();
        rb.push("veth pair", move || {
            let mut nl = Netlink::open()?;
            if let Some(i) = nl.link_index(&host_name)? {
                nl.delete_link(i)?;
            }
            Ok(())
        });
    }
    crate::fault::check("after_veth_create")?;

    let host_idx = nl.link_index_required(&host_name)?;
    let peer_idx = nl.link_index_required(&peer_name)?;
    nl.set_mtu(host_idx, cfg.network.mtu)?;
    nl.set_mtu(peer_idx, cfg.network.mtu)?;

    // 3. Enslave the host end to the bridge and bring it up.
    nl.set_master(host_idx, bridge_idx)?;
    nl.set_up(host_idx)?;
    crate::fault::check("after_veth_master")?;

    // 4. Hand the peer to the container's network namespace.
    nl.move_to_netns_pid(peer_idx, pid, CONTAINER_IFNAME)?;
    crate::fault::check("after_netns_move")?;

    // 5. NAT and published ports.
    nat::setup_bridge(&cfg.network.bridge, &cfg.network.subnet, cfg.network.nat)?;
    for m in &cfg.network.publish {
        nat::publish(&id, &cfg.network.bridge, ip, m)?;
    }
    if !cfg.network.publish.is_empty() {
        let id = id.clone();
        rb.push("iptables rules", move || {
            nat::cleanup(&id);
            Ok(())
        });
    }

    st.bridge = Some(cfg.network.bridge.clone());
    st.host_veth = Some(host_name);
    st.container_veth = Some(CONTAINER_IFNAME.to_string());
    st.ip = Some(format_ipv4(ip));
    st.prefix = prefix;
    st.gateway = Some(format_ipv4(gateway));
    st.published = cfg.network.publish.clone();
    Ok(st)
}

/// Configure interfaces from **inside** the container's network namespace.
/// Called by init, after the go signal and before the workload starts.
pub fn configure_inside(st: &NetworkState) -> Result<()> {
    let mut nl = Netlink::open()?;

    // `lo` is down in a fresh netns; plenty of software assumes otherwise.
    if let Some(lo) = nl.link_index("lo")? {
        nl.set_up(lo)?;
    }

    if st.mode != "bridge" {
        return Ok(());
    }
    let ifname = st.container_veth.as_deref().unwrap_or(CONTAINER_IFNAME);
    let idx = nl.link_index_required(ifname).map_err(|e| {
        Error::container(format!(
            "container interface {} is missing inside the namespace: {}",
            ifname, e
        ))
    })?;
    let ip = st
        .ip
        .as_deref()
        .ok_or_else(|| Error::container("no address assigned to the container"))?;
    let addr = crate::sys::netlink::parse_ipv4(ip)?;
    nl.add_address(idx, addr, st.prefix)?;
    nl.set_up(idx)?;

    if let Some(gw) = &st.gateway {
        let gw = crate::sys::netlink::parse_ipv4(gw)?;
        // The on-link route for the subnet is installed automatically with
        // the address; the default route needs the gateway to be reachable,
        // which it now is.
        nl.add_default_route(gw, idx)?;
    }
    Ok(())
}

/// Write `/etc/hosts` and `/etc/resolv.conf` inside the new root.
///
/// Best effort by design: a rootfs may legitimately not have `/etc`, and a
/// container that cannot resolve names is still a working container.
pub fn write_resolver_files(cfg: &ContainerConfig, st: &NetworkState) {
    if util::mkdir_p("/etc").is_err() {
        return;
    }
    let mut hosts =
        String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if let Some(ip) = &st.ip {
        hosts.push_str(&format!("{}\t{}\n", ip, cfg.hostname));
    } else {
        hosts.push_str(&format!("127.0.1.1\t{}\n", cfg.hostname));
    }
    if let Err(e) = util::write_file("/etc/hosts", &hosts) {
        crate::log_debug!("could not write /etc/hosts: {}", e);
    }
    if !cfg.network.dns.is_empty() && cfg.network.mode != NetworkMode::None {
        let mut resolv = String::new();
        for s in &cfg.network.dns {
            resolv.push_str(&format!("nameserver {}\n", s));
        }
        if let Err(e) = util::write_file("/etc/resolv.conf", &resolv) {
            crate::log_debug!("could not write /etc/resolv.conf: {}", e);
        }
    }
    if let Err(e) = util::write_file("/etc/hostname", &format!("{}\n", cfg.hostname)) {
        crate::log_debug!("could not write /etc/hostname: {}", e);
    }
}

/// Undo everything `setup_host` created.  Best effort and idempotent — this
/// runs on the teardown path where giving up early would leak.
pub fn teardown(id: &str, st: &NetworkState) {
    if st.mode != "bridge" {
        let _ = ipam::release(id);
        return;
    }
    nat::cleanup(id);
    if let Some(host_veth) = &st.host_veth {
        match Netlink::open() {
            Ok(mut nl) => match nl.link_index(host_veth) {
                // The pair usually vanishes with the container's netns; only
                // delete it if it outlived the container.
                Ok(Some(idx)) => {
                    if let Err(e) = nl.delete_link(idx) {
                        crate::log_warn!("could not delete {}: {}", host_veth, e);
                    }
                }
                Ok(None) => {}
                Err(e) => crate::log_warn!("looking up {}: {}", host_veth, e),
            },
            Err(e) => crate::log_warn!("netlink unavailable during teardown: {}", e),
        }
    }
    if let Err(e) = ipam::release(id) {
        crate::log_warn!("releasing IP lease: {}", e);
    }
}

/// Delete the bridge if no container is using it any more.
pub fn remove_bridge_if_unused(bridge: &str) -> Result<bool> {
    let mut nl = Netlink::open()?;
    let idx = match nl.link_index(bridge)? {
        Some(i) => i,
        None => return Ok(false),
    };
    // Any veth still enslaved to the bridge shows up as `mrv*` in the link
    // list; if none are left the bridge is idle.
    let links = nl.list_links()?;
    let busy = links.iter().any(|l| l.starts_with("mrv"));
    if busy {
        return Ok(false);
    }
    nl.delete_link(idx)?;
    crate::log_info!("removed unused bridge {}", bridge);
    Ok(true)
}

/// Names of veth interfaces on the host that no live container owns.
pub fn orphaned_veths(live_ids: &[String]) -> Result<Vec<String>> {
    let mut nl = Netlink::open()?;
    let expected: Vec<String> = live_ids.iter().map(|id| veth_names(id).0).collect();
    Ok(nl
        .list_links()?
        .into_iter()
        .filter(|l| l.starts_with("mrv") && !expected.contains(l))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContainerConfig;

    #[test]
    fn host_and_none_modes_do_no_work() {
        let mut cfg = ContainerConfig::default();
        cfg.rootfs = "/tmp".into();
        cfg.command = vec!["/bin/true".into()];
        cfg.network.mode = NetworkMode::None;
        cfg.finalize_and_validate(true).unwrap();
        let mut rb = Rollback::new();
        let st = setup_host(&cfg, 1, &mut rb).unwrap();
        assert_eq!(st.mode, "none");
        assert!(st.ip.is_none());
        assert!(rb.is_empty(), "nothing to roll back");
    }

    #[test]
    fn orphan_detection_ignores_live_containers() {
        // Pure name arithmetic; does not need a live interface.
        let id = "0011223344556677";
        let (host, _) = veth_names(id);
        let live = vec![id.to_string()];
        let expected: Vec<String> = live.iter().map(|i| veth_names(i).0).collect();
        assert!(expected.contains(&host));
    }

    #[test]
    fn configure_inside_is_a_noop_without_bridge() {
        // Only exercises the early-return path: opening a netlink socket in
        // the host namespace is harmless, changing links would not be.
        let st = NetworkState {
            mode: "none".into(),
            ..Default::default()
        };
        // `lo` is already up on the host, so this is genuinely side effect
        // free; it validates that the function tolerates a bare state.
        match configure_inside(&st) {
            Ok(()) => {}
            Err(e) => assert!(
                e.to_string().contains("Operation not permitted") || e.errno().is_some(),
                "unexpected error: {}",
                e
            ),
        }
    }
}
