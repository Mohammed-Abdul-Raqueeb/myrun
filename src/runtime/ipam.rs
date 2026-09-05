//! IP address management for the bridge network.
//!
//! Leases live in `<runtime root>/ipam.json` and every read-modify-write is
//! serialised by `flock` on `<runtime root>/ipam.lock`.  Two `myrun run`
//! processes racing each other must never be handed the same address, and a
//! plain "read the file, pick a free one, write it back" loop absolutely
//! will do that without the lock.
//!
//! ```json
//! { "subnet": "10.87.0.0/24",
//!   "leases": [ {"ip": "10.87.0.2", "id": "abc..."} ] }
//! ```

use crate::error::{Error, Result};
use crate::sys::netlink::{format_ipv4, parse_cidr, parse_ipv4};
use crate::sys::FileLock;
use crate::util::json::{self, Json};
use crate::util::{self};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub ip: [u8; 4],
    pub id: String,
}

#[derive(Debug, Clone, Default)]
pub struct Leases {
    pub subnet: String,
    pub entries: Vec<Lease>,
}

impl Leases {
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("subnet", Json::Str(self.subnet.clone()));
        o.set(
            "leases",
            Json::Arr(
                self.entries
                    .iter()
                    .map(|l| {
                        let mut e = Json::obj();
                        e.set("ip", Json::Str(format_ipv4(l.ip)));
                        e.set("id", Json::Str(l.id.clone()));
                        e
                    })
                    .collect(),
            ),
        );
        o
    }

    pub fn from_json(j: &Json) -> Leases {
        let mut out = Leases {
            subnet: j
                .get("subnet")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            entries: Vec::new(),
        };
        if let Some(a) = j.get("leases").and_then(|v| v.as_array()) {
            for e in a {
                let ip = e
                    .get("ip")
                    .and_then(|v| v.as_str())
                    .and_then(|s| parse_ipv4(s).ok());
                let id = e.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());
                if let (Some(ip), Some(id)) = (ip, id) {
                    out.entries.push(Lease { ip, id });
                }
            }
        }
        out
    }
}

fn state_path() -> PathBuf {
    super::runtime_root().join("ipam.json")
}

fn lock_path() -> PathBuf {
    super::runtime_root().join("ipam.lock")
}

fn load() -> Result<Leases> {
    let p = state_path();
    if !p.exists() {
        return Ok(Leases::default());
    }
    let text = util::read_to_string(&p)?;
    if text.trim().is_empty() {
        return Ok(Leases::default());
    }
    match json::parse(&text) {
        Ok(j) => Ok(Leases::from_json(&j)),
        Err(e) => {
            // A corrupt lease file must not wedge the runtime forever.
            crate::log_warn!(
                "ipam state {} is unreadable ({}); starting fresh",
                p.display(),
                e
            );
            Ok(Leases::default())
        }
    }
}

fn store(l: &Leases) -> Result<()> {
    util::mkdir_p(super::runtime_root())?;
    util::write_atomic(state_path(), &l.to_json().to_string_pretty())
}

fn guard() -> Result<FileLock> {
    util::mkdir_p(super::runtime_root())?;
    FileLock::acquire(&lock_path())
}

/// Usable host range of a subnet: everything except the network address,
/// the broadcast address and the gateway.
pub fn usable_range(subnet: &str) -> Result<(u32, u32)> {
    let (net, prefix) = parse_cidr(subnet)?;
    if prefix > 30 {
        return Err(Error::cfg(format!(
            "subnet {} is too small to allocate addresses from",
            subnet
        )));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    let base = u32::from_be_bytes(net) & mask;
    let last = base | !mask;
    Ok((base + 1, last - 1))
}

/// Allocate (or re-use) an address for `id`.
///
/// `requested` is honoured when free; otherwise the lowest free address in
/// the subnet is returned.  The gateway address is always reserved.
pub fn allocate(
    subnet: &str,
    id: &str,
    requested: Option<[u8; 4]>,
    gateway: [u8; 4],
) -> Result<([u8; 4], u8)> {
    let _lock = guard()?;
    let (_, prefix) = parse_cidr(subnet)?;
    let mut leases = load()?;

    // A different subnet means the old leases are meaningless.
    if leases.subnet != subnet {
        if !leases.entries.is_empty() && !leases.subnet.is_empty() {
            crate::log_warn!(
                "bridge subnet changed from {} to {}; dropping {} stale lease(s)",
                leases.subnet,
                subnet,
                leases.entries.len()
            );
        }
        leases = Leases {
            subnet: subnet.to_string(),
            entries: Vec::new(),
        };
    }

    // Idempotent: restarting a container keeps its address.
    if let Some(existing) = leases.entries.iter().find(|l| l.id == id) {
        let ip = existing.ip;
        if requested.map(|r| r == ip).unwrap_or(true) {
            return Ok((ip, prefix));
        }
        leases.entries.retain(|l| l.id != id);
    }

    let taken: Vec<[u8; 4]> = leases.entries.iter().map(|l| l.ip).collect();
    let gw_u32 = u32::from_be_bytes(gateway);

    let chosen = match requested {
        Some(ip) => {
            if taken.contains(&ip) {
                return Err(Error::cfg(format!(
                    "address {} is already leased to another container",
                    format_ipv4(ip)
                )));
            }
            if u32::from_be_bytes(ip) == gw_u32 {
                return Err(Error::cfg(format!(
                    "address {} is the bridge gateway",
                    format_ipv4(ip)
                )));
            }
            ip
        }
        None => {
            let (lo, hi) = usable_range(subnet)?;
            let mut found = None;
            for candidate in lo..=hi {
                if candidate == gw_u32 {
                    continue;
                }
                let addr = candidate.to_be_bytes();
                if !taken.contains(&addr) {
                    found = Some(addr);
                    break;
                }
            }
            found.ok_or_else(|| {
                Error::container(format!(
                    "no free addresses left in {} ({} in use)",
                    subnet,
                    taken.len()
                ))
            })?
        }
    };

    leases.entries.push(Lease {
        ip: chosen,
        id: id.to_string(),
    });
    store(&leases)?;
    crate::log_debug!("leased {} to {}", format_ipv4(chosen), util::short_id(id));
    Ok((chosen, prefix))
}

/// Give an address back.  Safe to call for a container that has no lease.
pub fn release(id: &str) -> Result<()> {
    let _lock = guard()?;
    let mut leases = load()?;
    let before = leases.entries.len();
    leases.entries.retain(|l| l.id != id);
    if leases.entries.len() != before {
        store(&leases)?;
        crate::log_debug!("released lease for {}", util::short_id(id));
    }
    Ok(())
}

pub fn lease_of(id: &str) -> Result<Option<[u8; 4]>> {
    let _lock = guard()?;
    Ok(load()?
        .entries
        .into_iter()
        .find(|l| l.id == id)
        .map(|l| l.ip))
}

pub fn all_leases() -> Result<Vec<Lease>> {
    let _lock = guard()?;
    Ok(load()?.entries)
}

/// Drop leases whose container no longer exists.
pub fn gc(live_ids: &[String]) -> Result<usize> {
    let _lock = guard()?;
    let mut leases = load()?;
    let before = leases.entries.len();
    leases.entries.retain(|l| live_ids.contains(&l.id));
    let removed = before - leases.entries.len();
    if removed > 0 {
        store(&leases)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testutil::TempRoot;

    #[test]
    fn allocation_lifecycle() {
        let _root = TempRoot::new("alloc");
        let subnet = "10.87.0.0/24";
        let gw = [10, 87, 0, 1];

        let (a, prefix) = allocate(subnet, "one", None, gw).unwrap();
        assert_eq!(prefix, 24);
        assert_eq!(a, [10, 87, 0, 2], "gateway is skipped");

        let (b, _) = allocate(subnet, "two", None, gw).unwrap();
        assert_eq!(b, [10, 87, 0, 3]);

        // Re-allocating for the same container is stable.
        let (a2, _) = allocate(subnet, "one", None, gw).unwrap();
        assert_eq!(a, a2);

        // Explicit requests are honoured, collisions rejected.
        let (c, _) = allocate(subnet, "three", Some([10, 87, 0, 50]), gw).unwrap();
        assert_eq!(c, [10, 87, 0, 50]);
        assert!(allocate(subnet, "four", Some([10, 87, 0, 50]), gw).is_err());
        assert!(allocate(subnet, "four", Some(gw), gw).is_err());

        assert_eq!(lease_of("two").unwrap(), Some(b));
        assert_eq!(all_leases().unwrap().len(), 3);

        // Release frees the address for reuse.
        release("one").unwrap();
        assert_eq!(lease_of("one").unwrap(), None);
        let (again, _) = allocate(subnet, "five", None, gw).unwrap();
        assert_eq!(again, [10, 87, 0, 2]);

        // gc drops leases for containers that are gone. At this point the
        // live leases are two, three and five; keeping only five drops two.
        let removed = gc(&["five".to_string()]).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(all_leases().unwrap().len(), 1);

        // Releasing an unknown id is not an error.
        release("nonexistent").unwrap();
    }

    #[test]
    fn exhaustion_and_small_subnets() {
        let _root = TempRoot::new("exhaust");
        // /29 -> .0 network, .7 broadcast, .1 gateway => .2-.6 usable (5).
        let subnet = "192.168.5.0/29";
        let gw = [192, 168, 5, 1];
        assert_eq!(
            usable_range(subnet).unwrap(),
            (
                u32::from_be_bytes([192, 168, 5, 1]),
                u32::from_be_bytes([192, 168, 5, 6])
            )
        );
        for i in 0..5 {
            allocate(subnet, &format!("c{}", i), None, gw).unwrap();
        }
        let e = allocate(subnet, "overflow", None, gw).unwrap_err();
        assert!(e.to_string().contains("no free addresses"), "{}", e);
        assert!(usable_range("10.0.0.0/31").is_err());
    }

    #[test]
    fn changing_subnet_resets_leases() {
        let _root = TempRoot::new("resubnet");
        allocate("10.87.0.0/24", "a", None, [10, 87, 0, 1]).unwrap();
        let (ip, _) = allocate("172.30.0.0/24", "b", None, [172, 30, 0, 1]).unwrap();
        assert_eq!(ip, [172, 30, 0, 2]);
        let leases = all_leases().unwrap();
        assert_eq!(leases.len(), 1, "old-subnet leases dropped");
    }

    #[test]
    fn corrupt_state_file_recovers() {
        let _root = TempRoot::new("corrupt");
        util::mkdir_p(super::super::runtime_root()).unwrap();
        std::fs::write(state_path(), "{not json at all").unwrap();
        let (ip, _) = allocate("10.87.0.0/24", "x", None, [10, 87, 0, 1]).unwrap();
        assert_eq!(ip, [10, 87, 0, 2]);
    }
}
