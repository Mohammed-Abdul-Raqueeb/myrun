//! Runtime statistics.
//!
//! Everything here is read from the kernel at the moment it is asked for —
//! nothing is cached, because a cached number that is a few seconds stale is
//! worse than no number at all when you are watching a container misbehave.

use crate::error::Result;
use crate::runtime::cgroup::{Cgroup, CgroupStats};
use crate::runtime::state::ContainerState;
use crate::sys::netlink::{LinkStats, Netlink};
use crate::util::json::Json;
use crate::util::{self, format_bytes};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub id: String,
    pub name: Option<String>,
    pub status: String,
    pub pid: i32,
    pub uptime_ms: u64,
    pub cgroup: CgroupStats,
    /// Direction is from the **container's** point of view.
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub net_rx_packets: u64,
    pub net_tx_packets: u64,
    pub net_available: bool,
    /// Process count from `/proc/<pid>/task` when no pids controller exists.
    pub process_count: Option<u64>,
}

impl Stats {
    /// CPU usage as a percentage of one core, averaged over the container's
    /// lifetime. Instantaneous usage needs two samples; `myrun stats
    /// --follow` computes that from successive calls.
    pub fn cpu_percent_lifetime(&self) -> Option<f64> {
        let usec = self.cgroup.cpu_usage_usec?;
        if self.uptime_ms == 0 {
            return None;
        }
        Some((usec as f64 / 1000.0) / self.uptime_ms as f64 * 100.0)
    }

    pub fn memory_percent(&self) -> Option<f64> {
        let cur = self.cgroup.memory_current?;
        let max = self.cgroup.memory_max?;
        if max == 0 {
            return None;
        }
        Some(cur as f64 / max as f64 * 100.0)
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("id", Json::Str(self.id.clone()));
        o.set(
            "name",
            self.name.clone().map(Json::Str).unwrap_or(Json::Null),
        );
        o.set("status", Json::Str(self.status.clone()));
        o.set("pid", Json::Int(self.pid as i64));
        o.set("uptime_ms", Json::Int(self.uptime_ms as i64));

        let opt = |v: Option<u64>| v.map(|x| Json::Int(x as i64)).unwrap_or(Json::Null);
        let mut mem = Json::obj();
        mem.set("current", opt(self.cgroup.memory_current));
        mem.set("peak", opt(self.cgroup.memory_peak));
        mem.set("limit", opt(self.cgroup.memory_max));
        mem.set("oom_kills", Json::Int(self.cgroup.oom_kills as i64));
        o.set("memory", mem);

        let mut cpu = Json::obj();
        cpu.set("usage_usec", opt(self.cgroup.cpu_usage_usec));
        cpu.set("user_usec", opt(self.cgroup.cpu_user_usec));
        cpu.set("system_usec", opt(self.cgroup.cpu_system_usec));
        cpu.set("nr_throttled", Json::Int(self.cgroup.nr_throttled as i64));
        cpu.set(
            "throttled_usec",
            Json::Int(self.cgroup.throttled_usec as i64),
        );
        o.set("cpu", cpu);

        let mut pids = Json::obj();
        pids.set(
            "current",
            opt(self.cgroup.pids_current.or(self.process_count)),
        );
        pids.set("limit", opt(self.cgroup.pids_max));
        o.set("pids", pids);

        let mut net = Json::obj();
        net.set("available", Json::Bool(self.net_available));
        net.set("rx_bytes", Json::Int(self.net_rx_bytes as i64));
        net.set("tx_bytes", Json::Int(self.net_tx_bytes as i64));
        net.set("rx_packets", Json::Int(self.net_rx_packets as i64));
        net.set("tx_packets", Json::Int(self.net_tx_packets as i64));
        o.set("network", net);
        o
    }

    /// One line for the `myrun stats` table.
    pub fn table_row(&self) -> Vec<String> {
        let dash = "-".to_string();
        vec![
            util::short_id(&self.id),
            self.name.clone().unwrap_or_else(|| dash.clone()),
            self.status.clone(),
            self.cpu_percent_lifetime()
                .map(|p| format!("{:.2}%", p))
                .unwrap_or_else(|| dash.clone()),
            match (self.cgroup.memory_current, self.cgroup.memory_max) {
                (Some(c), Some(m)) => format!("{} / {}", format_bytes(c), format_bytes(m)),
                (Some(c), None) => format!("{} / -", format_bytes(c)),
                _ => dash.clone(),
            },
            self.cgroup
                .pids_current
                .or(self.process_count)
                .map(|p| p.to_string())
                .unwrap_or_else(|| dash.clone()),
            if self.net_available {
                format!(
                    "{} / {}",
                    format_bytes(self.net_rx_bytes),
                    format_bytes(self.net_tx_bytes)
                )
            } else {
                dash
            },
        ]
    }

    pub const HEADERS: &'static [&'static str] = &[
        "CONTAINER",
        "NAME",
        "STATUS",
        "CPU",
        "MEM / LIMIT",
        "PIDS",
        "NET RX / TX",
    ];
}

/// Count threads/processes under a pid when the pids controller is absent.
fn process_count_via_proc(pid: i32) -> Option<u64> {
    if pid <= 0 {
        return None;
    }
    // Every process in the container's PID namespace appears in the host's
    // /proc too; counting them exactly requires walking /proc and comparing
    // namespaces, which is expensive. The init process's own children are a
    // good enough lower bound when there is no pids controller.
    let path = format!("/proc/{}/task", pid);
    std::fs::read_dir(path).ok().map(|d| d.count() as u64)
}

pub fn collect(st: &ContainerState) -> Result<Stats> {
    let mut s = Stats {
        id: st.id.clone(),
        name: st.name.clone(),
        status: st.status.as_str().to_string(),
        pid: st.init_pid,
        uptime_ms: st.uptime_ms(),
        process_count: process_count_via_proc(st.init_pid),
        ..Default::default()
    };

    if let Some(path) = &st.cgroup_path {
        if let Ok(cg) = Cgroup::attach(Path::new(path)) {
            s.cgroup = cg.stats();
        }
    }

    if let Some(veth) = &st.network.host_veth {
        if let Ok(mut nl) = Netlink::open() {
            if let Ok(stats) = nl.link_stats(veth) {
                // The host side of a veth pair sees the mirror image of what
                // the container sees: bytes the container transmits arrive
                // on the host end as receives. Swap so the numbers mean what
                // a user expects.
                s.net_rx_bytes = stats.tx_bytes;
                s.net_tx_bytes = stats.rx_bytes;
                s.net_rx_packets = stats.tx_packets;
                s.net_tx_packets = stats.rx_packets;
                s.net_available = true;
            }
        }
    }
    Ok(s)
}

/// Instantaneous CPU percentage between two samples.
pub fn cpu_delta_percent(prev: &Stats, cur: &Stats, interval_ms: u64) -> Option<f64> {
    let a = prev.cgroup.cpu_usage_usec?;
    let b = cur.cgroup.cpu_usage_usec?;
    if interval_ms == 0 || b < a {
        return None;
    }
    Some(((b - a) as f64 / 1000.0) / interval_ms as f64 * 100.0)
}

/// Direction-corrected view of a link's counters, for tests.
pub fn container_view(stats: &LinkStats) -> (u64, u64) {
    (stats.tx_bytes, stats.rx_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Stats {
        let mut s = Stats::default();
        s.id = "abcdef0123456789".into();
        s.status = "running".into();
        s.uptime_ms = 10_000;
        s.cgroup.cpu_usage_usec = Some(5_000_000); // 5s of CPU in 10s
        s.cgroup.memory_current = Some(50 * 1024 * 1024);
        s.cgroup.memory_max = Some(200 * 1024 * 1024);
        s.cgroup.pids_current = Some(3);
        s
    }

    #[test]
    fn lifetime_cpu_percentage() {
        let s = sample();
        let pct = s.cpu_percent_lifetime().unwrap();
        assert!((pct - 50.0).abs() < 0.001, "got {}", pct);
    }

    #[test]
    fn memory_percentage() {
        let s = sample();
        assert!((s.memory_percent().unwrap() - 25.0).abs() < 0.001);
        let mut unlimited = sample();
        unlimited.cgroup.memory_max = None;
        assert!(unlimited.memory_percent().is_none());
    }

    #[test]
    fn delta_cpu_needs_monotonic_samples() {
        let a = sample();
        let mut b = sample();
        b.cgroup.cpu_usage_usec = Some(5_500_000);
        // 0.5s of CPU over a 1s interval = 50%.
        assert!((cpu_delta_percent(&a, &b, 1000).unwrap() - 50.0).abs() < 0.001);
        // Counters going backwards (cgroup recreated) yields nothing rather
        // than a nonsense negative percentage.
        assert!(cpu_delta_percent(&b, &a, 1000).is_none());
        assert!(cpu_delta_percent(&a, &b, 0).is_none());
    }

    #[test]
    fn table_row_shape() {
        let row = sample().table_row();
        assert_eq!(row.len(), Stats::HEADERS.len());
        assert_eq!(row[0], "abcdef012345");
        assert!(row[3].ends_with('%'));
        assert!(row[4].contains('/'));
        assert_eq!(row[6], "-", "no network -> dash, not zero");
    }

    #[test]
    fn json_includes_every_section() {
        let j = sample().to_json();
        for key in ["memory", "cpu", "pids", "network", "uptime_ms"] {
            assert!(j.get(key).is_some(), "missing {}", key);
        }
        assert_eq!(
            j.get("memory").unwrap().get("limit").unwrap().as_u64(),
            Some(200 * 1024 * 1024)
        );
    }

    #[test]
    fn veth_direction_is_inverted_for_the_container() {
        let ls = LinkStats {
            rx_bytes: 100,
            tx_bytes: 900,
            rx_packets: 1,
            tx_packets: 9,
            ..Default::default()
        };
        // Host receives 100 => container transmitted 100.
        assert_eq!(container_view(&ls), (900, 100));
    }
}
