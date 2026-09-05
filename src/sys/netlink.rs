//! A hand-written `NETLINK_ROUTE` client.
//!
//! Container networking is done by talking to the kernel's routing socket
//! directly instead of shelling out to `ip(8)`.  That keeps the interesting
//! part of the engineering visible: every veth pair, address and route below
//! is a `struct nlmsghdr` we assemble byte by byte.
//!
//! Message layout (linux/netlink.h):
//!
//! ```text
//!  0        4      6      8        12       16
//!  +--------+------+------+--------+--------+---------------------------+
//!  | length | type | flags|  seq   |  pid   | family payload + attrs    |
//!  +--------+------+------+--------+--------+---------------------------+
//! ```
//!
//! Attributes are TLVs (`struct rtattr { u16 len; u16 type; }`) padded to a
//! 4-byte boundary; nested attributes are simply attributes whose payload is
//! itself a TLV stream.

use super::ffi::*;
use super::{chk, close_fd, cstr};
use crate::error::{Error, Result};
use std::os::raw::{c_int, c_void};

// --- netlink message flags -------------------------------------------------
pub const NLM_F_REQUEST: u16 = 0x001;
pub const NLM_F_MULTI: u16 = 0x002;
pub const NLM_F_ACK: u16 = 0x004;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

// --- rtnetlink message types ----------------------------------------------
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;

// --- IFLA_* (linux/if_link.h) ---------------------------------------------
pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_MASTER: u16 = 10;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_NET_NS_PID: u16 = 19;
pub const IFLA_STATS64: u16 = 23;
pub const IFLA_NET_NS_FD: u16 = 28;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;
pub const VETH_INFO_PEER: u16 = 1;

// --- IFA_* / RTA_* ---------------------------------------------------------
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_BROADCAST: u16 = 4;

pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PREFSRC: u16 = 7;

pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;

pub const RT_TABLE_MAIN: u8 = 254;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RTPROT_BOOT: u8 = 3;
pub const RTN_UNICAST: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NlMsgHdr {
    pub len: u32,
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IfInfoMsg {
    pub family: u8,
    pub _pad: u8,
    pub ty: u16,
    pub index: i32,
    pub flags: u32,
    pub change: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IfAddrMsg {
    pub family: u8,
    pub prefixlen: u8,
    pub flags: u8,
    pub scope: u8,
    pub index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtMsg {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub ty: u8,
    pub flags: u32,
}

#[inline]
pub fn nl_align(n: usize) -> usize {
    (n + 3) & !3
}

/// Incrementally built netlink request.
pub struct MsgBuilder {
    buf: Vec<u8>,
}

impl MsgBuilder {
    pub fn new(ty: u16, flags: u16) -> MsgBuilder {
        let mut buf = vec![0u8; 16];
        buf[4..6].copy_from_slice(&ty.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        MsgBuilder { buf }
    }

    /// Append the family-specific header (ifinfomsg / ifaddrmsg / rtmsg).
    pub fn payload<T: Copy>(&mut self, v: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.buf.extend_from_slice(bytes);
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
    }

    pub fn attr(&mut self, ty: u16, data: &[u8]) {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
    }

    pub fn attr_str(&mut self, ty: u16, s: &str) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        self.attr(ty, &v);
    }

    pub fn attr_u32(&mut self, ty: u16, v: u32) {
        self.attr(ty, &v.to_ne_bytes());
    }

    /// Open a nested attribute; returns the offset to hand back to
    /// [`MsgBuilder::end_nested`].
    pub fn begin_nested(&mut self, ty: u16) -> usize {
        let off = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // length patched later
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        off
    }

    pub fn end_nested(&mut self, off: usize) {
        let len = (self.buf.len() - off) as u16;
        self.buf[off..off + 2].copy_from_slice(&len.to_ne_bytes());
    }

    fn finish(mut self, seq: u32) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.buf
    }
}

/// One parsed attribute.
pub struct Attr<'a> {
    pub ty: u16,
    pub data: &'a [u8],
}

/// Iterate a TLV stream.
pub fn parse_attrs(mut buf: &[u8]) -> Vec<Attr<'_>> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ty = u16::from_ne_bytes([buf[2], buf[3]]);
        if len < 4 || len > buf.len() {
            break;
        }
        out.push(Attr {
            ty,
            data: &buf[4..len],
        });
        let step = nl_align(len);
        if step >= buf.len() {
            break;
        }
        buf = &buf[step..];
    }
    out
}

/// A netlink socket bound to the caller's current network namespace.
pub struct Netlink {
    fd: c_int,
    seq: u32,
}

impl Netlink {
    pub fn open() -> Result<Netlink> {
        let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
        let fd = chk(fd, "socket", "AF_NETLINK")?;
        let addr = SockaddrNl::default();
        let rc = unsafe {
            bind(
                fd,
                &addr as *const SockaddrNl as *const c_void,
                std::mem::size_of::<SockaddrNl>() as socklen_t,
            )
        };
        if rc < 0 {
            let e = errno();
            close_fd(fd);
            return Err(Error::Syscall {
                call: "bind",
                errno: e,
                ctx: "netlink socket".into(),
            });
        }
        // Never block forever on a lost ack.
        let tv = Timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &tv as *const Timeval as *const c_void,
                std::mem::size_of::<Timeval>() as socklen_t,
            );
        }
        Ok(Netlink { fd, seq: 1 })
    }

    fn send_recv(&mut self, msg: MsgBuilder, expect_dump: bool) -> Result<Vec<Vec<u8>>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let bytes = msg.finish(seq);
        let n = unsafe { send(self.fd, bytes.as_ptr() as *const c_void, bytes.len(), 0) };
        if n < 0 {
            return Err(Error::Syscall {
                call: "send",
                errno: errno(),
                ctx: "netlink request".into(),
            });
        }

        let mut replies = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = unsafe { recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
            if n < 0 {
                let e = errno();
                if e == EINTR {
                    continue;
                }
                return Err(Error::Syscall {
                    call: "recv",
                    errno: e,
                    ctx: "netlink reply".into(),
                });
            }
            let mut off = 0usize;
            let total = n as usize;
            let mut done = false;
            while off + 16 <= total {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                let ty = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                let flags = u16::from_ne_bytes([buf[off + 6], buf[off + 7]]);
                let mseq =
                    u32::from_ne_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]);
                if len < 16 || off + len > total {
                    break;
                }
                if mseq != seq {
                    off += nl_align(len);
                    continue;
                }
                match ty {
                    NLMSG_ERROR => {
                        let err = i32::from_ne_bytes([
                            buf[off + 16],
                            buf[off + 17],
                            buf[off + 18],
                            buf[off + 19],
                        ]);
                        if err != 0 {
                            return Err(Error::Syscall {
                                call: "netlink",
                                errno: -err,
                                ctx: "kernel rejected the request".into(),
                            });
                        }
                        done = true; // plain ack
                    }
                    NLMSG_DONE => done = true,
                    NLMSG_NOOP => {}
                    _ => {
                        replies.push(buf[off + 16..off + len].to_vec());
                        if !expect_dump && flags & NLM_F_MULTI == 0 {
                            done = true;
                        }
                    }
                }
                off += nl_align(len);
            }
            if done {
                break;
            }
        }
        Ok(replies)
    }

    fn request(&mut self, msg: MsgBuilder) -> Result<()> {
        self.send_recv(msg, false).map(|_| ())
    }

    // -----------------------------------------------------------------
    // link operations
    // -----------------------------------------------------------------

    /// Interface index, or `None` if the interface does not exist in the
    /// current network namespace.
    pub fn link_index(&self, name: &str) -> Result<Option<u32>> {
        let c = cstr(name)?;
        let idx = unsafe { if_nametoindex(c.as_ptr()) };
        if idx == 0 {
            Ok(None)
        } else {
            Ok(Some(idx))
        }
    }

    pub fn link_index_required(&self, name: &str) -> Result<u32> {
        self.link_index(name)?
            .ok_or_else(|| Error::not_found(format!("network interface {:?}", name)))
    }

    /// Create a veth pair.  The two ends are ordinary interfaces; moving one
    /// of them into another network namespace is what makes it a "cable"
    /// between namespaces.
    pub fn create_veth(&mut self, name: &str, peer: &str) -> Result<()> {
        let mut m = MsgBuilder::new(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        );
        m.payload(&IfInfoMsg::default());
        m.attr_str(IFLA_IFNAME, name);
        let li = m.begin_nested(IFLA_LINKINFO);
        m.attr_str(IFLA_INFO_KIND, "veth");
        let id = m.begin_nested(IFLA_INFO_DATA);
        let pe = m.begin_nested(VETH_INFO_PEER);
        m.payload(&IfInfoMsg::default());
        m.attr_str(IFLA_IFNAME, peer);
        m.end_nested(pe);
        m.end_nested(id);
        m.end_nested(li);
        self.request(m)
    }

    /// Create a bridge device (`ip link add name X type bridge`).
    pub fn create_bridge(&mut self, name: &str) -> Result<()> {
        let mut m = MsgBuilder::new(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        );
        m.payload(&IfInfoMsg::default());
        m.attr_str(IFLA_IFNAME, name);
        let li = m.begin_nested(IFLA_LINKINFO);
        m.attr_str(IFLA_INFO_KIND, "bridge");
        m.end_nested(li);
        self.request(m)
    }

    pub fn delete_link(&mut self, index: u32) -> Result<()> {
        let mut m = MsgBuilder::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
        m.payload(&IfInfoMsg {
            index: index as i32,
            ..Default::default()
        });
        self.request(m)
    }

    pub fn set_up(&mut self, index: u32) -> Result<()> {
        let mut m = MsgBuilder::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        m.payload(&IfInfoMsg {
            index: index as i32,
            flags: IFF_UP,
            change: IFF_UP,
            ..Default::default()
        });
        self.request(m)
    }

    pub fn set_down(&mut self, index: u32) -> Result<()> {
        let mut m = MsgBuilder::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        m.payload(&IfInfoMsg {
            index: index as i32,
            flags: 0,
            change: IFF_UP,
            ..Default::default()
        });
        self.request(m)
    }

    pub fn set_mtu(&mut self, index: u32, mtu: u32) -> Result<()> {
        let mut m = MsgBuilder::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        m.payload(&IfInfoMsg {
            index: index as i32,
            ..Default::default()
        });
        m.attr_u32(IFLA_MTU, mtu);
        self.request(m)
    }

    /// Enslave `index` to bridge `master`.
    pub fn set_master(&mut self, index: u32, master: u32) -> Result<()> {
        let mut m = MsgBuilder::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        m.payload(&IfInfoMsg {
            index: index as i32,
            ..Default::default()
        });
        m.attr_u32(IFLA_MASTER, master);
        self.request(m)
    }

    /// Move an interface into the network namespace of `pid`, renaming it in
    /// the same operation.
    ///
    /// The kernel's `do_setlink()` performs the namespace move first and uses
    /// `IFLA_IFNAME` as the name to take in the destination namespace, so one
    /// message is enough — and it avoids a window where the interface has a
    /// temporary name inside the container.
    pub fn move_to_netns_pid(&mut self, index: u32, pid: i32, new_name: &str) -> Result<()> {
        let mut m = MsgBuilder::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        m.payload(&IfInfoMsg {
            index: index as i32,
            ..Default::default()
        });
        m.attr_u32(IFLA_NET_NS_PID, pid as u32);
        m.attr_str(IFLA_IFNAME, new_name);
        self.request(m)
    }

    // -----------------------------------------------------------------
    // addresses and routes
    // -----------------------------------------------------------------

    pub fn add_address(&mut self, index: u32, addr: [u8; 4], prefix: u8) -> Result<()> {
        let mut m = MsgBuilder::new(
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        );
        m.payload(&IfAddrMsg {
            family: AF_INET as u8,
            prefixlen: prefix,
            flags: 0,
            scope: RT_SCOPE_UNIVERSE,
            index,
        });
        m.attr(IFA_LOCAL, &addr);
        m.attr(IFA_ADDRESS, &addr);
        // Broadcast address for the subnet, so that ARP/DHCP style traffic
        // behaves the way userspace expects.
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix as u32)
        };
        let base = u32::from_be_bytes(addr) & mask;
        let bcast = (base | !mask).to_be_bytes();
        m.attr(IFA_BROADCAST, &bcast);
        self.request(m)
    }

    /// Default route (`0.0.0.0/0 via gw dev oif`).
    pub fn add_default_route(&mut self, gw: [u8; 4], oif: u32) -> Result<()> {
        let mut m = MsgBuilder::new(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        );
        m.payload(&RtMsg {
            family: AF_INET as u8,
            dst_len: 0,
            table: RT_TABLE_MAIN,
            protocol: RTPROT_BOOT,
            scope: RT_SCOPE_UNIVERSE,
            ty: RTN_UNICAST,
            ..Default::default()
        });
        m.attr(RTA_GATEWAY, &gw);
        m.attr_u32(RTA_OIF, oif);
        self.request(m)
    }

    /// On-link route to a prefix (`dst/prefix dev oif scope link`).
    pub fn add_link_route(&mut self, dst: [u8; 4], prefix: u8, oif: u32) -> Result<()> {
        let mut m = MsgBuilder::new(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        );
        m.payload(&RtMsg {
            family: AF_INET as u8,
            dst_len: prefix,
            table: RT_TABLE_MAIN,
            protocol: RTPROT_BOOT,
            scope: RT_SCOPE_LINK,
            ty: RTN_UNICAST,
            ..Default::default()
        });
        m.attr(RTA_DST, &dst);
        m.attr_u32(RTA_OIF, oif);
        self.request(m)
    }

    // -----------------------------------------------------------------
    // statistics
    // -----------------------------------------------------------------

    /// Per-interface counters from `IFLA_STATS64`.
    pub fn link_stats(&mut self, name: &str) -> Result<LinkStats> {
        let mut m = MsgBuilder::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
        m.payload(&IfInfoMsg {
            family: AF_UNSPEC as u8,
            ..Default::default()
        });
        let replies = self.send_recv(m, true)?;
        for r in replies {
            if r.len() < std::mem::size_of::<IfInfoMsg>() {
                continue;
            }
            let attrs = parse_attrs(&r[std::mem::size_of::<IfInfoMsg>()..]);
            let this_name = attrs
                .iter()
                .find(|a| a.ty == IFLA_IFNAME)
                .map(|a| {
                    String::from_utf8_lossy(&a.data[..a.data.len().saturating_sub(1)]).to_string()
                })
                .unwrap_or_default();
            if this_name != name {
                continue;
            }
            if let Some(s) = attrs.iter().find(|a| a.ty == IFLA_STATS64) {
                return Ok(LinkStats::from_bytes(&this_name, s.data));
            }
            return Ok(LinkStats {
                name: this_name,
                ..Default::default()
            });
        }
        Err(Error::not_found(format!("interface {:?}", name)))
    }

    /// Names of every interface in the current network namespace.
    pub fn list_links(&mut self) -> Result<Vec<String>> {
        let mut m = MsgBuilder::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
        m.payload(&IfInfoMsg {
            family: AF_UNSPEC as u8,
            ..Default::default()
        });
        let replies = self.send_recv(m, true)?;
        let mut out = Vec::new();
        for r in replies {
            if r.len() < std::mem::size_of::<IfInfoMsg>() {
                continue;
            }
            for a in parse_attrs(&r[std::mem::size_of::<IfInfoMsg>()..]) {
                if a.ty == IFLA_IFNAME {
                    out.push(
                        String::from_utf8_lossy(&a.data[..a.data.len().saturating_sub(1)])
                            .to_string(),
                    );
                }
            }
        }
        Ok(out)
    }
}

impl Drop for Netlink {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

/// Subset of `struct rtnl_link_stats64` that we report.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LinkStats {
    pub name: String,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

impl LinkStats {
    fn from_bytes(name: &str, d: &[u8]) -> LinkStats {
        let g = |i: usize| -> u64 {
            let o = i * 8;
            if o + 8 > d.len() {
                return 0;
            }
            u64::from_ne_bytes([
                d[o],
                d[o + 1],
                d[o + 2],
                d[o + 3],
                d[o + 4],
                d[o + 5],
                d[o + 6],
                d[o + 7],
            ])
        };
        LinkStats {
            name: name.to_string(),
            rx_packets: g(0),
            tx_packets: g(1),
            rx_bytes: g(2),
            tx_bytes: g(3),
            rx_errors: g(4),
            tx_errors: g(5),
            rx_dropped: g(6),
            tx_dropped: g(7),
        }
    }
}

/// Parse dotted-quad IPv4.
pub fn parse_ipv4(s: &str) -> Result<[u8; 4]> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 4 {
        return Err(Error::cfg(format!("invalid IPv4 address {:?}", s)));
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p
            .parse::<u8>()
            .map_err(|_| Error::cfg(format!("invalid IPv4 octet {:?} in {:?}", p, s)))?;
    }
    Ok(out)
}

pub fn format_ipv4(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

/// Parse `a.b.c.d/prefix`.
pub fn parse_cidr(s: &str) -> Result<([u8; 4], u8)> {
    let (ip, pfx) = match s.split_once('/') {
        Some((a, b)) => (a, b),
        None => {
            return Err(Error::cfg(format!(
                "expected CIDR a.b.c.d/len, got {:?}",
                s
            )))
        }
    };
    let prefix: u8 = pfx
        .parse()
        .map_err(|_| Error::cfg(format!("invalid prefix length in {:?}", s)))?;
    if prefix > 32 {
        return Err(Error::cfg(format!("prefix length {} > 32", prefix)));
    }
    Ok((parse_ipv4(ip)?, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
    }

    #[test]
    fn builder_lays_out_header_and_attrs() {
        let mut m = MsgBuilder::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        m.payload(&IfInfoMsg::default());
        m.attr_str(IFLA_IFNAME, "veth0");
        let bytes = m.finish(42);
        // header: len, type, flags, seq, pid
        let len = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(len, bytes.len());
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), RTM_NEWLINK);
        assert_eq!(
            u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            42
        );
        // ifinfomsg is 16 bytes, so the attribute starts at 32.
        let attrs = parse_attrs(&bytes[16 + std::mem::size_of::<IfInfoMsg>()..]);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].ty, IFLA_IFNAME);
        assert_eq!(&attrs[0].data, b"veth0\0");
    }

    #[test]
    fn nested_attrs_get_correct_lengths() {
        let mut m = MsgBuilder::new(RTM_NEWLINK, NLM_F_REQUEST);
        m.payload(&IfInfoMsg::default());
        let li = m.begin_nested(IFLA_LINKINFO);
        m.attr_str(IFLA_INFO_KIND, "veth");
        m.end_nested(li);
        let bytes = m.finish(1);
        let attrs = parse_attrs(&bytes[16 + std::mem::size_of::<IfInfoMsg>()..]);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].ty, IFLA_LINKINFO);
        let inner = parse_attrs(attrs[0].data);
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].ty, IFLA_INFO_KIND);
        assert_eq!(&inner[0].data, b"veth\0");
    }

    #[test]
    fn struct_sizes_match_uapi() {
        assert_eq!(std::mem::size_of::<NlMsgHdr>(), 16);
        assert_eq!(std::mem::size_of::<IfInfoMsg>(), 16);
        assert_eq!(std::mem::size_of::<IfAddrMsg>(), 8);
        assert_eq!(std::mem::size_of::<RtMsg>(), 12);
    }

    #[test]
    fn ip_parsing() {
        assert_eq!(parse_ipv4("10.87.0.1").unwrap(), [10, 87, 0, 1]);
        assert_eq!(format_ipv4([192, 168, 1, 5]), "192.168.1.5");
        assert!(parse_ipv4("10.87.0").is_err());
        assert!(parse_ipv4("10.87.0.300").is_err());
        let (ip, p) = parse_cidr("10.87.0.0/24").unwrap();
        assert_eq!((ip, p), ([10, 87, 0, 0], 24));
        assert!(parse_cidr("10.87.0.0").is_err());
        assert!(parse_cidr("10.87.0.0/33").is_err());
    }

    #[test]
    fn stats_decoding() {
        let mut raw = Vec::new();
        for i in 0u64..8 {
            raw.extend_from_slice(&(i * 100).to_ne_bytes());
        }
        let s = LinkStats::from_bytes("eth0", &raw);
        assert_eq!(s.rx_packets, 0);
        assert_eq!(s.tx_packets, 100);
        assert_eq!(s.rx_bytes, 200);
        assert_eq!(s.tx_bytes, 300);
        assert_eq!(s.tx_dropped, 700);
    }

    #[test]
    fn can_open_and_list_host_links() {
        // Opening a netlink socket needs no privileges.
        let mut nl = Netlink::open().unwrap();
        let links = nl.list_links().unwrap();
        assert!(links.iter().any(|l| l == "lo"), "got {:?}", links);
        assert!(nl.link_index("lo").unwrap().is_some());
        assert!(nl.link_index("nope-not-here").unwrap().is_none());
        let st = nl.link_stats("lo").unwrap();
        assert_eq!(st.name, "lo");
    }
}
