//! The parent ↔ init synchronisation channel.
//!
//! A container cannot simply be `clone3`d and left to run: the parent has
//! work to do (put the process in its cgroup, hand it a network interface)
//! that must complete *before* the workload starts, and init has work to do
//! (mounts, pivot, seccomp) that the parent must know succeeded before it
//! declares the container running.
//!
//! ```text
//!   parent                              init (PID 1 in the container)
//!   ------                              ----------------------------
//!   clone3(...)  ------------------->   starts, reads config.json
//!                <---- R (ready) -----  "namespaces exist, I am waiting"
//!   cgroup + veth + limits
//!   --------- G (go) ------------->     hostname, mounts, pivot_root,
//!                                       network, caps, seccomp
//!                <---- S (started) ---  "about to exec the workload"
//!                  or  E + message      "setup failed, here is why"
//! ```
//!
//! Without the ready/go handshake the parent would be racing the child's
//! `execve`; without the started/error reply a failed pivot would surface
//! as a mysterious exit code instead of an error message.
//!
//! Framing is `[tag: u8][len: u32 LE][payload]` over an `AF_UNIX`
//! `SOCK_STREAM` socketpair. Length prefixing matters because a stream
//! socket may coalesce or split writes; a bare "read one byte" protocol
//! works right up until an error message arrives in two pieces.

use crate::error::{Error, Result};
use crate::sys::ffi::{self, c_int, c_void};
use crate::sys::{chk, close_fd};

/// init → parent: namespaces are set up, waiting for the go signal.
pub const TAG_READY: u8 = b'R';
/// parent → init: host-side setup is done, proceed.
pub const TAG_GO: u8 = b'G';
/// init → parent: container is configured, about to exec.
pub const TAG_STARTED: u8 = b'S';
/// init → parent: setup failed; payload is the message.
pub const TAG_ERROR: u8 = b'E';
/// init → parent: the workload exited; payload is 8 bytes (code, signal).
pub const TAG_EXIT: u8 = b'X';

const MAX_PAYLOAD: u32 = 64 * 1024;

pub fn tag_name(t: u8) -> &'static str {
    match t {
        TAG_READY => "ready",
        TAG_GO => "go",
        TAG_STARTED => "started",
        TAG_ERROR => "error",
        TAG_EXIT => "exit",
        _ => "unknown",
    }
}

/// One end of the synchronisation socketpair.
pub struct Channel {
    fd: c_int,
    owned: bool,
}

impl Channel {
    pub fn pair() -> Result<(Channel, Channel)> {
        let mut sv = [0 as c_int; 2];
        unsafe {
            chk(
                ffi::socketpair(ffi::AF_UNIX, ffi::SOCK_STREAM, 0, sv.as_mut_ptr()),
                "socketpair",
                "sync channel",
            )?;
        }
        Ok((
            Channel {
                fd: sv[0],
                owned: true,
            },
            Channel {
                fd: sv[1],
                owned: true,
            },
        ))
    }

    /// Wrap an inherited descriptor (init's end is always fd 3).
    pub fn from_raw(fd: c_int) -> Channel {
        Channel { fd, owned: true }
    }

    /// Borrow a descriptor without taking ownership of it.
    pub fn borrowed(fd: c_int) -> Channel {
        Channel { fd, owned: false }
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }

    /// Give up ownership; the caller is responsible for closing.
    pub fn into_raw(mut self) -> c_int {
        self.owned = false;
        self.fd
    }

    fn write_all(&self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = unsafe { ffi::write(self.fd, buf.as_ptr() as *const c_void, buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                let errno = e.raw_os_error().unwrap_or(0);
                if errno == ffi::EINTR {
                    continue;
                }
                return Err(Error::Syscall {
                    call: "write",
                    errno,
                    ctx: "sync channel".into(),
                });
            }
            if n == 0 {
                return Err(Error::io("sync channel closed while writing"));
            }
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    /// Read exactly `n` bytes. `Ok(None)` means a clean EOF at a frame
    /// boundary — the peer died or closed the channel.
    fn read_exact(&self, n: usize) -> Result<Option<Vec<u8>>> {
        let mut out = vec![0u8; n];
        let mut got = 0;
        while got < n {
            let r = unsafe { ffi::read(self.fd, out[got..].as_mut_ptr() as *mut c_void, n - got) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                let errno = e.raw_os_error().unwrap_or(0);
                if errno == ffi::EINTR {
                    continue;
                }
                return Err(Error::Syscall {
                    call: "read",
                    errno,
                    ctx: "sync channel".into(),
                });
            }
            if r == 0 {
                if got == 0 {
                    return Ok(None);
                }
                return Err(Error::io(format!(
                    "sync channel truncated: wanted {} bytes, got {}",
                    n, got
                )));
            }
            got += r as usize;
        }
        Ok(Some(out))
    }

    pub fn send(&self, tag: u8, payload: &[u8]) -> Result<()> {
        if payload.len() as u32 > MAX_PAYLOAD {
            return Err(Error::io("sync message too large"));
        }
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(tag);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        crate::log_trace!("sync: sending {} ({} bytes)", tag_name(tag), payload.len());
        self.write_all(&frame)
    }

    pub fn send_tag(&self, tag: u8) -> Result<()> {
        self.send(tag, &[])
    }

    pub fn send_error(&self, msg: &str) -> Result<()> {
        let bytes = msg.as_bytes();
        let clipped = &bytes[..bytes.len().min(MAX_PAYLOAD as usize)];
        self.send(TAG_ERROR, clipped)
    }

    pub fn send_exit(&self, code: i32, signal: i32) -> Result<()> {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&code.to_le_bytes());
        buf[4..].copy_from_slice(&signal.to_le_bytes());
        self.send(TAG_EXIT, &buf)
    }

    /// Receive one frame. `Ok(None)` on clean EOF.
    pub fn recv(&self) -> Result<Option<(u8, Vec<u8>)>> {
        let head = match self.read_exact(5)? {
            Some(h) => h,
            None => return Ok(None),
        };
        let tag = head[0];
        let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
        if len > MAX_PAYLOAD {
            return Err(Error::parse(format!(
                "sync frame claims {} bytes, which is beyond the {} byte limit",
                len, MAX_PAYLOAD
            )));
        }
        let payload = if len == 0 {
            Vec::new()
        } else {
            self.read_exact(len as usize)?
                .ok_or_else(|| Error::io("sync channel closed mid-frame"))?
        };
        crate::log_trace!("sync: received {} ({} bytes)", tag_name(tag), payload.len());
        Ok(Some((tag, payload)))
    }

    /// Receive a frame and require a particular tag.
    ///
    /// A `TAG_ERROR` frame is turned into the error it describes, which is
    /// how a failure deep inside init surfaces as a readable message in the
    /// parent instead of a numeric exit code.
    pub fn expect(&self, want: u8) -> Result<Vec<u8>> {
        match self.recv()? {
            None => Err(Error::container(format!(
                "container init exited before sending {}",
                tag_name(want)
            ))),
            Some((tag, payload)) if tag == want => Ok(payload),
            Some((TAG_ERROR, payload)) => Err(Error::container(
                String::from_utf8_lossy(&payload).to_string(),
            )),
            Some((tag, _)) => Err(Error::container(format!(
                "expected {} from container init, got {}",
                tag_name(want),
                tag_name(tag)
            ))),
        }
    }

    /// Decode an exit payload.
    pub fn parse_exit(payload: &[u8]) -> Option<(i32, i32)> {
        if payload.len() < 8 {
            return None;
        }
        let code = i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let signal = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        Some((code, signal))
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        if self.owned && self.fd >= 0 {
            close_fd(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        let (parent, child) = Channel::pair().unwrap();
        child.send_tag(TAG_READY).unwrap();
        assert!(parent.expect(TAG_READY).unwrap().is_empty());
        parent.send_tag(TAG_GO).unwrap();
        assert!(child.expect(TAG_GO).unwrap().is_empty());
        child.send_tag(TAG_STARTED).unwrap();
        parent.expect(TAG_STARTED).unwrap();
    }

    #[test]
    fn error_frames_become_errors() {
        let (parent, child) = Channel::pair().unwrap();
        child.send_error("pivot_root failed: EINVAL").unwrap();
        let err = parent.expect(TAG_STARTED).unwrap_err();
        assert!(err.to_string().contains("pivot_root failed"), "{}", err);
    }

    #[test]
    fn eof_is_reported_as_a_dead_init() {
        let (parent, child) = Channel::pair().unwrap();
        drop(child);
        assert!(parent.recv().unwrap().is_none());
        let err = parent.expect(TAG_READY).unwrap_err();
        assert!(err.to_string().contains("exited before"), "{}", err);
    }

    #[test]
    fn large_payloads_survive_stream_fragmentation() {
        // A stream socket may split this across reads; the length prefix is
        // what makes reassembly correct.
        let (parent, child) = Channel::pair().unwrap();
        let msg = "x".repeat(40_000);
        let writer = std::thread::spawn(move || {
            child.send_error(&msg).unwrap();
        });
        let (tag, payload) = parent.recv().unwrap().unwrap();
        writer.join().unwrap();
        assert_eq!(tag, TAG_ERROR);
        assert_eq!(payload.len(), 40_000);
    }

    #[test]
    fn exit_payloads_roundtrip() {
        let (parent, child) = Channel::pair().unwrap();
        child.send_exit(137, 9).unwrap();
        let (tag, payload) = parent.recv().unwrap().unwrap();
        assert_eq!(tag, TAG_EXIT);
        assert_eq!(Channel::parse_exit(&payload), Some((137, 9)));
        assert_eq!(Channel::parse_exit(&[1, 2]), None);
    }

    #[test]
    fn unexpected_tags_are_rejected() {
        let (parent, child) = Channel::pair().unwrap();
        child.send_tag(TAG_EXIT).unwrap();
        let err = parent.expect(TAG_READY).unwrap_err();
        assert!(err.to_string().contains("got exit"), "{}", err);
    }
}
