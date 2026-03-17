//! Thin safe wrapper around libmnl for netlink communication.
//!
//! Provides `MnlSocket` for opening/binding/sending/receiving on netlink sockets,
//! and `MnlMsg` for building properly formatted netlink messages with attributes.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

// ---------------------------------------------------------------------------
// libmnl FFI declarations
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types)]
type mnl_socket = libc::c_void;

extern "C" {
    fn mnl_socket_open(bus: libc::c_int) -> *mut mnl_socket;
    fn mnl_socket_open2(bus: libc::c_int, flags: libc::c_int) -> *mut mnl_socket;
    fn mnl_socket_bind(nl: *mut mnl_socket, groups: libc::c_uint, pid: libc::pid_t) -> libc::c_int;
    fn mnl_socket_close(nl: *mut mnl_socket) -> libc::c_int;
    fn mnl_socket_get_fd(nl: *const mnl_socket) -> libc::c_int;
    fn mnl_socket_get_portid(nl: *const mnl_socket) -> libc::c_uint;
    fn mnl_socket_sendto(
        nl: *const mnl_socket,
        buf: *const libc::c_void,
        len: libc::size_t,
    ) -> libc::ssize_t;
    fn mnl_socket_recvfrom(
        nl: *const mnl_socket,
        buf: *mut libc::c_void,
        bufsiz: libc::size_t,
    ) -> libc::ssize_t;

    fn mnl_nlmsg_put_header(buf: *mut libc::c_void) -> *mut libc::nlmsghdr;
    fn mnl_nlmsg_put_extra_header(
        nlh: *mut libc::nlmsghdr,
        size: libc::size_t,
    ) -> *mut libc::c_void;

    fn mnl_attr_put(
        nlh: *mut libc::nlmsghdr,
        attr_type: libc::c_uint,
        len: libc::size_t,
        data: *const libc::c_void,
    );
    fn mnl_attr_put_u8(nlh: *mut libc::nlmsghdr, attr_type: libc::c_uint, data: u8);
    fn mnl_attr_put_u16(nlh: *mut libc::nlmsghdr, attr_type: libc::c_uint, data: u16);
    fn mnl_attr_put_u32(nlh: *mut libc::nlmsghdr, attr_type: libc::c_uint, data: u32);
    fn mnl_attr_put_u64(nlh: *mut libc::nlmsghdr, attr_type: libc::c_uint, data: u64);
    fn mnl_attr_put_str(
        nlh: *mut libc::nlmsghdr,
        attr_type: libc::c_uint,
        data: *const libc::c_char,
    );
    fn mnl_attr_put_strz(
        nlh: *mut libc::nlmsghdr,
        attr_type: libc::c_uint,
        data: *const libc::c_char,
    );
    fn mnl_attr_nest_start(
        nlh: *mut libc::nlmsghdr,
        attr_type: libc::c_uint,
    ) -> *mut libc::nlattr;
    fn mnl_attr_nest_end(nlh: *mut libc::nlmsghdr, start: *mut libc::nlattr);
    fn mnl_attr_nest_cancel(nlh: *mut libc::nlmsghdr, start: *mut libc::nlattr);

    fn mnl_cb_run(
        buf: *const libc::c_void,
        numbytes: libc::size_t,
        seq: libc::c_uint,
        portid: libc::c_uint,
        cb_data: Option<
            unsafe extern "C" fn(
                nlh: *const libc::nlmsghdr,
                data: *mut libc::c_void,
            ) -> libc::c_int,
        >,
        data: *mut libc::c_void,
    ) -> libc::c_int;
}

// ---------------------------------------------------------------------------
// MnlSocket — safe netlink socket wrapper
// ---------------------------------------------------------------------------

/// A safe wrapper around a libmnl netlink socket.
pub struct MnlSocket {
    inner: *mut mnl_socket,
}

// MnlSocket is Send — the underlying fd is OS-managed and not thread-local.
unsafe impl Send for MnlSocket {}

impl MnlSocket {
    /// Open a netlink socket on the given bus (e.g., `libc::NETLINK_ROUTE`).
    pub fn open(bus: i32) -> io::Result<Self> {
        let ptr = unsafe { mnl_socket_open(bus) };
        if ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { inner: ptr })
    }

    /// Open a netlink socket with additional socket flags (e.g., `SOCK_CLOEXEC`).
    pub fn open2(bus: i32, flags: i32) -> io::Result<Self> {
        let ptr = unsafe { mnl_socket_open2(bus, flags) };
        if ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { inner: ptr })
    }

    /// Bind the socket to the given multicast groups. Use 0 for no groups.
    pub fn bind(&self, groups: u32, pid: i32) -> io::Result<()> {
        let ret = unsafe { mnl_socket_bind(self.inner, groups, pid) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Get the raw file descriptor for this socket.
    pub fn fd(&self) -> RawFd {
        unsafe { mnl_socket_get_fd(self.inner) }
    }

    /// Get the port ID assigned by the kernel.
    pub fn portid(&self) -> u32 {
        unsafe { mnl_socket_get_portid(self.inner) }
    }

    /// Send a built netlink message.
    pub fn send(&self, msg: &MnlMsg) -> io::Result<()> {
        let ret = unsafe {
            mnl_socket_sendto(
                self.inner,
                msg.buf.as_ptr() as *const libc::c_void,
                msg.nlh().nlmsg_len as usize,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send raw bytes (e.g., a batch of messages).
    pub fn send_raw(&self, data: &[u8]) -> io::Result<()> {
        let ret = unsafe {
            mnl_socket_sendto(
                self.inner,
                data.as_ptr() as *const libc::c_void,
                data.len(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receive data into the provided buffer. Returns the number of bytes received.
    pub fn recv_into(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe {
            mnl_socket_recvfrom(
                self.inner,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret as usize)
    }

    /// Send a message and wait for the kernel ACK. Returns an error if the
    /// kernel reports a non-zero error code.
    pub fn send_recv_ack(&self, msg: &MnlMsg) -> io::Result<()> {
        self.send(msg)?;
        self.recv_ack(msg.seq())
    }

    /// Receive and verify an ACK response for the given sequence number.
    pub fn recv_ack(&self, seq: u32) -> io::Result<()> {
        let mut buf = vec![0u8; 8192];
        let n = self.recv_into(&mut buf)?;
        let portid = self.portid();
        let ret = unsafe {
            mnl_cb_run(
                buf.as_ptr() as *const libc::c_void,
                n,
                seq,
                portid,
                None,
                std::ptr::null_mut(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send raw bytes and receive an ACK.
    pub fn send_raw_recv_ack(&self, data: &[u8], seq: u32) -> io::Result<()> {
        self.send_raw(data)?;
        self.recv_ack(seq)
    }
}

impl Drop for MnlSocket {
    fn drop(&mut self) {
        unsafe {
            mnl_socket_close(self.inner);
        }
    }
}

// ---------------------------------------------------------------------------
// MnlMsg — netlink message builder
// ---------------------------------------------------------------------------

/// Buffer size used for building a single netlink message.
const MNL_MSG_BUF_SIZE: usize = 8192;

/// A netlink message builder wrapping a buffer. Uses libmnl functions
/// to correctly format headers, extra headers, and attributes.
pub struct MnlMsg {
    buf: Vec<u8>,
}

impl MnlMsg {
    /// Create a new message with the given type, flags, and sequence number.
    pub fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        let mut buf = vec![0u8; MNL_MSG_BUF_SIZE];
        let nlh = unsafe { mnl_nlmsg_put_header(buf.as_mut_ptr() as *mut libc::c_void) };
        unsafe {
            (*nlh).nlmsg_type = msg_type;
            (*nlh).nlmsg_flags = flags;
            (*nlh).nlmsg_seq = seq;
        }
        Self { buf }
    }

    /// Get a pointer to the nlmsghdr.
    fn nlh_ptr(&mut self) -> *mut libc::nlmsghdr {
        self.buf.as_mut_ptr() as *mut libc::nlmsghdr
    }

    /// Get a reference to the nlmsghdr (immutable).
    fn nlh(&self) -> &libc::nlmsghdr {
        unsafe { &*(self.buf.as_ptr() as *const libc::nlmsghdr) }
    }

    /// Get the sequence number.
    pub fn seq(&self) -> u32 {
        self.nlh().nlmsg_seq
    }

    /// Get the current message length.
    pub fn len(&self) -> u32 {
        self.nlh().nlmsg_len
    }

    /// Allocate and return a mutable reference to an extra header of type T.
    /// This is typically used for protocol-specific headers like `ifinfomsg`,
    /// `ifaddrmsg`, `nfgenmsg`, etc.
    pub fn put_extra_header<T: Sized>(&mut self) -> &mut T {
        let ptr = unsafe {
            mnl_nlmsg_put_extra_header(self.nlh_ptr(), std::mem::size_of::<T>())
        };
        unsafe { &mut *(ptr as *mut T) }
    }

    /// Append a raw byte-slice attribute.
    pub fn put(&mut self, attr_type: u16, data: &[u8]) {
        unsafe {
            mnl_attr_put(
                self.nlh_ptr(),
                attr_type as libc::c_uint,
                data.len(),
                data.as_ptr() as *const libc::c_void,
            );
        }
    }

    /// Append a u8 attribute.
    pub fn put_u8(&mut self, attr_type: u16, val: u8) {
        unsafe { mnl_attr_put_u8(self.nlh_ptr(), attr_type as libc::c_uint, val) }
    }

    /// Append a u16 attribute (host byte order).
    pub fn put_u16(&mut self, attr_type: u16, val: u16) {
        unsafe { mnl_attr_put_u16(self.nlh_ptr(), attr_type as libc::c_uint, val) }
    }

    /// Append a u32 attribute (host byte order).
    pub fn put_u32(&mut self, attr_type: u16, val: u32) {
        unsafe { mnl_attr_put_u32(self.nlh_ptr(), attr_type as libc::c_uint, val) }
    }

    /// Append a u64 attribute (host byte order).
    pub fn put_u64(&mut self, attr_type: u16, val: u64) {
        unsafe { mnl_attr_put_u64(self.nlh_ptr(), attr_type as libc::c_uint, val) }
    }

    /// Append a null-terminated string attribute.
    pub fn put_strz(&mut self, attr_type: u16, val: &str) {
        let c = CString::new(val).expect("string contains interior NUL");
        unsafe {
            mnl_attr_put_strz(self.nlh_ptr(), attr_type as libc::c_uint, c.as_ptr());
        }
    }

    /// Append a string attribute (not null-terminated).
    pub fn put_str(&mut self, attr_type: u16, val: &str) {
        let c = CString::new(val).expect("string contains interior NUL");
        unsafe {
            mnl_attr_put_str(self.nlh_ptr(), attr_type as libc::c_uint, c.as_ptr());
        }
    }

    /// Start a nested attribute. Returns a `NestToken` that must be passed to
    /// `nest_end()` when done adding child attributes.
    pub fn nest_start(&mut self, attr_type: u16) -> NestToken {
        let ptr = unsafe { mnl_attr_nest_start(self.nlh_ptr(), attr_type as libc::c_uint) };
        NestToken { attr: ptr }
    }

    /// End a nested attribute started with `nest_start()`.
    pub fn nest_end(&mut self, token: NestToken) {
        unsafe { mnl_attr_nest_end(self.nlh_ptr(), token.attr) }
        // Don't run NestToken's drop
        std::mem::forget(token);
    }

    /// Cancel a nested attribute (remove it).
    pub fn nest_cancel(&mut self, token: NestToken) {
        unsafe { mnl_attr_nest_cancel(self.nlh_ptr(), token.attr) }
        std::mem::forget(token);
    }

    /// Get the raw bytes of this message (up to nlmsg_len).
    pub fn as_bytes(&self) -> &[u8] {
        let len = self.nlh().nlmsg_len as usize;
        &self.buf[..len]
    }
}

/// Token returned by `MnlMsg::nest_start()`. Must be consumed by `nest_end()`.
pub struct NestToken {
    attr: *mut libc::nlattr,
}

// ---------------------------------------------------------------------------
// Batch helper — concatenate multiple messages for atomic nftables batches
// ---------------------------------------------------------------------------

/// A batch of netlink messages. Used for nftables NFT_MSG_* batches.
pub struct MnlBatch {
    buf: Vec<u8>,
    seq: u32,
}

impl MnlBatch {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(16384),
            seq: 0,
        }
    }

    /// Append a message to the batch. Returns the sequence number used.
    pub fn push(&mut self, msg: &MnlMsg) -> u32 {
        let bytes = msg.as_bytes();
        self.buf.extend_from_slice(bytes);
        let seq = msg.seq();
        if seq > self.seq {
            self.seq = seq;
        }
        seq
    }

    /// Get the raw batch bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Get the highest sequence number in the batch.
    pub fn last_seq(&self) -> u32 {
        self.seq
    }
}

impl Default for MnlBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper: get interface index by name
// ---------------------------------------------------------------------------

/// Look up a network interface index by name.
pub fn if_nametoindex(name: &str) -> io::Result<i32> {
    let c = CString::new(name.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx as i32)
    }
}

// ---------------------------------------------------------------------------
// Public cb_run wrapper for batch processing
// ---------------------------------------------------------------------------

/// Run `mnl_cb_run` on a received buffer. Returns Ok(ret) where ret is the
/// callback return value (0 = done, >0 = more data expected), or Err on
/// netlink error.
pub fn cb_run(buf: &[u8], seq: u32, portid: u32) -> io::Result<i32> {
    let ret = unsafe {
        mnl_cb_run(
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            seq,
            portid,
            None,
            std::ptr::null_mut(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret)
}

// ---------------------------------------------------------------------------
// Re-export common constants
// ---------------------------------------------------------------------------

/// Netlink message flags
pub mod flags {
    pub const NLM_F_REQUEST: u16 = 0x0001;
    pub const NLM_F_ACK: u16 = 0x0004;
    pub const NLM_F_CREATE: u16 = 0x0400;
    pub const NLM_F_EXCL: u16 = 0x0200;
}

/// RTM message types
pub mod rtm {
    pub const RTM_NEWLINK: u16 = 16;
    pub const RTM_NEWADDR: u16 = 20;
    pub const RTM_NEWROUTE: u16 = 24;
    pub const RTM_DELROUTE: u16 = 25;
    pub const RTM_NEWRULE: u16 = 32;
    pub const RTM_DELRULE: u16 = 33;
}

/// Interface address attribute types
pub mod ifa {
    pub const IFA_ADDRESS: u16 = 1;
    pub const IFA_LOCAL: u16 = 2;
}

/// Route attribute types
pub mod rta {
    pub const RTA_TABLE: u16 = 15;
    pub const RTA_OIF: u16 = 4;
    pub const RTA_DST: u16 = 1;
}

/// FIB rule attribute types
pub mod fra {
    pub const FRA_FWMARK: u16 = 10;
    pub const FRA_TABLE: u16 = 15;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msg_construction() {
        let mut msg = MnlMsg::new(rtm::RTM_NEWLINK, flags::NLM_F_REQUEST | flags::NLM_F_ACK, 1);
        assert_eq!(msg.seq(), 1);

        // The initial length should be the nlmsghdr size (16 bytes).
        assert_eq!(msg.len(), 16);

        // Add an extra header (simulating ifinfomsg = 16 bytes).
        #[repr(C)]
        struct FakeIfinfomsg {
            family: u8,
            _pad: u8,
            type_: u16,
            index: i32,
            flags: u32,
            change: u32,
        }
        let hdr: &mut FakeIfinfomsg = msg.put_extra_header();
        hdr.family = libc::AF_UNSPEC as u8;
        hdr.index = 42;
        hdr.flags = libc::IFF_UP as u32;
        hdr.change = libc::IFF_UP as u32;

        // Now length should be 16 (nlmsghdr) + 16 (ifinfomsg) = 32.
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn test_msg_attributes() {
        let mut msg = MnlMsg::new(rtm::RTM_NEWADDR, flags::NLM_F_REQUEST | flags::NLM_F_ACK, 2);

        // Add a u32 attribute — this should increase the length.
        msg.put_u32(ifa::IFA_LOCAL, 0x0100007f); // 127.0.0.1

        // nlmsghdr(16) + rtattr(4) + u32(4) = 24
        assert!(msg.len() > 16);
    }

    #[test]
    fn test_nested_attributes() {
        let mut msg = MnlMsg::new(0, flags::NLM_F_REQUEST, 1);
        let token = msg.nest_start(1);
        msg.put_u32(2, 42);
        msg.nest_end(token);

        // Should have nlmsghdr + nested attr header + inner attr.
        assert!(msg.len() > 16);
    }

    #[test]
    fn test_batch() {
        let msg1 = MnlMsg::new(0, 0, 1);
        let msg2 = MnlMsg::new(0, 0, 2);
        let mut batch = MnlBatch::new();
        batch.push(&msg1);
        batch.push(&msg2);

        assert_eq!(batch.last_seq(), 2);
        assert_eq!(batch.as_bytes().len(), 32); // 2 × 16-byte headers
    }
}
