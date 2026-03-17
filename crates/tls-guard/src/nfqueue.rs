//! NFQUEUE classifier: reads queued packets, parses TLS version,
//! sets conntrack mark accordingly.

use std::io;
use tokio::io::unix::AsyncFd;

use crate::clienthello;

// ---------------------------------------------------------------------------
// libnetfilter_queue FFI
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types)]
type nfq_handle = libc::c_void;
#[allow(non_camel_case_types)]
type nfq_q_handle = libc::c_void;
#[allow(non_camel_case_types)]
type nfq_data = libc::c_void;
#[allow(non_camel_case_types)]
type nfqnl_msg_packet_hdr = PacketHdr;

#[repr(C)]
#[derive(Debug)]
struct PacketHdr {
    packet_id: u32,
    hw_protocol: u16,
    hook: u8,
}

// Verdict constants
const NF_ACCEPT: u32 = 1;
const NF_REPEAT: u32 = 4;

// Queue copy modes
const NFQNL_COPY_PACKET: u8 = 2;

// NFQA config flags
const NFQA_CFG_F_FAIL_OPEN: u32 = 8;

extern "C" {
    fn nfq_open() -> *mut nfq_handle;
    fn nfq_close(h: *mut nfq_handle) -> libc::c_int;
    fn nfq_bind_pf(h: *mut nfq_handle, pf: u16) -> libc::c_int;
    fn nfq_create_queue(
        h: *mut nfq_handle,
        num: u16,
        cb: extern "C" fn(
            qh: *mut nfq_q_handle,
            nfmsg: *mut libc::c_void,
            nfad: *mut nfq_data,
            data: *mut libc::c_void,
        ) -> libc::c_int,
        data: *mut libc::c_void,
    ) -> *mut nfq_q_handle;
    fn nfq_destroy_queue(qh: *mut nfq_q_handle) -> libc::c_int;
    fn nfq_set_mode(qh: *mut nfq_q_handle, mode: u8, range: u32) -> libc::c_int;
    fn nfq_set_queue_flags(qh: *mut nfq_q_handle, mask: u32, flags: u32) -> libc::c_int;
    fn nfq_set_verdict2(
        qh: *mut nfq_q_handle,
        id: u32,
        verdict: u32,
        mark: u32,
        data_len: u32,
        buf: *const u8,
    ) -> libc::c_int;
    fn nfq_get_msg_packet_hdr(nfad: *mut nfq_data) -> *mut nfqnl_msg_packet_hdr;
    fn nfq_get_payload(nfad: *mut nfq_data, data: *mut *mut u8) -> libc::c_int;
    fn nfq_fd(h: *mut nfq_handle) -> libc::c_int;
    fn nfq_handle_packet(h: *mut nfq_handle, buf: *mut u8, len: libc::c_int) -> libc::c_int;
}

// Conntrack marks
const MARK_MODERN: u32 = 0x1;
const MARK_LEGACY: u32 = 0x2;

/// NFQUEUE callback — invoked for each queued packet.
extern "C" fn nfq_callback(
    qh: *mut nfq_q_handle,
    _nfmsg: *mut libc::c_void,
    nfad: *mut nfq_data,
    _data: *mut libc::c_void,
) -> libc::c_int {
    unsafe {
        let ph = nfq_get_msg_packet_hdr(nfad);
        if ph.is_null() {
            return -1;
        }
        let packet_id = u32::from_be((*ph).packet_id);

        // Get the IP packet payload
        let mut payload_ptr: *mut u8 = std::ptr::null_mut();
        let payload_len = nfq_get_payload(nfad, &mut payload_ptr);
        if payload_len < 0 || payload_ptr.is_null() {
            // Can't read payload — pass through
            nfq_set_verdict2(qh, packet_id, NF_ACCEPT, MARK_MODERN, 0, std::ptr::null());
            return 0;
        }

        let ip_data = std::slice::from_raw_parts(payload_ptr, payload_len as usize);

        // Extract TCP payload from the IP packet
        let tcp_payload = extract_tcp_payload(ip_data);

        let (verdict, mark) = match tcp_payload {
            Some(data) if !data.is_empty() => {
                let version = clienthello::parse_tls_version(data);
                if version.is_legacy() {
                    log::info!(
                        "NFQUEUE: legacy {} detected, marking for TPROXY",
                        version.display_name()
                    );
                    (NF_REPEAT, MARK_LEGACY)
                } else if version.is_modern() {
                    log::debug!("NFQUEUE: modern TLS, accepting");
                    (NF_ACCEPT, MARK_MODERN)
                } else {
                    // Non-TLS or unrecognized — pass through
                    log::debug!("NFQUEUE: non-TLS traffic, passing through");
                    (NF_ACCEPT, MARK_MODERN)
                }
            }
            _ => {
                // No TCP payload or empty — pass through
                (NF_ACCEPT, MARK_MODERN)
            }
        };

        nfq_set_verdict2(qh, packet_id, verdict, mark, 0, std::ptr::null());
        0
    }
}

/// Extract TCP payload from an IP packet.
fn extract_tcp_payload(ip_data: &[u8]) -> Option<&[u8]> {
    if ip_data.len() < 20 {
        return None;
    }

    // IP header length (IHL field, lower nibble of first byte, in 32-bit words)
    let ihl = ((ip_data[0] & 0x0F) as usize) * 4;
    if ip_data.len() < ihl + 20 {
        return None;
    }

    // Check protocol is TCP (6)
    if ip_data[9] != 6 {
        return None;
    }

    let tcp = &ip_data[ihl..];
    // TCP data offset (upper nibble of byte 12, in 32-bit words)
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() < data_offset {
        return None;
    }

    Some(&tcp[data_offset..])
}

/// Wrapper around the nfq_handle for safe cleanup.
pub struct NfqHandle {
    h: *mut nfq_handle,
    qh: *mut nfq_q_handle,
}

unsafe impl Send for NfqHandle {}

impl Drop for NfqHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.qh.is_null() {
                nfq_destroy_queue(self.qh);
            }
            if !self.h.is_null() {
                nfq_close(self.h);
            }
        }
    }
}

/// Open and configure the NFQUEUE handle (requires CAP_NET_ADMIN).
///
/// Call this during privileged startup, then pass the result to
/// [`run_nfqueue`] after dropping privileges.
pub fn bind_nfqueue(queue_num: u16) -> io::Result<NfqHandle> {
    let handle = unsafe {
        let h = nfq_open();
        if h.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "nfq_open failed"));
        }

        // Bind to AF_INET
        if nfq_bind_pf(h, libc::AF_INET as u16) < 0 {
            nfq_close(h);
            return Err(io::Error::new(io::ErrorKind::Other, "nfq_bind_pf failed"));
        }

        let qh = nfq_create_queue(
            h,
            queue_num,
            nfq_callback,
            std::ptr::null_mut(),
        );
        if qh.is_null() {
            nfq_close(h);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "nfq_create_queue failed",
            ));
        }

        // Copy entire packet to userspace (up to 65535 bytes)
        if nfq_set_mode(qh, NFQNL_COPY_PACKET, 65535) < 0 {
            nfq_destroy_queue(qh);
            nfq_close(h);
            return Err(io::Error::new(io::ErrorKind::Other, "nfq_set_mode failed"));
        }

        // Enable fail-open so packets pass through if we crash
        let _ = nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);

        NfqHandle { h, qh }
    };

    log::info!("NFQUEUE: bound to queue {}", queue_num);
    Ok(handle)
}

/// Run the NFQUEUE classifier loop (no privileges required).
///
/// Takes a pre-bound [`NfqHandle`] from [`bind_nfqueue`].
pub async fn run_nfqueue(handle: NfqHandle) -> io::Result<()> {
    let fd = unsafe { nfq_fd(handle.h) };
    log::info!("NFQUEUE: processing packets");

    // Wrap the fd for async I/O
    let async_fd = AsyncFd::new(fd)?;

    let mut buf = vec![0u8; 65536];
    loop {
        let mut guard = async_fd.readable().await?;

        let n = unsafe {
            libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(err);
        }

        if n > 0 {
            unsafe {
                nfq_handle_packet(handle.h, buf.as_mut_ptr(), n as libc::c_int);
            }
        }

        guard.clear_ready();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tcp_payload_valid() {
        // Minimal IPv4 header (IHL=5, 20 bytes) + TCP header (data offset=5, 20 bytes) + payload
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 6;    // Protocol = TCP
        // TCP data offset = 5 (20 bytes) in upper nibble of byte 12 of TCP header
        pkt[32] = 0x50; // data_offset = 5 << 4
        // TCP payload starts at byte 40
        pkt[40] = 0x16; // TLS handshake content type
        pkt[41] = 0x03;
        pkt[42] = 0x01; // TLS 1.0
        pkt[43] = 0x00;

        let payload = extract_tcp_payload(&pkt).unwrap();
        assert_eq!(payload.len(), 4);
        assert_eq!(payload[0], 0x16);
    }

    #[test]
    fn test_extract_tcp_payload_too_short() {
        let pkt = vec![0u8; 10];
        assert!(extract_tcp_payload(&pkt).is_none());
    }

    #[test]
    fn test_extract_tcp_payload_not_tcp() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        assert!(extract_tcp_payload(&pkt).is_none());
    }
}
