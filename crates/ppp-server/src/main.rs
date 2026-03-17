//! Minimal PPP server over a Unix socket.
//!
//! Accepts connections from the SIP modem server, runs LCP and
//! IPCP state machines, then bridges IP datagrams to/from a TUN interface.

#![allow(dead_code)]

use clap::Parser;
use log::{debug, error, info, warn};
use md5::{Digest, Md5};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::Sender;

// -------------------------------------------------------------------------
// CLI
// -------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "ppp-server")]
struct Args {
    /// Unix socket path to listen on
    #[arg(long, default_value = "/run/ppp_server.sock")]
    listen: String,

    /// IP address pool CIDR (e.g. 10.0.0.0/24)
    #[arg(long, default_value = "10.0.0.0/24")]
    cidr: String,

    /// TUN interface name
    #[arg(long, default_value = "ppp0")]
    tun_name: String,

    /// Drop privileges to this user after setup (default: nobody)
    #[arg(long, default_value = "nobody")]
    user: String,

    /// PAP/CHAP authentication file (username password per line).
    /// If omitted, no authentication is required.
    #[arg(long)]
    auth_file: Option<String>,
}

// -------------------------------------------------------------------------
// PPP HDLC framing
// -------------------------------------------------------------------------

const FLAG: u8 = 0x7E;
const ESC: u8 = 0x7D;
const XOR: u8 = 0x20;

/// Build a CRC-16/CCITT (PPP FCS) lookup table.
fn crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    for i in 0u16..256 {
        let mut crc = i;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408; // reflected poly 0x1021
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }
    table
}

/// Compute PPP FCS (CRC-16/IBM, reflected, per RFC 1662).
fn crc16_fcs(data: &[u8]) -> u16 {
    static TABLE: std::sync::OnceLock<[u16; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(crc16_table);
    let mut crc = 0xFFFF_u16;
    for &b in data {
        let idx = ((crc ^ b as u16) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF
}

/// Decode one HDLC frame from the raw byte stream.
/// Returns the frame payload (address+control+protocol+data) without FCS,
/// or `None` if the frame is incomplete or FCS fails.
fn hdlc_decode(input: &[u8]) -> Option<Vec<u8>> {
    // Find opening FLAG
    let start = input.iter().position(|&b| b == FLAG)?;
    let rest = &input[start + 1..];

    // Find closing FLAG
    let end = rest.iter().position(|&b| b == FLAG)?;
    let raw = &rest[..end];

    // Unescape
    let mut unescaped = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == ESC {
            i += 1;
            if i < raw.len() {
                unescaped.push(raw[i] ^ XOR);
            }
        } else {
            unescaped.push(raw[i]);
        }
        i += 1;
    }

    // Must have at least address(1) + control(1) + protocol(2) + FCS(2)
    if unescaped.len() < 6 {
        return None;
    }

    // Verify FCS
    let fcs_pos = unescaped.len() - 2;
    let computed = crc16_fcs(&unescaped[..fcs_pos]);
    let received = u16::from_le_bytes([unescaped[fcs_pos], unescaped[fcs_pos + 1]]);
    if computed != received {
        debug!("HDLC FCS mismatch: computed={:#06x} received={:#06x}", computed, received);
        return None;
    }

    Some(unescaped[..fcs_pos].to_vec())
}

/// Encode a PPP frame payload into an HDLC framed byte sequence.
fn hdlc_encode(payload: &[u8]) -> Vec<u8> {
    // Compute FCS over the payload
    let fcs = crc16_fcs(payload);
    let fcs_bytes = fcs.to_le_bytes();

    let mut raw = payload.to_vec();
    raw.extend_from_slice(&fcs_bytes);

    // Escape
    let mut out = Vec::with_capacity(raw.len() * 2 + 2);
    out.push(FLAG);
    for &b in &raw {
        if b == FLAG || b == ESC || b < 0x20 {
            out.push(ESC);
            out.push(b ^ XOR);
        } else {
            out.push(b);
        }
    }
    out.push(FLAG);
    out
}

// -------------------------------------------------------------------------
// PPP protocol numbers
// -------------------------------------------------------------------------

const PPP_ADDR: u8 = 0xFF;
const PPP_CTRL: u8 = 0x03;
const PROTO_LCP: u16 = 0xC021;
const PROTO_IPCP: u16 = 0x8021;
const PROTO_IP: u16 = 0x0021;

// LCP / IPCP codes
const CODE_CONF_REQ: u8 = 1;
const CODE_CONF_ACK: u8 = 2;
const CODE_CONF_NAK: u8 = 3;
const CODE_CONF_REJ: u8 = 4;
const CODE_TERM_REQ: u8 = 5;
const CODE_TERM_ACK: u8 = 6;
const CODE_ECHO_REQ: u8 = 9;
const CODE_ECHO_REP: u8 = 10;

// LCP option types
const LCP_OPT_MRU: u8 = 1;
const LCP_OPT_ACCM: u8 = 2;
const LCP_OPT_AUTH: u8 = 3;
const LCP_OPT_MAGIC: u8 = 5;
const LCP_OPT_PFC: u8 = 7;
const LCP_OPT_ACFC: u8 = 8;

// Authentication protocols
const PROTO_PAP: u16 = 0xC023;
const PROTO_CHAP: u16 = 0xC223;
const PROTO_EAP: u16 = 0xC227;
const CHAP_MD5: u8 = 5;

// PAP codes
const PAP_AUTH_REQ: u8 = 1;
const PAP_AUTH_ACK: u8 = 2;
const PAP_AUTH_NAK: u8 = 3;

// CHAP codes
const CHAP_CHALLENGE: u8 = 1;
const CHAP_RESPONSE: u8 = 2;
const CHAP_SUCCESS: u8 = 3;
const CHAP_FAILURE: u8 = 4;

// IPCP option type for IP address
const IPCP_OPT_ADDR: u8 = 3;

// Maximum incoming buffer before we drop the connection
const MAX_INCOMING: usize = 64 * 1024;

// -------------------------------------------------------------------------
// Authentication credentials
// -------------------------------------------------------------------------

/// Credentials loaded from a simple text file: "username password" per line.
#[derive(Clone)]
struct AuthDb {
    users: HashMap<String, String>,
}

impl AuthDb {
    fn load(path: &str) -> io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut users = HashMap::new();
        for (lineno, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let username = parts.next().unwrap().to_string();
            let password = match parts.next() {
                Some(p) => p.trim().to_string(),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}:{}: missing password", path, lineno + 1),
                    ));
                }
            };
            users.insert(username, password);
        }
        if users.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: no users defined", path),
            ));
        }
        info!("Loaded {} user(s) from {}", users.len(), path);
        Ok(AuthDb { users })
    }

    fn check(&self, username: &str, password: &str) -> bool {
        self.users.get(username).map_or(false, |p| p == password)
    }

    fn get_password(&self, username: &str) -> Option<&str> {
        self.users.get(username).map(|s| s.as_str())
    }
}

// -------------------------------------------------------------------------
// PPP frame helpers
// -------------------------------------------------------------------------

fn ppp_protocol(frame: &[u8]) -> Option<u16> {
    // Frame is: FF 03 [protocol high] [protocol low] [data...]
    if frame.len() < 4 || frame[0] != PPP_ADDR || frame[1] != PPP_CTRL {
        return None;
    }
    Some(u16::from_be_bytes([frame[2], frame[3]]))
}

fn ppp_data(frame: &[u8]) -> &[u8] {
    if frame.len() >= 4 {
        &frame[4..]
    } else {
        &[]
    }
}

/// Build a PPP frame: FF 03 [proto_hi] [proto_lo] [data]
fn ppp_frame(proto: u16, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.push(PPP_ADDR);
    frame.push(PPP_CTRL);
    frame.push((proto >> 8) as u8);
    frame.push(proto as u8);
    frame.extend_from_slice(data);
    frame
}

/// Build an LCP/IPCP packet.
fn cp_packet(code: u8, id: u8, options: &[u8]) -> Vec<u8> {
    let len = (4 + options.len()) as u16;
    let mut pkt = vec![code, id, (len >> 8) as u8, len as u8];
    pkt.extend_from_slice(options);
    pkt
}

/// Build an LCP Echo-Reply.
fn lcp_echo_reply(id: u8, magic: u32) -> Vec<u8> {
    let mut pkt = vec![CODE_ECHO_REP, id, 0, 8];
    pkt.extend_from_slice(&magic.to_be_bytes());
    pkt
}

// -------------------------------------------------------------------------
// TUN device (using raw ioctl)
// -------------------------------------------------------------------------

const TUNSETIFF: u64 = 0x400454ca_u64;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

#[repr(C)]
struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: u16,
    _pad: [u8; 22],
}

/// Open /dev/net/tun and configure a TUN interface.
/// Returns (fd, actual_name).
fn open_tun(name: &str) -> io::Result<(RawFd, String)> {
    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    let raw_fd = fd.into_raw_fd();

    let mut ifr = IfReq {
        ifr_name: [0u8; 16],
        ifr_flags: IFF_TUN | IFF_NO_PI,
        _pad: [0u8; 22],
    };

    // Copy name (up to 15 chars)
    let name_bytes = name.as_bytes();
    let n = name_bytes.len().min(15);
    ifr.ifr_name[..n].copy_from_slice(&name_bytes[..n]);

    let ret = unsafe { libc::ioctl(raw_fd, TUNSETIFF, &ifr as *const IfReq) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(raw_fd) };
        return Err(err);
    }

    // Read back actual name
    let actual_name = std::str::from_utf8(
        &ifr.ifr_name[..ifr.ifr_name.iter().position(|&b| b == 0).unwrap_or(16)],
    )
    .unwrap_or(name)
    .to_string();

    Ok((raw_fd, actual_name))
}

// -------------------------------------------------------------------------
// Netlink: bring up TUN and assign address (via mnl crate)
// -------------------------------------------------------------------------

/// ifinfomsg struct for RTM_NEWLINK.
#[repr(C)]
struct Ifinfomsg {
    ifi_family: u8,
    _ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

/// ifaddrmsg struct for RTM_NEWADDR.
#[repr(C)]
struct Ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// Bring TUN interface up and assign server IP via netlink (no subprocess).
fn netlink_setup_tun(tun_name: &str, server_ip: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
    use mnl::{flags, ifa, rtm, MnlMsg, MnlSocket};

    let if_index = mnl::if_nametoindex(tun_name)?;

    let sock = MnlSocket::open(libc::NETLINK_ROUTE)?;
    sock.bind(0, 0)?;

    // RTM_NEWLINK: bring interface up
    let mut msg = MnlMsg::new(
        rtm::RTM_NEWLINK,
        flags::NLM_F_REQUEST | flags::NLM_F_ACK,
        1,
    );
    let hdr: &mut Ifinfomsg = msg.put_extra_header();
    hdr.ifi_family = libc::AF_UNSPEC as u8;
    hdr.ifi_index = if_index;
    hdr.ifi_flags = libc::IFF_UP as u32;
    hdr.ifi_change = libc::IFF_UP as u32;
    sock.send_recv_ack(&msg)?;
    info!("netlink: {} is up", tun_name);

    // RTM_NEWADDR: assign IP address
    let mut msg = MnlMsg::new(
        rtm::RTM_NEWADDR,
        flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE | flags::NLM_F_EXCL,
        2,
    );
    let addr: &mut Ifaddrmsg = msg.put_extra_header();
    addr.ifa_family = libc::AF_INET as u8;
    addr.ifa_prefixlen = prefix_len;
    addr.ifa_index = if_index as u32;
    msg.put(ifa::IFA_LOCAL, &server_ip.octets());
    msg.put(ifa::IFA_ADDRESS, &server_ip.octets());
    sock.send_recv_ack(&msg)?;
    info!("netlink: {}/{} assigned to {}", server_ip, prefix_len, tun_name);

    Ok(())
}

// -------------------------------------------------------------------------
// IP pool
// -------------------------------------------------------------------------

fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let addr: Ipv4Addr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some((addr, prefix))
}

fn first_host(network: Ipv4Addr) -> Ipv4Addr {
    let n = u32::from(network);
    Ipv4Addr::from(n + 1)
}

fn second_host(network: Ipv4Addr) -> Ipv4Addr {
    let n = u32::from(network);
    Ipv4Addr::from(n + 2)
}

struct IpPool {
    available: VecDeque<Ipv4Addr>,
}

impl IpPool {
    fn new(network: Ipv4Addr, prefix_len: u8) -> Self {
        let net = u32::from(network);
        let size = 1u32 << (32 - prefix_len);
        let broadcast = net | (size - 1);
        let _server = net + 1; // excluded (server IP)
        // Pool: net+2 ..= broadcast-1
        let available = ((net + 2)..broadcast).map(Ipv4Addr::from).collect();
        IpPool { available }
    }

    fn acquire(&mut self) -> Option<Ipv4Addr> {
        self.available.pop_front()
    }

    fn release(&mut self, ip: Ipv4Addr) {
        self.available.push_back(ip);
    }
}

// -------------------------------------------------------------------------
// Systemd socket activation
// -------------------------------------------------------------------------

/// Check for a systemd-provided socket (fd 3).
/// Returns a tokio UnixListener wrapping the socket if LISTEN_PID/LISTEN_FDS are set.
fn maybe_systemd_socket() -> Option<UnixListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if pid != std::process::id() {
        return None;
    }
    let fds: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if fds < 1 {
        return None;
    }
    let raw: RawFd = 3;
    unsafe {
        // Mark close-on-exec
        libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC);
        // Tokio requires O_NONBLOCK
        let flags = libc::fcntl(raw, libc::F_GETFL, 0);
        libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let std_listener = std::os::unix::net::UnixListener::from_raw_fd(raw);
        UnixListener::from_std(std_listener).ok()
    }
}

// Privilege drop functions are in the `privsep` crate.

// -------------------------------------------------------------------------
// PPP connection state machine
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LcpState {
    Closed,
    ReqSent,
    AckReceived,
    AckSent,
    Opened,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpcpState {
    Closed,
    ReqSent,
    Opened,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthState {
    /// No authentication required.
    None,
    /// LCP opened, waiting for PAP Authenticate-Request from peer.
    AwaitingPap,
    /// LCP opened, CHAP Challenge sent, waiting for Response.
    AwaitingChap,
    /// Authentication succeeded.
    Authenticated,
    /// Authentication failed — connection should be torn down.
    Failed,
}

/// Which auth protocol we're negotiating in LCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthProto {
    Pap,
    Chap,
}

struct PppState {
    lcp: LcpState,
    ipcp: IpcpState,
    auth: AuthState,
    /// Which auth protocol we advertised in our LCP Conf-Req.
    auth_proto: Option<AuthProto>,
    lcp_id: u8,
    ipcp_id: u8,
    auth_id: u8,
    server_ip: Ipv4Addr,
    client_ip: Ipv4Addr,
    pool_ip: Ipv4Addr,
    tun_name: String,
    /// CHAP challenge value (random bytes), kept for validating the response.
    chap_challenge: Vec<u8>,
    /// Auth database (None = no auth required).
    auth_db: Option<AuthDb>,
}

impl PppState {
    fn new(
        server_ip: Ipv4Addr,
        client_ip: Ipv4Addr,
        tun_name: String,
        auth_db: Option<AuthDb>,
    ) -> Self {
        let auth_proto = if auth_db.is_some() {
            Some(AuthProto::Pap)
        } else {
            None
        };
        Self {
            lcp: LcpState::Closed,
            ipcp: IpcpState::Closed,
            auth: if auth_db.is_some() {
                AuthState::AwaitingPap // will be set properly when LCP opens
            } else {
                AuthState::None
            },
            auth_proto,
            lcp_id: 0,
            ipcp_id: 0,
            auth_id: 0,
            server_ip,
            client_ip,
            pool_ip: client_ip,
            tun_name,
            chap_challenge: Vec::new(),
            auth_db,
        }
    }

    fn next_lcp_id(&mut self) -> u8 {
        self.lcp_id = self.lcp_id.wrapping_add(1);
        self.lcp_id
    }

    fn next_ipcp_id(&mut self) -> u8 {
        self.ipcp_id = self.ipcp_id.wrapping_add(1);
        self.ipcp_id
    }

    fn next_auth_id(&mut self) -> u8 {
        self.auth_id = self.auth_id.wrapping_add(1);
        self.auth_id
    }

    /// Whether the network phase (IPCP) can proceed.
    fn auth_ok(&self) -> bool {
        matches!(self.auth, AuthState::None | AuthState::Authenticated)
    }

    /// Build the LCP options for our Conf-Req.
    fn our_lcp_options(&self) -> Vec<u8> {
        let mut opts = Vec::new();
        if let Some(proto) = self.auth_proto {
            match proto {
                AuthProto::Pap => {
                    // Option 3, length 4, protocol 0xC023
                    opts.extend_from_slice(&[LCP_OPT_AUTH, 4, 0xC0, 0x23]);
                }
                AuthProto::Chap => {
                    // Option 3, length 5, protocol 0xC223, algorithm 5 (MD5)
                    opts.extend_from_slice(&[LCP_OPT_AUTH, 5, 0xC2, 0x23, CHAP_MD5]);
                }
            }
        }
        opts
    }
}

/// Classify peer's LCP options: split into accepted and rejected.
/// Known harmless options are accepted; unknown options are rejected.
fn classify_lcp_options(opts: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut i = 0;
    while i + 2 <= opts.len() {
        let opt_type = opts[i];
        let opt_len = opts[i + 1] as usize;
        if opt_len < 2 || i + opt_len > opts.len() {
            break;
        }
        match opt_type {
            // Known harmless options — we accept but don't use
            LCP_OPT_MRU | LCP_OPT_ACCM | LCP_OPT_MAGIC | LCP_OPT_PFC | LCP_OPT_ACFC => {
                accepted.extend_from_slice(&opts[i..i + opt_len]);
            }
            // Auth option from peer — we don't require the peer to auth us,
            // so accept whatever they propose (we just won't send credentials).
            LCP_OPT_AUTH => {
                accepted.extend_from_slice(&opts[i..i + opt_len]);
            }
            // Everything else: reject
            _ => {
                rejected.extend_from_slice(&opts[i..i + opt_len]);
            }
        }
        i += opt_len;
    }
    (accepted, rejected)
}

/// Process a received LCP packet, return frames to send.
fn handle_lcp(ppp: &mut PppState, data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() < 4 {
        return vec![];
    }
    let code = data[0];
    let id = data[1];
    let pkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    // Use the length field to bound the options, not the slice length
    let opts_end = pkt_len.min(data.len());
    let opts = if opts_end > 4 { &data[4..opts_end] } else { &[] };

    let mut out = vec![];

    match code {
        CODE_CONF_REQ => {
            let (accepted, rejected) = classify_lcp_options(opts);

            if !rejected.is_empty() {
                // Reject unknown options — peer must re-send without them
                debug!("LCP rejecting {} bytes of unknown options", rejected.len());
                let rej = cp_packet(CODE_CONF_REJ, id, &rejected);
                out.push(hdlc_encode(&ppp_frame(PROTO_LCP, &rej)));
                return out;
            }

            // All options accepted
            let ack = cp_packet(CODE_CONF_ACK, id, &accepted);
            out.push(hdlc_encode(&ppp_frame(PROTO_LCP, &ack)));

            // Send our own Conf-Req if not already done
            if ppp.lcp == LcpState::Closed {
                ppp.lcp = LcpState::AckSent;
                let req_id = ppp.next_lcp_id();
                let our_opts = ppp.our_lcp_options();
                let req = cp_packet(CODE_CONF_REQ, req_id, &our_opts);
                out.push(hdlc_encode(&ppp_frame(PROTO_LCP, &req)));
            } else {
                ppp.lcp = LcpState::Opened;
                info!("LCP opened");
                out.extend(on_lcp_opened(ppp));
            }
        }

        CODE_CONF_ACK => {
            if ppp.lcp == LcpState::ReqSent {
                ppp.lcp = LcpState::AckReceived;
            } else if ppp.lcp == LcpState::AckSent {
                ppp.lcp = LcpState::Opened;
                info!("LCP opened (ack received)");
                out.extend(on_lcp_opened(ppp));
            }
        }

        CODE_CONF_NAK => {
            // Peer NAK'd our options — check if it's about auth protocol
            let mut i = 0;
            while i + 2 <= opts.len() {
                let opt_type = opts[i];
                let opt_len = opts[i + 1] as usize;
                if opt_len < 2 || i + opt_len > opts.len() {
                    break;
                }
                if opt_type == LCP_OPT_AUTH && opt_len >= 4 {
                    let suggested = u16::from_be_bytes([opts[i + 2], opts[i + 3]]);
                    if (suggested == PROTO_CHAP || suggested == PROTO_EAP)
                        && ppp.auth_proto == Some(AuthProto::Pap)
                    {
                        // Peer wants CHAP (or EAP which we don't support — offer CHAP instead)
                        info!("Peer NAK'd PAP, switching to CHAP-MD5");
                        ppp.auth_proto = Some(AuthProto::Chap);
                    } else if suggested == PROTO_PAP
                        && ppp.auth_proto == Some(AuthProto::Chap)
                    {
                        info!("Peer NAK'd CHAP, switching to PAP");
                        ppp.auth_proto = Some(AuthProto::Pap);
                    }
                }
                i += opt_len;
            }
            // Re-send Conf-Req with updated options
            let req_id = ppp.next_lcp_id();
            let our_opts = ppp.our_lcp_options();
            let req = cp_packet(CODE_CONF_REQ, req_id, &our_opts);
            out.push(hdlc_encode(&ppp_frame(PROTO_LCP, &req)));
            // If LCP was already Opened (we already acked peer's ConfReq),
            // set AckSent so peer's ConfAck for our new ConfReq re-opens LCP.
            if ppp.lcp == LcpState::Opened {
                ppp.lcp = LcpState::AckSent;
            } else {
                ppp.lcp = LcpState::ReqSent;
            }
        }

        CODE_CONF_REJ => {
            // Peer rejected our options — check if it's the auth option
            let mut i = 0;
            while i + 2 <= opts.len() {
                let opt_type = opts[i];
                let opt_len = opts[i + 1] as usize;
                if opt_len < 2 || i + opt_len > opts.len() {
                    break;
                }
                if opt_type == LCP_OPT_AUTH {
                    if ppp.auth_db.is_some() {
                        warn!("Peer rejected authentication — disconnecting");
                        ppp.auth = AuthState::Failed;
                        let term_id = ppp.next_lcp_id();
                        let term = cp_packet(CODE_TERM_REQ, term_id, &[]);
                        out.push(hdlc_encode(&ppp_frame(PROTO_LCP, &term)));
                        return out;
                    } else {
                        ppp.auth_proto = None;
                    }
                }
                i += opt_len;
            }
            // Re-send Conf-Req without rejected options
            let req_id = ppp.next_lcp_id();
            let our_opts = ppp.our_lcp_options();
            let req = cp_packet(CODE_CONF_REQ, req_id, &our_opts);
            out.push(hdlc_encode(&ppp_frame(PROTO_LCP, &req)));
            ppp.lcp = LcpState::ReqSent;
        }

        CODE_ECHO_REQ => {
            let magic = if opts.len() >= 4 {
                u32::from_be_bytes([opts[0], opts[1], opts[2], opts[3]])
            } else {
                0
            };
            let reply = lcp_echo_reply(id, magic);
            out.push(hdlc_encode(&ppp_frame(PROTO_LCP, &reply)));
        }

        CODE_TERM_REQ => {
            let ack = cp_packet(CODE_TERM_ACK, id, &[]);
            out.push(hdlc_encode(&ppp_frame(PROTO_LCP, &ack)));
            ppp.lcp = LcpState::Closed;
            info!("LCP terminated by peer");
        }

        _ => {
            debug!("LCP unknown code {}", code);
        }
    }

    out
}

/// Called when LCP reaches Opened state. Starts auth phase or proceeds to IPCP.
fn on_lcp_opened(ppp: &mut PppState) -> Vec<Vec<u8>> {
    match ppp.auth_proto {
        Some(AuthProto::Pap) => {
            info!("Auth phase: waiting for PAP Authenticate-Request");
            ppp.auth = AuthState::AwaitingPap;
            vec![]
        }
        Some(AuthProto::Chap) => {
            info!("Auth phase: sending CHAP Challenge");
            ppp.auth = AuthState::AwaitingChap;
            // Generate 16-byte random challenge
            let mut challenge = vec![0u8; 16];
            let fd = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
            use std::io::Read;
            (&fd).take(16).read_exact(&mut challenge).expect("read urandom");
            ppp.chap_challenge = challenge.clone();

            let id = ppp.next_auth_id();
            let name = b"ppp-server";
            // CHAP packet: code(1) id(1) length(2) value-size(1) value(N) name(M)
            let pkt_len = 4 + 1 + challenge.len() + name.len();
            let mut pkt = vec![CHAP_CHALLENGE, id, (pkt_len >> 8) as u8, pkt_len as u8];
            pkt.push(challenge.len() as u8);
            pkt.extend_from_slice(&challenge);
            pkt.extend_from_slice(name);

            vec![hdlc_encode(&ppp_frame(PROTO_CHAP, &pkt))]
        }
        None => {
            ppp.auth = AuthState::None;
            vec![] // no auth, IPCP will start when peer sends Conf-Req
        }
    }
}

/// Process a received PAP packet, return frames to send.
fn handle_pap(ppp: &mut PppState, data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() < 4 {
        return vec![];
    }
    let code = data[0];
    let id = data[1];
    let pkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let payload_end = pkt_len.min(data.len());
    let payload = if payload_end > 4 { &data[4..payload_end] } else { &[] };

    if code != PAP_AUTH_REQ {
        debug!("PAP unexpected code {}", code);
        return vec![];
    }

    // Parse: peer-id-length(1) peer-id(N) passwd-length(1) passwd(M)
    if payload.is_empty() {
        return vec![pap_response(PAP_AUTH_NAK, id, "Malformed request")];
    }
    let peer_id_len = payload[0] as usize;
    if 1 + peer_id_len + 1 > payload.len() {
        return vec![pap_response(PAP_AUTH_NAK, id, "Malformed request")];
    }
    let peer_id = &payload[1..1 + peer_id_len];
    let passwd_len = payload[1 + peer_id_len] as usize;
    let passwd_start = 1 + peer_id_len + 1;
    if passwd_start + passwd_len > payload.len() {
        return vec![pap_response(PAP_AUTH_NAK, id, "Malformed request")];
    }
    let passwd = &payload[passwd_start..passwd_start + passwd_len];

    let username = String::from_utf8_lossy(peer_id);
    let password = String::from_utf8_lossy(passwd);

    let db = match &ppp.auth_db {
        Some(db) => db,
        None => {
            // No auth required but peer sent PAP anyway — accept
            info!("PAP auth from '{}' (no auth required, accepting)", username);
            ppp.auth = AuthState::Authenticated;
            return vec![pap_response(PAP_AUTH_ACK, id, "Welcome")];
        }
    };

    if db.check(&username, &password) {
        info!("PAP auth succeeded for '{}'", username);
        ppp.auth = AuthState::Authenticated;
        vec![pap_response(PAP_AUTH_ACK, id, "Welcome")]
    } else {
        warn!("PAP auth failed for '{}'", username);
        ppp.auth = AuthState::Failed;
        vec![pap_response(PAP_AUTH_NAK, id, "Authentication failed")]
    }
}

fn pap_response(code: u8, id: u8, msg: &str) -> Vec<u8> {
    let msg_bytes = msg.as_bytes();
    let pkt_len = 4 + 1 + msg_bytes.len();
    let mut pkt = vec![code, id, (pkt_len >> 8) as u8, pkt_len as u8];
    pkt.push(msg_bytes.len() as u8);
    pkt.extend_from_slice(msg_bytes);
    hdlc_encode(&ppp_frame(PROTO_PAP, &pkt))
}

/// Process a received CHAP packet, return frames to send.
fn handle_chap(ppp: &mut PppState, data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() < 4 {
        return vec![];
    }
    let code = data[0];
    let id = data[1];
    let pkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let payload_end = pkt_len.min(data.len());
    let payload = if payload_end > 4 { &data[4..payload_end] } else { &[] };

    if code != CHAP_RESPONSE {
        debug!("CHAP unexpected code {}", code);
        return vec![];
    }

    // Parse: value-size(1) value(N) name(M)
    if payload.is_empty() {
        return vec![chap_response(CHAP_FAILURE, id, "Malformed response")];
    }
    let value_size = payload[0] as usize;
    if 1 + value_size > payload.len() {
        return vec![chap_response(CHAP_FAILURE, id, "Malformed response")];
    }
    let value = &payload[1..1 + value_size];
    let name = &payload[1 + value_size..];
    let username = String::from_utf8_lossy(name);

    let db = match &ppp.auth_db {
        Some(db) => db,
        None => {
            info!("CHAP response from '{}' (no auth required, accepting)", username);
            ppp.auth = AuthState::Authenticated;
            return vec![chap_response(CHAP_SUCCESS, id, "Welcome")];
        }
    };

    let password = match db.get_password(&username) {
        Some(p) => p,
        None => {
            warn!("CHAP auth failed for '{}' (unknown user)", username);
            ppp.auth = AuthState::Failed;
            return vec![chap_response(CHAP_FAILURE, id, "Authentication failed")];
        }
    };

    // CHAP-MD5: expected = MD5(id || password || challenge)
    let mut hasher = Md5::new();
    hasher.update([id]);
    hasher.update(password.as_bytes());
    hasher.update(&ppp.chap_challenge);
    let expected = hasher.finalize();

    if value == expected.as_slice() {
        info!("CHAP auth succeeded for '{}'", username);
        ppp.auth = AuthState::Authenticated;
        vec![chap_response(CHAP_SUCCESS, id, "Welcome")]
    } else {
        warn!("CHAP auth failed for '{}' (bad hash)", username);
        ppp.auth = AuthState::Failed;
        vec![chap_response(CHAP_FAILURE, id, "Authentication failed")]
    }
}

fn chap_response(code: u8, id: u8, msg: &str) -> Vec<u8> {
    let msg_bytes = msg.as_bytes();
    let pkt_len = 4 + msg_bytes.len();
    let mut pkt = vec![code, id, (pkt_len >> 8) as u8, pkt_len as u8];
    pkt.extend_from_slice(msg_bytes);
    hdlc_encode(&ppp_frame(PROTO_CHAP, &pkt))
}

/// Process a received IPCP packet, return frames to send.
fn handle_ipcp(ppp: &mut PppState, data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() < 4 {
        return vec![];
    }
    let code = data[0];
    let id = data[1];
    let opts = if data.len() > 4 { &data[4..] } else { &[] };

    let mut out = vec![];

    match code {
        CODE_CONF_REQ => {
            // Parse client's requested IP address
            let mut client_ip_opt: Option<Ipv4Addr> = None;
            let mut i = 0;
            while i + 2 <= opts.len() {
                let opt_type = opts[i];
                let opt_len = opts[i + 1] as usize;
                if opt_type == IPCP_OPT_ADDR && opt_len == 6 && i + opt_len <= opts.len() {
                    let ip = Ipv4Addr::new(opts[i+2], opts[i+3], opts[i+4], opts[i+5]);
                    client_ip_opt = Some(ip);
                }
                if opt_len < 2 { break; }
                i += opt_len;
            }

            if let Some(client_ip) = client_ip_opt {
                if client_ip == Ipv4Addr::new(0, 0, 0, 0) {
                    // NAK with our suggested client IP
                    let mut nak_opts = vec![IPCP_OPT_ADDR, 6];
                    nak_opts.extend_from_slice(&ppp.pool_ip.octets());
                    let nak = cp_packet(CODE_CONF_NAK, id, &nak_opts);
                    out.push(hdlc_encode(&ppp_frame(PROTO_IPCP, &nak)));
                } else if client_ip != ppp.pool_ip {
                    // Client requested an IP other than what we assigned — NAK
                    // with our pool-assigned IP. Prevents IP hijacking.
                    warn!(
                        "IPCP: client requested {} but pool assigned {} — NAK",
                        client_ip, ppp.pool_ip
                    );
                    let mut nak_opts = vec![IPCP_OPT_ADDR, 6];
                    nak_opts.extend_from_slice(&ppp.pool_ip.octets());
                    let nak = cp_packet(CODE_CONF_NAK, id, &nak_opts);
                    out.push(hdlc_encode(&ppp_frame(PROTO_IPCP, &nak)));
                } else {
                    ppp.client_ip = client_ip;
                    // Ack client's IP
                    let ack = cp_packet(CODE_CONF_ACK, id, opts);
                    out.push(hdlc_encode(&ppp_frame(PROTO_IPCP, &ack)));

                    // Send our own IPCP Conf-Req if not already
                    if ppp.ipcp == IpcpState::Closed {
                        ppp.ipcp = IpcpState::ReqSent;
                        let req_id = ppp.next_ipcp_id();
                        let mut req_opts = vec![IPCP_OPT_ADDR, 6];
                        req_opts.extend_from_slice(&ppp.server_ip.octets());
                        let req = cp_packet(CODE_CONF_REQ, req_id, &req_opts);
                        out.push(hdlc_encode(&ppp_frame(PROTO_IPCP, &req)));
                    } else {
                        ppp.ipcp = IpcpState::Opened;
                        info!("IPCP opened: server={} client={}", ppp.server_ip, ppp.client_ip);
                    }
                }
            } else {
                // Reject unknown options
                let rej = cp_packet(CODE_CONF_REJ, id, opts);
                out.push(hdlc_encode(&ppp_frame(PROTO_IPCP, &rej)));
            }
        }

        CODE_CONF_ACK => {
            if ppp.ipcp == IpcpState::ReqSent {
                ppp.ipcp = IpcpState::Opened;
                info!("IPCP opened (ack): server={} client={}", ppp.server_ip, ppp.client_ip);
            }
        }

        CODE_TERM_REQ => {
            let ack = cp_packet(CODE_TERM_ACK, id, &[]);
            out.push(hdlc_encode(&ppp_frame(PROTO_IPCP, &ack)));
            ppp.ipcp = IpcpState::Closed;
        }

        _ => {
            debug!("IPCP unknown code {}", code);
        }
    }

    out
}

// -------------------------------------------------------------------------
// main
// -------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    // Parse CIDR
    let (network, prefix_len) = parse_cidr(&args.cidr).expect("invalid CIDR");
    assert!(
        prefix_len <= 30,
        "prefix length must be <= 30 (need at least server + 1 client IP)"
    );
    let server_ip = first_host(network);
    let ip_pool = Arc::new(Mutex::new(IpPool::new(network, prefix_len)));

    // Load auth database if configured
    let auth_db = args
        .auth_file
        .as_ref()
        .map(|path| AuthDb::load(path).expect("load auth file"));

    info!(
        "ppp-server: listen={} server={}/{} tun={} auth={}",
        args.listen,
        server_ip,
        prefix_len,
        args.tun_name,
        if auth_db.is_some() { "required" } else { "none" }
    );

    // --- Socket setup ---
    let (listener, socket_activated) = if let Some(l) = maybe_systemd_socket() {
        info!("Using systemd-provided socket (fd 3)");
        (l, true)
    } else {
        // Remove stale socket only if the path exists and is actually a socket
        if let Ok(meta) = std::fs::metadata(&args.listen) {
            if meta.file_type().is_socket() {
                std::fs::remove_file(&args.listen).expect("remove stale socket");
            }
        }
        let listener = UnixListener::bind(&args.listen).expect("bind Unix socket");
        // Allow non-root processes (sip-modem-server) to connect
        std::fs::set_permissions(
            &args.listen,
            std::os::unix::fs::PermissionsExt::from_mode(0o666),
        )
        .expect("chmod socket");
        info!("Listening on {}", args.listen);
        (listener, false)
    };

    // --- Open TUN at startup (needs CAP_NET_ADMIN) ---
    let (tun_raw_fd, actual_tun_name) =
        open_tun(&args.tun_name).expect("open TUN device");
    info!("TUN device opened: {}", actual_tun_name);

    // Hold TUN fd for lifetime of process; non-persistent TUN disappears when last fd closes.
    let tun_owned = unsafe { OwnedFd::from_raw_fd(tun_raw_fd) };
    let tun_startup_fd = tun_owned.as_raw_fd();

    // --- Configure TUN via netlink (needs CAP_NET_ADMIN) ---
    netlink_setup_tun(&actual_tun_name, server_ip, prefix_len)
        .expect("netlink TUN setup");

    // --- Shared dispatch table: client_ip → channel sender ---
    let dispatch: Arc<Mutex<HashMap<Ipv4Addr, Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Global TUN dispatch task: reads TUN, routes packets to per-connection channels by dst IP.
    {
        let dispatch_clone = dispatch.clone();
        let tun_read_fd = unsafe { libc::dup(tun_startup_fd) };
        let mut tun_reader = unsafe { tokio::fs::File::from_raw_fd(tun_read_fd) };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match tun_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // IPv4: version nibble == 4, destination at bytes 16..20
                        if n >= 20 && (buf[0] >> 4) == 4 {
                            let dst = Ipv4Addr::from([buf[16], buf[17], buf[18], buf[19]]);
                            let guard = dispatch_clone.lock().unwrap();
                            if let Some(tx) = guard.get(&dst) {
                                let _ = tx.try_send(buf[..n].to_vec());
                            }
                        }
                    }
                }
            }
        });
    }

    // --- Privilege drop ---
    let (uid, gid) = privsep::lookup_user(&args.user).expect("lookup user for privilege drop");
    if unsafe { libc::getuid() } == uid {
        // Already the target user (e.g. systemd spawned us as nobody).
        // CAP_SETGID/CAP_SETUID may not be present, so skip setgroups/setuid.
        info!("Already running as uid={}, skipping privilege drop", uid);
    } else {
        if !socket_activated {
            // Chown socket so the target user can unlink it later
            let c_path = CString::new(args.listen.as_bytes()).unwrap();
            unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
        }
        privsep::drop_privileges(uid, gid).expect("drop privileges");
        info!("Dropped privileges to uid={} gid={}", uid, gid);
    }
    // TUN and netlink setup are done — drop all remaining capabilities.
    // In the systemd case this drops CAP_NET_ADMIN granted by AmbientCapabilities=.
    // In the non-systemd case setuid already cleared caps, but this is belt-and-suspenders.
    privsep::drop_capabilities(&[privsep::CAP_NET_ADMIN]).expect("drop capabilities");
    info!("Dropped all capabilities");

    // --- Accept loop ---
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let client_ip = {
                    let mut pool = ip_pool.lock().unwrap();
                    pool.acquire()
                };
                match client_ip {
                    None => {
                        warn!("IP pool exhausted, rejecting connection");
                        // stream drops here, closing the connection
                    }
                    Some(client_ip) => {
                        info!("PPP client connected (client_ip={})", client_ip);
                        let tun_name = actual_tun_name.clone();
                        let dispatch_clone = dispatch.clone();
                        let ip_pool_clone = ip_pool.clone();
                        let auth_db_clone = auth_db.clone();
                        tokio::spawn(handle_ppp_connection(
                            stream,
                            server_ip,
                            client_ip,
                            tun_startup_fd,
                            tun_name,
                            dispatch_clone,
                            ip_pool_clone,
                            auth_db_clone,
                        ));
                    }
                }
            }
            Err(e) => {
                error!("accept error: {}", e);
            }
        }
    }

    // Cleanup on exit (unreachable in normal flow, but good practice)
    #[allow(unreachable_code)]
    {
        drop(tun_owned); // closes TUN fd → kernel removes ppp0
        if !socket_activated {
            let _ = std::fs::remove_file(&args.listen);
        }
    }
}

/// Handle a single PPP connection.
async fn handle_ppp_connection(
    mut stream: UnixStream,
    server_ip: Ipv4Addr,
    client_ip: Ipv4Addr,
    tun_startup_fd: RawFd,
    tun_name: String,
    dispatch: Arc<Mutex<HashMap<Ipv4Addr, Sender<Vec<u8>>>>>,
    ip_pool: Arc<Mutex<IpPool>>,
    auth_db: Option<AuthDb>,
) {
    let mut ppp = PppState::new(server_ip, client_ip, tun_name.clone(), auth_db);

    // Register this connection in the dispatch table
    let (tun_pkt_tx, mut tun_pkt_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    {
        let mut guard = dispatch.lock().unwrap();
        guard.insert(client_ip, tun_pkt_tx);
    }

    // Dup TUN fd for writing (each connection gets its own write fd)
    let tun_write_fd = unsafe { libc::dup(tun_startup_fd) };
    let mut tun_writer = unsafe { tokio::fs::File::from_raw_fd(tun_write_fd) };

    // Send initial LCP Configure-Request immediately (don't wait for peer to go first)
    {
        let id = ppp.next_lcp_id();
        let our_opts = ppp.our_lcp_options();
        let req = cp_packet(CODE_CONF_REQ, id, &our_opts);
        let frame = hdlc_encode(&ppp_frame(PROTO_LCP, &req));
        if let Err(e) = stream.write_all(&frame).await {
            error!("Failed to send initial LCP Configure-Request: {}", e);
            cleanup_connection(client_ip, &dispatch, &ip_pool);
            drop(tun_writer);
            return;
        }
        ppp.lcp = LcpState::ReqSent;
        info!("Sent initial LCP Configure-Request (client_ip={})", client_ip);
    }

    // Incoming stream buffer
    let mut incoming: Vec<u8> = Vec::with_capacity(4096);

    loop {
        let mut buf = [0u8; 4096];

        tokio::select! {
            // Data from modem (PPP stream)
            result = stream.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        info!("PPP stream closed (client_ip={})", client_ip);
                        break;
                    }
                    Ok(n) => {
                        incoming.extend_from_slice(&buf[..n]);

                        // Buffer overflow protection
                        if incoming.len() > MAX_INCOMING {
                            warn!("PPP incoming buffer overflow ({}B), dropping connection", incoming.len());
                            break;
                        }

                        process_incoming(&mut incoming, &mut stream, &mut tun_writer, &mut ppp).await;

                        // Auth failure → tear down
                        if ppp.auth == AuthState::Failed {
                            warn!("Authentication failed, closing connection");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("PPP stream read error: {}", e);
                        break;
                    }
                }
            }

            // IP packet from TUN dispatch → wrap in PPP and send to modem
            pkt = tun_pkt_rx.recv() => {
                match pkt {
                    Some(ip_pkt) => {
                        if ppp.ipcp == IpcpState::Opened {
                            let frame = ppp_frame(PROTO_IP, &ip_pkt);
                            let encoded = hdlc_encode(&frame);
                            if let Err(e) = stream.write_all(&encoded).await {
                                error!("PPP stream write error: {}", e);
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }
        }
    }

    // Cleanup
    drop(tun_writer);
    cleanup_connection(client_ip, &dispatch, &ip_pool);
    info!("PPP connection closed (client_ip={})", client_ip);
}

fn cleanup_connection(
    client_ip: Ipv4Addr,
    dispatch: &Arc<Mutex<HashMap<Ipv4Addr, Sender<Vec<u8>>>>>,
    ip_pool: &Arc<Mutex<IpPool>>,
) {
    dispatch.lock().unwrap().remove(&client_ip);
    ip_pool.lock().unwrap().release(client_ip);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- CRC-16/FCS ---

    #[test]
    fn crc16_fcs_deterministic() {
        assert_eq!(crc16_fcs(b"Hello PPP"), crc16_fcs(b"Hello PPP"));
    }

    #[test]
    fn crc16_fcs_mutation_detected() {
        let data = b"Hello PPP";
        let fcs = crc16_fcs(data);
        let mut mutated = data.to_vec();
        mutated[0] ^= 0x01;
        assert_ne!(crc16_fcs(&mutated), fcs);
    }

    #[test]
    fn crc16_fcs_residual() {
        // Appending the FCS (LE) to the data and re-computing should yield a
        // constant "good FCS" residual — same for any valid payload.
        // (0x0F47 is the residual for this reflected CRC-16/CCITT variant with
        // init=0xFFFF and final XOR=0xFFFF.)
        let residual = |data: &[u8]| -> u16 {
            let fcs = crc16_fcs(data);
            let mut buf = data.to_vec();
            buf.extend_from_slice(&fcs.to_le_bytes());
            crc16_fcs(&buf)
        };
        let r1 = residual(b"RFC1662 test frame");
        let r2 = residual(b"Hello PPP world");
        let r3 = residual(b"\xFF\x03\x00\x21\xDE\xAD\xBE\xEF");
        // All three payloads must produce the same constant residual.
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    // --- HDLC framing ---

    #[test]
    fn hdlc_round_trip() {
        let payload: Vec<u8> = vec![0xFF, 0x03, 0x00, 0x21, 0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let encoded = hdlc_encode(&payload);
        let decoded = hdlc_decode(&encoded).expect("hdlc_decode failed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn hdlc_fcs_mismatch_rejected() {
        let payload: Vec<u8> = vec![0xFF, 0x03, 0x00, 0x21, 0x41, 0x42, 0x43];
        let mut encoded = hdlc_encode(&payload);
        // Corrupt a byte in the middle (skip opening FLAG at index 0)
        let mid = encoded.len() / 2;
        encoded[mid] ^= 0x01;
        assert!(hdlc_decode(&encoded).is_none(), "corrupted frame should be rejected");
    }

    #[test]
    fn hdlc_escapes_special_bytes() {
        // A payload containing FLAG and ESC bytes must round-trip correctly.
        let payload = vec![0xFF, 0x03, 0x00, 0x21, FLAG, ESC, 0x7F];
        let encoded = hdlc_encode(&payload);
        // Encoded form should not contain bare FLAG between the framing flags.
        let inner = &encoded[1..encoded.len() - 1];
        assert!(!inner.contains(&FLAG), "unescaped FLAG in frame body");
        assert_eq!(hdlc_decode(&encoded).unwrap(), payload);
    }

    // --- PPP frame helpers ---

    #[test]
    fn ppp_frame_round_trip() {
        let data = b"test payload";
        let frame = ppp_frame(PROTO_LCP, data);
        assert_eq!(ppp_protocol(&frame), Some(PROTO_LCP));
        assert_eq!(ppp_data(&frame), data.as_ref());
    }

    #[test]
    fn ppp_protocol_bad_address_returns_none() {
        let bad = vec![0x00, PPP_CTRL, 0xC0, 0x21]; // wrong address byte
        assert_eq!(ppp_protocol(&bad), None);
    }

    #[test]
    fn ppp_data_short_frame() {
        assert_eq!(ppp_data(&[]), &[] as &[u8]);
        assert_eq!(ppp_data(&[0xFF, 0x03, 0xC0]), &[] as &[u8]);
    }

    // --- cp_packet / lcp_echo_reply ---

    #[test]
    fn cp_packet_length_field() {
        let opts = b"\x01\x04\x05\xD4"; // MRU option
        let pkt = cp_packet(CODE_CONF_REQ, 1, opts);
        assert_eq!(pkt[0], CODE_CONF_REQ);
        assert_eq!(pkt[1], 1);
        let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        assert_eq!(len, 4 + opts.len());
    }

    #[test]
    fn lcp_echo_reply_structure() {
        let reply = lcp_echo_reply(42, 0xDEADBEEF);
        assert_eq!(reply[0], CODE_ECHO_REP);
        assert_eq!(reply[1], 42);
        assert_eq!(u16::from_be_bytes([reply[2], reply[3]]), 8);
        assert_eq!(u32::from_be_bytes([reply[4], reply[5], reply[6], reply[7]]), 0xDEADBEEF);
    }

    // --- IP pool helpers ---

    #[test]
    fn parse_cidr_valid() {
        let (addr, prefix) = parse_cidr("10.0.0.0/24").unwrap();
        assert_eq!(addr, "10.0.0.0".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-a-cidr").is_none());
        assert!(parse_cidr("10.0.0.0").is_none());
        assert!(parse_cidr("10.0.0.0/bad").is_none());
    }

    #[test]
    fn first_second_host_correct() {
        let net = "10.0.0.0".parse::<std::net::Ipv4Addr>().unwrap();
        assert_eq!(first_host(net), "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(second_host(net), "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[test]
    fn ip_pool_acquire_release() {
        let net: Ipv4Addr = "10.0.0.0".parse().unwrap();
        let mut pool = IpPool::new(net, 30); // /30: net=.0, server=.1, pool=.2, broadcast=.3
        // For /30: size=4, broadcast=net|3, pool = net+2..broadcast-1 = .2..2 = just .2
        let ip = pool.acquire();
        assert_eq!(ip, Some("10.0.0.2".parse().unwrap()));
        assert_eq!(pool.acquire(), None); // exhausted

        pool.release(ip.unwrap());
        assert_eq!(pool.acquire(), Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn ip_pool_24_range() {
        let net: Ipv4Addr = "10.0.0.0".parse().unwrap();
        let mut pool = IpPool::new(net, 24);
        // pool = 10.0.0.2 ..= 10.0.0.253 (253 - 2 + 1 = 252 entries? wait..
        // net+2=2, broadcast=255, so 2..255 = 10.0.0.2 ..= 10.0.0.254 = 253 entries
        let first = pool.acquire().unwrap();
        assert_eq!(first, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        // Drain the rest
        let mut count = 1;
        while pool.acquire().is_some() { count += 1; }
        assert_eq!(count, 253);
    }

    // --- LCP state machine (Tier 2 PPP integration) ---

    fn make_ppp() -> PppState {
        PppState::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "ppp0test".to_string(),
            None,
        )
    }

    fn lcp_payload(frame: &[u8]) -> Vec<u8> {
        let decoded = hdlc_decode(frame).expect("hdlc_decode");
        assert_eq!(ppp_protocol(&decoded), Some(PROTO_LCP));
        ppp_data(&decoded).to_vec()
    }

    fn ipcp_payload(frame: &[u8]) -> Vec<u8> {
        let decoded = hdlc_decode(frame).expect("hdlc_decode");
        assert_eq!(ppp_protocol(&decoded), Some(PROTO_IPCP));
        ppp_data(&decoded).to_vec()
    }

    #[test]
    fn lcp_conf_req_triggers_ack_and_our_req() {
        let mut ppp = make_ppp();
        let peer_req = cp_packet(CODE_CONF_REQ, 7, &[]);
        let responses = handle_lcp(&mut ppp, &peer_req);
        assert_eq!(responses.len(), 2, "expected ack + our conf-req");

        let ack = lcp_payload(&responses[0]);
        assert_eq!(ack[0], CODE_CONF_ACK);
        assert_eq!(ack[1], 7); // echo peer's ID

        let our_req = lcp_payload(&responses[1]);
        assert_eq!(our_req[0], CODE_CONF_REQ);
        assert_eq!(ppp.lcp, LcpState::AckSent);
    }

    #[test]
    fn lcp_full_negotiation_reaches_opened() {
        let mut ppp = make_ppp();
        // Step 1: receive peer's conf-req → AckSent
        let peer_req = cp_packet(CODE_CONF_REQ, 1, &[]);
        handle_lcp(&mut ppp, &peer_req);
        assert_eq!(ppp.lcp, LcpState::AckSent);

        // Step 2: receive ack for our conf-req (id = ppp.lcp_id = 1) → Opened
        let ack_for_us = cp_packet(CODE_CONF_ACK, ppp.lcp_id, &[]);
        let responses = handle_lcp(&mut ppp, &ack_for_us);
        assert_eq!(responses.len(), 0);
        assert_eq!(ppp.lcp, LcpState::Opened);
    }

    #[test]
    fn lcp_echo_req_gets_reply() {
        let mut ppp = make_ppp();
        ppp.lcp = LcpState::Opened;
        let magic_bytes = 0xDEADBEEF_u32.to_be_bytes();
        let echo_req = cp_packet(CODE_ECHO_REQ, 5, &magic_bytes);
        let responses = handle_lcp(&mut ppp, &echo_req);
        assert_eq!(responses.len(), 1);
        let reply = lcp_payload(&responses[0]);
        assert_eq!(reply[0], CODE_ECHO_REP);
        assert_eq!(reply[1], 5);
    }

    #[test]
    fn lcp_term_req_closes_and_acks() {
        let mut ppp = make_ppp();
        ppp.lcp = LcpState::Opened;
        let term = cp_packet(CODE_TERM_REQ, 3, &[]);
        let responses = handle_lcp(&mut ppp, &term);
        assert_eq!(responses.len(), 1);
        let ack = lcp_payload(&responses[0]);
        assert_eq!(ack[0], CODE_TERM_ACK);
        assert_eq!(ack[1], 3);
        assert_eq!(ppp.lcp, LcpState::Closed);
    }

    // --- IPCP state machine ---

    #[test]
    fn ipcp_zero_ip_gets_nak_with_suggestion() {
        let mut ppp = make_ppp();
        ppp.lcp = LcpState::Opened;
        // Client requests 0.0.0.0
        let opts = vec![IPCP_OPT_ADDR, 6, 0, 0, 0, 0];
        let req = cp_packet(CODE_CONF_REQ, 1, &opts);
        let responses = handle_ipcp(&mut ppp, &req);
        assert_eq!(responses.len(), 1);
        let nak = ipcp_payload(&responses[0]);
        assert_eq!(nak[0], CODE_CONF_NAK);
        // NAK options should contain our suggested client IP (10.0.0.2)
        assert_eq!(&nak[4..], &[IPCP_OPT_ADDR, 6, 10, 0, 0, 2]);
    }

    #[test]
    fn ipcp_good_ip_when_req_sent_opens() {
        let mut ppp = make_ppp();
        ppp.lcp = LcpState::Opened;
        ppp.ipcp = IpcpState::ReqSent; // already sent our IPCP req

        // Client requests 10.0.0.2
        let opts = vec![IPCP_OPT_ADDR, 6, 10, 0, 0, 2];
        let req = cp_packet(CODE_CONF_REQ, 1, &opts);
        let responses = handle_ipcp(&mut ppp, &req);

        assert!(!responses.is_empty());
        let ack = ipcp_payload(&responses[0]);
        assert_eq!(ack[0], CODE_CONF_ACK);
        assert_eq!(ppp.ipcp, IpcpState::Opened);
    }

    #[test]
    fn ipcp_good_ip_when_closed_sends_our_req() {
        let mut ppp = make_ppp();
        ppp.lcp = LcpState::Opened;
        ppp.ipcp = IpcpState::Closed;

        let opts = vec![IPCP_OPT_ADDR, 6, 10, 0, 0, 2];
        let req = cp_packet(CODE_CONF_REQ, 1, &opts);
        let responses = handle_ipcp(&mut ppp, &req);

        // Ack + our IPCP conf-req
        assert_eq!(responses.len(), 2);
        let ack = ipcp_payload(&responses[0]);
        assert_eq!(ack[0], CODE_CONF_ACK);
        let our_req = ipcp_payload(&responses[1]);
        assert_eq!(our_req[0], CODE_CONF_REQ);
        assert_eq!(ppp.ipcp, IpcpState::ReqSent);
    }

    #[test]
    fn ipcp_wrong_ip_gets_nak() {
        let mut ppp = make_ppp();
        ppp.lcp = LcpState::Opened;

        // Client requests 10.0.0.99 but pool assigned 10.0.0.2
        let opts = vec![IPCP_OPT_ADDR, 6, 10, 0, 0, 99];
        let req = cp_packet(CODE_CONF_REQ, 1, &opts);
        let responses = handle_ipcp(&mut ppp, &req);

        assert_eq!(responses.len(), 1);
        let nak = ipcp_payload(&responses[0]);
        assert_eq!(nak[0], CODE_CONF_NAK);
        // NAK should contain the pool-assigned IP (10.0.0.2)
        assert_eq!(&nak[4..10], &[IPCP_OPT_ADDR, 6, 10, 0, 0, 2]);
    }

    #[test]
    fn lcp_rejects_unknown_options() {
        let mut ppp = make_ppp();
        // Unknown option type 42
        let opts = vec![42, 4, 0x00, 0x00];
        let req = cp_packet(CODE_CONF_REQ, 1, &opts);
        let responses = handle_lcp(&mut ppp, &req);

        assert_eq!(responses.len(), 1);
        let rej = lcp_payload(&responses[0]);
        assert_eq!(rej[0], CODE_CONF_REJ);
        // Rejected options should contain the unknown option
        assert_eq!(&rej[4..8], &[42, 4, 0x00, 0x00]);
    }

    #[test]
    fn lcp_accepts_known_options() {
        let mut ppp = make_ppp();
        // MRU=1500 + Magic=0x12345678
        let opts = vec![
            LCP_OPT_MRU, 4, 0x05, 0xDC,
            LCP_OPT_MAGIC, 6, 0x12, 0x34, 0x56, 0x78,
        ];
        let req = cp_packet(CODE_CONF_REQ, 1, &opts);
        let responses = handle_lcp(&mut ppp, &req);

        // Should get Ack + our Conf-Req
        assert!(responses.len() >= 1);
        let ack = lcp_payload(&responses[0]);
        assert_eq!(ack[0], CODE_CONF_ACK);
    }

    fn make_auth_db() -> AuthDb {
        let mut users = HashMap::new();
        users.insert("dustin".to_string(), "dial1999".to_string());
        users.insert("guest".to_string(), "guest".to_string());
        AuthDb { users }
    }

    fn make_ppp_with_auth() -> PppState {
        PppState::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "ppp0test".to_string(),
            Some(make_auth_db()),
        )
    }

    #[test]
    fn pap_auth_succeeds() {
        let mut ppp = make_ppp_with_auth();
        ppp.lcp = LcpState::Opened;
        ppp.auth = AuthState::AwaitingPap;

        // PAP Authenticate-Request: user="dustin" pass="dial1999"
        let user = b"dustin";
        let pass = b"dial1999";
        let mut payload = vec![user.len() as u8];
        payload.extend_from_slice(user);
        payload.push(pass.len() as u8);
        payload.extend_from_slice(pass);
        let pkt_len = (4 + payload.len()) as u16;
        let mut pkt = vec![PAP_AUTH_REQ, 1, (pkt_len >> 8) as u8, pkt_len as u8];
        pkt.extend_from_slice(&payload);

        let responses = handle_pap(&mut ppp, &pkt);
        assert_eq!(ppp.auth, AuthState::Authenticated);

        let decoded = hdlc_decode(&responses[0]).unwrap();
        assert_eq!(ppp_protocol(&decoded), Some(PROTO_PAP));
        let resp = ppp_data(&decoded);
        assert_eq!(resp[0], PAP_AUTH_ACK);
    }

    #[test]
    fn pap_auth_fails_wrong_password() {
        let mut ppp = make_ppp_with_auth();
        ppp.lcp = LcpState::Opened;
        ppp.auth = AuthState::AwaitingPap;

        let user = b"dustin";
        let pass = b"wrong";
        let mut payload = vec![user.len() as u8];
        payload.extend_from_slice(user);
        payload.push(pass.len() as u8);
        payload.extend_from_slice(pass);
        let pkt_len = (4 + payload.len()) as u16;
        let mut pkt = vec![PAP_AUTH_REQ, 1, (pkt_len >> 8) as u8, pkt_len as u8];
        pkt.extend_from_slice(&payload);

        let responses = handle_pap(&mut ppp, &pkt);
        assert_eq!(ppp.auth, AuthState::Failed);

        let decoded = hdlc_decode(&responses[0]).unwrap();
        let resp = ppp_data(&decoded);
        assert_eq!(resp[0], PAP_AUTH_NAK);
    }

    #[test]
    fn chap_md5_auth_succeeds() {
        let mut ppp = make_ppp_with_auth();
        ppp.lcp = LcpState::Opened;
        ppp.auth = AuthState::AwaitingChap;
        ppp.chap_challenge = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

        // Compute MD5(id=1 || password || challenge)
        let id: u8 = 1;
        let mut hasher = Md5::new();
        hasher.update([id]);
        hasher.update(b"dial1999");
        hasher.update(&ppp.chap_challenge);
        let hash = hasher.finalize();

        // CHAP Response: value-size(1) value(16) name("dustin")
        let name = b"dustin";
        let mut payload = vec![16]; // value-size
        payload.extend_from_slice(&hash);
        payload.extend_from_slice(name);
        let pkt_len = (4 + payload.len()) as u16;
        let mut pkt = vec![CHAP_RESPONSE, id, (pkt_len >> 8) as u8, pkt_len as u8];
        pkt.extend_from_slice(&payload);

        let responses = handle_chap(&mut ppp, &pkt);
        assert_eq!(ppp.auth, AuthState::Authenticated);

        let decoded = hdlc_decode(&responses[0]).unwrap();
        assert_eq!(ppp_protocol(&decoded), Some(PROTO_CHAP));
        let resp = ppp_data(&decoded);
        assert_eq!(resp[0], CHAP_SUCCESS);
    }

    #[test]
    fn chap_md5_auth_fails_wrong_hash() {
        let mut ppp = make_ppp_with_auth();
        ppp.lcp = LcpState::Opened;
        ppp.auth = AuthState::AwaitingChap;
        ppp.chap_challenge = vec![0xAA; 16];

        // Send garbage hash
        let name = b"dustin";
        let mut payload = vec![16];
        payload.extend_from_slice(&[0xDE; 16]); // wrong hash
        payload.extend_from_slice(name);
        let pkt_len = (4 + payload.len()) as u16;
        let mut pkt = vec![CHAP_RESPONSE, 1, (pkt_len >> 8) as u8, pkt_len as u8];
        pkt.extend_from_slice(&payload);

        let responses = handle_chap(&mut ppp, &pkt);
        assert_eq!(ppp.auth, AuthState::Failed);

        let decoded = hdlc_decode(&responses[0]).unwrap();
        let resp = ppp_data(&decoded);
        assert_eq!(resp[0], CHAP_FAILURE);
    }

    #[test]
    fn auth_gates_ipcp() {
        let mut ppp = make_ppp_with_auth();
        ppp.lcp = LcpState::Opened;
        ppp.auth = AuthState::AwaitingPap; // not yet authenticated

        assert!(!ppp.auth_ok());

        // IPCP should be gated
        let opts = vec![IPCP_OPT_ADDR, 6, 0, 0, 0, 0];
        let req = cp_packet(CODE_CONF_REQ, 1, &opts);
        // handle_ipcp would still work, but process_incoming gates it

        // After auth succeeds
        ppp.auth = AuthState::Authenticated;
        assert!(ppp.auth_ok());

        // Now IPCP should proceed
        let responses = handle_ipcp(&mut ppp, &req);
        assert!(!responses.is_empty());
    }

    #[test]
    fn lcp_conf_req_includes_auth_option() {
        let ppp = make_ppp_with_auth();
        let opts = ppp.our_lcp_options();
        // Should contain Auth-Protocol PAP: type=3 len=4 0xC0 0x23
        assert_eq!(&opts, &[LCP_OPT_AUTH, 4, 0xC0, 0x23]);
    }

    #[test]
    fn prefix_len_30_works() {
        // /30 = 4 addresses: .0=net, .1=server, .2=client, .3=broadcast
        let pool = IpPool::new("10.0.0.0".parse().unwrap(), 30);
        assert_eq!(pool.available.len(), 1); // only .2
    }

    #[test]
    fn auth_file_whitespace_variants() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("ppp_test_auth.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "# comment line").unwrap();
            writeln!(f, "alice   secret1").unwrap();       // multiple spaces
            writeln!(f, "bob\t\tpassword2").unwrap();      // tabs
            writeln!(f, "carol \t pass word3").unwrap();    // mixed; password has a space
            writeln!(f, "").unwrap();                       // blank line
        }
        let db = AuthDb::load(path.to_str().unwrap()).unwrap();
        assert!(db.check("alice", "secret1"));
        assert!(db.check("bob", "password2"));
        // "pass word3" — password with internal space is preserved
        assert!(db.check("carol", "pass word3"));
        assert!(!db.check("alice", "wrong"));
        assert!(!db.check("nobody", "x"));
        std::fs::remove_file(&path).unwrap();
    }
}

/// Process buffered incoming data, dispatching complete HDLC frames.
async fn process_incoming(
    buf: &mut Vec<u8>,
    stream: &mut UnixStream,
    tun: &mut tokio::fs::File,
    ppp: &mut PppState,
) {
    // Find and process all complete frames
    loop {
        // Look for FLAG...FLAG sequence
        let start = match buf.iter().position(|&b| b == FLAG) {
            Some(p) => p,
            None => {
                buf.clear();
                break;
            }
        };

        // Skip leading flags
        if start > 0 {
            buf.drain(..start);
        }
        if buf.is_empty() {
            break;
        }

        // Find next FLAG after position 1
        let end = match buf[1..].iter().position(|&b| b == FLAG) {
            Some(p) => p + 1,
            None => break, // incomplete frame, wait for more data
        };

        let frame_raw = buf[..=end].to_vec();
        buf.drain(..end); // keep closing FLAG — it may be the next frame's opening FLAG

        if let Some(frame) = hdlc_decode(&frame_raw) {
            let proto = match ppp_protocol(&frame) {
                Some(p) => p,
                None => {
                    debug!("PPP frame with bad address/control");
                    continue;
                }
            };
            let data = ppp_data(&frame);

            let responses: Vec<Vec<u8>> = match proto {
                PROTO_LCP => {
                    debug!("LCP rx {} bytes", data.len());
                    handle_lcp(ppp, data)
                }
                PROTO_PAP => {
                    debug!("PAP rx {} bytes", data.len());
                    handle_pap(ppp, data)
                }
                PROTO_CHAP => {
                    debug!("CHAP rx {} bytes", data.len());
                    handle_chap(ppp, data)
                }
                PROTO_IPCP => {
                    if !ppp.auth_ok() {
                        debug!("IPCP rx before auth complete — ignoring");
                        vec![]
                    } else {
                        debug!("IPCP rx {} bytes", data.len());
                        handle_ipcp(ppp, data)
                    }
                }
                PROTO_IP => {
                    // Forward IP packet to TUN
                    if ppp.ipcp == IpcpState::Opened {
                        // Validate source IP matches assigned client IP
                        if data.len() >= 16 {
                            let src = Ipv4Addr::from([data[12], data[13], data[14], data[15]]);
                            if src != ppp.client_ip {
                                debug!("Dropping spoofed packet from {} (expected {})", src, ppp.client_ip);
                                continue;
                            }
                        }
                        debug!("IP rx {} bytes -> TUN", data.len());
                        if let Err(e) = tun.write_all(data).await {
                            error!("TUN write error: {}", e);
                        }
                    }
                    vec![]
                }
                _ => {
                    debug!("Unknown PPP protocol 0x{:04X}", proto);
                    vec![]
                }
            };

            for resp in responses {
                if let Err(e) = stream.write_all(&resp).await {
                    error!("PPP response write error: {}", e);
                    return;
                }
            }
        }
    }
}
