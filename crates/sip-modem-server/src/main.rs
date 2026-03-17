//! SIP + RTP modem termination server.
//!
//! Implements a minimal SIP UA over raw UDP (no pjsip dependency) and
//! drives the modem engine with 8 kHz μ-law audio extracted from RTP.
//!
//! Architecture (per-call):
//!   - `sip_task`    — UDP on port 5060, handles SIP messages, owns HashMap<call_id, CallHandle>
//!   - `rtp_recv_task` — per-call UDP on ephemeral port, handles inbound RTP packets
//!   - `rtp_send_task` — per-call UDP, handles outbound RTP packets
//!   - `audio_thread`  — per-call std::thread, 20 ms timer loop, drives modem engine
//!   - `bridge_task`   — per-call, connects to ppp-server Unix socket once in DATA state

use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender};
use log::{debug, error, info, warn};
use modem_engine::{Law, ModemEngine, ModemState};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, UnixStream};

// -------------------------------------------------------------------------
// CLI
// -------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "sip-modem-server")]
struct Args {
    /// Address to bind SIP and RTP sockets
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// SIP UDP port
    #[arg(long, default_value_t = 5060)]
    sip_port: u16,

    /// Unix socket path for the async serial interface (ppp-server, BBS, etc.)
    #[arg(long, default_value = "/run/ppp_server.sock")]
    serial_socket: String,

    /// SIP Basic auth file (username password per line).
    /// If omitted, no authentication is required.
    #[arg(long)]
    auth_file: Option<String>,
}

// -------------------------------------------------------------------------
// SIP Basic authentication
// -------------------------------------------------------------------------

/// Credentials loaded from a simple text file: "username password" per line.
/// Same format as ppp-server's auth file.
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
        info!("Loaded {} SIP user(s) from {}", users.len(), path);
        Ok(AuthDb { users })
    }

    fn check(&self, username: &str, password: &str) -> bool {
        self.users.get(username).map_or(false, |p| p == password)
    }
}

/// Extract Basic auth credentials from an Authorization header value.
/// Expects: `Basic <base64(user:pass)>`
fn parse_basic_auth(header_value: &str) -> Option<(String, String)> {
    let value = header_value.trim();
    let encoded = value.strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = String::from_utf8(
        base64_decode(encoded.trim())
    ).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Minimal base64 decoder (standard alphabet, no padding required).
fn base64_decode(input: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input.bytes().filter_map(val).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() >= 2 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        if chunk.len() >= 3 {
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() >= 4 {
            out.push((chunk[2] << 6) | chunk[3]);
        }
    }
    out
}

// -------------------------------------------------------------------------
// G.711 μ-law codec
// -------------------------------------------------------------------------

/// Encode a linear 16-bit sample to μ-law (G.711 PCMU).
fn ulaw_encode(mut sample: i16) -> u8 {
    const BIAS: i32 = 33;
    const CLIP: i16 = 8159; // (63 << 7) - 33 — max value representable

    let sign: u8 = if sample < 0 {
        sample = -sample;
        0x00 // negative → sign bit clear in inverted form
    } else {
        0x80 // positive → sign bit set in inverted form
    };

    if sample > CLIP {
        sample = CLIP;
    }
    let biased = (sample as i32) + BIAS;

    // Choose the largest exponent N such that biased >= BIAS << N.
    // This is the inverse of the decode formula:
    //   decode(exp, mantissa) = ((mantissa<<1) + BIAS) << exp - BIAS
    let exp = if biased >= (BIAS << 7) { 7 }
              else if biased >= (BIAS << 6) { 6 }
              else if biased >= (BIAS << 5) { 5 }
              else if biased >= (BIAS << 4) { 4 }
              else if biased >= (BIAS << 3) { 3 }
              else if biased >= (BIAS << 2) { 2 }
              else if biased >= (BIAS << 1) { 1 }
              else { 0 };

    // mantissa = ((biased >> exp) - BIAS) / 2, clamped to 0-15
    let mantissa = (((biased >> exp) - BIAS) >> 1).clamp(0, 15) as u8;

    !(sign | ((exp as u8) << 4) | mantissa)
}

/// Decode a μ-law byte to a linear 16-bit sample (G.711 PCMU).
fn ulaw_decode(byte: u8) -> i16 {
    let b = !byte;
    let sign = b & 0x80;
    let exponent = ((b >> 4) & 0x07) as i32;
    let mantissa = (b & 0x0F) as i32;
    let mut sample = ((mantissa << 1) + 33) << exponent;
    sample -= 33;
    if sign == 0 {
        -(sample as i16)
    } else {
        sample as i16
    }
}

// -------------------------------------------------------------------------
// RTP header
// -------------------------------------------------------------------------

const RTP_HEADER_LEN: usize = 12;

struct RtpHeader {
    payload_type: u8,
    _seq: u16,
    _timestamp: u32,
    _ssrc: u32,
}

fn parse_rtp_header(buf: &[u8]) -> Option<RtpHeader> {
    if buf.len() < RTP_HEADER_LEN {
        return None;
    }
    // Version must be 2
    if (buf[0] >> 6) != 2 {
        return None;
    }
    let payload_type = buf[1] & 0x7F;
    let seq = u16::from_be_bytes([buf[2], buf[3]]);
    let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    Some(RtpHeader {
        payload_type,
        _seq: seq,
        _timestamp: timestamp,
        _ssrc: ssrc,
    })
}

fn build_rtp_packet(seq: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(RTP_HEADER_LEN + payload.len());
    pkt.push(0x80); // V=2, P=0, X=0, CC=0
    pkt.push(0x00); // M=0, PT=0 (PCMU)
    pkt.push((seq >> 8) as u8);
    pkt.push(seq as u8);
    pkt.push((timestamp >> 24) as u8);
    pkt.push((timestamp >> 16) as u8);
    pkt.push((timestamp >> 8) as u8);
    pkt.push(timestamp as u8);
    pkt.push((ssrc >> 24) as u8);
    pkt.push((ssrc >> 16) as u8);
    pkt.push((ssrc >> 8) as u8);
    pkt.push(ssrc as u8);
    pkt.extend_from_slice(payload);
    pkt
}

// -------------------------------------------------------------------------
// SIP parsing helpers
// -------------------------------------------------------------------------

fn sip_header<'a>(msg: &'a str, name: &str) -> Option<&'a str> {
    let lower_name = name.to_lowercase();
    for line in msg.lines() {
        let lower_line = line.to_lowercase();
        if lower_line.starts_with(&lower_name) {
            if let Some(rest) = line.get(name.len()..) {
                let rest = rest.trim_start_matches(':').trim();
                return Some(rest);
            }
        }
    }
    None
}

fn sip_method(msg: &str) -> Option<&str> {
    msg.split_whitespace().next()
}


/// Extract remote RTP port from SDP body.
fn sdp_rtp_port(sdp: &str) -> Option<u16> {
    for line in sdp.lines() {
        if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

// -------------------------------------------------------------------------
// SIP response builder
// -------------------------------------------------------------------------

fn build_sip_response(
    status: u32,
    reason: &str,
    call_id: &str,
    from: &str,
    to: &str,
    cseq: &str,
    via: &str,
    extra: &str,
) -> String {
    format!(
        "SIP/2.0 {status} {reason}\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Content-Length: {clen}\r\n\
         {extra}\r\n",
        status = status,
        reason = reason,
        via = via,
        from = from,
        to = to,
        call_id = call_id,
        cseq = cseq,
        extra = extra,
        clen = 0,
    )
}

fn build_sip_bye(
    call_id: &str,
    from: &str,
    to: &str,
    remote_addr: SocketAddr,
    local_ip: &str,
    sip_port: u16,
) -> String {
    // As UAS we're the ones initiating this BYE, so From/To are swapped vs the
    // INVITE: our To (with our tag) becomes From, their From becomes To.
    let branch = format!("z9hG4bK{:08x}", rand_u32());
    format!(
        "BYE sip:{remote} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local_ip}:{sip_port};branch={branch}\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 BYE\r\n\
         Content-Length: 0\r\n\
         \r\n",
        remote = remote_addr,
        local_ip = local_ip,
        sip_port = sip_port,
        branch = branch,
        from = from,
        to = to,
        call_id = call_id,
    )
}

fn build_sip_200_invite(
    call_id: &str,
    from: &str,
    to: &str,
    cseq: &str,
    via: &str,
    local_ip: &str,
    rtp_port: u16,
    local_tag: &str,
) -> String {
    // Add To tag if not already present (required by RFC 3261 for final responses)
    let to_tagged = if to.contains("tag=") {
        to.to_string()
    } else {
        format!("{};tag={}", to, local_tag)
    };

    let sdp = format!(
        "v=0\r\no=- 0 0 IN IP4 {local_ip}\r\ns=-\r\nc=IN IP4 {local_ip}\r\nt=0 0\r\nm=audio {rtp_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=ptime:20\r\na=sendrecv\r\n",
        local_ip = local_ip,
        rtp_port = rtp_port,
    );

    format!(
        "SIP/2.0 200 OK\r\nVia: {via}\r\nFrom: {from}\r\nTo: {to_tagged}\r\nCall-ID: {call_id}\r\nCSeq: {cseq}\r\nContact: <sip:{local_ip}:{sip_port}>\r\nContent-Type: application/sdp\r\nContent-Length: {clen}\r\n\r\n{sdp}",
        via = via,
        from = from,
        to_tagged = to_tagged,
        call_id = call_id,
        cseq = cseq,
        local_ip = local_ip,
        sip_port = 5060,
        clen = sdp.len(),
        sdp = sdp,
    )
}

// -------------------------------------------------------------------------
// Audio thread channels
// -------------------------------------------------------------------------

/// Samples from RTP → audio thread
type RtpRxSender = Sender<Vec<i16>>;
type RtpRxReceiver = Receiver<Vec<i16>>;

/// Samples from audio thread → RTP TX
type RtpTxSender = Sender<Vec<i16>>;
type RtpTxReceiver = Receiver<Vec<i16>>;

/// Signal to audio thread
#[derive(Debug, Clone, Copy)]
enum AudioSignal {
    CallConnected,
    #[allow(dead_code)]
    CallDisconnected,
}

type AudioSignalSender = Sender<AudioSignal>;
type AudioSignalReceiver = Receiver<AudioSignal>;

// -------------------------------------------------------------------------
// Per-call handle
// -------------------------------------------------------------------------

struct CallHandle {
    /// Dropping this signals the audio thread to exit (Disconnected on channel close)
    audio_sig: AudioSignalSender,
    rtp_rx_task: tokio::task::JoinHandle<()>,
    rtp_tx_task: tokio::task::JoinHandle<()>,
    // Metadata for sending BYE
    call_id: String,
    sip_from_bye: String, // our To+tag → From in BYE
    sip_to_bye: String,   // their From → To in BYE
    remote_addr: SocketAddr,
}

impl Drop for CallHandle {
    fn drop(&mut self) {
        self.rtp_rx_task.abort();
        self.rtp_tx_task.abort();
        // audio_sig drop signals audio thread to exit via Disconnected channel error
    }
}

// -------------------------------------------------------------------------
// main
// -------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    info!(
        "sip-modem-server starting: SIP={}:{} serial-socket={}",
        args.bind, args.sip_port, args.serial_socket
    );

    // TODO(multi-homed): On a multi-homed host, use IP_PKTINFO / recvmsg with
    // IP_RECVPKTINFO to determine which local IP the SIP INVITE actually arrived on,
    // then bind the ephemeral RTP socket to <that-ip>:0 and advertise the same IP
    // in the SDP c= line.  The current 8.8.8.8-probe approach correctly discovers
    // the right outbound IP on a single-NIC machine but would pick the wrong
    // interface on a multi-homed one.
    let local_ip = {
        let bind_ip: IpAddr = args.bind.parse().unwrap_or("0.0.0.0".parse().unwrap());
        if bind_ip.is_unspecified() {
            // Connect a UDP socket to an external address to discover the
            // local outbound IP without actually sending any packets.
            let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            probe.connect("8.8.8.8:53").unwrap();
            probe.local_addr().unwrap().ip().to_string()
        } else {
            bind_ip.to_string()
        }
    };
    info!("Local IP for SDP/Contact: {}", local_ip);

    let sip_bind = format!("{}:{}", args.bind, args.sip_port);

    let sip_sock = UdpSocket::bind(&sip_bind)
        .await
        .expect("bind SIP socket");
    info!("SIP listening on {}", sip_bind);

    let socket_path = args.serial_socket.clone();

    // Load SIP auth database if configured
    let auth_db = match &args.auth_file {
        Some(path) => {
            let db = AuthDb::load(path).expect("failed to load SIP auth file");
            info!("SIP Basic auth enabled");
            Some(db)
        }
        None => {
            info!("SIP auth disabled (no --auth-file)");
            None
        }
    };

    // hangup channel: audio threads send Call-ID here when bridge closes
    let (hangup_tx, hangup_rx) = tokio::sync::mpsc::channel::<String>(16);

    // ---- SIP task ----
    sip_task(
        sip_sock,
        local_ip,
        args.sip_port,
        socket_path,
        hangup_tx,
        hangup_rx,
        auth_db,
    )
    .await;
}

// -------------------------------------------------------------------------
// RTP receive task (per-call)
// -------------------------------------------------------------------------

async fn rtp_recv_task(
    sock: Arc<UdpSocket>,
    tx: RtpRxSender,
    remote: Arc<Mutex<Option<SocketAddr>>>,
    pkt_counter: Arc<AtomicU32>,
) {
    let mut buf = [0u8; 2048];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                // Record remote address for symmetric RTP.
                // Update on every packet so that a new call from a
                // different source port is picked up immediately.
                {
                    let mut r = remote.lock().unwrap();
                    if *r != Some(addr) {
                        info!("RTP remote: {}", addr);
                        *r = Some(addr);
                    }
                }

                let pkt = &buf[..len];
                if let Some(hdr) = parse_rtp_header(pkt) {
                    if hdr.payload_type == 0 && len > RTP_HEADER_LEN {
                        // PCMU payload → linear PCM
                        let payload = &pkt[RTP_HEADER_LEN..];

                        // Diagnostic: log first 20 packets per call.
                        let n = pkt_counter.fetch_add(1, Ordering::Relaxed) + 1;
                        if n <= 20 {
                            let peak_linear = payload
                                .iter()
                                .map(|&b| ulaw_decode(b).unsigned_abs())
                                .max()
                                .unwrap_or(0);
                            info!(
                                "RTP pkt #{}: {} bytes, ulaw[0..4]={:02X} {:02X} {:02X} {:02X}, peak_linear={}",
                                n,
                                payload.len(),
                                payload.get(0).copied().unwrap_or(0xFF),
                                payload.get(1).copied().unwrap_or(0xFF),
                                payload.get(2).copied().unwrap_or(0xFF),
                                payload.get(3).copied().unwrap_or(0xFF),
                                peak_linear
                            );
                        } else if n == 21 {
                            info!("RTP diagnostic: first 20 packets logged, suppressing further raw dumps");
                        }

                        let samples: Vec<i16> =
                            payload.iter().map(|&b| ulaw_decode(b)).collect();
                        let _ = tx.try_send(samples);
                    } else {
                        let n = pkt_counter.load(Ordering::Relaxed);
                        if n <= 5 {
                            info!("RTP pkt #{}: PT={} (not PCMU), len={}", n, hdr.payload_type, len);
                        }
                    }
                }
            }
            Err(e) => {
                error!("RTP recv error: {}", e);
                break;
            }
        }
    }
}

// -------------------------------------------------------------------------
// RTP send task (per-call)
// -------------------------------------------------------------------------

async fn rtp_send_task(
    sock: Arc<UdpSocket>,
    rx: RtpTxReceiver,
    remote: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut seq: u16 = rand_u16();
    let mut ts: u32 = rand_u32();
    let ssrc: u32 = rand_u32();

    loop {
        let samples = match rx.try_recv() {
            Ok(s) => s,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };

        let remote_addr = {
            let r = remote.lock().unwrap();
            *r
        };

        if let Some(addr) = remote_addr {
            let payload: Vec<u8> = samples.iter().map(|&s| ulaw_encode(s)).collect();
            let pkt = build_rtp_packet(seq, ts, ssrc, &payload);
            if let Err(e) = sock.send_to(&pkt, addr).await {
                debug!("RTP send error: {}", e);
            }
            seq = seq.wrapping_add(1);
            ts = ts.wrapping_add(160);
        }
    }
}

// -------------------------------------------------------------------------
// SIP task
// -------------------------------------------------------------------------

async fn sip_task(
    sock: UdpSocket,
    local_ip: String,
    sip_port: u16,
    socket_path: String,
    hangup_tx: tokio::sync::mpsc::Sender<String>,
    mut hangup_rx: tokio::sync::mpsc::Receiver<String>,
    auth_db: Option<AuthDb>,
) {
    let mut calls: HashMap<String, CallHandle> = HashMap::new();
    let mut buf = [0u8; 8192];

    loop {
        tokio::select! {
            result = sock.recv_from(&mut buf) => {
                let (len, remote) = match result {
                    Ok(x) => x,
                    Err(e) => {
                        error!("SIP recv error: {}", e);
                        continue;
                    }
                };

                let msg = match std::str::from_utf8(&buf[..len]) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                debug!("SIP<< {}", remote);

                let method = match sip_method(msg) {
                    Some(m) => m.to_string(),
                    None => continue,
                };

                let call_id = sip_header(msg, "Call-ID").unwrap_or("").to_string();
                let from = sip_header(msg, "From").unwrap_or("").to_string();
                let to = sip_header(msg, "To").unwrap_or("").to_string();
                let cseq = sip_header(msg, "CSeq").unwrap_or("").to_string();
                let via = sip_header(msg, "Via").unwrap_or("").to_string();

                match method.as_str() {
                    "REGISTER" => {
                        let resp = build_sip_response(
                            200, "OK", &call_id, &from, &to, &cseq, &via, "",
                        );
                        let _ = sock.send_to(resp.as_bytes(), remote).await;
                        info!("REGISTER from {} -> 200 OK", remote);
                    }

                    "INVITE" => {
                        // Check Basic auth if configured
                        if let Some(ref db) = auth_db {
                            let authorized = sip_header(msg, "Authorization")
                                .and_then(parse_basic_auth)
                                .map_or(false, |(user, pass)| db.check(&user, &pass));
                            if !authorized {
                                let resp = build_sip_response(
                                    401, "Unauthorized",
                                    &call_id, &from, &to, &cseq, &via,
                                    "WWW-Authenticate: Basic realm=\"cybercafe\"\r\n",
                                );
                                let _ = sock.send_to(resp.as_bytes(), remote).await;
                                warn!("INVITE from {} -> 401 Unauthorized", remote);
                                continue;
                            }
                        }

                        // Extract remote RTP port from SDP
                        let body_start = msg.find("\r\n\r\n").map(|p| p + 4).unwrap_or(msg.len());
                        let body = &msg[body_start..];
                        let _remote_rtp = sdp_rtp_port(body);

                        // Generate a local tag for the To header
                        let local_tag = format!("{:08x}", rand_u32());
                        let to_tagged = format!("{};tag={}", to, local_tag);

                        // Bind ephemeral UDP socket for this call's RTP
                        let rtp_sock = match UdpSocket::bind("0.0.0.0:0").await {
                            Ok(s) => s,
                            Err(e) => {
                                error!("Failed to bind RTP socket: {}", e);
                                let resp = build_sip_response(
                                    500, "Server Internal Error",
                                    &call_id, &from, &to, &cseq, &via, "",
                                );
                                let _ = sock.send_to(resp.as_bytes(), remote).await;
                                continue;
                            }
                        };
                        let rtp_port = rtp_sock.local_addr().unwrap().port();
                        info!("Allocated RTP port {} for call {}", rtp_port, call_id);

                        // Per-call channels
                        let (rtp_rx_tx, rtp_rx_rx): (RtpRxSender, RtpRxReceiver) = bounded(32);
                        let (rtp_tx_tx, rtp_tx_rx): (RtpTxSender, RtpTxReceiver) = bounded(32);
                        let (audio_sig_tx, audio_sig_rx): (AudioSignalSender, AudioSignalReceiver) = bounded(4);

                        // Per-call RTP packet counter and remote address
                        let pkt_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
                        let rtp_remote: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

                        // Share socket across recv/send tasks
                        let rtp_sock = Arc::new(rtp_sock);
                        let rtp_sock_recv = Arc::clone(&rtp_sock);
                        let rtp_sock_send = Arc::clone(&rtp_sock);
                        let rtp_remote_recv = Arc::clone(&rtp_remote);
                        let rtp_remote_send = Arc::clone(&rtp_remote);

                        // Spawn per-call RTP tasks
                        let rx_task = tokio::spawn(rtp_recv_task(
                            rtp_sock_recv,
                            rtp_rx_tx,
                            rtp_remote_recv,
                            Arc::clone(&pkt_counter),
                        ));
                        let tx_task = tokio::spawn(rtp_send_task(
                            rtp_sock_send,
                            rtp_tx_rx,
                            rtp_remote_send,
                        ));

                        // Spawn per-call audio thread
                        let call_id_audio = call_id.clone();
                        let call_hangup_tx = hangup_tx.clone();
                        let sp = socket_path.clone();
                        std::thread::spawn(move || {
                            audio_thread_fn(
                                rtp_rx_rx,
                                rtp_tx_tx,
                                audio_sig_rx,
                                sp,
                                call_id_audio,
                                call_hangup_tx,
                            )
                        });

                        let handle = CallHandle {
                            audio_sig: audio_sig_tx,
                            rtp_rx_task: rx_task,
                            rtp_tx_task: tx_task,
                            call_id: call_id.clone(),
                            sip_from_bye: to_tagged.clone(),
                            sip_to_bye: from.clone(),
                            remote_addr: remote,
                        };
                        calls.insert(call_id.clone(), handle);

                        // 100 Trying
                        let trying = build_sip_response(
                            100, "Trying", &call_id, &from, &to, &cseq, &via, "",
                        );
                        let _ = sock.send_to(trying.as_bytes(), remote).await;

                        // 180 Ringing
                        let ringing = build_sip_response(
                            180, "Ringing", &call_id, &from, &to, &cseq, &via, "",
                        );
                        let _ = sock.send_to(ringing.as_bytes(), remote).await;

                        // Small delay then 200 OK with SDP
                        tokio::time::sleep(Duration::from_millis(200)).await;

                        let ok = build_sip_200_invite(
                            &call_id, &from, &to, &cseq, &via,
                            &local_ip, rtp_port, &local_tag,
                        );
                        let _ = sock.send_to(ok.as_bytes(), remote).await;
                        info!("INVITE from {} -> 200 OK (RTP port {})", remote, rtp_port);
                    }

                    "CANCEL" => {
                        // RFC 3261: respond 200 OK to the CANCEL itself
                        let resp = build_sip_response(
                            200, "OK", &call_id, &from, &to, &cseq, &via, "",
                        );
                        let _ = sock.send_to(resp.as_bytes(), remote).await;

                        // Then send 487 Request Terminated for the original INVITE
                        if let Some(handle) = calls.get(&call_id) {
                            let terminated = build_sip_response(
                                487, "Request Terminated",
                                &call_id, &handle.sip_to_bye, &handle.sip_from_bye,
                                &cseq, &via, "",
                            );
                            let _ = sock.send_to(terminated.as_bytes(), remote).await;
                        }
                        calls.remove(&call_id); // Drop handles cleanup
                        info!("CANCEL from {} -> 200 OK + 487", remote);
                    }

                    "ACK" => {
                        info!("ACK from {}", remote);
                        if let Some(handle) = calls.get(&call_id) {
                            let _ = handle.audio_sig.try_send(AudioSignal::CallConnected);
                        }
                    }

                    "BYE" => {
                        let resp = build_sip_response(
                            200, "OK", &call_id, &from, &to, &cseq, &via, "",
                        );
                        let _ = sock.send_to(resp.as_bytes(), remote).await;
                        info!("BYE from {}", remote);
                        calls.remove(&call_id); // Drop handles cleanup
                    }

                    "OPTIONS" => {
                        let resp = build_sip_response(
                            200, "OK", &call_id, &from, &to, &cseq, &via,
                            "Allow: INVITE, ACK, BYE, OPTIONS, REGISTER\r\n",
                        );
                        let _ = sock.send_to(resp.as_bytes(), remote).await;
                    }

                    _ => {
                        debug!("Unhandled SIP method: {}", method);
                    }
                }
            }

            Some(call_id) = hangup_rx.recv() => {
                // Bridge terminated — send SIP BYE and remove call
                if let Some(handle) = calls.remove(&call_id) {
                    let bye = build_sip_bye(
                        &handle.call_id,
                        &handle.sip_from_bye,
                        &handle.sip_to_bye,
                        handle.remote_addr,
                        &local_ip,
                        sip_port,
                    );
                    info!("Sending BYE to {} (bridge terminated for call {})", handle.remote_addr, call_id);
                    let _ = sock.send_to(bye.as_bytes(), handle.remote_addr).await;
                }
            }
        }
    }
}

// -------------------------------------------------------------------------
// Audio thread (per-call)
// -------------------------------------------------------------------------

fn audio_thread_fn(
    rtp_rx: RtpRxReceiver,
    rtp_tx: RtpTxSender,
    audio_sig: AudioSignalReceiver,
    socket_path: String,
    call_id: String,
    call_hangup_tx: tokio::sync::mpsc::Sender<String>,
) {
    let mut engine = ModemEngine::new();
    let mut connected = false;
    let mut rx_buf: Vec<i16> = Vec::with_capacity(320);

    // Bridge (PPP server) I/O channels — created once at thread start
    // (each call has its own audio thread, so no need to recreate between calls)
    let (bridge_tx_send, bridge_tx_recv_opt_init): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(64);
    let (bridge_rx_send, bridge_rx_recv): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(64);
    let (bridge_done_tx, bridge_done_rx): (Sender<()>, Receiver<()>) = bounded(1);
    let mut bridge_tx_recv_opt: Option<Receiver<Vec<u8>>> = Some(bridge_tx_recv_opt_init);
    let mut bridge_connected = false;

    // T3: training timeout and RTP carrier-loss watchdogs
    let mut training_started_at: Option<Instant> = None;
    let mut rtp_last_received: Instant = Instant::now();

    loop {
        // Check for signals (non-blocking)
        match audio_sig.try_recv() {
            Ok(sig) => match sig {
                AudioSignal::CallConnected => {
                    if !connected {
                        // Discard audio that queued during SIP negotiation — it's
                        // comfort noise / ringback, not modem signal, and feeding it
                        // to spandsp at super-real-time would misfire training timers.
                        while rtp_rx.try_recv().is_ok() {}
                        rx_buf.clear();
                        info!("Audio [{}]: call connected, starting modem (answerer)", call_id);
                        engine.on_sip_connected(false, Law::Ulaw);
                        connected = true;
                        rtp_last_received = Instant::now(); // reset watchdog
                    }
                }
                AudioSignal::CallDisconnected => {
                    if connected {
                        info!("Audio [{}]: call disconnected", call_id);
                        engine.on_sip_disconnected();
                    }
                    // Exit the thread — this call is done
                    break;
                }
            },
            Err(crossbeam_channel::TryRecvError::Empty) => {}
            Err(crossbeam_channel::TryRecvError::Disconnected) => {
                // CallHandle dropped (BYE or CANCEL processed by SIP task)
                info!("Audio [{}]: signal channel disconnected, exiting", call_id);
                break;
            }
        }

        // T3: track training start time and check timeout (30 s)
        if connected {
            if engine.state() == ModemState::Training && training_started_at.is_none() {
                training_started_at = Some(Instant::now());
            } else if engine.state() != ModemState::Training {
                training_started_at = None;
            }
        } else {
            training_started_at = None;
        }
        if let Some(started) = training_started_at {
            if started.elapsed() > Duration::from_secs(30) {
                warn!("Audio [{}]: training timeout (30 s), hanging up", call_id);
                engine.on_sip_disconnected();
                let _ = call_hangup_tx.blocking_send(call_id.clone());
                break;
            }
        }

        // Drain all available RTP frames into rx_buf; track when audio last arrived
        while let Ok(samples) = rtp_rx.try_recv() {
            rx_buf.extend_from_slice(&samples);
            rtp_last_received = Instant::now();
        }

        // T3: RTP carrier-loss watchdog — no audio for 10 s while connected
        if connected && rtp_last_received.elapsed() > Duration::from_secs(10) {
            warn!("Audio [{}]: no RTP for 10 s, treating as carrier loss, hanging up", call_id);
            engine.on_sip_disconnected();
            let _ = call_hangup_tx.blocking_send(call_id.clone());
            break;
        }

        // Process exactly one 20 ms frame per tick to keep spandsp at real-time pace.
        // Feeding multiple buffered frames in one tight loop would over-clock its
        // timing-sensitive training state machine.
        if rx_buf.len() >= 160 {
            let frame: Vec<i16> = rx_buf.drain(..160).collect();
            if connected {
                engine.rx_audio(&frame);
            }
        }

        // Generate TX audio
        if connected {
            let mut tx_buf = vec![0i16; 160];
            engine.tx_audio(&mut tx_buf);
            let _ = rtp_tx.try_send(tx_buf);
        }

        // Bridge management — connect to PPP server when we reach DATA state
        if connected && !bridge_connected && engine.state() == ModemState::Data {
            bridge_connected = true; // set immediately to prevent re-entry
            info!("Audio [{}]: modem in DATA state, connecting to PPP bridge: {}", call_id, socket_path);
            if let Some(btr) = bridge_tx_recv_opt.take() {
                let sp = socket_path.clone();
                let brs = bridge_rx_send.clone();
                let done_tx = bridge_done_tx.clone();
                std::thread::spawn(move || {
                    bridge_rt_fn(sp, btr, brs, done_tx);
                });
            } else {
                error!("Audio [{}]: bridge receiver already consumed", call_id);
            }
        }

        // Check if the bridge thread has exited (connection failure or ppp-server closed).
        // Disconnect the modem engine and ask the SIP task to send BYE.
        if bridge_connected && bridge_done_rx.try_recv().is_ok() {
            info!("Audio [{}]: bridge done, disconnecting call", call_id);
            engine.on_sip_disconnected();
            let _ = call_hangup_tx.blocking_send(call_id.clone());
            break;
        }

        // Forward app data from bridge to modem engine (socket → downstream → v22bis TX)
        {
            let mut put_total = 0usize;
            while let Ok(data) = bridge_rx_recv.try_recv() {
                put_total += data.len();
                engine.put_data(&data);
            }
            if put_total > 0 {
                debug!("bridge→downstream: {} bytes", put_total);
            }
        }

        // Forward modem upstream data to bridge (v22bis RX → upstream → socket)
        if bridge_connected {
            let mut buf = [0u8; 256];
            let n = engine.get_data(&mut buf);
            if n > 0 {
                debug!("upstream→bridge: {} bytes", n);
                let _ = bridge_tx_send.try_send(buf[..n].to_vec());
            }
        }

        // 20 ms sleep
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Bridge I/O thread: connects a Unix stream socket to the PPP server.
/// from_modem: receives bytes from the modem engine (upstream RX) to write to the socket.
/// to_modem: sends bytes read from the socket into the modem engine (downstream TX).
fn bridge_rt_fn(
    socket_path: String,
    from_modem: Receiver<Vec<u8>>,
    to_modem: Sender<Vec<u8>>,
    done_tx: Sender<()>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let stream = match UnixStream::connect(&socket_path).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to serial socket {}: {}", socket_path, e);
                let _ = to_modem.try_send(
                    b"\r\nNO SERVICE - backend not available\r\n\r\n".to_vec(),
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = done_tx.try_send(());
                return;
            }
        };
        info!("Connected to PPP bridge: {}", socket_path);

        let (mut rd, mut wr) = stream.into_split();
        let (wr_tx, mut wr_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

        // Blocking thread: polls crossbeam Receiver (from_modem) and forwards to tokio channel.
        // Move wr_tx (don't clone) so that when from_modem disconnects and this task exits,
        // wr_tx is the sole sender and wr_rx closes, allowing the write task to exit and drop
        // wr, which shuts down the write half of the socket so ppp-server sees EOF.
        let wr_tx2 = wr_tx; // sole sender — NOT a clone
        tokio::task::spawn_blocking(move || {
            while let Ok(data) = from_modem.recv() {
                if wr_tx2.blocking_send(data).is_err() {
                    break;
                }
            }
        });

        // Async write task: drains tokio channel → socket
        tokio::spawn(async move {
            while let Some(data) = wr_rx.recv().await {
                if let Err(e) = wr.write_all(&data).await {
                    debug!("Bridge write error: {}", e);
                    break;
                }
            }
        });

        // Read loop: socket → to_modem
        let mut buf = [0u8; 4096];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    info!("PPP bridge closed");
                    break;
                }
                Ok(n) => {
                    let _ = to_modem.try_send(buf[..n].to_vec());
                }
                Err(e) => {
                    error!("Bridge read error: {}", e);
                    break;
                }
            }
        }

        // Signal the audio thread that the bridge is gone (normal or error close).
        let _ = done_tx.try_send(());
    });
}

// -------------------------------------------------------------------------
// Random helpers (simple LCG, no rand crate dependency)
// -------------------------------------------------------------------------

fn rand_u16() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    t as u16
}

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    t ^ (t >> 16)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- G.711 μ-law codec ---

    #[test]
    fn ulaw_decode_silence() {
        // 0xFF is the G.711 PCMU silence codeword; it must decode to 0.
        assert_eq!(ulaw_decode(0xFF), 0);
    }

    #[test]
    fn ulaw_decode_sign_symmetry() {
        // Positive and negative extremes should be equal in magnitude.
        let pos = ulaw_decode(0x00); // largest positive
        let neg = ulaw_decode(0x80); // largest negative (sign bit set before inversion)
        assert!(pos > 0);
        assert!(neg < 0);
        // Allow a small asymmetry from the bias term.
        assert!((pos as i32 + neg as i32).abs() < 200);
    }

    #[test]
    fn ulaw_encode_decode_round_trip() {
        // encode→decode should round-trip within G.711 quantisation error (~6%).
        for &sample in &[0i16, 10, 50, 100, 500, 1000, 2000, 4000, 8000] {
            let encoded = ulaw_encode(sample);
            let decoded = ulaw_decode(encoded);
            // Tolerance scales with magnitude; minimum 4 to allow the bias offset.
            let tolerance = (sample.abs() / 10).max(4) as i32;
            let diff = (decoded as i32 - sample as i32).abs();
            assert!(
                diff <= tolerance,
                "sample={} encoded={:#04x} decoded={} diff={} tolerance={}",
                sample, encoded, decoded, diff, tolerance
            );
        }
    }

    #[test]
    fn ulaw_encode_negative_samples() {
        // Negative samples should produce a different encoding than the mirror
        // positive sample (sign bit differs in the G.711 byte).
        let pos = ulaw_encode(4000);
        let neg = ulaw_encode(-4000);
        assert_ne!(pos, neg);
        // The decoded signs should be opposite.
        assert!(ulaw_decode(pos) > 0);
        assert!(ulaw_decode(neg) < 0);
    }

    // --- SIP header parsing ---

    #[test]
    fn sip_header_extracts_value() {
        let msg = "INVITE sip:user@host SIP/2.0\r\nCall-ID: abc123@host\r\nFrom: <sip:a@b>\r\n\r\n";
        assert_eq!(sip_header(msg, "Call-ID"), Some("abc123@host"));
        assert_eq!(sip_header(msg, "From"), Some("<sip:a@b>"));
    }

    #[test]
    fn sip_header_case_insensitive() {
        let msg = "INVITE sip:user@host SIP/2.0\r\ncall-id: lower123\r\n\r\n";
        assert_eq!(sip_header(msg, "call-id"), Some("lower123"));
        assert_eq!(sip_header(msg, "Call-ID"), Some("lower123"));
    }

    #[test]
    fn sip_header_missing_returns_none() {
        let msg = "INVITE sip:user@host SIP/2.0\r\nFrom: <sip:a@b>\r\n\r\n";
        assert_eq!(sip_header(msg, "Contact"), None);
    }

    // --- SDP RTP port extraction ---

    #[test]
    fn sdp_rtp_port_found() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.1\r\nm=audio 5004 RTP/AVP 0\r\n";
        assert_eq!(sdp_rtp_port(sdp), Some(5004));
    }

    #[test]
    fn sdp_rtp_port_missing() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.1\r\n";
        assert_eq!(sdp_rtp_port(sdp), None);
    }

    // --- build_sip_response basic shape ---

    #[test]
    fn build_sip_response_starts_with_status_line() {
        let resp = build_sip_response(200, "OK", "call1", "from1", "to1", "1 INVITE", "via1", "");
        assert!(resp.starts_with("SIP/2.0 200 OK\r\n"), "got: {}", resp);
        assert!(resp.contains("Call-ID: call1"));
        assert!(resp.contains("Content-Length: 0"));
    }

    #[test]
    fn build_sip_response_100_trying() {
        let resp = build_sip_response(100, "Trying", "c", "f", "t", "1 INVITE", "v", "");
        assert!(resp.starts_with("SIP/2.0 100 Trying\r\n"));
    }

    // --- build_sip_bye From/To swap ---

    #[test]
    fn build_sip_bye_swaps_from_to() {
        // UAS-initiated BYE: our To becomes From, their From becomes To.
        let bye = build_sip_bye(
            "call-id-1",
            "our-to-with-tag",   // from (already swapped by caller)
            "their-from",        // to
            "127.0.0.1:5060".parse().unwrap(),
            "127.0.0.1",
            5060,
        );
        assert!(bye.starts_with("BYE "), "got: {}", bye);
        assert!(bye.contains("From: our-to-with-tag"));
        assert!(bye.contains("To: their-from"));
        assert!(bye.contains("Call-ID: call-id-1"));
        assert!(bye.contains("CSeq: 1 BYE"));
        assert!(bye.contains("Content-Length: 0"));
    }

    // --- SIP smoke test (Tier 3): full INVITE→ACK→BYE exchange ---

    #[tokio::test]
    async fn sip_invite_ack_bye() {
        // Bind the SIP server on an ephemeral port.
        let sip_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sip_addr = sip_sock.local_addr().unwrap();
        let sip_port = sip_addr.port();

        let (hangup_tx, hangup_rx) = tokio::sync::mpsc::channel::<String>(16);

        let _task = tokio::spawn(async move {
            sip_task(
                sip_sock,
                "127.0.0.1".to_string(),
                sip_port,
                "/run/ppp_server.sock".to_string(),
                hangup_tx,
                hangup_rx,
                None,
            )
            .await;
        });

        // UAC test socket.
        let uac = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let uac_addr = uac.local_addr().unwrap();

        let call_id = "testcall-1234@127.0.0.1";
        let from = "<sip:user@127.0.0.1>;tag=testTag1";
        let to = "<sip:modem@127.0.0.1>";
        let via = format!("SIP/2.0/UDP {};branch=z9hG4bKtest001", uac_addr);

        // Send INVITE
        let invite = format!(
            "INVITE sip:modem@127.0.0.1:{sip_port} SIP/2.0\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );
        uac.send_to(invite.as_bytes(), sip_addr).await.unwrap();

        let mut buf = [0u8; 4096];
        let timeout = Duration::from_secs(2);

        // Expect 100 Trying
        let (n, _) = tokio::time::timeout(timeout, uac.recv_from(&mut buf))
            .await
            .expect("timeout waiting for 100 Trying")
            .unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.starts_with("SIP/2.0 100"), "Expected 100, got: {}", resp);

        // Expect 180 Ringing
        let (n, _) = tokio::time::timeout(timeout, uac.recv_from(&mut buf))
            .await
            .expect("timeout waiting for 180 Ringing")
            .unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.starts_with("SIP/2.0 180"), "Expected 180, got: {}", resp);

        // Expect 200 OK (after ~200 ms delay in sip_task)
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), uac.recv_from(&mut buf))
            .await
            .expect("timeout waiting for 200 OK")
            .unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.starts_with("SIP/2.0 200"), "Expected 200, got: {}", resp);

        // Send ACK
        let ack = format!(
            "ACK sip:modem@127.0.0.1:{sip_port} SIP/2.0\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 ACK\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );
        uac.send_to(ack.as_bytes(), sip_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send BYE
        let bye = format!(
            "BYE sip:modem@127.0.0.1:{sip_port} SIP/2.0\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 2 BYE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );
        uac.send_to(bye.as_bytes(), sip_addr).await.unwrap();

        // Expect 200 OK to BYE
        let (n, _) = tokio::time::timeout(timeout, uac.recv_from(&mut buf))
            .await
            .expect("timeout waiting for 200 OK to BYE")
            .unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.starts_with("SIP/2.0 200"), "Expected 200 OK to BYE, got: {}", resp);
    }

    // --- Base64 decode ---

    #[test]
    fn base64_decode_basic() {
        // "dXNlcjpwYXNz" = "user:pass"
        let decoded = String::from_utf8(base64_decode("dXNlcjpwYXNz")).unwrap();
        assert_eq!(decoded, "user:pass");
    }

    #[test]
    fn base64_decode_with_padding() {
        // "YTpi" = "a:b"
        let decoded = String::from_utf8(base64_decode("YTpi")).unwrap();
        assert_eq!(decoded, "a:b");
    }

    // --- parse_basic_auth ---

    #[test]
    fn parse_basic_auth_valid() {
        // "Basic dXNlcjpwYXNz" -> ("user", "pass")
        let result = parse_basic_auth("Basic dXNlcjpwYXNz");
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn parse_basic_auth_missing_prefix() {
        assert_eq!(parse_basic_auth("Digest dXNlcjpwYXNz"), None);
    }

    #[test]
    fn parse_basic_auth_no_colon() {
        // "bm9jb2xvbg==" = "nocolon"
        assert_eq!(parse_basic_auth("Basic bm9jb2xvbg=="), None);
    }

    // --- AuthDb ---

    #[test]
    fn auth_db_check() {
        let db = AuthDb {
            users: HashMap::from([
                ("alice".to_string(), "secret".to_string()),
                ("bob".to_string(), "hunter2".to_string()),
            ]),
        };
        assert!(db.check("alice", "secret"));
        assert!(db.check("bob", "hunter2"));
        assert!(!db.check("alice", "wrong"));
        assert!(!db.check("nobody", "secret"));
    }

    // --- SIP auth integration: INVITE rejected without credentials ---

    #[tokio::test]
    async fn sip_invite_rejected_without_auth() {
        let sip_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sip_addr = sip_sock.local_addr().unwrap();
        let sip_port = sip_addr.port();

        let (hangup_tx, hangup_rx) = tokio::sync::mpsc::channel::<String>(16);

        let auth_db = Some(AuthDb {
            users: HashMap::from([("user".to_string(), "pass".to_string())]),
        });

        let _task = tokio::spawn(async move {
            sip_task(
                sip_sock,
                "127.0.0.1".to_string(),
                sip_port,
                "/run/ppp_server.sock".to_string(),
                hangup_tx,
                hangup_rx,
                auth_db,
            )
            .await;
        });

        let uac = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let uac_addr = uac.local_addr().unwrap();

        let call_id = "authtest-1@127.0.0.1";
        let from = "<sip:user@127.0.0.1>;tag=authTag1";
        let to = "<sip:modem@127.0.0.1>";
        let via = format!("SIP/2.0/UDP {};branch=z9hG4bKauth001", uac_addr);

        // INVITE without Authorization header
        let invite = format!(
            "INVITE sip:modem@127.0.0.1:{sip_port} SIP/2.0\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );
        uac.send_to(invite.as_bytes(), sip_addr).await.unwrap();

        let mut buf = [0u8; 4096];
        let timeout = Duration::from_secs(2);

        // Expect 401 Unauthorized
        let (n, _) = tokio::time::timeout(timeout, uac.recv_from(&mut buf))
            .await
            .expect("timeout waiting for 401")
            .unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.starts_with("SIP/2.0 401"), "Expected 401, got: {}", resp);
        assert!(resp.contains("WWW-Authenticate: Basic realm=\"cybercafe\""), "Missing WWW-Authenticate header");
    }

    #[tokio::test]
    async fn sip_invite_accepted_with_auth() {
        let sip_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sip_addr = sip_sock.local_addr().unwrap();
        let sip_port = sip_addr.port();

        let (hangup_tx, hangup_rx) = tokio::sync::mpsc::channel::<String>(16);

        let auth_db = Some(AuthDb {
            users: HashMap::from([("user".to_string(), "pass".to_string())]),
        });

        let _task = tokio::spawn(async move {
            sip_task(
                sip_sock,
                "127.0.0.1".to_string(),
                sip_port,
                "/run/ppp_server.sock".to_string(),
                hangup_tx,
                hangup_rx,
                auth_db,
            )
            .await;
        });

        let uac = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let uac_addr = uac.local_addr().unwrap();

        let call_id = "authtest-2@127.0.0.1";
        let from = "<sip:user@127.0.0.1>;tag=authTag2";
        let to = "<sip:modem@127.0.0.1>";
        let via = format!("SIP/2.0/UDP {};branch=z9hG4bKauth002", uac_addr);

        // INVITE with valid Authorization header
        // "user:pass" -> base64 "dXNlcjpwYXNz"
        let invite = format!(
            "INVITE sip:modem@127.0.0.1:{sip_port} SIP/2.0\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Authorization: Basic dXNlcjpwYXNz\r\n\
             Content-Length: 0\r\n\
             \r\n"
        );
        uac.send_to(invite.as_bytes(), sip_addr).await.unwrap();

        let mut buf = [0u8; 4096];
        let timeout = Duration::from_secs(2);

        // Expect 100 Trying (auth passed, call proceeds)
        let (n, _) = tokio::time::timeout(timeout, uac.recv_from(&mut buf))
            .await
            .expect("timeout waiting for 100 Trying")
            .unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.starts_with("SIP/2.0 100"), "Expected 100, got: {}", resp);
    }
}
