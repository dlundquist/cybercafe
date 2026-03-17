//! sip-modem-dial — outbound SIP + V.22bis caller with stdin/stdout DCE bridge.
//!
//! Usage:
//!   sip-modem-dial [--local-ip IP] [--sip-port PORT] <PEER_IP> <NUMBER>
//!
//! With pppd:
//!   pppd pty "sip-modem-dial 192.168.3.250 5552020" \
//!        noauth nodetach debug lcp-max-configure 30
//!
//! Dials NUMBER via SIP INVITE to PEER_IP:5060, performs V.22bis handshake
//! as the calling party, then bridges modem data to stdin/stdout.
//! All diagnostic output goes to stderr; stdout carries only modem payload.

use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender};
use log::{debug, error, info, warn};
use modem_engine::{Law, ModemEngine, ModemState};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

// -------------------------------------------------------------------------
// PTY raw mode
// -------------------------------------------------------------------------

/// Put the pty slave (our stdin/stdout) into raw mode.
///
/// When pppd spawns us via `pty "..."`, our stdin/stdout is the slave side of
/// a pty pair.  The slave has default termios with OPOST|ONLCR|ICRNL|IXON
/// active.  These mangle binary data:
///   ONLCR  — converts 0x0A → 0x0D 0x0A in output (corrupts HDLC frames)
///   IXON   — treats 0x13 (XOFF) as flow-control, pausing output
///   ICRNL  — converts 0x0D → 0x0A in input
///   ECHO   — echoes input back as output (creates a data loop)
///
/// cfmakeraw() disables all of this.  The call silently fails (ENOTTY) when
/// stdin is not a tty, so it is safe to call unconditionally.
fn set_raw_mode() {
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut t) == 0 {
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(0, libc::TCSANOW, &t);
            eprintln!("[sip-modem-dial] pty slave set to raw mode");
        }
    }
}

// -------------------------------------------------------------------------
// CLI
// -------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "sip-modem-dial",
    about = "Outbound SIP + V.22bis caller; bridges modem data to stdin/stdout"
)]
struct Args {
    /// SIP peer IP address (e.g. 192.168.3.250)
    peer_ip: String,

    /// Phone number to dial (e.g. 5552020)
    number: String,

    /// Local IP to advertise in SIP/SDP (auto-detected if omitted)
    #[arg(long)]
    local_ip: Option<String>,

    /// Local SIP UDP port
    #[arg(long, default_value_t = 5062)]
    sip_port: u16,

    /// Remote SIP UDP port
    #[arg(long, default_value_t = 5060)]
    peer_sip_port: u16,
}

// -------------------------------------------------------------------------
// G.711 μ-law codec
// -------------------------------------------------------------------------

fn ulaw_encode(mut sample: i16) -> u8 {
    const BIAS: i32 = 33;
    const CLIP: i16 = 8159;
    let sign: u8 = if sample < 0 {
        sample = -sample;
        0x00
    } else {
        0x80
    };
    if sample > CLIP {
        sample = CLIP;
    }
    let biased = (sample as i32) + BIAS;
    let exp = if biased >= (BIAS << 7) { 7 }
        else if biased >= (BIAS << 6) { 6 }
        else if biased >= (BIAS << 5) { 5 }
        else if biased >= (BIAS << 4) { 4 }
        else if biased >= (BIAS << 3) { 3 }
        else if biased >= (BIAS << 2) { 2 }
        else if biased >= (BIAS << 1) { 1 }
        else { 0 };
    let mantissa = (((biased >> exp) - BIAS) >> 1).clamp(0, 15) as u8;
    !(sign | ((exp as u8) << 4) | mantissa)
}

fn ulaw_decode(byte: u8) -> i16 {
    let b = !byte;
    let sign = b & 0x80;
    let exponent = ((b >> 4) & 0x07) as i32;
    let mantissa = (b & 0x0F) as i32;
    let mut sample = ((mantissa << 1) + 33) << exponent;
    sample -= 33;
    if sign == 0 { -(sample as i16) } else { sample as i16 }
}

// -------------------------------------------------------------------------
// RTP
// -------------------------------------------------------------------------

const RTP_HEADER_LEN: usize = 12;

fn parse_rtp_header(buf: &[u8]) -> Option<u8> {
    if buf.len() < RTP_HEADER_LEN || (buf[0] >> 6) != 2 {
        return None;
    }
    Some(buf[1] & 0x7F) // payload type
}

fn build_rtp_packet(seq: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(RTP_HEADER_LEN + payload.len());
    pkt.push(0x80);
    pkt.push(0x00); // PT=0 PCMU, M=0
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&timestamp.to_be_bytes());
    pkt.extend_from_slice(&ssrc.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

// -------------------------------------------------------------------------
// SIP parsing helpers
// -------------------------------------------------------------------------

fn sip_header<'a>(msg: &'a str, name: &str) -> Option<&'a str> {
    let lower_name = name.to_lowercase();
    for line in msg.lines() {
        if line.to_lowercase().starts_with(&lower_name) {
            if let Some(rest) = line.get(name.len()..) {
                return Some(rest.trim_start_matches(':').trim());
            }
        }
    }
    None
}

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

fn sdp_connection_ip(sdp: &str) -> Option<&str> {
    for line in sdp.lines() {
        if line.starts_with("c=IN IP4 ") {
            return Some(line["c=IN IP4 ".len()..].trim());
        }
    }
    None
}

// -------------------------------------------------------------------------
// Random helpers
// -------------------------------------------------------------------------

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    t ^ (t >> 16)
}

fn rand_u16() -> u16 {
    rand_u32() as u16
}

// -------------------------------------------------------------------------
// SIP UAC message builders (outbound caller)
// -------------------------------------------------------------------------

fn build_invite(
    peer_ip: &str,
    peer_sip_port: u16,
    number: &str,
    local_ip: &str,
    sip_port: u16,
    rtp_port: u16,
    call_id: &str,
    from_tag: &str,
    branch: &str,
) -> String {
    let sdp = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 {local_ip}\r\n\
         s=-\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=ptime:20\r\n\
         a=sendrecv\r\n",
        local_ip = local_ip,
        rtp_port = rtp_port,
    );
    format!(
        "INVITE sip:{number}@{peer_ip}:{peer_sip_port} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local_ip}:{sip_port};branch={branch}\r\n\
         From: <sip:modem@{local_ip}:{sip_port}>;tag={from_tag}\r\n\
         To: <sip:{number}@{peer_ip}:{peer_sip_port}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:{local_ip}:{sip_port}>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {clen}\r\n\
         \r\n\
         {sdp}",
        number = number,
        peer_ip = peer_ip,
        peer_sip_port = peer_sip_port,
        local_ip = local_ip,
        sip_port = sip_port,
        branch = branch,
        from_tag = from_tag,
        call_id = call_id,
        clen = sdp.len(),
        sdp = sdp,
    )
}

fn build_ack(
    peer_ip: &str,
    peer_sip_port: u16,
    number: &str,
    local_ip: &str,
    sip_port: u16,
    call_id: &str,
    from_tag: &str,
    to_header: &str,
    branch: &str,
) -> String {
    format!(
        "ACK sip:{number}@{peer_ip}:{peer_sip_port} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local_ip}:{sip_port};branch={branch}\r\n\
         From: <sip:modem@{local_ip}:{sip_port}>;tag={from_tag}\r\n\
         To: {to_header}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 ACK\r\n\
         Content-Length: 0\r\n\
         \r\n",
        number = number,
        peer_ip = peer_ip,
        peer_sip_port = peer_sip_port,
        local_ip = local_ip,
        sip_port = sip_port,
        branch = branch,
        from_tag = from_tag,
        to_header = to_header,
        call_id = call_id,
    )
}

fn build_bye(
    peer_ip: &str,
    peer_sip_port: u16,
    number: &str,
    local_ip: &str,
    sip_port: u16,
    call_id: &str,
    from_tag: &str,
    to_header: &str,
) -> String {
    let branch = format!("z9hG4bK{:08x}", rand_u32());
    format!(
        "BYE sip:{number}@{peer_ip}:{peer_sip_port} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local_ip}:{sip_port};branch={branch}\r\n\
         From: <sip:modem@{local_ip}:{sip_port}>;tag={from_tag}\r\n\
         To: {to_header}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 2 BYE\r\n\
         Content-Length: 0\r\n\
         \r\n",
        number = number,
        peer_ip = peer_ip,
        peer_sip_port = peer_sip_port,
        local_ip = local_ip,
        sip_port = sip_port,
        branch = branch,
        from_tag = from_tag,
        to_header = to_header,
        call_id = call_id,
    )
}

// -------------------------------------------------------------------------
// Channel type aliases
// -------------------------------------------------------------------------

type RtpRxSender = Sender<Vec<i16>>;
type RtpRxReceiver = Receiver<Vec<i16>>;
type RtpTxSender = Sender<Vec<i16>>;
type RtpTxReceiver = Receiver<Vec<i16>>;

#[derive(Debug, Clone, Copy)]
enum AudioSignal {
    CallConnected,
    CallDisconnected,
}

type AudioSignalSender = Sender<AudioSignal>;
type AudioSignalReceiver = Receiver<AudioSignal>;

// -------------------------------------------------------------------------
// RTP recv task
// -------------------------------------------------------------------------

async fn rtp_recv_task(
    sock: Arc<UdpSocket>,
    tx: RtpRxSender,
    pkt_counter: Arc<AtomicU32>,
) {
    let mut buf = [0u8; 2048];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, _addr)) => {
                if let Some(pt) = parse_rtp_header(&buf[..len]) {
                    if pt == 0 && len > RTP_HEADER_LEN {
                        let payload = &buf[RTP_HEADER_LEN..len];
                        let n = pkt_counter.fetch_add(1, Ordering::Relaxed) + 1;
                        if n <= 5 {
                            info!("RTP pkt #{}: {} payload bytes", n, payload.len());
                        }
                        let samples: Vec<i16> =
                            payload.iter().map(|&b| ulaw_decode(b)).collect();
                        let _ = tx.try_send(samples);
                    } else if pt != 0 {
                        let n = pkt_counter.load(Ordering::Relaxed);
                        warn!("RTP pkt after #{}: unexpected PT={} len={} (gateway codec switch?)", n, pt, len);
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
// RTP send task
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

        let addr = *remote.lock().unwrap();
        if let Some(addr) = addr {
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
// Stdin reader thread
// -------------------------------------------------------------------------

fn stdin_reader_fn(tx: Sender<Vec<u8>>, done_tx: tokio::sync::mpsc::Sender<()>) {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut buf = [0u8; 256];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).is_err() {
                    break; // audio thread dropped the receiver (call ended)
                }
            }
            Err(_) => break,
        }
    }
    debug!("stdin reader: EOF");
    let _ = done_tx.blocking_send(());
}

// -------------------------------------------------------------------------
// Audio thread
// -------------------------------------------------------------------------

fn audio_thread_fn(
    rtp_rx: RtpRxReceiver,
    rtp_tx: RtpTxSender,
    audio_sig: AudioSignalReceiver,
    stdin_rx: Receiver<Vec<u8>>,
    done_tx: tokio::sync::mpsc::Sender<()>,
) {
    let mut engine = ModemEngine::new();
    let mut connected = false;
    let mut data_mode = false;
    let mut rx_buf: Vec<i16> = Vec::with_capacity(320);
    let mut training_started_at: Option<Instant> = None;
    let mut rtp_last_received = Instant::now();
    let mut stat_tx_bytes: usize = 0; // stdin → modem (downstream)
    let mut stat_rx_bytes: usize = 0; // modem → stdout (upstream)
    let mut stat_last = Instant::now();
    // Deadline-based pacing: generate TX frames at exactly 50 Hz (20 ms)
    // to prevent jitter buffer underrun on the Cisco.  A fixed sleep(20ms)
    // drifts ~5% slow due to processing overhead, causing the Cisco to
    // insert silence/concealment roughly once per second.
    let mut next_tick = Instant::now();

    loop {
        // Check for signals (non-blocking)
        match audio_sig.try_recv() {
            Ok(AudioSignal::CallConnected) => {
                if !connected {
                    // Flush queued audio (ringback, comfort noise)
                    while rtp_rx.try_recv().is_ok() {}
                    rx_buf.clear();
                    info!("Audio: call connected, starting V.22bis (caller)");
                    engine.on_sip_connected(true, Law::Ulaw); // calling_party = true
                    connected = true;
                    rtp_last_received = Instant::now();
                    next_tick = Instant::now(); // reset pacing clock
                }
            }
            Ok(AudioSignal::CallDisconnected) => {
                if connected {
                    engine.on_sip_disconnected();
                }
                break;
            }
            Err(crossbeam_channel::TryRecvError::Disconnected) => {
                info!("Audio: signal channel disconnected, exiting");
                break;
            }
            Err(crossbeam_channel::TryRecvError::Empty) => {}
        }

        // Training timeout (30 s)
        if connected {
            if engine.state() == ModemState::Training {
                if training_started_at.is_none() {
                    training_started_at = Some(Instant::now());
                } else if training_started_at.unwrap().elapsed() > Duration::from_secs(30) {
                    warn!("Audio: training timeout (30 s)");
                    engine.on_sip_disconnected();
                    let _ = done_tx.blocking_send(());
                    break;
                }
            } else {
                training_started_at = None;
            }
        }

        // Drain RTP → rx_buf
        while let Ok(samples) = rtp_rx.try_recv() {
            rx_buf.extend_from_slice(&samples);
            rtp_last_received = Instant::now();
        }

        // RTP carrier-loss watchdog (10 s)
        if connected && rtp_last_received.elapsed() > Duration::from_secs(10) {
            warn!("Audio: no RTP for 10 s, carrier loss");
            engine.on_sip_disconnected();
            let _ = done_tx.blocking_send(());
            break;
        }

        // Process RX and generate TX on a strict 20 ms deadline.
        // Generate as many frames as needed to keep up with wall-clock time.
        // This prevents the ~5% timing drift from sleep(20ms) + processing
        // overhead, which causes the Cisco's jitter buffer to underrun.
        // Cap at 3 frames per iteration to prevent burst flooding after delays.
        let now = Instant::now();
        let mut frames_this_iter = 0u32;
        while next_tick <= now && frames_this_iter < 3 {
            frames_this_iter += 1;
            // Process one 20 ms RX frame if available
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

            next_tick += Duration::from_millis(20);
        }
        // If we're still behind after the capped burst, skip ahead to avoid
        // an ever-growing backlog (e.g. after a long signal check or GC pause).
        if next_tick < Instant::now() {
            next_tick = Instant::now();
        }

        // Transition to DATA mode
        if connected && !data_mode && engine.state() == ModemState::Data {
            data_mode = true;
            stat_tx_bytes = 0;
            stat_rx_bytes = 0;
            stat_last = Instant::now();
            info!("Audio: modem in DATA state, bridging stdin/stdout");
        }

        if data_mode {
            // stdin → modem downstream TX
            let mut put_total = 0usize;
            while let Ok(data) = stdin_rx.try_recv() {
                put_total += data.len();
                engine.put_data(&data);
            }
            stat_tx_bytes += put_total;

            // modem upstream RX → stdout
            let mut buf = [0u8; 256];
            let n = engine.get_data(&mut buf);
            if n > 0 {
                let _ = std::io::stdout().write_all(&buf[..n]);
                let _ = std::io::stdout().flush();
                stat_rx_bytes += n;
            }

            // Periodic data-mode throughput report (every 5 s)
            if stat_last.elapsed() >= Duration::from_secs(5) {
                let (tx_bytes, rx_bytes, rx_err, pending) = engine.uart_stats();
                info!(
                    "Data stats: {}B down, {}B up | UART tx={} rx={} err={} pending={}",
                    stat_tx_bytes, stat_rx_bytes,
                    tx_bytes, rx_bytes, rx_err, pending
                );
                stat_last = Instant::now();
            }
        } else if connected {
            // Drain stdin during training to prevent pty buffer fill
            while stdin_rx.try_recv().is_ok() {}
        }

        // Sleep until the next tick, or 1 ms minimum to yield CPU
        let until_next = next_tick.saturating_duration_since(Instant::now());
        std::thread::sleep(until_next.max(Duration::from_millis(1)));
    }

    // Final summary
    if data_mode {
        let elapsed = stat_last.elapsed();
        let (tx_bytes, rx_bytes, rx_err, pending) = engine.uart_stats();
        info!(
            "Session end: {}B down, {}B up | UART tx={} rx={} err={} pending={}",
            stat_tx_bytes, stat_rx_bytes,
            tx_bytes, rx_bytes, rx_err, pending
        );
        let _ = elapsed; // suppress unused warning
    }

    let _ = done_tx.blocking_send(());
}

// -------------------------------------------------------------------------
// main
// -------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // env_logger defaults to stderr, which is what we want (stdout = modem data)
    env_logger::init();

    // Parse args first so that --help / --version exit before raw mode is set.
    // If we set raw mode before Args::parse(), clap's help output has no newlines
    // and the caller's terminal is left in raw mode after we exit.
    let args = Args::parse();

    // Put the pty slave into raw mode now that we know we're running for real.
    // cfmakeraw() disables OPOST|ONLCR|ICRNL|IXON|ECHO which would corrupt
    // binary modem data.  Silently no-ops (ENOTTY) when stdin is not a tty.
    set_raw_mode();

    // Discover local IP by routing toward the peer (no packets sent)
    let local_ip = args.local_ip.clone().unwrap_or_else(|| {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        probe
            .connect(format!("{}:53", args.peer_ip))
            .unwrap_or_else(|e| {
                eprintln!("Cannot route to {}: {}", args.peer_ip, e);
                std::process::exit(1);
            });
        probe.local_addr().unwrap().ip().to_string()
    });
    eprintln!(
        "[sip-modem-dial] Dialing {} via {}:{} (local {}:{})",
        args.number, args.peer_ip, args.peer_sip_port, local_ip, args.sip_port
    );

    let peer_sip_addr: SocketAddr =
        format!("{}:{}", args.peer_ip, args.peer_sip_port)
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("Bad peer address: {}", e);
                std::process::exit(1);
            });

    // Bind SIP socket
    let sip_sock = UdpSocket::bind(format!("0.0.0.0:{}", args.sip_port))
        .await
        .unwrap_or_else(|e| {
            eprintln!(
                "Failed to bind SIP socket 0.0.0.0:{}: {}",
                args.sip_port, e
            );
            std::process::exit(1);
        });
    info!("SIP bound to 0.0.0.0:{}", args.sip_port);

    // Bind RTP socket
    let rtp_sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind RTP socket");
    let rtp_port = rtp_sock.local_addr().unwrap().port();
    info!("RTP bound to 0.0.0.0:{}", rtp_port);

    // Per-call identifiers
    let call_id = format!(
        "{:08x}{:08x}@{}",
        rand_u32(),
        rand_u32(),
        local_ip
    );
    let from_tag = format!("{:08x}", rand_u32());
    let invite_branch = format!("z9hG4bK{:08x}", rand_u32());

    // RTP remote address — set when 200 OK arrives, read by RTP send task
    let rtp_remote: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Channels
    let (rtp_rx_tx, rtp_rx_rx): (RtpRxSender, RtpRxReceiver) = bounded(32);
    let (rtp_tx_tx, rtp_tx_rx): (RtpTxSender, RtpTxReceiver) = bounded(32);
    let (audio_sig_tx, audio_sig_rx): (AudioSignalSender, AudioSignalReceiver) = bounded(4);
    let (stdin_tx, stdin_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(64);
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(4);

    // Spawn RTP tasks
    let rtp_sock = Arc::new(rtp_sock);
    let pkt_counter = Arc::new(AtomicU32::new(0));
    tokio::spawn(rtp_recv_task(
        Arc::clone(&rtp_sock),
        rtp_rx_tx,
        Arc::clone(&pkt_counter),
    ));
    tokio::spawn(rtp_send_task(
        Arc::clone(&rtp_sock),
        rtp_tx_rx,
        Arc::clone(&rtp_remote),
    ));

    // Spawn audio thread
    let done_tx_audio = done_tx.clone();
    std::thread::spawn(move || {
        audio_thread_fn(rtp_rx_rx, rtp_tx_tx, audio_sig_rx, stdin_rx, done_tx_audio);
    });

    // Spawn stdin reader thread
    let done_tx_stdin = done_tx.clone();
    std::thread::spawn(move || {
        stdin_reader_fn(stdin_tx, done_tx_stdin);
    });

    // Send initial INVITE
    let invite = build_invite(
        &args.peer_ip,
        args.peer_sip_port,
        &args.number,
        &local_ip,
        args.sip_port,
        rtp_port,
        &call_id,
        &from_tag,
        &invite_branch,
    );
    sip_sock
        .send_to(invite.as_bytes(), peer_sip_addr)
        .await
        .expect("send INVITE");
    info!("INVITE sent to {}", peer_sip_addr);

    // SIP UAC state machine
    let mut to_header = format!(
        "<sip:{}@{}:{}>",
        args.number, args.peer_ip, args.peer_sip_port
    );
    let mut call_established = false;

    // Dial timeout: if no 200 OK within 30 s, give up.  The Cisco
    // sometimes fails to send a SIP error after an ISDN-level rejection
    // (e.g. Q.931 cause 38 "network out of order"), leaving us hanging
    // with only 100 Trying.  30 s is generous — a normal call connects
    // in under 2 s.
    let dial_deadline = Instant::now() + Duration::from_secs(30);

    let mut sip_buf = [0u8; 8192];

    'sip: loop {
        // Check dial timeout
        if !call_established && Instant::now() > dial_deadline {
            eprintln!("[sip-modem-dial] Dial timeout: no answer in 30 s");
            break 'sip;
        }

        tokio::select! {
            result = sip_sock.recv_from(&mut sip_buf) => {
                let (len, from_addr) = match result {
                    Ok(x) => x,
                    Err(e) => { error!("SIP recv: {}", e); break 'sip; }
                };
                let msg = match std::str::from_utf8(&sip_buf[..len]) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let first_line = msg.lines().next().unwrap_or("");
                debug!("SIP<< [{}] from {}", first_line, from_addr);

                if first_line.starts_with("SIP/2.0 100") {
                    info!("100 Trying");
                } else if first_line.starts_with("SIP/2.0 180")
                    || first_line.starts_with("SIP/2.0 183")
                {
                    info!("{}", first_line);
                } else if first_line.starts_with("SIP/2.0 200") {
                    if call_established {
                        // Retransmitted 200 OK — resend ACK
                        let ack_branch = format!("z9hG4bK{:08x}", rand_u32());
                        let ack = build_ack(
                            &args.peer_ip, args.peer_sip_port, &args.number,
                            &local_ip, args.sip_port,
                            &call_id, &from_tag, &to_header, &ack_branch,
                        );
                        let _ = sip_sock.send_to(ack.as_bytes(), peer_sip_addr).await;
                        continue;
                    }
                    info!("200 OK — call established");

                    // Extract To header with remote tag (needed for ACK/BYE)
                    if let Some(t) = sip_header(msg, "To") {
                        to_header = t.to_string();
                    }

                    // Parse remote RTP address from SDP body
                    let body_start = msg
                        .find("\r\n\r\n")
                        .map(|p| p + 4)
                        .unwrap_or(msg.len());
                    let sdp = &msg[body_start..];
                    let remote_rtp_port = sdp_rtp_port(sdp).unwrap_or(0);
                    let remote_rtp_ip = sdp_connection_ip(sdp)
                        .unwrap_or(&args.peer_ip)
                        .to_string();
                    let remote_rtp_addr: SocketAddr =
                        format!("{}:{}", remote_rtp_ip, remote_rtp_port)
                            .parse()
                            .unwrap_or_else(|_| {
                                format!("{}:{}", args.peer_ip, remote_rtp_port)
                                    .parse()
                                    .unwrap()
                            });
                    info!("Remote RTP: {}", remote_rtp_addr);
                    *rtp_remote.lock().unwrap() = Some(remote_rtp_addr);

                    // Send ACK
                    let ack_branch = format!("z9hG4bK{:08x}", rand_u32());
                    let ack = build_ack(
                        &args.peer_ip, args.peer_sip_port, &args.number,
                        &local_ip, args.sip_port,
                        &call_id, &from_tag, &to_header, &ack_branch,
                    );
                    sip_sock
                        .send_to(ack.as_bytes(), peer_sip_addr)
                        .await
                        .expect("send ACK");
                    info!("ACK sent");

                    // Start modem engine as caller
                    let _ = audio_sig_tx.try_send(AudioSignal::CallConnected);
                    call_established = true;
                } else if first_line.starts_with("SIP/2.0 4")
                    || first_line.starts_with("SIP/2.0 5")
                    || first_line.starts_with("SIP/2.0 6")
                {
                    error!("Call failed: {}", first_line);
                    let _ = audio_sig_tx.try_send(AudioSignal::CallDisconnected);
                    break 'sip;
                } else if msg.starts_with("BYE ") {
                    info!("BYE received");
                    // Respond 200 OK to BYE
                    let ci = sip_header(msg, "Call-ID").unwrap_or("").to_string();
                    let fr = sip_header(msg, "From").unwrap_or("").to_string();
                    let to = sip_header(msg, "To").unwrap_or("").to_string();
                    let cs = sip_header(msg, "CSeq").unwrap_or("").to_string();
                    let vi = sip_header(msg, "Via").unwrap_or("").to_string();
                    let resp = format!(
                        "SIP/2.0 200 OK\r\n\
                         Via: {vi}\r\nFrom: {fr}\r\nTo: {to}\r\n\
                         Call-ID: {ci}\r\nCSeq: {cs}\r\n\
                         Content-Length: 0\r\n\r\n",
                        vi = vi, fr = fr, to = to, ci = ci, cs = cs,
                    );
                    let _ = sip_sock.send_to(resp.as_bytes(), from_addr).await;
                    let _ = audio_sig_tx.try_send(AudioSignal::CallDisconnected);
                    break 'sip;
                } else if msg.starts_with("OPTIONS ") {
                    // Respond to keep-alive OPTIONS
                    let ci = sip_header(msg, "Call-ID").unwrap_or("").to_string();
                    let fr = sip_header(msg, "From").unwrap_or("").to_string();
                    let to = sip_header(msg, "To").unwrap_or("").to_string();
                    let cs = sip_header(msg, "CSeq").unwrap_or("").to_string();
                    let vi = sip_header(msg, "Via").unwrap_or("").to_string();
                    let resp = format!(
                        "SIP/2.0 200 OK\r\n\
                         Via: {vi}\r\nFrom: {fr}\r\nTo: {to}\r\n\
                         Call-ID: {ci}\r\nCSeq: {cs}\r\n\
                         Content-Length: 0\r\n\r\n",
                        vi = vi, fr = fr, to = to, ci = ci, cs = cs,
                    );
                    let _ = sip_sock.send_to(resp.as_bytes(), from_addr).await;
                }
            }

            _ = done_rx.recv() => {
                // Audio thread or stdin reader signaled done
                info!("Call ended (audio/stdin done)");
                if call_established {
                    let bye = build_bye(
                        &args.peer_ip, args.peer_sip_port, &args.number,
                        &local_ip, args.sip_port,
                        &call_id, &from_tag, &to_header,
                    );
                    let _ = sip_sock.send_to(bye.as_bytes(), peer_sip_addr).await;
                    info!("BYE sent");
                }
                break 'sip;
            }

            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                // Periodic check for dial timeout (handled at top of loop)
            }
        }
    }

    eprintln!("[sip-modem-dial] Done");
}
