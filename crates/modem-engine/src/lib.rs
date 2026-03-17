//! Safe Rust wrapper around the spandsp modem state machine.
//!
//! Ported from `v90modem/modem_engine.c`.  Implements a V.8 → V.34/V.22bis
//! state machine over 8 kHz linear PCM audio.
//!
//! # Thread safety
//!
//! Each `ModemEngine` instance owns an `Arc<Mutex<EngineInner>>`.  All spandsp
//! callbacks receive a raw pointer to the `Mutex<EngineInner>` as user_data and
//! recover the lock from that pointer.  Multiple simultaneous calls are supported
//! because each call creates its own `ModemEngine`.

pub mod clock_recovery;
pub mod v90_encoder;

pub use v90_encoder::Law;

use clock_recovery::ClockRecovery;
use v90_encoder::V90Encoder;

use libc::c_void;
use log::{debug, error, info, warn};
use spandsp_sys::*;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};

// -------------------------------------------------------------------------
// Public state/modulation enums
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModemState {
    Idle,
    V8,
    Training,
    Data,
    Hangup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modulation {
    None,
    V34,
    V22Bis,
    V90,
}

// -------------------------------------------------------------------------
// Ring buffer for data flowing between audio thread and application
// -------------------------------------------------------------------------

const DATA_RING_SIZE: usize = 16384;

struct DataRing {
    buf: VecDeque<u8>,
}

impl DataRing {
    fn new() -> Self {
        Self {
            buf: VecDeque::with_capacity(DATA_RING_SIZE),
        }
    }

    fn write(&mut self, data: &[u8]) -> usize {
        let space = DATA_RING_SIZE - self.buf.len();
        let n = data.len().min(space);
        self.buf.extend(&data[..n]);
        n
    }

    fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.buf.len());
        for b in out[..n].iter_mut() {
            *b = self.buf.pop_front().unwrap();
        }
        n
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// -------------------------------------------------------------------------
// TX echo-cancel ring buffer constants
// -------------------------------------------------------------------------

const TX_BUF_SIZE: usize = 4096;
const TX_BUF_MASK: usize = TX_BUF_SIZE - 1;
const ECHO_CAN_TAPS: libc::c_int = 512;

// -------------------------------------------------------------------------
// Per-callback bit accumulators (accessed only while holding the Mutex)
// -------------------------------------------------------------------------

/// Inner state owned by each ModemEngine's Arc<Mutex<EngineInner>>.
struct EngineInner {
    state: ModemState,
    modulation: Modulation,
    calling_party: bool,

    // SpanDSP contexts (raw pointers; freed in Drop via explicit teardown)
    v8: *mut V8State,
    v22bis: *mut V22bisState,
    v34: *mut V34State,
    echo_can: *mut ModemEchoCan,

    // V.90 downstream encoder
    v90_enc: V90Encoder,

    // G.711 law in use
    law: Law,

    // Data rings
    downstream: DataRing, // app → modem → TX audio
    upstream: DataRing,   // RX audio → modem → app

    // V.34 TX/RX bit accumulator (raw 8-bit, no start/stop)
    v34_tx_byte: u8,
    v34_tx_bits: i32,
    v34_rx_byte: u8,
    v34_rx_bits: i32,

    // V.22bis async UART TX state machine
    //   -1 = IDLE (send MARK=1, no byte loaded)
    //    0 = sending start bit (0)
    //  1-8 = sending data bit at position (bits-1)
    //    9 = sending stop bit (1)
    v22bis_tx_byte: u8,
    v22bis_tx_bits: i32,

    // V.22bis async UART RX state machine
    //   -1 = IDLE (waiting for start bit = 0)
    //  0-7 = accumulating data bit at this position
    //    8 = expecting stop bit (1)
    v22bis_rx_byte: u8,
    v22bis_rx_bits: i32,

    // Echo canceller TX ring buffer
    tx_buf: Box<[i16; TX_BUF_SIZE]>,
    tx_buf_wr: usize,
    tx_buf_rd: usize,

    // Clock recovery
    clock_recovery: ClockRecovery,

    // V.34 startup parameters (tunable via env vars)
    v34_start_baud: i32,
    v34_start_bps: i32,

    // Training RX energy diagnostics
    training_rx_energy: i64,
    training_rx_count: i32,
    v8_rx_energy: i64,
    v8_rx_count: i32,

    // V.8 ANSam/ detection: track RMS to detect when the answerer transitions
    // from ANSam/ (2100 Hz) to V.34 training.  Digital modems (Cisco MICA)
    // skip the V.8 CM/JM exchange and go straight to V.34 training after
    // ANSam/.  We detect this transition and follow into V.34.
    v8_ansam_detected: bool,          // true once RMS exceeds ANSam threshold
    v8_ansam_rms_prev: f64,           // previous 1-second RMS
    v8_post_ansam_samples: i32,       // samples since ANSam/ detected
    v8_exit_to_v34: bool,             // set when we should bail out of V.8 → V.34

    // V.8 audio capture for offline analysis (enabled by ME_V8_CAPTURE=1)
    v8_capture_rx: Option<std::fs::File>,
    v8_capture_tx: Option<std::fs::File>,

    // V.22bis false-training guard
    // Counts RX samples fed during the current V.22bis training session.
    // Real V.22bis training takes ≥4 s; premature TRAINING_SUCCEEDED is echo artefact.
    v22bis_training_samples: i64,
    // Set by v22bis_put_bit_cb when TRAINING_SUCCEEDED fires too early; cleared
    // and acted on by rx_audio() *after* v22bis_rx() returns (safe to free then).
    v22bis_restart_pending: bool,

    // V.22bis TX/RX diagnostics
    v22bis_tx_getbit_data: u64, // get_bit calls that returned a data bit
    v22bis_tx_getbit_idle: u64, // get_bit calls that returned MARK (no data)
    v22bis_tx_bytes_sent: u64,  // complete UART bytes transmitted
    v22bis_rx_bytes_rcvd: u64,  // complete UART bytes received (valid stop bit)
    v22bis_rx_framing_err: u64, // UART frames with bad stop bit
}

// SAFETY: Raw pointers to spandsp contexts are only accessed while holding
// the Mutex; no references escape the lock.
unsafe impl Send for EngineInner {}

impl EngineInner {
    fn new() -> Self {
        let v34_start_baud = parse_env_int("ME_V34_BAUD", 2400);
        let v34_start_bps = parse_env_int("ME_V34_BPS", 21600);

        EngineInner {
            state: ModemState::Idle,
            modulation: Modulation::None,
            calling_party: false,
            v8: std::ptr::null_mut(),
            v22bis: std::ptr::null_mut(),
            v34: std::ptr::null_mut(),
            echo_can: std::ptr::null_mut(),
            v90_enc: V90Encoder::new(),
            law: Law::Ulaw,
            downstream: DataRing::new(),
            upstream: DataRing::new(),
            v34_tx_byte: 0,
            v34_tx_bits: 0,
            v34_rx_byte: 0,
            v34_rx_bits: 0,
            v22bis_tx_byte: 0,
            v22bis_tx_bits: -1, // IDLE
            v22bis_rx_byte: 0,
            v22bis_rx_bits: -1, // IDLE
            tx_buf: Box::new([0i16; TX_BUF_SIZE]),
            tx_buf_wr: 0,
            tx_buf_rd: 0,
            clock_recovery: ClockRecovery::new(8000),
            v34_start_baud: if valid_v34_baud(v34_start_baud) {
                v34_start_baud
            } else {
                2400
            },
            v34_start_bps: if valid_v34_bps(v34_start_bps) {
                v34_start_bps
            } else {
                21600
            },
            training_rx_energy: 0,
            training_rx_count: 0,
            v8_rx_energy: 0,
            v8_rx_count: 0,
            v8_ansam_detected: false,
            v8_ansam_rms_prev: 0.0,
            v8_post_ansam_samples: 0,
            v8_exit_to_v34: false,
            v8_capture_rx: None,
            v8_capture_tx: None,
            v22bis_training_samples: 0,
            v22bis_restart_pending: false,
            v22bis_tx_getbit_data: 0,
            v22bis_tx_getbit_idle: 0,
            v22bis_tx_bytes_sent: 0,
            v22bis_rx_bytes_rcvd: 0,
            v22bis_rx_framing_err: 0,
        }
    }

    /// Free all spandsp contexts.  Safe to call multiple times.
    fn teardown(&mut self) {
        unsafe {
            if !self.v8.is_null() {
                v8_free(self.v8);
                self.v8 = std::ptr::null_mut();
            }
            if !self.v22bis.is_null() {
                v22bis_free(self.v22bis);
                self.v22bis = std::ptr::null_mut();
            }
            if !self.v34.is_null() {
                v34_free(self.v34);
                self.v34 = std::ptr::null_mut();
            }
            if !self.echo_can.is_null() {
                modem_echo_can_segment_free(self.echo_can);
                self.echo_can = std::ptr::null_mut();
            }
        }
    }

    // ---- V.22bis training --------------------------------------------------

    fn start_v22bis_training(&mut self, engine_ptr: *mut c_void) {
        self.modulation = Modulation::V22Bis;
        self.state = ModemState::Training;
        self.v22bis_training_samples = 0;
        self.v22bis_restart_pending = false;
        info!("entering TRAINING: mod=V22BIS role={}", if self.calling_party { "caller" } else { "answerer" });

        if !self.v22bis.is_null() {
            unsafe { v22bis_free(self.v22bis) };
            self.v22bis = std::ptr::null_mut();
        }
        self.v22bis_tx_byte = 0;
        self.v22bis_tx_bits = -1; // IDLE
        self.v22bis_rx_byte = 0;
        self.v22bis_rx_bits = -1; // IDLE

        // V.22bis bit rate: 2400 (QAM-16) or 1200 (V.22 DPSK fallback).
        // The MICA digital modem negotiates V.22 (1200 bps DPSK).  If we
        // transmit at 2400 bps QAM-16, the MICA's DPSK demodulator can't
        // decode it — our TX is unintelligible.  Default to 1200 to match.
        // Override with ME_V22BIS_BPS=2400 to test V.22bis.
        let v22bis_bps = parse_env_int("ME_V22BIS_BPS", 1200);
        info!("V.22bis init: {} bps", v22bis_bps);

        let ptr = unsafe {
            v22bis_init(
                std::ptr::null_mut(),
                v22bis_bps,
                V22BIS_GUARD_TONE_NONE,
                self.calling_party,
                v22bis_get_bit_cb,
                engine_ptr,
                v22bis_put_bit_cb,
                engine_ptr,
            )
        };
        if ptr.is_null() {
            error!("v22bis_init failed");
        }
        self.v22bis = ptr;

        // Initialise echo canceller to suppress near-end hybrid echo from the VG's
        // FXS interface.  Preserve existing canceller across restarts so its adapted
        // filter weights (which model the same echo path) are not thrown away.
        if self.echo_can.is_null() {
            let ec = unsafe { modem_echo_can_segment_init(ECHO_CAN_TAPS) };
            if ec.is_null() {
                warn!("echo canceller init failed");
            } else {
                unsafe { modem_echo_can_adaption_mode(ec, 1) };
                info!("echo canceller initialised ({} taps) for V.22bis", ECHO_CAN_TAPS);
            }
            self.echo_can = ec;
            // Only reset TX ring on first init; on restarts we preserve it so the
            // echo canceller's adapted weights and ring-buffer alignment stay consistent.
            self.tx_buf_wr = 0;
            self.tx_buf_rd = 0;
        }
    }

    // ---- V.34 training -----------------------------------------------------

    fn start_v34_training(&mut self, engine_ptr: *mut c_void) {
        self.modulation = Modulation::V34;
        self.state = ModemState::Training;
        info!(
            "entering TRAINING: mod=V34 role={} baud={} bps={}",
            if self.calling_party { "caller" } else { "answerer" },
            self.v34_start_baud,
            self.v34_start_bps
        );

        self.training_rx_energy = 0;
        self.training_rx_count = 0;
        self.v34_tx_byte = 0;
        self.v34_tx_bits = 0;
        self.v34_rx_byte = 0;
        self.v34_rx_bits = 0;

        if !self.v34.is_null() {
            unsafe { v34_free(self.v34) };
            self.v34 = std::ptr::null_mut();
        }

        let ptr = unsafe {
            v34_init(
                std::ptr::null_mut(),
                self.v34_start_baud,
                self.v34_start_bps,
                self.calling_party,
                true, // full duplex
                v34_get_bit_cb,
                engine_ptr,
                v34_put_bit_cb,
                engine_ptr,
            )
        };
        if ptr.is_null() {
            error!("v34_init failed, falling back to V.22bis");
            self.start_v22bis_training(engine_ptr);
            return;
        }
        self.v34 = ptr;

        unsafe {
            let log = v34_get_logging_state(self.v34);
            if !log.is_null() {
                span_log_set_level(
                    log,
                    SPAN_LOG_SHOW_SEVERITY | SPAN_LOG_SHOW_PROTOCOL | SPAN_LOG_FLOW,
                );
            }
            v34_tx_power(self.v34, -16.0_f32);
        }

        // Initialise echo canceller
        if !self.echo_can.is_null() {
            unsafe { modem_echo_can_segment_free(self.echo_can) };
            self.echo_can = std::ptr::null_mut();
        }
        let ec = unsafe { modem_echo_can_segment_init(ECHO_CAN_TAPS) };
        if ec.is_null() {
            warn!("echo canceller init failed");
        } else {
            unsafe { modem_echo_can_adaption_mode(ec, 1) };
            info!("echo canceller initialised ({} taps)", ECHO_CAN_TAPS);
        }
        self.echo_can = ec;
        self.tx_buf_wr = 0;
        self.tx_buf_rd = 0;
    }

    // ---- V.8 negotiation ---------------------------------------------------

    fn start_v8(&mut self, engine_ptr: *mut c_void) {
        self.state = ModemState::V8;
        self.modulation = Modulation::None;
        self.v8_rx_energy = 0;
        self.v8_rx_count = 0;
        self.v8_ansam_detected = false;
        self.v8_ansam_rms_prev = 0.0;
        self.v8_post_ansam_samples = 0;
        self.v8_exit_to_v34 = false;

        // Open V.8 audio capture files if ME_V8_CAPTURE=1
        let capture = std::env::var("ME_V8_CAPTURE")
            .map(|v| v == "1")
            .unwrap_or(false);
        if capture {
            match std::fs::File::create("/tmp/v8_rx.raw") {
                Ok(f) => { self.v8_capture_rx = Some(f); info!("V.8 RX capture → /tmp/v8_rx.raw"); }
                Err(e) => warn!("V.8 capture: cannot create rx file: {}", e),
            }
            match std::fs::File::create("/tmp/v8_tx.raw") {
                Ok(f) => { self.v8_capture_tx = Some(f); info!("V.8 TX capture → /tmp/v8_tx.raw"); }
                Err(e) => warn!("V.8 capture: cannot create tx file: {}", e),
            }
        }

        if !self.v8.is_null() {
            unsafe { v8_free(self.v8) };
            self.v8 = std::ptr::null_mut();
        }

        // Build V.8 parameter block — advertise V.34 + V.22bis.
        // V.90 advertised via ME_ADVERTISE_V90=1.
        let advertise_v90 = std::env::var("ME_ADVERTISE_V90")
            .map(|v| v == "1" || v == "yes" || v == "true")
            .unwrap_or(false);

        let mut modulations = V8_MOD_V34 | V8_MOD_V22;
        if advertise_v90 {
            modulations |= V8_MOD_V90;
        }

        let mut v8_parms = V8Parms {
            status: 0,
            gateway_mode: false,
            modem_connect_tone: if self.calling_party {
                MODEM_CONNECT_TONES_NONE
            } else {
                MODEM_CONNECT_TONES_ANSAM_PR
            },
            send_ci: 1, // send CI so answering modem knows we support V.8
            v92: -1,    // don't send V.92 extension
            jm_cm: V8CmJmParms {
                call_function: V8_CALL_V_SERIES,
                modulations,
                protocols: V8_PROTOCOL_LAPM_V42,
                pstn_access: if advertise_v90 {
                    V8_PSTN_ACCESS_DCE_ON_DIGITAL
                } else {
                    0
                },
                nsf: -1,
                pcm_modem_availability: if advertise_v90 {
                    V8_PSTN_PCM_MODEM_V90_V92_DIGITAL
                } else {
                    0
                },
                t66: -1,
            },
        };

        let ptr = unsafe {
            v8_init(
                std::ptr::null_mut(),
                self.calling_party,
                &mut v8_parms,
                v8_result_handler,
                engine_ptr,
            )
        };
        if ptr.is_null() {
            error!("v8_init failed");
            return;
        }
        self.v8 = ptr;

        unsafe {
            let log = v8_get_logging_state(self.v8);
            if !log.is_null() {
                span_log_set_level(
                    log,
                    SPAN_LOG_SHOW_SEVERITY | SPAN_LOG_SHOW_PROTOCOL | SPAN_LOG_FLOW,
                );
            }
        }

        info!(
            "V.8 started as {} — advertised: {}",
            if self.calling_party { "caller" } else { "answerer" },
            if advertise_v90 { "V90|V34|V22" } else { "V34|V22" }
        );
    }
}

// -------------------------------------------------------------------------
// spandsp FFI callbacks (module-level extern "C" fns — no closures)
//
// user_data is a *const Mutex<EngineInner> obtained from Arc::as_ptr().
// The Arc outlives all spandsp contexts (spandsp contexts are freed in
// teardown() before ModemEngine is dropped), so the pointer is valid for the
// entire lifetime of the callback.
// -------------------------------------------------------------------------

extern "C" fn v34_get_bit_cb(user_data: *mut c_void) -> libc::c_int {
    let mtx = unsafe { &*(user_data as *const Mutex<EngineInner>) };
    let mut guard = mtx.lock().unwrap();
    let inner = &mut *guard;
    if inner.v34_tx_bits == 0 {
        let mut b = [0u8; 1];
        if inner.downstream.read(&mut b) == 1 {
            inner.v34_tx_byte = b[0];
            inner.v34_tx_bits = 8;
        } else {
            // Send MARK (1) when no data — keeps carrier alive in Data state
            // and prevents premature training abort in Training state.
            return 1;
        }
    }
    let bit = (inner.v34_tx_byte & 1) as libc::c_int;
    inner.v34_tx_byte >>= 1;
    inner.v34_tx_bits -= 1;
    bit
}

extern "C" fn v34_put_bit_cb(user_data: *mut c_void, bit: libc::c_int) {
    if bit < 0 {
        // Status event
        debug!("V34 rx status={}", bit);
        if bit == SIG_STATUS_CARRIER_UP || bit == SIG_STATUS_TRAINING_SUCCEEDED {
            let mtx = unsafe { &*(user_data as *const Mutex<EngineInner>) };
            let mut guard = mtx.lock().unwrap();
            if guard.state == ModemState::Training {
                guard.state = ModemState::Data;
                let rate = unsafe { v34_get_current_bit_rate(guard.v34) };
                info!("V.34 training complete ({} bps)", rate);
            }
        }
        return;
    }
    let mtx = unsafe { &*(user_data as *const Mutex<EngineInner>) };
    let mut guard = mtx.lock().unwrap();
    let inner = &mut *guard;
    inner.v34_rx_byte |= ((bit & 1) as u8) << inner.v34_rx_bits;
    inner.v34_rx_bits += 1;
    if inner.v34_rx_bits == 8 {
        let b = inner.v34_rx_byte;
        inner.upstream.write(&[b]);
        inner.v34_rx_byte = 0;
        inner.v34_rx_bits = 0;
    }
}

/// V.22bis TX: async UART framing (start + 8 data + stop) per byte.
///
/// The MICA modem expects async serial framing on the V.22(bis) link.
/// State machine:
///   -1       IDLE  — send MARK (1); try to load next byte → state 0
///    0       START — send start bit (0) → state 1
///   1..8     DATA  — send data bit at position (state-1), LSB first → state+1
///    9       STOP  — send stop bit (1) → state -1
extern "C" fn v22bis_get_bit_cb(user_data: *mut c_void) -> libc::c_int {
    let mtx = unsafe { &*(user_data as *const Mutex<EngineInner>) };
    let mut guard = mtx.lock().unwrap();
    let inner = &mut *guard;

    let result = match inner.v22bis_tx_bits {
        -1 => {
            // IDLE — try to load a byte from downstream
            let mut b = [0u8; 1];
            if inner.downstream.read(&mut b) == 1 {
                inner.v22bis_tx_byte = b[0];
                inner.v22bis_tx_bits = 1; // next call sends data bit 0
                inner.v22bis_tx_getbit_data += 1;
                0 // start bit
            } else {
                inner.v22bis_tx_getbit_idle += 1;
                1 // MARK (idle)
            }
        }
        1..=8 => {
            // DATA bit at position (state - 1), LSB first
            let pos = inner.v22bis_tx_bits - 1;
            let bit = ((inner.v22bis_tx_byte >> pos) & 1) as libc::c_int;
            inner.v22bis_tx_bits += 1;
            inner.v22bis_tx_getbit_data += 1;
            bit
        }
        9 => {
            // STOP bit
            inner.v22bis_tx_bits = -1; // back to IDLE
            inner.v22bis_tx_getbit_data += 1;
            inner.v22bis_tx_bytes_sent += 1;
            1
        }
        _ => 1, // shouldn't happen; send MARK
    };
    result
}

extern "C" fn v22bis_put_bit_cb(user_data: *mut c_void, bit: libc::c_int) {
    if bit < 0 {
        debug!("V22bis rx status={}", bit);
        // Only declare training complete on TRAINING_SUCCEEDED (not CARRIER_UP).
        // Real V.22bis training: 2.6 s ANS + S1 exchange ≈ 4–5 s total.
        // Anything faster is near-end echo from the VG's FXS hybrid.
        // If it fires early: set restart_pending (deferred — we may be inside
        // v22bis_rx() right now; freeing the context here would be a use-after-free).
        if bit == SIG_STATUS_TRAINING_SUCCEEDED {
            // Guard against premature TRAINING_SUCCEEDED from near-end echo.
            //
            // Caller: early media (SIP 183) means the MICA's ANS/S1 sequence
            // may already be in progress when our sample counter starts at the
            // 200 OK.  Real training completes at ~23 500 samples (2.94 s) in
            // this scenario.  Guard at 16 000 (2.0 s) catches FXS echo
            // artefacts (~8 000 samples) while accepting the real event.
            //
            // Answerer: FXS hybrid echo can fire at ~8 000 samples; real
            // training is ≥24 000 samples.
            //
            // IMPORTANT: do NOT restart (free+reinit) on a rejected event.
            // Restarting destroys the trained equaliser/descrambler.  spandsp
            // has internally transitioned to data mode, so a new context would
            // have to "train" on modulated data instead of training tones,
            // producing garbled output.  Instead we accept the event if it
            // passes the guard, and ignore it otherwise (the 30 s training
            // timeout will catch truly stuck sessions).
            const MIN_ANSWERER: i64 = 24_000;
            const MIN_CALLER: i64 = 16_000;
            let mtx = unsafe { &*(user_data as *const Mutex<EngineInner>) };
            let mut guard = mtx.lock().unwrap();
            if guard.state == ModemState::Training {
                let min_samples = if guard.calling_party { MIN_CALLER } else { MIN_ANSWERER };
                if guard.v22bis_training_samples >= min_samples {
                    guard.state = ModemState::Data;
                    // Reset the bit accumulator so the first data bit lands at
                    // position 0.  During training spandsp calls put_bit with
                    // the descrambled training pattern (the 0xAA sync bytes
                    // visible in the upstream dump), which leaves rx_bits at
                    // some non-zero offset.  Without a reset every subsequent
                    // data byte would be rotated by that offset.
                    info!(
                        "V.22bis training complete after {} samples \
                         (rx_bits offset at training end: {})",
                        guard.v22bis_training_samples,
                        guard.v22bis_rx_bits
                    );
                    guard.v22bis_rx_byte = 0;
                    guard.v22bis_rx_bits = -1; // UART IDLE — wait for start bit
                    guard.v22bis_tx_byte = 0;
                    guard.v22bis_tx_bits = -1; // UART IDLE
                } else {
                    warn!(
                        "V.22bis: ignoring premature TRAINING_SUCCEEDED after {} samples \
                         (<{}) — likely near-end echo; waiting for real event or timeout",
                        guard.v22bis_training_samples, min_samples
                    );
                    // Do NOT restart: spandsp has internally entered data mode.
                    // A fresh v22bis_init would train on data (not training tones),
                    // producing garbled descrambler output.  Leave our state as
                    // Training; the 30 s timeout catches truly stuck sessions.
                }
            }
        }
        return;
    }
    // Async UART RX: strip start/stop bits, extract 8 data bits per byte.
    //
    // The MICA modem sends async serial framing over V.22(bis):
    //   MARK (1) = idle,  start bit (0),  8 data bits (LSB first),  stop bit (1)
    //
    // State machine (v22bis_rx_bits):
    //   -1       IDLE — waiting for start bit (0)
    //   0..7     DATA — accumulating data bit at this position
    //   8        STOP — expecting stop bit (1), then emit byte
    let mtx = unsafe { &*(user_data as *const Mutex<EngineInner>) };
    let mut guard = mtx.lock().unwrap();
    let inner = &mut *guard;
    let b = (bit & 1) as u8;

    match inner.v22bis_rx_bits {
        -1 => {
            // IDLE — look for start bit (0)
            if b == 0 {
                inner.v22bis_rx_byte = 0;
                inner.v22bis_rx_bits = 0; // next bit is data bit 0
            }
            // else: MARK (1), stay idle
        }
        0..=7 => {
            // DATA — accumulate bit at current position
            inner.v22bis_rx_byte |= b << inner.v22bis_rx_bits;
            inner.v22bis_rx_bits += 1;
            if inner.v22bis_rx_bits == 8 {
                // All 8 data bits received; next bit should be stop
                // (state 8 handled below on next call)
            }
        }
        8 => {
            // STOP bit expected (should be 1)
            if b == 1 {
                // Valid frame — emit byte
                let byte = inner.v22bis_rx_byte;
                inner.upstream.write(&[byte]);
                inner.v22bis_rx_bytes_rcvd += 1;
            } else {
                inner.v22bis_rx_framing_err += 1;
            }
            // Whether stop bit was valid or not, return to IDLE.
            // A framing error (stop=0) means we lost sync; IDLE will
            // resync on the next start bit.
            inner.v22bis_rx_bits = -1;
        }
        _ => {
            inner.v22bis_rx_bits = -1; // shouldn't happen; reset
        }
    }
}

/// V.8 result handler: selects modulation and starts training.
///
/// SAFETY: called from spandsp's v8_rx internal state machine, which is
/// invoked from `rx_audio`.  We lock the engine Mutex here; it must not
/// already be held on this thread.  Because `rx_audio` releases the lock
/// before calling v8_rx, this is safe.
extern "C" fn v8_result_handler(user_data: *mut c_void, result: *mut V8Parms) {
    // SAFETY: result is a valid pointer provided by spandsp.
    let result = unsafe { &*result };

    info!(
        "V.8 result: status={} modulations=0x{:X}",
        result.status, result.jm_cm.modulations
    );

    if result.status == V8_STATUS_IN_PROGRESS || result.status == V8_STATUS_V8_OFFERED {
        return;
    }

    let mtx = unsafe { &*(user_data as *const Mutex<EngineInner>) };
    let mut guard = mtx.lock().unwrap();
    let ep = mtx as *const Mutex<EngineInner> as *mut c_void;

    // Close V.8 capture files
    guard.v8_capture_rx.take();
    guard.v8_capture_tx.take();

    if result.status == V8_STATUS_NON_V8_CALL {
        warn!("Non-V.8 call, falling back to V.22bis");
        guard.start_v22bis_training(ep);
        return;
    }

    if result.status != V8_STATUS_V8_CALL {
        // Treat any non-success as "non-V.8 call" and fall back to V.22bis.
        // This handles modems in compatibility mode that don't send V.8 CI.
        warn!("V.8 no negotiation (status={}), falling back to V.22bis", result.status);
        guard.start_v22bis_training(ep);
        return;
    }

    if result.jm_cm.modulations & V8_MOD_V90 != 0
        && result.jm_cm.modulations & V8_MOD_V34 != 0
    {
        // V.90: upstream uses V.34 modulation, downstream uses PCM.
        // Start V.34 training; after training completes, tx_audio will
        // switch to V.90 PCM injection for downstream.
        info!("V.8 negotiated V.90 (upstream V.34 + downstream PCM)");
        guard.modulation = Modulation::V90;
        guard.start_v34_training(ep);
        // modulation is set back to V90 after start_v34_training sets it to V34
        guard.modulation = Modulation::V90;
    } else if result.jm_cm.modulations & V8_MOD_V34 != 0 {
        info!("V.8 negotiated V.34");
        guard.start_v34_training(ep);
    } else if result.jm_cm.modulations & V8_MOD_V22 != 0 {
        info!("V.8 negotiated V.22bis");
        guard.start_v22bis_training(ep);
    } else {
        error!(
            "V.8 no usable modulation (0x{:X}), hanging up",
            result.jm_cm.modulations
        );
        guard.state = ModemState::Hangup;
    }
}

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

/// The modem engine.  Each instance owns its own state; multiple simultaneous
/// calls are supported by creating one `ModemEngine` per call.
pub struct ModemEngine {
    inner: Arc<Mutex<EngineInner>>,
}

impl ModemEngine {
    pub fn new() -> Self {
        ModemEngine {
            inner: Arc::new(Mutex::new(EngineInner::new())),
        }
    }

    /// Returns a stable raw pointer to the `Mutex<EngineInner>` inside the Arc.
    /// Safe to pass to spandsp as user_data because:
    /// - The Arc outlives any spandsp context (spandsp contexts are freed in
    ///   `teardown()` before ModemEngine is dropped)
    /// - After `v22bis_free` / `v34_free`, no more callbacks fire
    fn engine_ptr(&self) -> *mut c_void {
        Arc::as_ptr(&self.inner) as *mut c_void
    }

    /// Called when SIP call media becomes active.
    pub fn on_sip_connected(&mut self, calling_party: bool, law: Law) {
        let ep = self.engine_ptr();
        let mut guard = self.inner.lock().unwrap();
        let inner = &mut *guard;

        inner.teardown();
        inner.clock_recovery.reset();
        inner.v8_rx_energy = 0;
        inner.v8_rx_count = 0;
        inner.law = law;
        inner.calling_party = calling_party;

        // ME_MODULATION selects initial modulation:
        //   "v8"     → V.8 negotiation (auto-selects V.34/V.22bis/V.90)
        //   "v34"    → skip V.8, start V.34 training directly
        //   "v22bis" → skip V.8, start V.22bis training directly (default)
        let modulation = std::env::var("ME_MODULATION")
            .unwrap_or_else(|_| "v22bis".to_string());
        match modulation.as_str() {
            "v8" => {
                info!(
                    "SIP connected as {} — starting V.8 negotiation",
                    if calling_party { "caller" } else { "answerer" }
                );
                inner.start_v8(ep);
            }
            "v34" => {
                info!(
                    "SIP connected as {} — skipping V.8, starting V.34 directly",
                    if calling_party { "caller" } else { "answerer" }
                );
                inner.start_v34_training(ep);
            }
            _ => {
                info!(
                    "SIP connected as {} — skipping V.8, starting V.22bis directly",
                    if calling_party { "caller" } else { "answerer" }
                );
                inner.start_v22bis_training(ep);
            }
        }
    }

    /// Called when the SIP call is torn down.
    pub fn on_sip_disconnected(&mut self) {
        let mut guard = self.inner.lock().unwrap();
        guard.teardown();
        guard.state = ModemState::Idle;
        guard.modulation = Modulation::None;
        guard.calling_party = false;
        info!("SIP disconnected, modem reset to Idle");
    }

    /// Process received audio (from RTP). Called at 8 kHz, typically 160
    /// samples (20 ms) per call.
    pub fn rx_audio(&mut self, amp: &[i16]) {
        let state = {
            let g = self.inner.lock().unwrap();
            g.state
        };

        match state {
            ModemState::V8 => {
                // Energy diagnostic + ANSam/ → V.34 transition detection
                let bail_to_v34;
                {
                    let mut g = self.inner.lock().unwrap();
                    for &s in amp {
                        g.v8_rx_energy += (s as i64) * (s as i64);
                    }
                    g.v8_rx_count += amp.len() as i32;
                    if g.v8_rx_count >= 8000 {
                        let rms = ((g.v8_rx_energy as f64) / g.v8_rx_count as f64).sqrt();
                        if rms < 10.0 {
                            warn!("V.8 rx RMS={:.1} — near-silence, check conference bridge", rms);
                        } else {
                            debug!("V.8 rx RMS={:.1}", rms);
                        }

                        // Detect ANSam/ → V.34 transition.
                        // ANSam/ is a steady ~598 RMS. When the MICA switches to
                        // V.34 training, RMS jumps to ~680+. If we've seen ANSam/
                        // (RMS 400-650) and it then rises >640, the MICA has moved on.
                        if !g.v8_ansam_detected && rms > 400.0 && rms < 650.0 {
                            g.v8_ansam_detected = true;
                            info!("V.8: ANSam/ tone detected (RMS={:.1})", rms);
                        }
                        if g.v8_ansam_detected && g.v8_ansam_rms_prev > 400.0 && rms > 640.0
                            && (rms - g.v8_ansam_rms_prev) > 50.0
                        {
                            info!(
                                "V.8: RMS jump {:.0}→{:.0}, answerer likely moved to V.34 training",
                                g.v8_ansam_rms_prev, rms
                            );
                            g.v8_exit_to_v34 = true;
                        }
                        g.v8_ansam_rms_prev = rms;

                        g.v8_rx_energy = 0;
                        g.v8_rx_count = 0;
                    }

                    // Also count samples after ANSam detection for a hard timeout.
                    // If ANSam detected but V.8 still running after 3 seconds,
                    // bail to V.34 regardless of RMS.
                    if g.v8_ansam_detected {
                        g.v8_post_ansam_samples += amp.len() as i32;
                        if g.v8_post_ansam_samples > 3 * 8000 && !g.v8_exit_to_v34 {
                            info!("V.8: 3s since ANSam/ with no JM, bailing to V.34");
                            g.v8_exit_to_v34 = true;
                        }
                    }

                    bail_to_v34 = g.v8_exit_to_v34;
                }

                if bail_to_v34 {
                    let mtx = &*self.inner;
                    let mut g = mtx.lock().unwrap();
                    let ep = mtx as *const Mutex<EngineInner> as *mut c_void;
                    // Close capture files
                    g.v8_capture_rx.take();
                    g.v8_capture_tx.take();
                    // Free V.8 state
                    if !g.v8.is_null() {
                        unsafe { v8_free(g.v8) };
                        g.v8 = std::ptr::null_mut();
                    }
                    info!("V.8 abbreviated: CI/ANSam exchanged, skipping CM/JM → V.34");
                    g.start_v34_training(ep);
                    return;
                }

                // Feed to V.8 receiver (release lock first)
                let v8_ptr = {
                    let g = self.inner.lock().unwrap();
                    g.v8
                };
                if !v8_ptr.is_null() {
                    // Log first 5 frames of raw RX samples to diagnose audio path
                    {
                        let g = self.inner.lock().unwrap();
                        if g.v8_rx_count < 800 && !amp.is_empty() {
                            let peak = amp.iter().map(|&s| s.unsigned_abs()).max().unwrap_or(0);
                            debug!("V.8 RX frame: {} samples, peak={}, first=[{},{},{},{}]",
                                amp.len(), peak,
                                amp.get(0).copied().unwrap_or(0),
                                amp.get(1).copied().unwrap_or(0),
                                amp.get(2).copied().unwrap_or(0),
                                amp.get(3).copied().unwrap_or(0));
                        }
                    }
                    unsafe { v8_rx(v8_ptr, amp.as_ptr(), amp.len() as libc::c_int) };
                    // Capture RX audio
                    {
                        let mut g = self.inner.lock().unwrap();
                        if let Some(ref mut f) = g.v8_capture_rx {
                            let bytes: Vec<u8> = amp.iter()
                                .flat_map(|s| s.to_le_bytes())
                                .collect();
                            let _ = f.write_all(&bytes);
                        }
                    }
                }
                // After v8_rx the result handler may have fired and changed state.
            }

            ModemState::Training | ModemState::Data => {
                // Training RX energy diagnostic
                if state == ModemState::Training {
                    let mut g = self.inner.lock().unwrap();
                    for &s in amp {
                        g.training_rx_energy += (s as i64) * (s as i64);
                    }
                    g.training_rx_count += amp.len() as i32;
                    if g.training_rx_count >= 8000 {
                        let rms =
                            ((g.training_rx_energy as f64) / g.training_rx_count as f64).sqrt();
                        if rms < 20.0 || rms > 2000.0 {
                            warn!("Training RX RMS={:.1}", rms);
                        }
                        g.training_rx_energy = 0;
                        g.training_rx_count = 0;
                    }
                }

                let (modulation, v34_ptr, v22bis_ptr, echo_can_ptr) = {
                    let g = self.inner.lock().unwrap();
                    (g.modulation, g.v34, g.v22bis, g.echo_can)
                };

                if (modulation == Modulation::V34 || modulation == Modulation::V90)
                    && !v34_ptr.is_null()
                {
                    // V.34 RX: used for pure V.34, and for V.90 upstream
                    // (V.90 upstream uses V.34 modulation).
                    // Apply echo cancellation during DATA mode
                    if state == ModemState::Data && !echo_can_ptr.is_null() {
                        let clean: Vec<i16> = {
                            let mut g = self.inner.lock().unwrap();
                            let inner = &mut *g;
                            amp.iter()
                                .map(|&rx| {
                                    let tx = if inner.tx_buf_rd != inner.tx_buf_wr {
                                        let s = inner.tx_buf[inner.tx_buf_rd];
                                        inner.tx_buf_rd = (inner.tx_buf_rd + 1) & TX_BUF_MASK;
                                        s
                                    } else {
                                        0i16
                                    };
                                    unsafe { modem_echo_can_update(inner.echo_can, tx, rx) }
                                })
                                .collect()
                        };
                        unsafe { v34_rx(v34_ptr, clean.as_ptr(), clean.len() as libc::c_int) };
                    } else {
                        unsafe { v34_rx(v34_ptr, amp.as_ptr(), amp.len() as libc::c_int) };
                    }
                } else if !v22bis_ptr.is_null() {
                    // Count samples (used by the false-training gate in the callback).
                    // Only count in Training state; once we reach Data the gate is moot.
                    if state == ModemState::Training {
                        self.inner.lock().unwrap().v22bis_training_samples += amp.len() as i64;
                    }

                    // Suppress near-end echo during the ANS phase by zero-muting RX.
                    //
                    // Why not LMS echo cancellation: the ANS is a pure 2100 Hz sine wave.
                    // LMS converges extremely slowly on narrow-band signals (the input
                    // autocorrelation matrix is ill-conditioned for a pure tone), so the
                    // adaptive filter cannot null the echo before spandsp fires the first
                    // TRAINING_SUCCEEDED at ~8160 samples (~1 s).
                    //
                    // Per the V.22bis spec the caller is silent while detecting our ANS,
                    // so every RX sample during this window is echo.  Zero-muting is safe:
                    // spandsp advances its TX state machine on fixed timing, not on anything
                    // received during ANS.  After the mute window the S1 exchange can
                    // proceed normally.
                    //
                    // When we ARE the caller we must hear the remote answerer's ANS —
                    // muting would break our own training.  Only mute as the answerer.
                    const ANS_MUTE_SAMPLES: i64 = 20_000; // 2.5 s @ 8 kHz (ANS ≈ 2.6 s)
                    let (training_samples, is_answerer) = if state == ModemState::Training {
                        let g = self.inner.lock().unwrap();
                        (g.v22bis_training_samples, !g.calling_party)
                    } else {
                        (i64::MAX, false)
                    };

                    let silence;
                    let rx_input: &[i16] =
                        if is_answerer
                            && state == ModemState::Training
                            && training_samples < ANS_MUTE_SAMPLES
                        {
                            silence = vec![0i16; amp.len()];
                            &silence
                        } else {
                            amp
                        };

                    unsafe {
                        v22bis_rx(v22bis_ptr, rx_input.as_ptr(), rx_input.len() as libc::c_int)
                    };

                    // (Previously: deferred restart on premature TRAINING_SUCCEEDED.
                    // Removed — restarting destroys the trained context and forces a
                    // retrain on data, producing garbled output.  Premature events are
                    // now simply ignored; see v22bis_put_bit_cb.)
                }
            }

            _ => {}
        }
    }

    /// Generate transmit audio (to RTP). Fills `amp` with 160 samples.
    pub fn tx_audio(&mut self, amp: &mut [i16]) {
        let state = {
            let g = self.inner.lock().unwrap();
            g.state
        };

        for s in amp.iter_mut() {
            *s = 0;
        }

        match state {
            ModemState::V8 => {
                let v8_ptr = {
                    let g = self.inner.lock().unwrap();
                    g.v8
                };
                if !v8_ptr.is_null() {
                    unsafe { v8_tx(v8_ptr, amp.as_mut_ptr(), amp.len() as libc::c_int) };
                    // Capture TX audio
                    {
                        let mut g = self.inner.lock().unwrap();
                        if let Some(ref mut f) = g.v8_capture_tx {
                            let bytes: Vec<u8> = amp.iter()
                                .flat_map(|s| s.to_le_bytes())
                                .collect();
                            let _ = f.write_all(&bytes);
                        }
                    }
                }
            }

            ModemState::Training | ModemState::Data => {
                let (modulation, v34_ptr, v22bis_ptr, echo_can_ptr) = {
                    let g = self.inner.lock().unwrap();
                    (g.modulation, g.v34, g.v22bis, g.echo_can)
                };

                if (modulation == Modulation::V34 || modulation == Modulation::V90)
                    && !v34_ptr.is_null()
                    && !(modulation == Modulation::V90 && state == ModemState::Data)
                {
                    // V.34 TX: used for pure V.34, and during V.90 training
                    // (V.90 uses V.34 for Phase 2/3 training in both directions).
                    unsafe { v34_tx(v34_ptr, amp.as_mut_ptr(), amp.len() as libc::c_int) };

                    // Buffer TX samples for echo canceller
                    if !echo_can_ptr.is_null() {
                        let samples: Vec<i16> = amp.to_vec();
                        let mut g = self.inner.lock().unwrap();
                        for s in samples {
                            let wr = g.tx_buf_wr;
                            g.tx_buf[wr] = s;
                            g.tx_buf_wr = (wr + 1) & TX_BUF_MASK;
                        }
                    }
                } else if modulation == Modulation::V90 && state == ModemState::Data {
                    // V.90 downstream PCM injection
                    let mut pos = 0;
                    while pos + 6 <= amp.len() {
                        let frame: Option<[u8; 6]> = {
                            let mut g = self.inner.lock().unwrap();
                            let mut data = [0u8; 6];
                            if g.downstream.read(&mut data) == 6 {
                                Some(data)
                            } else {
                                None
                            }
                        };

                        if let Some(data) = frame {
                            let law = self.inner.lock().unwrap().law;
                            let pcm_out = {
                                let mut g = self.inner.lock().unwrap();
                                g.v90_enc.encode_frame(&data, law)
                            };
                            for (i, &cw) in pcm_out.iter().enumerate() {
                                amp[pos + i] = ulaw_decode_rust(cw);
                            }
                        } else {
                            // Silence
                            let idle = {
                                let g = self.inner.lock().unwrap();
                                pcm_idle(g.law)
                            };
                            for i in 0..6 {
                                amp[pos + i] = ulaw_decode_rust(idle);
                            }
                        }
                        pos += 6;
                    }
                } else if !v22bis_ptr.is_null() {
                    unsafe { v22bis_tx(v22bis_ptr, amp.as_mut_ptr(), amp.len() as libc::c_int) };
                    // Buffer TX samples as reference for the echo canceller.
                    if !echo_can_ptr.is_null() {
                        let samples: Vec<i16> = amp.to_vec();
                        let mut g = self.inner.lock().unwrap();
                        for s in samples {
                            let wr = g.tx_buf_wr;
                            g.tx_buf[wr] = s;
                            g.tx_buf_wr = (wr + 1) & TX_BUF_MASK;
                        }
                    }
                }
            }

            _ => {}
        }
    }

    /// Push data bytes from the application into the downstream TX buffer.
    pub fn put_data(&mut self, data: &[u8]) -> usize {
        self.inner.lock().unwrap().downstream.write(data)
    }

    /// Pull received data bytes from the upstream RX buffer.
    pub fn get_data(&mut self, buf: &mut [u8]) -> usize {
        self.inner.lock().unwrap().upstream.read(buf)
    }

    pub fn has_rx_data(&self) -> bool {
        !self.inner.lock().unwrap().upstream.is_empty()
    }

    pub fn state(&self) -> ModemState {
        self.inner.lock().unwrap().state
    }

    pub fn modulation(&self) -> Modulation {
        self.inner.lock().unwrap().modulation
    }

    pub fn set_law(&mut self, law: Law) {
        self.inner.lock().unwrap().law = law;
    }

    pub fn law(&self) -> Law {
        self.inner.lock().unwrap().law
    }

    /// UART diagnostics: (tx_bytes, rx_bytes, rx_framing_errors, downstream_pending)
    pub fn uart_stats(&self) -> (u64, u64, u64, usize) {
        let g = self.inner.lock().unwrap();
        (
            g.v22bis_tx_bytes_sent,
            g.v22bis_rx_bytes_rcvd,
            g.v22bis_rx_framing_err,
            g.downstream.buf.len(),
        )
    }
}

impl Default for ModemEngine {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn pcm_idle(law: Law) -> u8 {
    match law {
        Law::Alaw => 0xD5,
        Law::Ulaw => 0xFF,
    }
}

/// Minimal µ-law decode (used only for V.90 PCM → linear conversion in
/// tx_audio; we do not call spandsp ulaw_to_linear here to avoid re-entering
/// the lock while it might be held elsewhere).
fn ulaw_decode_rust(byte: u8) -> i16 {
    let b = !byte;
    let sign = b & 0x80;
    let exponent = ((b >> 4) & 0x07) as i32;
    let mantissa = (b & 0x0F) as i32;
    let mut sample = ((mantissa << 1) + 33) << exponent;
    sample -= 33;
    if sign != 0 {
        -(sample as i16)
    } else {
        sample as i16
    }
}

fn parse_env_int(name: &str, fallback: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(fallback)
}

fn valid_v34_baud(baud: i32) -> bool {
    matches!(baud, 2400 | 2743 | 2800 | 3000 | 3200 | 3429)
}

fn valid_v34_bps(bps: i32) -> bool {
    matches!(
        bps,
        4800 | 7200
            | 9600
            | 12000
            | 14400
            | 16800
            | 19200
            | 21600
            | 24000
            | 26400
            | 28800
            | 31200
            | 33600
    )
}
