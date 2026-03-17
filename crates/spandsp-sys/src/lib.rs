//! Raw FFI bindings to libspandsp.
//!
//! Only the modem-relevant functions are bound: V.8 negotiation, V.34 and
//! V.22bis data-pump, modem echo canceller, and G.711 codec helpers.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

use libc::{c_char, c_float, c_int, c_void};

// -------------------------------------------------------------------------
// Opaque state types (spandsp structs are large and version-dependent;
// we never inspect them from Rust — only pass pointers).
// -------------------------------------------------------------------------

/// Opaque V.8 state.
#[repr(C)]
pub struct V8State {
    _private: [u8; 0],
}

/// Opaque V.34 state.
#[repr(C)]
pub struct V34State {
    _private: [u8; 0],
}

/// Opaque V.22bis state.
#[repr(C)]
pub struct V22bisState {
    _private: [u8; 0],
}

/// Opaque logging state.
#[repr(C)]
pub struct LoggingState {
    _private: [u8; 0],
}

/// Opaque modem echo canceller.
#[repr(C)]
pub struct ModemEchoCan {
    _private: [u8; 0],
}

// -------------------------------------------------------------------------
// Callback function pointer types
// -------------------------------------------------------------------------

/// `get_bit` callback: returns the next bit to transmit (0 or 1), or a
/// negative `SIG_STATUS_*` value.
pub type SpanGetBitFunc =
    unsafe extern "C" fn(user_data: *mut c_void) -> c_int;

/// `put_bit` callback: receives one demodulated bit (0 or 1), or a negative
/// `SIG_STATUS_*` status code.
pub type SpanPutBitFunc =
    unsafe extern "C" fn(user_data: *mut c_void, bit: c_int);

/// V.8 result handler callback.
pub type V8ResultHandler =
    unsafe extern "C" fn(user_data: *mut c_void, result: *mut V8Parms);

// -------------------------------------------------------------------------
// SIG_STATUS values (from spandsp/async.h)
// -------------------------------------------------------------------------
pub const SIG_STATUS_CARRIER_DOWN: i32 = -1;
pub const SIG_STATUS_CARRIER_UP: i32 = -2;
pub const SIG_STATUS_TRAINING_IN_PROGRESS: i32 = -3;
pub const SIG_STATUS_TRAINING_SUCCEEDED: i32 = -4;
pub const SIG_STATUS_TRAINING_FAILED: i32 = -5;
pub const SIG_STATUS_FRAMING_OK: i32 = -6;
pub const SIG_STATUS_END_OF_DATA: i32 = -7;
pub const SIG_STATUS_ABORT: i32 = -8;
pub const SIG_STATUS_BREAK: i32 = -9;
pub const SIG_STATUS_SHUTDOWN_COMPLETE: i32 = -10;

// -------------------------------------------------------------------------
// V.8 modulation bitmask constants (from spandsp/v8.h)
// -------------------------------------------------------------------------
pub const V8_MOD_V17: u32 = 1 << 0;
pub const V8_MOD_V21: u32 = 1 << 1;
pub const V8_MOD_V22: u32 = 1 << 2;
pub const V8_MOD_V23HDX: u32 = 1 << 3;
pub const V8_MOD_V23: u32 = 1 << 4;
pub const V8_MOD_V26BIS: u32 = 1 << 5;
pub const V8_MOD_V26TER: u32 = 1 << 6;
pub const V8_MOD_V27TER: u32 = 1 << 7;
pub const V8_MOD_V29: u32 = 1 << 8;
pub const V8_MOD_V32: u32 = 1 << 9;
pub const V8_MOD_V34HDX: u32 = 1 << 10;
pub const V8_MOD_V34: u32 = 1 << 11;
pub const V8_MOD_V90: u32 = 1 << 12;
pub const V8_MOD_V92: u32 = 1 << 13;

// -------------------------------------------------------------------------
// V.8 status codes (from spandsp/v8.h)
// -------------------------------------------------------------------------
pub const V8_STATUS_IN_PROGRESS: i32 = 0;
pub const V8_STATUS_V8_OFFERED: i32 = 1;
pub const V8_STATUS_V8_CALL: i32 = 2;
pub const V8_STATUS_NON_V8_CALL: i32 = 3;
pub const V8_STATUS_FAILED: i32 = 4;

// -------------------------------------------------------------------------
// V.8 call-function codes (from spandsp/v8.h)
// -------------------------------------------------------------------------
pub const V8_CALL_TBS: i32 = 0;
pub const V8_CALL_H324: i32 = 1;
pub const V8_CALL_V18: i32 = 2;
pub const V8_CALL_T101: i32 = 3;
pub const V8_CALL_T30_TX: i32 = 4;
pub const V8_CALL_T30_RX: i32 = 5;
pub const V8_CALL_V_SERIES: i32 = 6;

// -------------------------------------------------------------------------
// V.8 protocol codes (from spandsp/v8.h)
// -------------------------------------------------------------------------
pub const V8_PROTOCOL_NONE: i32 = 0;
pub const V8_PROTOCOL_LAPM_V42: i32 = 1;

// -------------------------------------------------------------------------
// V.8 PSTN access / PCM modem codes (from spandsp/v8.h)
// -------------------------------------------------------------------------
pub const V8_PSTN_ACCESS_DCE_ON_DIGITAL: i32 = 0x04;
pub const V8_PSTN_PCM_MODEM_V90_V92_DIGITAL: i32 = 0x02;

// -------------------------------------------------------------------------
// modem_connect_tones constants
// -------------------------------------------------------------------------
pub const MODEM_CONNECT_TONES_NONE: i32 = 0;
pub const MODEM_CONNECT_TONES_ANSAM_PR: i32 = 3;

// -------------------------------------------------------------------------
// SpanDSP logging level flags (from spandsp/logging.h)
// -------------------------------------------------------------------------
pub const SPAN_LOG_SHOW_SEVERITY: u32 = 0x01;
pub const SPAN_LOG_SHOW_PROTOCOL: u32 = 0x02;
pub const SPAN_LOG_FLOW: u32 = 0x10;

// -------------------------------------------------------------------------
// V.22bis guard tone constants (from spandsp/v22bis.h)
// -------------------------------------------------------------------------
pub const V22BIS_GUARD_TONE_NONE: i32 = 0;
pub const V22BIS_GUARD_TONE_550HZ: i32 = 1;
pub const V22BIS_GUARD_TONE_1800HZ: i32 = 2;

// -------------------------------------------------------------------------
// V.8 parameter structs (must match spandsp/v8.h exactly)
// -------------------------------------------------------------------------

/// Parameters for the CM/JM message exchanged during V.8 negotiation.
#[repr(C)]
pub struct V8CmJmParms {
    pub call_function: c_int,
    pub modulations: u32,
    pub protocols: c_int,
    pub pstn_access: c_int,
    pub nsf: c_int,
    pub pcm_modem_availability: c_int,
    pub t66: c_int,
}

/// Top-level V.8 parameter block passed to `v8_init` and returned in the
/// result callback.
#[repr(C)]
pub struct V8Parms {
    pub status: c_int,
    pub gateway_mode: bool,
    pub modem_connect_tone: c_int,
    pub send_ci: c_int,
    pub v92: c_int,
    pub jm_cm: V8CmJmParms,
}

// -------------------------------------------------------------------------
// FFI declarations
// -------------------------------------------------------------------------

extern "C" {
    // ---- V.8 ---------------------------------------------------------------
    pub fn v8_init(
        s: *mut V8State,
        calling_party: bool,
        parms: *mut V8Parms,
        result_handler: V8ResultHandler,
        user_data: *mut c_void,
    ) -> *mut V8State;

    pub fn v8_free(s: *mut V8State) -> c_int;

    pub fn v8_tx(s: *mut V8State, amp: *mut i16, max_len: c_int) -> c_int;

    pub fn v8_rx(s: *mut V8State, amp: *const i16, len: c_int) -> c_int;

    pub fn v8_get_logging_state(s: *mut V8State) -> *mut LoggingState;

    pub fn v8_status_to_str(status: c_int) -> *const c_char;

    // ---- V.34 --------------------------------------------------------------
    pub fn v34_init(
        s: *mut V34State,
        baud_rate: c_int,
        bit_rate: c_int,
        calling_party: bool,
        duplex: bool,
        get_bit: SpanGetBitFunc,
        get_bit_user_data: *mut c_void,
        put_bit: SpanPutBitFunc,
        put_bit_user_data: *mut c_void,
    ) -> *mut V34State;

    pub fn v34_free(s: *mut V34State) -> c_int;

    pub fn v34_tx(s: *mut V34State, amp: *mut i16, len: c_int) -> c_int;

    pub fn v34_rx(s: *mut V34State, amp: *const i16, len: c_int) -> c_int;

    pub fn v34_tx_power(s: *mut V34State, power: c_float);

    pub fn v34_get_current_bit_rate(s: *mut V34State) -> c_int;

    pub fn v34_get_logging_state(s: *mut V34State) -> *mut LoggingState;

    // ---- V.22bis -----------------------------------------------------------
    pub fn v22bis_init(
        s: *mut V22bisState,
        bit_rate: c_int,
        guard_tone: c_int,
        calling_party: bool,
        get_bit: SpanGetBitFunc,
        get_bit_user_data: *mut c_void,
        put_bit: SpanPutBitFunc,
        put_bit_user_data: *mut c_void,
    ) -> *mut V22bisState;

    pub fn v22bis_free(s: *mut V22bisState) -> c_int;

    pub fn v22bis_tx(s: *mut V22bisState, amp: *mut i16, len: c_int) -> c_int;

    pub fn v22bis_rx(s: *mut V22bisState, amp: *const i16, len: c_int) -> c_int;

    // ---- Modem echo canceller ----------------------------------------------
    // v90modem's spandsp uses segment_init/free; Debian uses init/free.
    pub fn modem_echo_can_segment_init(taps: c_int) -> *mut ModemEchoCan;

    pub fn modem_echo_can_segment_free(ec: *mut ModemEchoCan);

    pub fn modem_echo_can_adaption_mode(ec: *mut ModemEchoCan, adapt: c_int);

    pub fn modem_echo_can_update(ec: *mut ModemEchoCan, tx: i16, rx: i16) -> i16;

    // ---- G.711 -------------------------------------------------------------
    pub fn ulaw_to_linear(ulaw: u8) -> i16;

    pub fn alaw_to_linear(alaw: u8) -> i16;

    // ---- Logging -----------------------------------------------------------
    pub fn span_log_set_level(log: *mut LoggingState, level: u32);
}
