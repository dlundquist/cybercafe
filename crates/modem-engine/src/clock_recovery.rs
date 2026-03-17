//! DPLL clock recovery for RTP jitter compensation.
//!
//! Direct Rust port of `v90modem/clock_recovery.c`.
//!
//! Tracks the rate at which RTP timestamps advance relative to the local wall
//! clock and emits slip signals (+1 insert, −1 drop) to keep the modem's
//! symbol clock locked to the remote 8 kHz PCM clock.

/// PI-controller DPLL clock recovery state.
pub struct ClockRecovery {
    pub sample_rate: i32,
    initialized: bool,
    phase_acc: f64,
    phase_err_int: f64,
    last_rtp_ts: u32,
    last_local_ns: i64,
    kp: f64,
    ki: f64,
    /// Latest accumulated phase error in samples (informational).
    pub phase_error_samples: f32,
}

impl ClockRecovery {
    /// Create a new clock recovery instance for the given sample rate (Hz).
    pub fn new(sample_rate: i32) -> Self {
        Self {
            sample_rate,
            initialized: false,
            phase_acc: 0.0,
            phase_err_int: 0.0,
            last_rtp_ts: 0,
            last_local_ns: 0,
            kp: 0.01,
            ki: 0.001,
            phase_error_samples: 0.0,
        }
    }

    /// Reset to initial state, preserving sample_rate.
    pub fn reset(&mut self) {
        let sr = self.sample_rate;
        *self = Self::new(sr);
    }

    /// Update the clock recovery state with a new RTP timestamp and local
    /// wall-clock time (nanoseconds).
    pub fn update(&mut self, rtp_ts: u32, local_ns: i64) {
        if !self.initialized {
            self.last_rtp_ts = rtp_ts;
            self.last_local_ns = local_ns;
            self.initialized = true;
            return;
        }

        // Elapsed RTP samples (handle 32-bit wrap via signed cast)
        let rtp_delta = rtp_ts.wrapping_sub(self.last_rtp_ts) as i32;

        // Elapsed wall-clock samples
        let wall_ns_delta = local_ns - self.last_local_ns;
        let wall_samples = wall_ns_delta as f64 * self.sample_rate as f64 / 1e9;

        // Phase error: positive → remote is ahead (insert a sample)
        let mut err = rtp_delta as f64 - wall_samples;

        // Clamp to avoid wild swings on packet loss
        if err > 160.0 {
            err = 160.0;
        }
        if err < -160.0 {
            err = -160.0;
        }

        // PI controller
        self.phase_err_int += err * self.ki;
        let correction = err * self.kp + self.phase_err_int;

        self.phase_acc += correction;
        self.phase_error_samples = self.phase_acc as f32;

        self.last_rtp_ts = rtp_ts;
        self.last_local_ns = local_ns;
    }

    /// Return the slip to apply this frame: +1 = insert silence, −1 = drop,
    /// 0 = no change.
    pub fn get_adjustment(&mut self) -> i32 {
        if self.phase_acc >= 0.5 {
            self.phase_acc -= 1.0;
            return 1;
        }
        if self.phase_acc <= -0.5 {
            self.phase_acc += 1.0;
            return -1;
        }
        0
    }
}
