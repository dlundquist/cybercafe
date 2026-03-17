//! V.90 scrambler/descrambler and downstream encoder/upstream decoder.
//!
//! Ported from `v90modem/modem_engine.c` (the v90_scrambler_t / v90_enc_t
//! sections).  Encodes 6 data bytes per 6-symbol frame using the V.34
//! self-synchronising scrambler polynomial GPC(x) = x^23 + x^5 + 1.

/// Which G.711 companding law is in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Law {
    Ulaw,
    Alaw,
}

// A-law positive codewords indexed by Ucode (ITU-T V.90 Table 1/V.90).
#[rustfmt::skip]
static V90_UCODE_TO_ALAW: [u8; 128] = [
    0xD5, 0xD4, 0xD7, 0xD6, 0xD1, 0xD0, 0xD3, 0xD2,
    0xDD, 0xDC, 0xDF, 0xDE, 0xD9, 0xD8, 0xDB, 0xDA,
    0xC5, 0xC4, 0xC7, 0xC6, 0xC1, 0xC0, 0xC3, 0xC2,
    0xCD, 0xCC, 0xCF, 0xCE, 0xC9, 0xC8, 0xCB, 0xCA,
    0xF5, 0xF4, 0xF7, 0xF6, 0xF1, 0xF0, 0xF3, 0xF2,
    0xFD, 0xFC, 0xFF, 0xFE, 0xF9, 0xF8, 0xFB, 0xFA,
    0xE5, 0xE4, 0xE7, 0xE6, 0xE1, 0xE0, 0xE3, 0xE2,
    0xED, 0xEC, 0xEF, 0xEE, 0xE9, 0xE8, 0xEB, 0xEA,
    0x95, 0x94, 0x97, 0x96, 0x91, 0x90, 0x93, 0x92,
    0x9D, 0x9C, 0x9F, 0x9E, 0x99, 0x98, 0x9B, 0x9A,
    0x85, 0x84, 0x87, 0x86, 0x81, 0x80, 0x83, 0x82,
    0x8D, 0x8C, 0x8F, 0x8E, 0x89, 0x88, 0x8B, 0x8A,
    0xB5, 0xB4, 0xB7, 0xB6, 0xB1, 0xB0, 0xB3, 0xB2,
    0xBD, 0xBC, 0xBF, 0xBE, 0xB9, 0xB8, 0xBB, 0xBA,
    0xA5, 0xA4, 0xA7, 0xA6, 0xA1, 0xA0, 0xA3, 0xA2,
    0xAD, 0xAC, 0xAF, 0xAE, 0xA9, 0xA8, 0xAB, 0xAA,
];

/// Self-synchronising scrambler: GPC(x) = x^23 + x^5 + 1 (23-stage LFSR).
pub struct V90Scrambler {
    /// 23-bit shift register.
    sr: u32,
}

impl V90Scrambler {
    pub fn new() -> Self {
        Self { sr: 0x7F_FFFF } // all-ones start state
    }

    /// Scramble one byte LSB-first, returning the scrambled byte.
    pub fn scramble_byte(&mut self, input: u8) -> u8 {
        let mut out = 0u8;
        for i in 0..8u32 {
            let in_bit = ((input >> i) & 1) as u32;
            // x^23 XOR x^5: bits 22 and 4 of the 23-bit SR
            let fb = ((self.sr >> 22) ^ (self.sr >> 4)) & 1;
            let out_bit = in_bit ^ fb;
            self.sr = ((self.sr << 1) | out_bit) & 0x7F_FFFF;
            out |= (out_bit as u8) << i;
        }
        out
    }
}

impl Default for V90Scrambler {
    fn default() -> Self {
        Self::new()
    }
}

/// V.90 downstream encoder: maps 6-byte data frames to 6 G.711 codewords.
pub struct V90Encoder {
    scrambler: V90Scrambler,
    /// Differential coding state: $5 of the previous frame.
    prev_sign: i32,
}

impl V90Encoder {
    pub fn new() -> Self {
        Self {
            scrambler: V90Scrambler::new(),
            prev_sign: 0,
        }
    }

    /// Encode one 6-symbol data frame.
    ///
    /// - `data`: 6 raw data bytes (one per symbol)
    /// - `law`:  G.711 companding law in use
    ///
    /// Returns 6 G.711 codewords ready for injection into the RTP stream.
    pub fn encode_frame(&mut self, data: &[u8; 6], law: Law) -> [u8; 6] {
        let mut out = [0u8; 6];
        let mut sign = self.prev_sign;

        for i in 0..6 {
            let s = self.scrambler.scramble_byte(data[i]);
            let mag = s & 0x7F;           // Ucode: 0..127
            let s_bit = ((s >> 7) & 1) as i32;

            // §5.4.5.1 differential coding (Sr=0): $i = s_i XOR $_{i-1}
            sign = s_bit ^ sign;

            // Map Ucode → positive G.711 codeword
            let mut codeword = ucode_to_pcm_positive(mag, law);

            // Apply polarity: G.711 MSB=1 → positive, MSB=0 → negative
            if sign == 0 {
                codeword &= 0x7F; // make negative (clear MSB)
            }

            out[i] = codeword;
        }

        self.prev_sign = sign; // save $5 for next frame
        out
    }
}

impl Default for V90Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a Ucode (0–127) to the positive G.711 codeword for the given law.
#[inline]
fn ucode_to_pcm_positive(ucode: u8, law: Law) -> u8 {
    match law {
        Law::Alaw => V90_UCODE_TO_ALAW[(ucode & 0x7F) as usize],
        Law::Ulaw => 0xFF - ucode,
    }
}

// -------------------------------------------------------------------------
// V.90 upstream decoder (reverse of downstream encoder)
// -------------------------------------------------------------------------

// A-law codeword → Ucode reverse lookup (built from V90_UCODE_TO_ALAW).
static V90_ALAW_TO_UCODE: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0u8;
    loop {
        // Positive codeword
        let cw = V90_UCODE_TO_ALAW[i as usize];
        table[cw as usize] = i;
        // Negative codeword (MSB cleared)
        table[(cw & 0x7F) as usize] = i;
        if i == 127 {
            break;
        }
        i += 1;
    }
    table
};

/// Self-synchronising descrambler: GPC(x) = x^23 + x^5 + 1.
///
/// Inverse of `V90Scrambler::scramble_byte`.  The descrambler feeds the
/// *scrambled* (received) bits into the shift register, so it self-synchronises
/// after 23 bits regardless of initial state.
pub struct V90Descrambler {
    sr: u32,
}

impl V90Descrambler {
    pub fn new() -> Self {
        Self { sr: 0x7F_FFFF }
    }

    /// Descramble one byte LSB-first, returning the original data byte.
    pub fn descramble_byte(&mut self, scrambled: u8) -> u8 {
        let mut out = 0u8;
        for i in 0..8u32 {
            let sc_bit = ((scrambled >> i) & 1) as u32;
            let fb = ((self.sr >> 22) ^ (self.sr >> 4)) & 1;
            let data_bit = sc_bit ^ fb;
            // Feed scrambled bit into SR (same as encoder)
            self.sr = ((self.sr << 1) | sc_bit) & 0x7F_FFFF;
            out |= (data_bit as u8) << i;
        }
        out
    }
}

impl Default for V90Descrambler {
    fn default() -> Self {
        Self::new()
    }
}

/// V.90 upstream decoder: maps 6 G.711 codewords back to 6 data bytes.
///
/// Reverse of `V90Encoder::encode_frame`.
pub struct V90Decoder {
    descrambler: V90Descrambler,
    prev_sign: i32,
}

impl V90Decoder {
    pub fn new() -> Self {
        Self {
            descrambler: V90Descrambler::new(),
            prev_sign: 0,
        }
    }

    /// Decode one 6-symbol frame.
    ///
    /// - `codewords`: 6 G.711 codewords from the RTP stream
    /// - `law`:       G.711 companding law in use
    ///
    /// Returns 6 decoded data bytes.
    pub fn decode_frame(&mut self, codewords: &[u8; 6], law: Law) -> [u8; 6] {
        let mut out = [0u8; 6];
        let mut prev_sign = self.prev_sign;

        for i in 0..6 {
            let cw = codewords[i];

            // Recover polarity: G.711 MSB=1 → positive ($=1), MSB=0 → negative ($=0)
            let sign = ((cw >> 7) & 1) as i32;

            // Reverse differential coding: s_i = $i XOR $_{i-1}
            let s_bit = sign ^ prev_sign;
            prev_sign = sign;

            // Map G.711 codeword → Ucode (magnitude)
            let mag = pcm_positive_to_ucode(cw | 0x80, law); // force positive for lookup

            // Reconstruct scrambled byte: MSB=s_bit, lower 7 = Ucode
            let scrambled = (mag & 0x7F) | ((s_bit as u8) << 7);

            // Descramble
            out[i] = self.descrambler.descramble_byte(scrambled);
        }

        self.prev_sign = prev_sign;
        out
    }
}

impl Default for V90Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a positive G.711 codeword back to Ucode (0–127).
#[inline]
fn pcm_positive_to_ucode(codeword: u8, law: Law) -> u8 {
    match law {
        Law::Alaw => V90_ALAW_TO_UCODE[codeword as usize],
        Law::Ulaw => 0xFF - codeword,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scramble_descramble_round_trip() {
        let mut scr = V90Scrambler::new();
        let mut dsc = V90Descrambler::new();
        let data: [u8; 16] = [0x7E, 0xFF, 0x03, 0xC0, 0x21, 0x01, 0x00, 0x00,
                              0x00, 0x15, 0x03, 0x06, 0x00, 0x00, 0x00, 0x00];
        for &b in &data {
            let scrambled = scr.scramble_byte(b);
            let recovered = dsc.descramble_byte(scrambled);
            assert_eq!(b, recovered, "round-trip failed for byte 0x{:02X}", b);
        }
    }

    #[test]
    fn encode_decode_round_trip_ulaw() {
        let mut enc = V90Encoder::new();
        let mut dec = V90Decoder::new();
        let data = [0x7E, 0xFF, 0x03, 0xC0, 0x21, 0x01];
        let codewords = enc.encode_frame(&data, Law::Ulaw);
        let recovered = dec.decode_frame(&codewords, Law::Ulaw);
        assert_eq!(data, recovered);
    }

    #[test]
    fn encode_decode_round_trip_alaw() {
        let mut enc = V90Encoder::new();
        let mut dec = V90Decoder::new();
        let data = [0x00, 0x55, 0xAA, 0xFF, 0x80, 0x7F];
        let codewords = enc.encode_frame(&data, Law::Alaw);
        let recovered = dec.decode_frame(&codewords, Law::Alaw);
        assert_eq!(data, recovered);
    }

    #[test]
    fn encode_decode_multi_frame() {
        let mut enc = V90Encoder::new();
        let mut dec = V90Decoder::new();
        let frames: [[u8; 6]; 4] = [
            [0x7E, 0xFF, 0x03, 0xC0, 0x21, 0x01],
            [0x00, 0x00, 0x00, 0x15, 0x03, 0x06],
            [0x00, 0x00, 0x00, 0x00, 0xAB, 0xCD],
            [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
        ];
        for data in &frames {
            let cw = enc.encode_frame(data, Law::Ulaw);
            let recovered = dec.decode_frame(&cw, Law::Ulaw);
            assert_eq!(*data, recovered);
        }
    }
}
