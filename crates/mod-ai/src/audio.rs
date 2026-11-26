//! G.711 (µ-law, A-law) and a streaming resampler.
//!
//! The G.711 code follows the public-domain Sun reference (`g711.c`).

use std::num::{NonZeroU32, NonZeroU64};

/// The narrowband codecs a call can use (RTP/AVP static payload types).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Pcmu,
    Pcma,
}

impl Codec {
    pub fn pt(self) -> u8 {
        match self {
            Codec::Pcmu => 0,
            Codec::Pcma => 8,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Codec::Pcmu => "PCMU",
            Codec::Pcma => "PCMA",
        }
    }
    pub fn decode(self, b: u8) -> i16 {
        match self {
            Codec::Pcmu => ulaw_decode(b),
            Codec::Pcma => alaw_decode(b),
        }
    }
    pub fn encode(self, s: i16) -> u8 {
        match self {
            Codec::Pcmu => ulaw_encode(s),
            Codec::Pcma => alaw_encode(s),
        }
    }
}

fn segment(v: i32, ends: &[i32; 8]) -> usize {
    ends.iter().position(|&e| v <= e).unwrap_or(8)
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "a G.711 code word is 8 bits by construction: segment (< 8) and 4-bit step XOR an 8-bit mask"
)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "v = s >> 2 lies within ±2^13: negating it, adding the bias and shifting by seg + 1 (seg < 8) cannot overflow"
)]
pub fn ulaw_encode(s: i16) -> u8 {
    const ENDS: [i32; 8] = [0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF];
    let mut v = i32::from(s) >> 2;
    let mask = if v < 0 {
        v = -v;
        0x7F
    } else {
        0xFF
    };
    v = v.min(8159) + (0x84 >> 2);
    let seg = segment(v, &ENDS);
    if seg >= 8 { (0x7F ^ mask) as u8 } else { (((seg as i32) << 4 | ((v >> (seg + 1)) & 0xF)) ^ mask) as u8 }
}

#[allow(clippy::arithmetic_side_effects, reason = "magnitudes stay within 32256 (see below) and the shift is at most 7")]
pub fn ulaw_decode(u: u8) -> i16 {
    // In i16 throughout: the largest magnitude is (0xF << 3 | 0x84) << 7 = 32256.
    let u = !u;
    let mut t = (i16::from(u & 0x0F) << 3) + 0x84;
    t <<= (u & 0x70) >> 4;
    if u & 0x80 != 0 { 0x84 - t } else { t - 0x84 }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "a G.711 code word is 8 bits by construction: segment (< 8) and 4-bit step XOR an 8-bit mask"
)]
#[allow(clippy::arithmetic_side_effects, reason = "v = s >> 3 lies within ±2^12, so -v - 1 cannot overflow; shift amounts are below 8")]
pub fn alaw_encode(s: i16) -> u8 {
    const ENDS: [i32; 8] = [0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF];
    let mut v = i32::from(s) >> 3;
    let mask = if v >= 0 {
        0xD5
    } else {
        v = -v - 1;
        0x55
    };
    let seg = segment(v, &ENDS);
    if seg >= 8 {
        return (0x7F ^ mask) as u8;
    }
    let q = if seg < 2 { (v >> 1) & 0xF } else { (v >> seg) & 0xF };
    (((seg as i32) << 4 | q) ^ mask) as u8
}

#[allow(clippy::arithmetic_side_effects, reason = "magnitudes stay within 32256 (see below); seg is 2..=7 in the shift, so seg - 1 cannot underflow")]
pub fn alaw_decode(a: u8) -> i16 {
    // In i16 throughout: the largest magnitude is (0xF << 4 | 0x108) << 6 = 32256.
    let a = a ^ 0x55;
    let mut t = i16::from(a & 0x0F) << 4;
    match (a & 0x70) >> 4 {
        0 => t += 8,
        1 => t += 0x108,
        seg => {
            t += 0x108;
            t <<= seg - 1;
        }
    }
    if a & 0x80 != 0 { t } else { -t }
}

/// Little-endian 16-bit PCM bytes → samples.
pub fn pcm16_from_le(b: &[u8]) -> Vec<i16> {
    b.as_chunks::<2>().0.iter().map(|c| i16::from_le_bytes(*c)).collect()
}

pub fn pcm16_to_le(s: &[i16]) -> Vec<u8> {
    s.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// Rational resampler (`up`/`down`), polyphase over a windowed-sinc
/// low-pass. Streams: keeps the input history it still needs, so chunks
/// of any size can be pushed with no clicks at the joins.
pub struct Resampler {
    up: NonZeroU64,
    down: NonZeroU64,
    /// `up` as a tap stride.
    step: usize,
    taps: Vec<f32>,
    hist: Vec<f32>,
    /// Absolute index of `hist[0]` in the input stream.
    base: u64,
    /// Next output sample (absolute).
    n: u64,
}

/// The largest reduced `up`/`down` factor accepted: the filter has
/// `32·factor + 1` taps, so this bounds it at 2M taps (8 MB).
const MAX_FACTOR: u32 = 1 << 16;

impl Resampler {
    /// `None` for a zero rate, or a ratio so irregular (e.g. 8000 →
    /// 100003 Hz) that the filter would be unreasonably long.
    pub fn new(from_hz: u32, to_hz: u32) -> Option<Self> {
        let (from, to) = (NonZeroU32::new(from_hz)?, NonZeroU32::new(to_hz)?);
        let g = gcd(from, to_hz);
        let (up, down) = (NonZeroU32::new(to.get() / g)?, NonZeroU32::new(from.get() / g)?);
        if up.max(down).get() > MAX_FACTOR {
            return None;
        }
        let m = usize::try_from(up.max(down).get()).ok()?;
        let step = usize::try_from(up.get()).ok()?;
        // Cut-off a little below the lower Nyquist rate, relative to the
        // upsampled rate; 16 zero crossings either side.
        let fc = 0.45 / m as f64;
        let span = m.checked_mul(32)?; // taps 0..=span
        let mid = span as f64 / 2.0;
        let taps = (0..=span)
            .map(|k| {
                let x = k as f64 - mid;
                let sinc = if x == 0.0 { 2.0 * fc } else { (2.0 * std::f64::consts::PI * fc * x).sin() / (std::f64::consts::PI * x) };
                let w = 0.42 - 0.5 * (2.0 * std::f64::consts::PI * k as f64 / span as f64).cos()
                    + 0.08 * (4.0 * std::f64::consts::PI * k as f64 / span as f64).cos();
                to_f32(sinc * w * step as f64)
            })
            .collect();
        Some(Self { up: up.into(), down: down.into(), step, taps, hist: Vec::new(), base: 0, n: 0 })
    }

    pub fn push(&mut self, input: &[i16], out: &mut Vec<i16>) {
        if self.up == self.down {
            out.extend_from_slice(input);
            return;
        }
        self.hist.extend(input.iter().map(|&s| f32::from(s)));
        let (up, down, len) = (self.up, self.down.get(), self.taps.len() as u64);
        let end = self.base.saturating_add(self.hist.len() as u64);
        // Output n is upsampled index t = n·down; it uses inputs m with
        // 0 <= t - m·up < len.
        while let Some(t) = self.n.checked_mul(down) {
            let m_hi = t / up;
            if m_hi >= end {
                break;
            }
            let m_lo = t.saturating_add(up.get()).saturating_sub(len) / up;
            // Inputs first..=m_hi: hist from h0 on, taps from k0 down by `up`
            // (first <= m_hi = t / up, so first·up <= t).
            let first = m_lo.max(self.base);
            let (Some(h0), Some(k0)) = (first.checked_sub(self.base), first.checked_mul(up.get()).and_then(|f| t.checked_sub(f))) else {
                break;
            };
            let (Ok(h0), Ok(k0)) = (usize::try_from(h0), usize::try_from(k0)) else { break };
            let (Some(taps), Some(hist)) = (self.taps.get(..=k0), self.hist.get(h0..)) else { break };
            // k0, k0 - up, … ≥ 0 is m_hi - first + 1 taps; hist has inputs up to m_hi.
            let acc = taps.iter().rev().step_by(self.step).zip(hist).fold(0f32, |acc, (&k, &x)| acc + k * x);
            out.push(saturate_i16(acc));
            self.n = self.n.saturating_add(1);
        }
        // Drop inputs no later output can reach.
        let keep_from = self.n.saturating_mul(down).saturating_add(up.get()).saturating_sub(len) / up;
        let drop = keep_from.saturating_sub(self.base);
        self.hist.drain(..usize::try_from(drop).unwrap_or(usize::MAX).min(self.hist.len()));
        self.base = self.base.saturating_add(drop);
    }
}

/// A filtered sample back to 16 bits: rounded, then saturated at the i16
/// range (clipping, never wrapping).
#[allow(clippy::cast_possible_truncation, reason = "rounded and clamped to the i16 range first, so the cast is exact")]
fn saturate_i16(x: f32) -> i16 {
    x.round().clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16
}

/// A filter tap in single precision (the rounding is intended).
#[allow(clippy::cast_possible_truncation, reason = "taps are stored in single precision; rounding to nearest f32 is intended")]
fn to_f32(x: f64) -> f32 {
    x as f32
}

fn gcd(a: NonZeroU32, b: u32) -> NonZeroU32 {
    match NonZeroU32::new(b) {
        None => a,
        Some(b) => gcd(b, a.get() % b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g711_round_trip() {
        for c in 0..=255u8 {
            assert_eq!(ulaw_decode(ulaw_encode(ulaw_decode(c))), ulaw_decode(c), "µ-law {c:#x}");
            assert_eq!(alaw_encode(alaw_decode(c)), c, "A-law {c:#x}");
        }
        assert_eq!(ulaw_encode(0), 0xFF);
        assert_eq!(alaw_encode(0), 0xD5);
        // Within the quantisation step across the range.
        for s in (i16::MIN..i16::MAX).step_by(97) {
            let e = (i32::from(ulaw_decode(ulaw_encode(s))) - i32::from(s)).abs();
            assert!(e <= i32::from(s).abs() / 16 + 8, "µ-law error {e} at {s}");
            let e = (i32::from(alaw_decode(alaw_encode(s))) - i32::from(s)).abs();
            assert!(e <= i32::from(s).abs() / 16 + 16, "A-law error {e} at {s}");
        }
    }

    #[allow(clippy::cast_possible_truncation, reason = "test tone of amplitude 8000: always within i16")]
    fn tone(hz: f64, rate: u32, n: usize) -> Vec<i16> {
        (0..n).map(|i| (8000.0 * (2.0 * std::f64::consts::PI * hz * i as f64 / f64::from(rate)).sin()) as i16).collect()
    }

    fn rms(s: &[i16]) -> f64 {
        (s.iter().map(|&v| f64::from(v).powi(2)).sum::<f64>() / s.len() as f64).sqrt()
    }

    #[test]
    fn resample_rates_and_levels() {
        for (from, to) in [(8000, 16000), (24000, 8000), (16000, 8000), (8000, 24000)] {
            let input = tone(440.0, from, from as usize); // one second
            let mut r = Resampler::new(from, to).unwrap();
            let mut out = Vec::new();
            // Odd chunk sizes: joins must not matter.
            for c in input.chunks(77) {
                r.push(c, &mut out);
            }
            let want = to as usize;
            assert!(out.len().abs_diff(want) <= 40, "{from}->{to}: {} samples", out.len());
            let level = rms(&out[200..out.len() - 200]) / rms(&input);
            assert!((0.95..1.05).contains(&level), "{from}->{to}: level {level}");
        }
        // Above the new Nyquist rate: filtered out.
        let mut r = Resampler::new(24000, 8000).unwrap();
        let mut out = Vec::new();
        r.push(&tone(6000.0, 24000, 24000), &mut out);
        assert!(rms(&out[200..]) < 8000.0 / 2f64.sqrt() * 0.05, "aliasing: {}", rms(&out[200..]));
    }

    #[test]
    fn resampler_rejects_bad_rates() {
        // A zero rate would make `down` 0 and `push` loop forever.
        assert!(Resampler::new(0, 8000).is_none());
        assert!(Resampler::new(8000, 0).is_none());
        // A large prime rate would ask for a 137-billion-tap filter.
        assert!(Resampler::new(4_294_967_291, 8000).is_none());
        assert!(Resampler::new(100_003, 8000).is_none());
        let mut r = Resampler::new(44100, 8000).unwrap();
        let mut out = Vec::new();
        r.push(&[1000; 4410], &mut out);
        assert!(out.len().abs_diff(800) <= 40);
    }

    /// FNV-1a over the bytes: pins outputs bit for bit.
    fn fnv(bytes: impl IntoIterator<Item = u8>) -> u64 {
        bytes.into_iter().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
    }

    #[allow(clippy::cast_possible_truncation, reason = "a deterministic test signal: amplitude 12000 plus a ramp, within i16")]
    fn signal(n: usize) -> Vec<i16> {
        (0..n).map(|i| (12000.0 * (i as f64 * 0.07).sin() + (i % 50) as f64 * 100.0) as i16).collect()
    }

    #[test]
    fn g711_reference_values() {
        // Sun g711.c: µ-law 0xFF/0x7F are ±0, 0x00/0x80 the extremes;
        // A-law 0xD5/0x55 are the smallest steps, 0xAA/0x2A the extremes.
        let ulaw: &[(u8, i16)] = &[(0xFF, 0), (0x7F, 0), (0x00, -32124), (0x80, 32124), (0xFE, 8), (0x7E, -8), (0xF0, 120)];
        for &(u, s) in ulaw {
            assert_eq!(ulaw_decode(u), s, "µ-law {u:#04x}");
        }
        let alaw: &[(u8, i16)] = &[(0xD5, 8), (0x55, -8), (0xAA, 32256), (0x2A, -32256), (0xD4, 24)];
        for &(a, s) in alaw {
            assert_eq!(alaw_decode(a), s, "A-law {a:#04x}");
        }
        let enc: &[(i16, u8, u8)] =
            &[(0, 0xFF, 0xD5), (-1, 0x7E, 0x55), (i16::MAX, 0x80, 0xAA), (i16::MIN, 0x00, 0x2A), (-32124, 0x00, 0x2A), (1000, 0xCE, 0xFA)];
        for &(s, u, a) in enc {
            assert_eq!((ulaw_encode(s), alaw_encode(s)), (u, a), "encode {s}");
        }
    }

    #[test]
    fn g711_tables_are_bit_identical() {
        let dec = |f: fn(u8) -> i16| fnv((0..=255u8).flat_map(|c| f(c).to_le_bytes()));
        let enc = |f: fn(i16) -> u8| fnv((i16::MIN..=i16::MAX).map(f));
        assert_eq!(dec(ulaw_decode), ULAW_DEC, "µ-law decode table");
        assert_eq!(dec(alaw_decode), ALAW_DEC, "A-law decode table");
        assert_eq!(enc(ulaw_encode), ULAW_ENC, "µ-law encoder over all of i16");
        assert_eq!(enc(alaw_encode), ALAW_ENC, "A-law encoder over all of i16");
    }

    const ULAW_DEC: u64 = 0xb91e_65d6_8481_a1a8;
    const ALAW_DEC: u64 = 0x693a_40ca_62a3_d2a5;
    const ULAW_ENC: u64 = 0xd5ee_23f7_d0ff_ae91;
    const ALAW_ENC: u64 = 0xf030_666e_b780_cf25;

    #[test]
    fn resampler_output_is_bit_identical() {
        let input = signal(4000);
        // (from, to, FNV of the output, output length)
        let cases: &[(u32, u32, u64, usize)] = &[
            (8000, 16000, 0xa57a_75dc_ef9f_b41d, 8000),
            (16000, 8000, 0x3158_c792_21df_8a21, 2000),
            (24000, 8000, 0x9fea_4066_ef99_b907, 1334),
            (8000, 24000, 0x0fda_4ac1_cac7_72b7, 12000),
            (44100, 8000, 0x245f_0ce6_bdde_0726, 726),
        ];
        for &(from, to, hash, len) in cases {
            let mut r = Resampler::new(from, to).unwrap();
            let mut out = Vec::new();
            r.push(&input, &mut out);
            assert_eq!((fnv(pcm16_to_le(&out)), out.len()), (hash, len), "{from} -> {to}");
        }
    }

    #[test]
    fn resampler_output_does_not_depend_on_chunking() {
        let input = signal(3000);
        for (from, to) in [(8000, 16000), (24000, 8000), (16000, 8000), (8000, 24000), (44100, 8000), (22050, 16000)] {
            let mut whole = Vec::new();
            Resampler::new(from, to).unwrap().push(&input, &mut whole);
            for size in [1, 7, 160, 999] {
                let mut r = Resampler::new(from, to).unwrap();
                let mut parts = Vec::new();
                for c in input.chunks(size) {
                    r.push(c, &mut parts);
                }
                assert_eq!(parts, whole, "{from} -> {to} in chunks of {size}");
            }
        }
    }

    #[test]
    fn resampler_edge_inputs() {
        let mut same = Resampler::new(16000, 16000).unwrap();
        let mut out = Vec::new();
        same.push(&[1, -2, 3], &mut out);
        assert_eq!(out, [1, -2, 3], "equal rates pass samples through");
        let mut r = Resampler::new(8000, 16000).unwrap();
        out.clear();
        r.push(&[], &mut out);
        assert!(out.is_empty());
        // Full-scale input clips instead of wrapping.
        let mut r = Resampler::new(8000, 16000).unwrap();
        let square: Vec<i16> = (0..800).map(|i| if i % 8 < 4 { i16::MAX } else { i16::MIN }).collect();
        r.push(&square, &mut out);
        assert!(out.contains(&i16::MAX) && out.contains(&i16::MIN), "overshoot saturates");
        assert_eq!(saturate_i16(1e9), i16::MAX);
        assert_eq!(saturate_i16(-1e9), i16::MIN);
        assert_eq!(saturate_i16(2.5), 3);
        assert_eq!(saturate_i16(-2.5), -3);
        assert_eq!(saturate_i16(f32::NAN), 0);
    }

    #[test]
    fn rate_ratios_are_reduced_before_the_size_check() {
        // (from, to, accepted)
        let cases: &[(u32, u32, bool)] = &[
            (8000, 16000, true),
            (48000, 8000, true),
            (44100, 8000, true),
            (65536, 1, true),
            (65537, 1, false),
            (1, 65537, false),
            (131_072, 2, true),
            (u32::MAX, u32::MAX, true),
        ];
        for &(from, to, ok) in cases {
            assert_eq!(Resampler::new(from, to).is_some(), ok, "{from} -> {to}");
        }
        let g = |a: u32, b: u32| gcd(NonZeroU32::new(a).unwrap(), b).get();
        assert_eq!((g(8000, 24000), g(44100, 8000), g(7, 0), g(13, 7)), (8000, 100, 7, 1));
    }

    #[test]
    fn codecs_and_pcm_bytes() {
        assert_eq!((Codec::Pcmu.pt(), Codec::Pcmu.name(), Codec::Pcma.pt(), Codec::Pcma.name()), (0, "PCMU", 8, "PCMA"));
        for b in 0..=255u8 {
            assert_eq!(Codec::Pcmu.decode(b), ulaw_decode(b));
            assert_eq!(Codec::Pcma.decode(b), alaw_decode(b));
        }
        assert_eq!((Codec::Pcmu.encode(1000), Codec::Pcma.encode(1000)), (ulaw_encode(1000), alaw_encode(1000)));
        assert_eq!(pcm16_to_le(&[1, -2, 0x1234]), [1, 0, 0xFE, 0xFF, 0x34, 0x12]);
        assert_eq!(pcm16_from_le(&[1, 0, 0xFE, 0xFF, 0x34]), [1, -2], "an odd trailing byte is dropped");
        assert!(pcm16_from_le(&[]).is_empty());
        let s = signal(500);
        assert_eq!(pcm16_from_le(&pcm16_to_le(&s)), s);
    }
}
