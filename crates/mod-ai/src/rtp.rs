//! Minimal RTP (RFC 3550): what one audio stream needs.

/// (payload type, sequence number, payload) of a valid RTP packet.
pub fn parse(p: &[u8]) -> Option<(u8, u16, &[u8])> {
    let [b0, b1, s0, s1, _, _, _, _, _, _, _, _, body @ ..] = p else { return None };
    if b0 >> 6 != 2 {
        return None;
    }
    // Padding: the last octet counts the octets to drop, itself included
    // (so at least 1, and never part of the fixed header).
    let body = if b0 & 0x20 != 0 {
        let pad = usize::from(*body.last()?);
        if pad == 0 {
            return None;
        }
        body.get(..body.len().checked_sub(pad)?)?
    } else {
        body
    };
    let body = skip_words(body, usize::from(b0 & 0x0F))?; // CSRC list
    let body = if b0 & 0x10 != 0 {
        let [_, _, l0, l1, ext @ ..] = body else { return None };
        skip_words(ext, usize::from(u16::from_be_bytes([*l0, *l1])))?
    } else {
        body
    };
    Some((b1 & 0x7F, u16::from_be_bytes([*s0, *s1]), body))
}

/// `b` past `n` 32-bit words.
fn skip_words(b: &[u8], n: usize) -> Option<&[u8]> {
    b.get(n.checked_mul(4)?..)
}

/// The sending side of one stream.
pub struct Sender {
    seq: u16,
    ts: u32,
    ssrc: u32,
    first: bool,
}

impl Sender {
    pub fn new(seed: [u8; 10]) -> Self {
        Self {
            seq: u16::from_be_bytes([seed[0], seed[1]]),
            ts: u32::from_be_bytes([seed[2], seed[3], seed[4], seed[5]]),
            ssrc: u32::from_be_bytes([seed[6], seed[7], seed[8], seed[9]]),
            first: true,
        }
    }

    /// One packet of `payload` (8 kHz: one sample per byte).
    pub fn packet(&mut self, pt: u8, payload: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.push(0x80);
        out.push(pt | if self.first { 0x80 } else { 0 });
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.extend_from_slice(payload);
        self.first = false;
        self.seq = self.seq.wrapping_add(1);
        // RTP timestamps are modulo 2^32 (RFC 3550 §5.1).
        #[allow(clippy::cast_possible_truncation, reason = "RTP timestamp arithmetic is modulo 2^32")]
        let samples = payload.len() as u32;
        self.ts = self.ts.wrapping_add(samples);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_bad_packets() {
        let mut s = Sender::new([0, 1, 0, 0, 0, 0, 1, 2, 3, 4]);
        let mut p = Vec::new();
        s.packet(8, &[1, 2, 3], &mut p);
        assert_eq!(p[1], 0x88, "marker on the first packet");
        assert_eq!(parse(&p), Some((8, 1, &[1u8, 2, 3][..])));
        s.packet(8, &[4], &mut p);
        assert_eq!(parse(&p), Some((8, 2, &[4u8][..])));
        assert_eq!(p[1], 8);
        assert_eq!(parse(&p[..11]), None);
        let mut v1 = p.clone();
        v1[0] = 0x40;
        assert_eq!(parse(&v1), None);
        // Padding longer than the packet, extension past the end.
        let mut pad = p.clone();
        pad[0] |= 0x20;
        *pad.last_mut().unwrap() = 200;
        assert_eq!(parse(&pad), None);
        let mut ext = p.clone();
        ext[0] |= 0x10;
        assert_eq!(parse(&ext), None);
    }

    /// A packet: first octet, PT octet, seq 7, ts 0, ssrc 0, then `rest`.
    fn pkt(b0: u8, rest: &[u8]) -> Vec<u8> {
        let mut p = vec![b0, 0x08, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(rest);
        p
    }

    #[test]
    fn parse_cases() {
        // (packet, expected payload or None)
        let cases: Vec<(Vec<u8>, Option<&[u8]>)> = vec![
            (pkt(0x80, &[]), Some(&[])),
            (pkt(0x80, &[1, 2]), Some(&[1, 2])),
            (pkt(0x00, &[1]), None),
            (pkt(0xC0, &[1]), None),
            // Padding: the count includes itself.
            (pkt(0xA0, &[1, 2, 0, 0, 3]), Some(&[1, 2])),
            (pkt(0xA0, &[1]), Some(&[])),
            (pkt(0xA0, &[]), None),
            (pkt(0xA0, &[1, 2, 0]), None),
            (pkt(0xA0, &[9, 9, 9]), None),
            // CSRC list.
            (pkt(0x82, &[0, 0, 0, 1, 0, 0, 0, 2, 7]), Some(&[7])),
            (pkt(0x82, &[0, 0, 0, 1, 0, 0, 0]), None),
            (pkt(0x8F, &[0; 60]), Some(&[])),
            // Header extension: profile, length in words, the words.
            (pkt(0x90, &[0xBE, 0xDE, 0, 1, 1, 2, 3, 4, 5]), Some(&[5])),
            (pkt(0x90, &[0xBE, 0xDE, 0, 0, 5]), Some(&[5])),
            (pkt(0x90, &[0xBE, 0xDE, 0, 2, 1, 2, 3, 4]), None),
            (pkt(0x90, &[0xBE, 0xDE]), None),
            // CSRC, extension and padding together.
            (pkt(0xB1, &[0, 0, 0, 1, 0, 0, 0, 1, 9, 9, 9, 9, 6, 6, 0, 2]), Some(&[6, 6])),
        ];
        for (p, want) in cases {
            assert_eq!(parse(&p).map(|(_, _, b)| b), want, "{p:02x?}");
        }
        assert_eq!(parse(&pkt(0x80, &[])).map(|(pt, seq, _)| (pt, seq)), Some((8, 7)));
        let mut marked = pkt(0x80, &[]);
        marked[1] = 0x80 | 101;
        assert_eq!(parse(&marked).map(|(pt, _, _)| pt), Some(101), "the marker bit is not part of the PT");
    }

    #[test]
    fn sender_headers_are_exact_and_wrap() {
        let mut s = Sender::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xA0, 0xDE, 0xAD, 0xBE, 0xEF]);
        let mut p = Vec::new();
        s.packet(0, &[0xFF; 160], &mut p);
        assert_eq!(p[..12], [0x80, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xA0, 0xDE, 0xAD, 0xBE, 0xEF], "marker on the first packet");
        assert_eq!(p.len(), 172);
        s.packet(0, &[0xFF; 160], &mut p);
        // seq 0xFFFF + 1 wraps to 0; ts 0xFFFFFFA0 + 160 wraps to 0x40.
        assert_eq!(p[..12], [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xDE, 0xAD, 0xBE, 0xEF]);
        s.packet(8, &[], &mut p);
        assert_eq!(p[..12], [0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0xE0, 0xDE, 0xAD, 0xBE, 0xEF]);
        s.packet(8, &[1], &mut p);
        assert_eq!(&p[4..8], &[0, 0, 0, 0xE0], "an empty payload doesn't advance the timestamp");
        assert_eq!(parse(&p), Some((8, 2, &[1u8][..])));
    }
}
