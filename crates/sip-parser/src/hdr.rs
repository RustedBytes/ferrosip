//! Header kinds and the "which headers have been parsed" bitmask.
//! Mirrors Kamailio's `hdr_flags_t` / `HDR_*_F` (src/core/parser/hf.h).

use std::ops::{BitOr, BitOrAssign};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum HdrKind {
    Via = 0,
    From,
    To,
    CallId,
    CSeq,
    MaxForwards,
    ContentLength,
    Contact,
    Route,
    RecordRoute,
    UserAgent,
    Other,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct HdrFlags(pub u32);

impl HdrFlags {
    pub const NONE: Self = Self(0);
    pub const VIA: Self = Self::of(HdrKind::Via);
    pub const FROM: Self = Self::of(HdrKind::From);
    pub const TO: Self = Self::of(HdrKind::To);
    pub const CALLID: Self = Self::of(HdrKind::CallId);
    pub const CSEQ: Self = Self::of(HdrKind::CSeq);
    pub const MAXFWD: Self = Self::of(HdrKind::MaxForwards);
    pub const CLEN: Self = Self::of(HdrKind::ContentLength);
    pub const CONTACT: Self = Self::of(HdrKind::Contact);
    /// Second Via value (may live in the same header line as the first).
    pub const VIA2: Self = Self(1 << 30);
    /// End of headers reached: everything is parsed.
    pub const EOH: Self = Self(1 << 31);

    pub const fn of(k: HdrKind) -> Self {
        match k {
            HdrKind::Other => Self(0),
            k => Self(1 << k as u32),
        }
    }
    #[inline]
    pub const fn contains(self, o: Self) -> bool {
        self.0 & o.0 == o.0
    }
}

impl BitOr for HdrFlags {
    type Output = Self;
    fn bitor(self, o: Self) -> Self {
        Self(self.0 | o.0)
    }
}
impl BitOrAssign for HdrFlags {
    fn bitor_assign(&mut self, o: Self) {
        self.0 |= o.0
    }
}

/// Header-name classification. Dispatching on length first means most names
/// are rejected/accepted with one or two compares (Kamailio's parse_hname2.c
/// does the same trick with 4-byte words).
#[inline]
pub fn kind_of(name: &[u8]) -> HdrKind {
    use HdrKind::*;
    if let [c] = name {
        return match c.to_ascii_lowercase() {
            b'v' => Via,
            b'f' => From,
            b't' => To,
            b'i' => CallId,
            b'l' => ContentLength,
            b'm' => Contact,
            _ => Other,
        };
    }
    let eq = |s: &[u8]| name.eq_ignore_ascii_case(s);
    match name.len() {
        2 if eq(b"to") => To,
        3 if eq(b"via") => Via,
        4 if eq(b"from") => From,
        4 if eq(b"cseq") => CSeq,
        5 if eq(b"route") => Route,
        7 if eq(b"call-id") => CallId,
        7 if eq(b"contact") => Contact,
        10 if eq(b"user-agent") => UserAgent,
        12 if eq(b"max-forwards") => MaxForwards,
        12 if eq(b"record-route") => RecordRoute,
        14 if eq(b"content-length") => ContentLength,
        _ => Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_of_classifies_full_and_compact_names_case_insensitively() {
        use HdrKind::*;
        let cases: &[(&[u8], HdrKind)] = &[
            (b"Via", Via),
            (b"VIA", Via),
            (b"v", Via),
            (b"V", Via),
            (b"From", From),
            (b"f", From),
            (b"To", To),
            (b"t", To),
            (b"Call-ID", CallId),
            (b"call-id", CallId),
            (b"i", CallId),
            (b"CSeq", CSeq),
            (b"cseq", CSeq),
            (b"Max-Forwards", MaxForwards),
            (b"Content-Length", ContentLength),
            (b"CONTENT-LENGTH", ContentLength),
            (b"l", ContentLength),
            (b"Contact", Contact),
            (b"m", Contact),
            (b"Route", Route),
            (b"Record-Route", RecordRoute),
            (b"User-Agent", UserAgent),
            // Compact forms the core does not track.
            (b"c", Other),
            (b"k", Other),
            (b"s", Other),
            (b"e", Other),
            // Near misses.
            (b"", Other),
            (b"Vias", Other),
            (b"X-Content-Length", Other),
            (b"Call-I", Other),
            (b"Contacts", Other),
            (b"Record_Route", Other),
            (b"Content-Type", Other),
        ];
        for &(name, want) in cases {
            assert_eq!(kind_of(name), want, "{:?}", String::from_utf8_lossy(name));
        }
    }

    #[test]
    fn hdr_flags_of_other_is_empty_and_flags_combine() {
        assert_eq!(HdrFlags::of(HdrKind::Other), HdrFlags::NONE);
        let mut f = HdrFlags::VIA | HdrFlags::CALLID;
        assert!(f.contains(HdrFlags::VIA) && f.contains(HdrFlags::CALLID));
        assert!(!f.contains(HdrFlags::FROM));
        assert!(!f.contains(HdrFlags::VIA | HdrFlags::FROM), "contains needs every flag");
        assert!(f.contains(HdrFlags::NONE));
        f |= HdrFlags::FROM;
        assert!(f.contains(HdrFlags::VIA | HdrFlags::FROM));
        let all = [
            HdrKind::Via,
            HdrKind::From,
            HdrKind::To,
            HdrKind::CallId,
            HdrKind::CSeq,
            HdrKind::MaxForwards,
            HdrKind::ContentLength,
            HdrKind::Contact,
            HdrKind::Route,
            HdrKind::RecordRoute,
            HdrKind::UserAgent,
        ];
        let bits = all.iter().fold(HdrFlags::NONE, |acc, &k| acc | HdrFlags::of(k));
        assert_eq!(bits.0.count_ones(), 11, "every kind has its own bit");
        assert_eq!(bits.0 & (HdrFlags::VIA2.0 | HdrFlags::EOH.0), 0, "VIA2/EOH do not collide with kinds");
    }
}
