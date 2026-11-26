//! Diameter (RFC 6733) for the IMS modules — the Kamailio `cdp` /
//! `cdp_avp` equivalent: a message/AVP codec ([`Msg`], [`Avp`]) and a
//! peer manager ([`Peers`]) that keeps TCP, TLS or SCTP connections to the
//! configured peers open (CER/CEA, DWR/DWA watchdog, reconnects), answers DPR, accepts
//! incoming peers, and sends requests with blocking, timed answers.
#![forbid(unsafe_code)]
// An ignored Result here is a decision: say why (`#[allow]` + reason).
#![warn(clippy::let_underscore_must_use)]

pub mod codes;
mod error;
mod peer;
mod watchdog;
mod wire;

pub use codes::{AppId, AvpCode, CmdCode, ResultCode, VendorId};
pub use error::DiameterError;
pub use peer::{AnswerFn, Config, Handler, PeerCfg, PeerInfo, Peers, Route, TlsCfg, parse_xml_config};
pub use wire::Proto;

use std::net::IpAddr;

/// One AVP. `data` is the raw payload (unpadded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Avp {
    pub code: AvpCode,
    /// V (0x80), M (0x40), P (0x20).
    pub flags: u8,
    pub vendor: Option<VendorId>,
    pub data: Vec<u8>,
}

pub const FLAG_V: u8 = 0x80;
pub const FLAG_M: u8 = 0x40;

impl Avp {
    /// A mandatory AVP, vendor-specific when `vendor` is given.
    pub fn new(code: AvpCode, vendor: Option<VendorId>, data: Vec<u8>) -> Self {
        Avp { code, flags: FLAG_M | if vendor.is_some() { FLAG_V } else { 0 }, vendor, data }
    }
    pub fn str(code: AvpCode, vendor: Option<VendorId>, s: &str) -> Self {
        Self::new(code, vendor, s.as_bytes().to_vec())
    }
    /// An Unsigned32 (an id or a result code goes in as `.get()`:
    /// `Avp::u32(VENDOR_ID, None, VENDOR_3GPP.get())`).
    pub fn u32(code: AvpCode, vendor: Option<VendorId>, v: u32) -> Self {
        Self::new(code, vendor, v.to_be_bytes().to_vec())
    }
    pub fn u64(code: AvpCode, vendor: Option<VendorId>, v: u64) -> Self {
        Self::new(code, vendor, v.to_be_bytes().to_vec())
    }
    pub fn group(code: AvpCode, vendor: Option<VendorId>, avps: Vec<Avp>) -> Self {
        let mut d = Vec::new();
        for a in &avps {
            a.encode(&mut d);
        }
        Self::new(code, vendor, d)
    }
    /// Address type (RFC 6733 §4.3.1).
    pub fn addr(code: AvpCode, ip: IpAddr) -> Self {
        let mut d = Vec::new();
        match ip {
            IpAddr::V4(v) => {
                d.extend_from_slice(&1u16.to_be_bytes());
                d.extend_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                d.extend_from_slice(&2u16.to_be_bytes());
                d.extend_from_slice(&v.octets());
            }
        }
        Self::new(code, None, d)
    }
    /// Not mandatory (clears M).
    pub fn optional(mut self) -> Self {
        self.flags &= !FLAG_M;
        self
    }

    pub fn as_str(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
    pub fn as_u32(&self) -> Option<u32> {
        Some(u32::from_be_bytes(self.data.get(..4)?.try_into().ok()?))
    }
    pub fn as_u64(&self) -> Option<u64> {
        Some(u64::from_be_bytes(self.data.get(..8)?.try_into().ok()?))
    }
    /// Children of a grouped AVP.
    pub fn group_avps(&self) -> Vec<Avp> {
        decode_avps(&self.data).unwrap_or_default()
    }

    /// Encoded length without padding.
    fn len(&self) -> usize {
        self.data.len().saturating_add(if self.vendor.is_some() { 12 } else { 8 })
    }

    /// Encode (the length must fit in 24 bits: see [`Msg::try_encode`]).
    pub fn encode(&self, out: &mut Vec<u8>) {
        let len = self.len();
        out.extend_from_slice(&self.code.0.to_be_bytes());
        let flags = if self.vendor.is_some() { self.flags | FLAG_V } else { self.flags & !FLAG_V };
        out.push(flags);
        out.extend_from_slice(&len24(len));
        if let Some(v) = self.vendor {
            out.extend_from_slice(&v.0.to_be_bytes());
        }
        out.extend_from_slice(&self.data);
        out.extend(std::iter::repeat_n(0, padding(len)));
    }
}

/// Zero bytes that pad `len` up to a multiple of 4 (RFC 6733 §4.1):
/// (4 - len % 4) % 4, i.e. -len mod 4.
fn padding(len: usize) -> usize {
    len.wrapping_neg() % 4
}

/// Decode a run of AVPs.
pub fn decode_avps(mut b: &[u8]) -> Option<Vec<Avp>> {
    let mut v = Vec::new();
    while !b.is_empty() {
        let &[c0, c1, c2, c3, flags, l0, l1, l2, ref after_len @ ..] = b else { return None };
        let code = AvpCode(u32::from_be_bytes([c0, c1, c2, c3]));
        let len = u32::from_be_bytes([0, l0, l1, l2]) as usize;
        let (vendor, hlen) = if flags & FLAG_V != 0 { (Some(VendorId(u32::from_be_bytes(*after_len.first_chunk()?))), 12) } else { (None, 8) };
        if len < hlen {
            return None;
        }
        v.push(Avp { code, flags, vendor, data: b.get(hlen..len)?.to_vec() });
        // The last AVP may lack its padding.
        b = b.get(len.saturating_add(padding(len))..).unwrap_or_default();
    }
    Some(v)
}

/// Find an AVP among `avps`.
pub fn find(avps: &[Avp], code: AvpCode, vendor: Option<VendorId>) -> Option<&Avp> {
    avps.iter().find(|a| a.code == code && a.vendor == vendor)
}

/// A Diameter message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    /// R (0x80), P (0x40), E (0x20), T (0x10).
    pub flags: u8,
    pub cmd: CmdCode,
    pub app: AppId,
    pub hbh: u32,
    pub e2e: u32,
    pub avps: Vec<Avp>,
}

/// Largest value of the 24-bit length and command code fields.
pub const MAX_24: u32 = 0xff_ffff;

/// A length as the 3-byte wire field, saturating at [`MAX_24`] (callers
/// check the limit first: [`Msg::try_encode`]).
fn len24(len: usize) -> [u8; 3] {
    let [_, a, b, c] = u32::try_from(len).unwrap_or(MAX_24).min(MAX_24).to_be_bytes();
    [a, b, c]
}

pub const FLAG_R: u8 = 0x80;
pub const FLAG_P: u8 = 0x40;
pub const FLAG_E: u8 = 0x20;

impl Msg {
    pub fn request(cmd: CmdCode, app: AppId) -> Self {
        Msg { flags: FLAG_R | FLAG_P, cmd, app, hbh: 0, e2e: 0, avps: Vec::new() }
    }
    pub fn is_request(&self) -> bool {
        self.flags & FLAG_R != 0
    }
    /// An answer to `self` (same ids, R cleared).
    pub fn answer(&self) -> Msg {
        Msg { flags: self.flags & FLAG_P, cmd: self.cmd, app: self.app, hbh: self.hbh, e2e: self.e2e, avps: Vec::new() }
    }
    pub fn add(&mut self, a: Avp) -> &mut Self {
        self.avps.push(a);
        self
    }
    pub fn with(mut self, a: Avp) -> Self {
        self.avps.push(a);
        self
    }
    pub fn get(&self, code: AvpCode, vendor: Option<VendorId>) -> Option<&Avp> {
        find(&self.avps, code, vendor)
    }
    pub fn get_all(&self, code: AvpCode, vendor: Option<VendorId>) -> Vec<&Avp> {
        self.avps.iter().filter(|a| a.code == code && a.vendor == vendor).collect()
    }
    pub fn str(&self, code: AvpCode) -> Option<String> {
        self.get(code, None).map(Avp::as_str)
    }
    /// Result-Code, or the Experimental-Result-Code inside Experimental-Result.
    pub fn result(&self) -> Option<ResultCode> {
        if let Some(r) = self.get(codes::RESULT_CODE, None).and_then(Avp::as_u32) {
            return Some(ResultCode(r));
        }
        let er = self.get(codes::EXPERIMENTAL_RESULT, None)?.group_avps();
        find(&er, codes::EXPERIMENTAL_RESULT_CODE, None).and_then(Avp::as_u32).map(ResultCode)
    }

    /// [`Msg::encode`], or an error when the command code or a length does
    /// not fit its 24-bit field (the encoding would be silently wrong).
    pub fn try_encode(&self) -> Result<Vec<u8>, String> {
        if self.cmd.0 > MAX_24 {
            return Err(format!("Diameter command code {} does not fit in 24 bits", self.cmd));
        }
        if let Some(a) = self.avps.iter().find(|a| a.len() > MAX_24 as usize) {
            return Err(format!("Diameter AVP {} is {} bytes, over the 24-bit length", a.code, a.len()));
        }
        let b = self.encode();
        if b.len() > MAX_24 as usize {
            return Err(format!("Diameter message (command {}) is {} bytes, over the 24-bit length", self.cmd, b.len()));
        }
        Ok(b)
    }

    /// Encode; the fields are assumed to fit (use [`Msg::try_encode`] for
    /// what goes on the wire).
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for a in &self.avps {
            a.encode(&mut body);
        }
        let len = body.len().saturating_add(20);
        let mut out = Vec::with_capacity(len);
        out.push(1);
        out.extend_from_slice(&len24(len));
        out.push(self.flags);
        let [_, cmd @ ..] = self.cmd.0.to_be_bytes(); // 24 bits
        out.extend_from_slice(&cmd);
        out.extend_from_slice(&self.app.0.to_be_bytes());
        out.extend_from_slice(&self.hbh.to_be_bytes());
        out.extend_from_slice(&self.e2e.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Length of the message at the start of `b` (needs 4 bytes).
    pub fn frame_len(b: &[u8]) -> Option<usize> {
        match *b {
            [1, l0, l1, l2, ..] => Some(u32::from_be_bytes([0, l0, l1, l2]) as usize),
            _ => None,
        }
    }

    pub fn decode(b: &[u8]) -> Option<Msg> {
        let len = Self::frame_len(b)?;
        let (hdr, avps) = b.get(..len)?.split_first_chunk::<20>()?;
        let [_ver, _, _, _, flags, c0, c1, c2, a0, a1, a2, a3, h0, h1, h2, h3, e0, e1, e2, e3] = *hdr;
        Some(Msg {
            flags,
            cmd: CmdCode(u32::from_be_bytes([0, c0, c1, c2])),
            app: AppId(u32::from_be_bytes([a0, a1, a2, a3])),
            hbh: u32::from_be_bytes([h0, h1, h2, h3]),
            e2e: u32::from_be_bytes([e0, e1, e2, e3]),
            avps: decode_avps(avps)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_fields_are_refused() {
        let mut m = Msg::request(codes::CMD_MAR, codes::APP_CX);
        m.add(Avp::str(codes::SESSION_ID, None, "s"));
        assert!(m.try_encode().is_ok());
        let mut big = m.clone();
        big.add(Avp::new(codes::USER_NAME, None, vec![0; MAX_24 as usize]));
        assert!(big.try_encode().unwrap_err().contains("AVP"));
        // Each AVP fits, the message does not.
        let mut big = m.clone();
        big.add(Avp::new(codes::USER_NAME, None, vec![0; 9 << 20])).add(Avp::new(codes::USER_NAME, None, vec![0; 9 << 20]));
        assert!(big.try_encode().unwrap_err().contains("message"));
        let mut bad = m.clone();
        bad.cmd = CmdCode(1 << 24);
        assert!(bad.try_encode().unwrap_err().contains("command code"));
    }

    #[test]
    fn roundtrip() {
        let mut m = Msg::request(codes::CMD_MAR, codes::APP_CX);
        m.hbh = 7;
        m.add(Avp::str(codes::SESSION_ID, None, "s;1;2"))
            .add(Avp::str(codes::PUBLIC_IDENTITY, Some(codes::VENDOR_3GPP), "sip:a@x"))
            .add(Avp::group(
                codes::SIP_AUTH_DATA_ITEM,
                Some(codes::VENDOR_3GPP),
                vec![Avp::str(codes::SIP_AUTHENTICATION_SCHEME, Some(codes::VENDOR_3GPP), "SIP Digest")],
            ))
            .add(Avp::u32(codes::SIP_NUMBER_AUTH_ITEMS, Some(codes::VENDOR_3GPP), 1));
        let b = m.encode();
        assert_eq!(b.len() % 4, 0);
        let d = Msg::decode(&b).unwrap();
        assert_eq!(d, m);
        assert_eq!(d.get(codes::PUBLIC_IDENTITY, Some(codes::VENDOR_3GPP)).unwrap().as_str(), "sip:a@x");
        let g = d.get(codes::SIP_AUTH_DATA_ITEM, Some(codes::VENDOR_3GPP)).unwrap().group_avps();
        assert_eq!(find(&g, codes::SIP_AUTHENTICATION_SCHEME, Some(codes::VENDOR_3GPP)).unwrap().as_str(), "SIP Digest");
        let mut a = d.answer();
        a.add(Avp::group(
            codes::EXPERIMENTAL_RESULT,
            None,
            vec![Avp::u32(codes::VENDOR_ID, None, 10415), Avp::u32(codes::EXPERIMENTAL_RESULT_CODE, None, 5001)],
        ));
        assert_eq!(a.result(), Some(ResultCode(5001)));
        assert!(!a.is_request() && a.hbh == 7);
    }
    /// The bytes of one AVP as [`Avp::encode`] writes them.
    fn enc(a: &Avp) -> Vec<u8> {
        let mut v = Vec::new();
        a.encode(&mut v);
        v
    }

    #[test]
    fn avp_header_length_and_padding_are_exact() {
        // (data length, vendor, encoded length field, total bytes on the wire)
        let cases: &[(usize, bool, u32, usize)] = &[
            (0, false, 8, 8),
            (1, false, 9, 12),
            (2, false, 10, 12),
            (3, false, 11, 12),
            (4, false, 12, 12),
            (5, false, 13, 16),
            (0, true, 12, 12),
            (1, true, 13, 16),
            (4, true, 16, 16),
        ];
        for &(n, vendor, len, total) in cases {
            let a = Avp::new(codes::USER_NAME, vendor.then_some(codes::VENDOR_3GPP), vec![0xab; n]);
            let b = enc(&a);
            assert_eq!(b.len(), total, "wire size for {n} bytes, vendor {vendor}");
            assert_eq!(u32::from_be_bytes([0, b[5], b[6], b[7]]), len, "length field for {n} bytes, vendor {vendor}");
            assert!(b[len as usize..].iter().all(|&x| x == 0), "padding is zeros");
            assert_eq!(decode_avps(&b), Some(vec![a]), "round trip of {n} bytes, vendor {vendor}");
        }
    }

    #[test]
    fn avp_flags_and_vendor_field_on_the_wire() {
        let b = enc(&Avp::u32(codes::SIP_NUMBER_AUTH_ITEMS, codes::V, 1));
        assert_eq!(b, [0, 0, 2, 95, FLAG_V | FLAG_M, 0, 0, 16, 0, 0, 0x28, 0xaf, 0, 0, 0, 1]);
        // optional() clears M only.
        let b = enc(&Avp::str(codes::PRODUCT_NAME, None, "x").optional());
        assert_eq!(b[4], 0);
        // The V flag follows the vendor field, whatever the flags say.
        let stray = Avp { code: codes::USER_NAME, flags: FLAG_V | FLAG_M, vendor: None, data: vec![] };
        assert_eq!(enc(&stray)[4], FLAG_M);
        let missing = Avp { code: codes::USER_NAME, flags: FLAG_M, vendor: Some(codes::VENDOR_3GPP), data: vec![] };
        assert_eq!(enc(&missing)[4], FLAG_V | FLAG_M);
        // The P flag survives the round trip.
        let p = Avp { code: codes::USER_NAME, flags: FLAG_M | 0x20, vendor: None, data: b"a".to_vec() };
        assert_eq!(decode_avps(&enc(&p)).unwrap()[0].flags, FLAG_M | 0x20);
    }

    #[test]
    fn malformed_avp_runs_are_refused() {
        let good = enc(&Avp::str(codes::USER_NAME, None, "alice"));
        let cases: &[(&str, Vec<u8>)] = &[
            ("header cut short", good[..7].to_vec()),
            ("length below the header", vec![0, 0, 0, 1, 0, 0, 0, 7]),
            ("vendor header length below 12", vec![0, 0, 0, 1, FLAG_V, 0, 0, 11, 0, 0, 0x28, 0xaf]),
            ("vendor flag without a vendor id", vec![0, 0, 0, 1, FLAG_V, 0, 0, 8]),
            ("length past the end", vec![0, 0, 0, 1, 0, 0, 0, 13, b'a', b'b', b'c', b'd']),
        ];
        for (what, b) in cases {
            assert_eq!(decode_avps(b), None, "{what}");
        }
        assert_eq!(decode_avps(&[]), Some(vec![]));
        // The last AVP may come without its padding.
        let unpadded = &good[..13];
        assert_eq!(decode_avps(unpadded).unwrap()[0].as_str(), "alice");
        // A bad AVP inside a group: no children, no panic.
        let g = Avp::new(codes::SIP_AUTH_DATA_ITEM, codes::V, vec![0, 0, 0, 1, 0, 0, 0, 99]);
        assert!(g.group_avps().is_empty());
    }

    #[test]
    fn numeric_and_address_values() {
        assert_eq!(Avp::u32(codes::RESULT_CODE, None, 2001).as_u32(), Some(2001));
        assert_eq!(Avp::u64(codes::CC_TIME, None, u64::MAX).as_u64(), Some(u64::MAX));
        assert_eq!(Avp::new(codes::RESULT_CODE, None, vec![0, 0, 7]).as_u32(), None);
        assert_eq!(Avp::new(codes::CC_TIME, None, vec![0; 7]).as_u64(), None);
        let v4 = Avp::addr(codes::HOST_IP_ADDRESS, "192.0.2.1".parse().unwrap());
        assert_eq!(v4.data, [0, 1, 192, 0, 2, 1]);
        let v6 = Avp::addr(codes::HOST_IP_ADDRESS, "::1".parse().unwrap());
        assert_eq!(v6.data.len(), 18);
        assert_eq!(&v6.data[..2], &[0, 2]);
        assert_eq!(v6.data[17], 1);
        assert_eq!(enc(&v4).len(), 16, "6 data bytes + 8 header, padded");
    }

    #[test]
    fn message_header_on_the_wire() {
        let mut m = Msg::request(codes::CMD_UAR, codes::APP_CX);
        m.hbh = 0x0102_0304;
        m.e2e = 0x0a0b_0c0d;
        let b = m.encode();
        assert_eq!(b, [1, 0, 0, 20, FLAG_R | FLAG_P, 0, 1, 44, 1, 0, 0, 0, 1, 2, 3, 4, 10, 11, 12, 13]);
        assert_eq!(Msg::frame_len(&b), Some(20));
        assert_eq!(Msg::decode(&b), Some(m));
        // The 24-bit command code at its limit.
        let mut big = Msg::request(CmdCode(MAX_24), codes::APP_CX);
        big.add(Avp::str(codes::SESSION_ID, None, "s"));
        let d = Msg::decode(&big.try_encode().unwrap()).unwrap();
        assert_eq!(d.cmd, CmdCode(MAX_24));
    }

    #[test]
    fn malformed_messages_are_refused() {
        let mut m = Msg::request(codes::CMD_MAR, codes::APP_CX);
        m.add(Avp::str(codes::SESSION_ID, None, "abc"));
        let good = m.encode();
        let mut v2 = good.clone();
        v2[0] = 2;
        let mut short_len = good.clone();
        short_len[3] = 19;
        let mut long_len = good.clone();
        long_len[3] = u8::try_from(good.len() + 4).unwrap();
        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("not version 1", &v2),
            ("length under the 20-byte header", &short_len),
            ("length beyond the buffer", &long_len),
            ("header cut short", &good[..19]),
        ];
        for (what, b) in cases {
            assert_eq!(Msg::decode(b), None, "{what}");
        }
        assert_eq!(Msg::frame_len(&[1, 0, 0]), None);
        // Bytes after the frame belong to the next message.
        let mut two = good.clone();
        two.extend_from_slice(&good);
        assert_eq!(Msg::decode(&two), Some(m));
    }

    #[test]
    fn answers_keep_ids_and_proxiable_only() {
        let mut m = Msg::request(codes::CMD_SAR, codes::APP_CX);
        m.flags |= FLAG_E | 0x10;
        m.hbh = 5;
        m.e2e = 6;
        m.add(Avp::str(codes::SESSION_ID, None, "s"));
        let a = m.answer();
        assert_eq!((a.flags, a.cmd, a.app, a.hbh, a.e2e), (FLAG_P, codes::CMD_SAR, codes::APP_CX, 5, 6));
        assert!(a.avps.is_empty() && !a.is_request());
    }

    #[test]
    fn result_prefers_result_code_then_experimental() {
        let base = Msg::request(codes::CMD_UAR, codes::APP_CX).answer();
        assert_eq!(base.result(), None);
        let exp = |code: u32| {
            Avp::group(codes::EXPERIMENTAL_RESULT, None, vec![Avp::u32(codes::VENDOR_ID, None, 10415), Avp::u32(codes::EXPERIMENTAL_RESULT_CODE, None, code)])
        };
        let only_exp = base.clone().with(exp(2003));
        assert_eq!(only_exp.result(), Some(ResultCode(2003)));
        let both = base.clone().with(exp(5001)).with(Avp::u32(codes::RESULT_CODE, None, 2001));
        assert_eq!(both.result(), Some(ResultCode(2001)));
        // A vendor-specific Result-Code is not the base AVP.
        let vendor_rc = base.clone().with(Avp::u32(codes::RESULT_CODE, codes::V, 2001));
        assert_eq!(vendor_rc.result(), None);
        let empty_group = base.with(Avp::group(codes::EXPERIMENTAL_RESULT, None, vec![]));
        assert_eq!(empty_group.result(), None);
    }

    #[test]
    fn lookups_match_code_and_vendor() {
        let m = Msg::request(codes::CMD_SAR, codes::APP_CX)
            .with(Avp::str(codes::PUBLIC_IDENTITY, codes::V, "sip:a@x"))
            .with(Avp::str(codes::PUBLIC_IDENTITY, codes::V, "tel:+1"))
            .with(Avp::str(codes::PUBLIC_IDENTITY, None, "other"));
        assert_eq!(m.get_all(codes::PUBLIC_IDENTITY, codes::V).iter().map(|a| a.as_str()).collect::<Vec<_>>(), ["sip:a@x", "tel:+1"]);
        assert_eq!(m.get(codes::PUBLIC_IDENTITY, None).unwrap().as_str(), "other");
        assert_eq!(m.str(codes::PUBLIC_IDENTITY).as_deref(), Some("other"));
        assert!(m.get(codes::PUBLIC_IDENTITY, Some(VendorId(1))).is_none());
    }

    #[test]
    fn nested_groups_round_trip() {
        let inner = Avp::group(
            codes::SUBSCRIPTION_ID,
            None,
            vec![Avp::u32(codes::SUBSCRIPTION_ID_TYPE, None, 2), Avp::str(codes::SUBSCRIPTION_ID_DATA, None, "sip:a@x")],
        );
        let outer = Avp::group(codes::MULTIPLE_SERVICES_CREDIT_CONTROL, None, vec![inner.clone(), Avp::new(codes::USED_SERVICE_UNIT, None, vec![])]);
        let m = Msg::request(codes::CMD_CC, codes::APP_CC).with(outer);
        let b = m.try_encode().unwrap();
        assert_eq!(Msg::frame_len(&b), Some(b.len()));
        let d = Msg::decode(&b).unwrap();
        let g = d.get(codes::MULTIPLE_SERVICES_CREDIT_CONTROL, None).unwrap().group_avps();
        assert_eq!(g[0], inner);
        assert_eq!(find(&g[0].group_avps(), codes::SUBSCRIPTION_ID_DATA, None).unwrap().as_str(), "sip:a@x");
        assert!(g[1].data.is_empty());
    }

    #[test]
    fn an_avp_at_the_24_bit_limit_is_accepted() {
        let at = Avp::new(codes::USER_NAME, None, vec![0; MAX_24 as usize - 8]);
        assert_eq!(at.len(), MAX_24 as usize);
        let mut m = Msg::request(codes::CMD_MAR, codes::APP_CX);
        m.add(at);
        // The AVP fits; the message (20 more bytes plus padding) does not.
        assert!(m.try_encode().unwrap_err().contains("message"));
        let over = Avp::new(codes::USER_NAME, codes::V, vec![0; MAX_24 as usize - 11]);
        assert!(Msg::request(codes::CMD_MAR, codes::APP_CX).with(over).try_encode().unwrap_err().contains("AVP"));
        assert_eq!(len24(usize::MAX), [0xff, 0xff, 0xff]);
        assert_eq!(padding(usize::MAX), 1);
    }
}
