//! RFC 5626 flow tokens (the `outbound` module): an edge proxy puts a
//! token naming the client's connection into the user part of its
//! Path / Record-Route URI, so requests routed back through it go out
//! over that same flow. Token = base32hex(proto ‖ ip ‖ port ‖ conn id ‖
//! HMAC-SHA256(secret, those)[..8]) — tamper-proof and stateless.

use crate::net::{Dest, Proto};
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

static KEY: OnceLock<ring::hmac::Key> = OnceLock::new();

static FORCE_FLAG: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(-1);

/// outbound `force_outbound_flag`: use a flow token even without `;ob`.
pub fn set_force_flag(f: i64) {
    FORCE_FLAG.store(f, std::sync::atomic::Ordering::Relaxed);
}

/// Should an edge proxy put a flow token into its Path/Record-Route for
/// this request? (outbound on; the client is our direct neighbour — one
/// Via — and its Contact has `;ob`, or the force flag is set).
pub fn wanted(ctx: &mut crate::Ctx<'_, '_>) -> bool {
    use sip_parser::{HdrFlags, HdrKind};
    if !enabled() || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
        return false;
    }
    let vias: usize = ctx.msg.headers.iter().filter(|h| h.kind == HdrKind::Via).map(|h| sip_parser::uri::split_list(h.body).len()).sum();
    if vias != 1 {
        return false;
    }
    let f = FORCE_FLAG.load(std::sync::atomic::Ordering::Relaxed);
    if (0..64).contains(&f) && ctx.ext::<crate::TxnVars>().is_some_and(|t| t.flags & (1 << f) != 0) {
        return true;
    }
    ctx.msg.get(HdrKind::Contact).is_some_and(|h| {
        sip_parser::uri::split_list(h.body).iter().any(|c| sip_parser::parse_uri(sip_parser::uri::name_addr(c).0).is_some_and(|u| u.param(b"ob").is_some()))
    })
}

/// Turn flow tokens on (outbound module `mod_init`).
pub fn enable(secret: &[u8]) {
    #[allow(clippy::let_underscore_must_use, reason = "set once: a later call keeps the first value")]
    let _ = KEY.set(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret));
}

pub fn enabled() -> bool {
    KEY.get().is_some()
}

const ALPHA: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "bits stays below 13 and shifts by less than 32; symbols are masked to 0..32, the length of ALPHA"
)]
fn b32(data: &[u8]) -> String {
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHA[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHA[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[allow(clippy::arithmetic_side_effects, reason = "bits stays below 13, shifts are by less than 32 and the accumulator only keeps its low bits")]
fn unb32(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.bytes() {
        let v = u32::try_from(ALPHA.iter().position(|&a| a == c.to_ascii_lowercase())?).ok()?;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation, reason = "the low 8 bits of the accumulator are the decoded byte")]
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn raw(d: &Dest) -> Vec<u8> {
    let mut v = vec![d.proto as u8];
    match d.addr.ip() {
        IpAddr::V4(ip) => v.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => v.extend_from_slice(&ip.octets()),
    }
    v.extend_from_slice(&d.addr.port().to_be_bytes());
    v.extend_from_slice(&d.conn.unwrap_or(0).to_be_bytes());
    v
}

/// Token for the flow `d` (None when outbound isn't enabled).
pub fn encode(d: &Dest) -> Option<String> {
    let key = KEY.get()?;
    let mut v = raw(d);
    let mac = ring::hmac::sign(key, &v);
    v.extend_from_slice(mac.as_ref().get(..8)?);
    Some(b32(&v))
}

/// The flow a token names, if it is one of ours.
pub fn decode(tok: &str) -> Option<Dest> {
    let key = KEY.get()?;
    let v = unb32(tok)?;
    if v.len() != 1 + 4 + 2 + 8 + 8 && v.len() != 1 + 16 + 2 + 8 + 8 {
        return None;
    }
    let (body, mac) = v.split_last_chunk::<8>()?;
    if ring::hmac::sign(key, body).as_ref().first_chunk::<8>() != Some(mac) {
        return None;
    }
    // proto ‖ ip (4 or 16) ‖ port (2) ‖ conn (8)
    let (&proto, rest) = body.split_first()?;
    let proto = *Proto::ALL.get(usize::from(proto))?;
    let (ip, tail): (IpAddr, _) = match rest.split_first_chunk::<4>() {
        Some((v4, tail)) if tail.len() == 10 => (IpAddr::from(*v4), tail),
        _ => {
            let (v6, tail) = rest.split_first_chunk::<16>()?;
            (IpAddr::from(*v6), tail)
        }
    };
    let [p0, p1, c0, c1, c2, c3, c4, c5, c6, c7] = <[u8; 10]>::try_from(tail).ok()?;
    let port = u16::from_be_bytes([p0, p1]);
    let conn = u64::from_be_bytes([c0, c1, c2, c3, c4, c5, c6, c7]);
    let mut d = Dest::new(proto, SocketAddr::new(ip, port));
    d.conn = (conn != 0).then_some(conn);
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        enable(b"secret");
        let mut d = Dest::new(Proto::Tcp, "10.1.2.3:5070".parse().unwrap());
        d.conn = Some(42);
        let t = encode(&d).unwrap();
        assert!(t.bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(decode(&t), Some(d));
        let mut bad = t.clone().into_bytes();
        bad[3] = if bad[3] == b'0' { b'1' } else { b'0' };
        assert_eq!(decode(std::str::from_utf8(&bad).unwrap()), None, "tampered token");
        let v6 = Dest::new(Proto::Udp, "[2001:db8::1]:5060".parse().unwrap());
        assert_eq!(decode(&encode(&v6).unwrap()), Some(v6));
    }

    #[test]
    fn roundtrip_for_each_transport_and_family() {
        enable(b"secret");
        for proto in Proto::ALL {
            for addr in ["192.0.2.1:1", "[2001:db8::ff]:65535", "0.0.0.0:0"] {
                for conn in [None, Some(1), Some(u64::MAX)] {
                    let mut d = Dest::new(proto, addr.parse().unwrap());
                    d.conn = conn;
                    let t = encode(&d).unwrap();
                    assert_eq!(decode(&t), Some(d), "{d}");
                    assert_eq!(decode(&t.to_ascii_uppercase()), Some(d), "tokens are case-insensitive");
                }
            }
        }
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        enable(b"secret");
        let t = encode(&Dest::new(Proto::Udp, "192.0.2.1:5060".parse().unwrap())).unwrap();
        let cases = ["", "0", "w", t.get(..t.len() - 1).unwrap(), &format!("{t}00"), &t.replace(|c: char| c.is_ascii_digit(), "x")];
        for bad in cases {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn base32hex_known_values() {
        let cases: &[(&[u8], &str)] =
            &[(b"", ""), (b"f", "co"), (b"fo", "cpng"), (b"foo", "cpnmu"), (b"foob", "cpnmuog"), (b"fooba", "cpnmuoj1"), (b"foobar", "cpnmuoj1e8")];
        for (raw, enc) in cases {
            assert_eq!(b32(raw), *enc);
            assert_eq!(unb32(enc).as_deref(), Some(*raw));
        }
        assert_eq!(unb32("w"), None, "outside the alphabet");
    }
}
