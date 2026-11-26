//! Carrier-grade routing and accounting modules (Kamailio names, one
//! `loadmodule` each): `dialplan`, `lcr` (with the Sipwise patches),
//! `acc`, `uac`, `topoh`, `topos`.

use sip_core::Module;
use sip_parser::uri::name_addr;
use sip_parser::{HdrFlags, HdrKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod acc;
mod dialplan;
mod lcr;
#[cfg(test)]
mod testutil;
mod topo;
mod uac;

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &["dialplan", "lcr", "acc", "uac", "topoh", "topos"];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "dialplan" => Arc::new(dialplan::Dialplan::default()),
        "lcr" => Arc::new(lcr::Lcr::default()),
        "acc" => Arc::new(acc::Acc::default()),
        "uac" => Arc::new(uac::Uac::default()),
        "topoh" => Arc::new(topo::Topo::new(false)),
        "topos" => Arc::new(topo::Topo::new(true)),
        _ => return None,
    })
}

pub(crate) fn rand_u64() -> u64 {
    static S: AtomicU64 = AtomicU64::new(0);
    let mut x = S.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
        ^ SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs().wrapping_mul(1_000_000_000).wrapping_add(u64::from(d.subsec_nanos())));
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// A header value split into (display + `<uri>` part, uri, rest-with-params).
/// `"A" <sip:a@x>;tag=1` → (`"A" <sip:a@x>`, `sip:a@x`, `;tag=1`).
pub(crate) fn split_nameaddr(body: &str) -> (String, String, String) {
    let body = body.trim();
    if let Some((head, rest)) = body.find('>').and_then(|gt| body.split_at_checked(gt.checked_add(1)?)) {
        let uri = String::from_utf8_lossy(name_addr(head.as_bytes()).0).into_owned();
        return (head.to_string(), uri, rest.to_string());
    }
    match body.find(';').and_then(|i| body.split_at_checked(i)) {
        Some((uri, params)) => (uri.to_string(), uri.to_string(), params.to_string()),
        None => (body.to_string(), body.to_string(), String::new()),
    }
}

/// `(header line start, end, body)` of the first header of `kind`.
pub(crate) fn hdr_span(ctx: &mut sip_core::Ctx<'_, '_>, kind: HdrKind) -> Option<(usize, usize, String)> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    let h = ctx.msg.get(kind)?;
    let start = ctx.msg.offset_of(h.body);
    Some((start, start.saturating_add(h.body.len()), String::from_utf8_lossy(h.body).into_owned()))
}

/// `want_args`, as an array to destructure: `let [name, value] = args(a)?;`.
pub(crate) fn args<const N: usize>(a: &[sip_core::Arg]) -> Result<&[sip_core::Arg; N], String> {
    <&[sip_core::Arg; N]>::try_from(a).map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

/// Shell-style glob (`*`, `?`, `[abc]`, `[!a-z]`) for dialplan's fnmatch
/// rules; a `[` without `]` is a literal `[`.
///
/// Iterative, backtracking only to the last `*` (every other token matches
/// exactly one byte): O(len(pat)·len(s)) time and constant stack for any
/// input — `s` is usually a number or URI part from the wire.
pub(crate) fn fnmatch(pat: &[u8], s: &[u8]) -> bool {
    let (mut p_at, mut s_at) = (pat, s);
    // Where to retry after a mismatch: just past the last `*`, and the
    // input that `*` hasn't swallowed yet.
    let mut star: Option<(&[u8], &[u8])> = None;
    loop {
        if let Some((b'*', after)) = p_at.split_first() {
            star = Some((after, s_at));
            p_at = after;
            continue;
        }
        match s_at.split_first() {
            None if p_at.is_empty() => return true,
            Some((&c, s_rest)) => {
                if let Some(p_rest) = fnmatch_one(p_at, c) {
                    (p_at, s_at) = (p_rest, s_rest);
                    continue;
                }
            }
            None => {}
        }
        // Mismatch: the last `*` takes one more byte.
        let Some((p_star, Some((_, s_star)))) = star.map(|(sp, ss)| (sp, ss.split_first())) else { return false };
        star = Some((p_star, s_star));
        (p_at, s_at) = (p_star, s_star);
    }
}

/// The pattern after its first token (not `*`) if that token matches `c`.
fn fnmatch_one(p: &[u8], c: u8) -> Option<&[u8]> {
    let (&first, rest) = p.split_first()?;
    match first {
        b'?' => Some(rest),
        b'[' if rest.contains(&b']') => {
            let mut parts = rest.splitn(2, |&x| x == b']');
            let (set, after) = (parts.next()?, parts.next()?);
            let (neg, mut set) = match set.split_first() {
                Some((b'!', set)) => (true, set),
                _ => (false, set),
            };
            let mut hit = false;
            loop {
                set = match set {
                    [lo, b'-', hi, more @ ..] => {
                        hit |= (*lo..=*hi).contains(&c);
                        more
                    }
                    [x, more @ ..] => {
                        hit |= *x == c;
                        more
                    }
                    [] => break,
                };
            }
            (hit != neg).then_some(after)
        }
        _ => (first == c).then_some(rest),
    }
}

/// Unpadded URL-safe base64.
pub(crate) fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = String::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for c in data.chunks(3) {
        let byte = |i: usize| u32::from(c.get(i).copied().unwrap_or(0));
        let n = byte(0) << 16 | byte(1) << 8 | byte(2);
        // Unpadded: the bytes' c.len() + 1 leading sextets.
        let sextets = [n >> 18, n >> 12, n >> 6, n].map(|x| (x & 63) as usize);
        o.extend(sextets.iter().take(c.len().saturating_add(1)).filter_map(|&i| T.get(i)).map(|&b| char::from(b)));
    }
    o
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    let v = |c: u8| -> Option<u32> {
        // (abs_diff: c is at or above the range start.)
        Some(u32::from(match c {
            b'A'..=b'Z' => c.abs_diff(b'A'),
            b'a'..=b'z' => c.abs_diff(b'a').saturating_add(26),
            b'0'..=b'9' => c.abs_diff(b'0').saturating_add(52),
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        }))
    };
    let b = s.trim_end_matches('=').as_bytes();
    let mut o = Vec::with_capacity(b.len().saturating_mul(3) / 4);
    for c in b.chunks(4) {
        if c.len() < 2 {
            return None;
        }
        let n = c.iter().try_fold(0u32, |n, &x| Some(n << 6 | v(x)?))?;
        // A short last group: as if padded with zero sextets.
        let n = (c.len()..4).fold(n, |n, _| n << 6);
        // n holds 24 bits: big-endian bytes 1..=3, of which c.len() - 1 are real.
        o.extend_from_slice(n.to_be_bytes().get(1..c.len()).unwrap_or_default());
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert!(fnmatch(b"49*", b"4930") && fnmatch(b"0[1-9]?", b"012") && !fnmatch(b"0[!1-9]*", b"01"));
        for s in [&b""[..], b"a", b"ab", b"abc", b"sip:x@1.2.3.4:5060;transport=tcp"] {
            assert_eq!(unb64(&b64(s)).unwrap(), s);
        }
        assert_eq!(split_nameaddr("\"A\" <sip:a@x>;tag=1"), ("\"A\" <sip:a@x>".into(), "sip:a@x".into(), ";tag=1".into()));
        assert_eq!(split_nameaddr("sip:a@x;tag=1").2, ";tag=1");
        assert_eq!(split_nameaddr(" sip:a@x "), ("sip:a@x".into(), "sip:a@x".into(), String::new()), "a bare URI without parameters");
    }

    /// The recursive matcher `fnmatch` replaced (it overflowed the stack on
    /// long input and took exponential time on several `*`).
    #[allow(clippy::arithmetic_side_effects, reason = "test oracle: the old matcher verbatim; i + 2 < set.len() bounds every index")]
    fn fnmatch_ref(pat: &[u8], s: &[u8]) -> bool {
        match (pat.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => fnmatch_ref(&pat[1..], s) || (!s.is_empty() && fnmatch_ref(pat, &s[1..])),
            (Some(b'?'), Some(_)) => fnmatch_ref(&pat[1..], &s[1..]),
            (Some(b'['), Some(&c)) => match pat.iter().position(|&x| x == b']') {
                Some(e) => {
                    let set = &pat[1..e];
                    let (neg, set) = if set.first() == Some(&b'!') { (true, &set[1..]) } else { (false, set) };
                    let mut hit = false;
                    let mut i = 0;
                    while i < set.len() {
                        if i + 2 < set.len() && set[i + 1] == b'-' {
                            hit |= (set[i]..=set[i + 2]).contains(&c);
                            i += 3;
                        } else {
                            hit |= set[i] == c;
                            i += 1;
                        }
                    }
                    hit != neg && fnmatch_ref(&pat[e + 1..], &s[1..])
                }
                None => c == b'[' && fnmatch_ref(&pat[1..], &s[1..]),
            },
            (Some(&p), Some(&c)) => p == c && fnmatch_ref(&pat[1..], &s[1..]),
            _ => false,
        }
    }

    #[test]
    fn fnmatch_matches_reference() {
        // Every pattern up to length 4 against every input up to length 5.
        let words = |alpha: &[u8], max: usize| {
            let mut out: Vec<Vec<u8>> = vec![Vec::new()];
            let mut last = vec![Vec::new()];
            for _ in 0..max {
                last = last.iter().flat_map(|w: &Vec<u8>| alpha.iter().map(move |&c| [w.as_slice(), &[c]].concat())).collect();
                out.extend(last.iter().cloned());
            }
            out
        };
        let (pats, texts) = (words(b"*?[]!-a1", 4), words(b"a1-[", 5));
        for p in &pats {
            for t in &texts {
                assert_eq!(fnmatch(p, t), fnmatch_ref(p, t), "{:?} vs {:?}", String::from_utf8_lossy(p), String::from_utf8_lossy(t));
            }
        }
    }

    #[test]
    fn fnmatch_long_and_pathological_inputs() {
        let long = vec![b'4'; 4 << 20];
        assert!(fnmatch(b"4*", &long) && !fnmatch(b"*5", &long));
        let s = vec![b'1'; 200];
        assert!(!fnmatch(b"*1*1*1*1*1*1*1*1*1*1*2", &s));
    }

    #[test]
    fn base64_lengths() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg");
        assert_eq!(b64(b"fo"), "Zm8");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(&[0xfb, 0xff]), "-_8");
        assert_eq!(unb64("Zm9vYg").as_deref(), Some(&b"foob"[..]));
        assert_eq!(unb64("Zm9vYg==").as_deref(), Some(&b"foob"[..]));
        assert_eq!(unb64("+/8").as_deref(), Some(&[0xfb, 0xff][..]));
        assert_eq!(unb64("Z"), None);
        assert_eq!(unb64("Zm9*"), None);
    }
}
