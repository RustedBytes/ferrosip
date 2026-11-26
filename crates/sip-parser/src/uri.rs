//! SIP URI, name-addr and Contact-list parsing (zero-copy).
//! Kamailio equivalents: parse_uri.c, parse_nameaddr.c, contact/parse_contact.c.

use crate::util::{parse_u32, split_host_port, split_once, trim};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uri<'a> {
    /// `sip`, `sips`, `tel`… (as written).
    pub scheme: &'a [u8],
    pub user: Option<&'a [u8]>,
    pub host: &'a [u8],
    pub port: Option<u16>,
    /// Everything after the first `;` of the host part (without headers `?…`).
    pub params: &'a [u8],
}

impl<'a> Uri<'a> {
    pub fn is_sips(&self) -> bool {
        self.scheme.eq_ignore_ascii_case(b"sips")
    }
    /// Value of URI parameter `name` (`Some(b"")` for a flag parameter).
    pub fn param(&self, name: &[u8]) -> Option<&'a [u8]> {
        param(self.params, name)
    }
}

/// `;a=1;b;c=x` → value of `name` (case-insensitive name).
pub fn param<'a>(params: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    params.split(|&c| c == b';').map(trim).find_map(|p| {
        let (k, v) = split_once(p, b'=').map_or((p, &b""[..]), |(k, v)| (trim(k), trim(v)));
        k.eq_ignore_ascii_case(name).then_some(v)
    })
}

/// `sip:user:pw@host:port;params?headers`
pub fn parse_uri(s: &[u8]) -> Option<Uri<'_>> {
    let s = trim(s);
    let (scheme, rest) = split_once(s, b':')?;
    if scheme.is_empty() || !scheme.iter().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let rest = split_once(rest, b'?').map_or(rest, |(r, _headers)| r);
    // userinfo ends at the first '@' (it may itself contain ';' user params).
    let (user, hostpart) = match split_once(rest, b'@') {
        Some((u, hostpart)) => (Some(split_once(u, b':').map_or(u, |(user, _password)| user)), hostpart),
        None => (None, rest),
    };
    let (hp, params) = split_once(hostpart, b';').unwrap_or((hostpart, b""));
    let (host, port) = split_host_port(hp);
    if host.is_empty() {
        return None;
    }
    Some(Uri { scheme, user: user.filter(|u| !u.is_empty()), host, port, params })
}

/// A name-addr / addr-spec: returns (uri, header params after it).
/// `"Bob" <sip:bob@x;transport=tcp>;expires=60` → (`sip:bob@x;transport=tcp`, `expires=60`)
/// `sip:bob@x;expires=60` (no brackets) → (`sip:bob@x`, `expires=60`) — RFC 3261
/// §20: without `<>`, the parameters belong to the header, not the URI.
pub fn name_addr(s: &[u8]) -> (&[u8], &[u8]) {
    let s = trim(s);
    if let Some(after_lt) = after_unquoted(s, b'<')
        && let Some((uri, after)) = split_once(after_lt, b'>')
    {
        let after = trim(after);
        return (trim(uri), after.strip_prefix(b";").unwrap_or(after));
    }
    match split_once(s, b';') {
        Some((uri, params)) => (trim(uri), params),
        None => (s, &b""[..]),
    }
}

/// The bytes after the first `ch` that is not inside double quotes.
fn after_unquoted(s: &[u8], ch: u8) -> Option<&[u8]> {
    let mut q = false;
    let i = s.iter().position(|&c| {
        if c == b'"' {
            q = !q;
        }
        c == ch && !q
    })?;
    s.get(i..)?.get(1..)
}

/// Split a header value on top-level commas (not inside quotes or `<>`).
pub fn split_list(s: &[u8]) -> Vec<&[u8]> {
    let (mut out, mut rest, mut q, mut angle, mut esc) = (Vec::new(), s, false, false, false);
    loop {
        // The quote/bracket state carries over from one item to the next.
        let comma = rest.iter().position(|&c| match c {
            _ if esc => {
                esc = false;
                false
            }
            // A quoted-pair (`\"`, `\\`) inside a quoted-string.
            b'\\' if q => {
                esc = true;
                false
            }
            b'"' if !angle => {
                q = !q;
                false
            }
            b'<' if !q => {
                angle = true;
                false
            }
            b'>' if !q => {
                angle = false;
                false
            }
            b',' => !q && !angle,
            _ => false,
        });
        match comma.and_then(|i| rest.split_at_checked(i)) {
            Some((item, tail)) => {
                out.push(trim(item));
                rest = tail.get(1..).unwrap_or_default();
            }
            None => {
                out.push(trim(rest));
                break;
            }
        }
    }
    out.retain(|p| !p.is_empty());
    out
}

/// One Contact header entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContactSpec<'a> {
    /// `Contact: *`
    pub star: bool,
    pub uri: &'a [u8],
    pub expires: Option<u32>,
    /// q-value in thousandths (q=0.5 → 500).
    pub q: Option<u16>,
    /// RFC 5626 `+sip.instance` (quotes kept off).
    pub instance: Option<&'a [u8]>,
    pub reg_id: Option<u32>,
}

pub fn parse_contact(s: &[u8]) -> ContactSpec<'_> {
    if trim(s) == b"*" {
        return ContactSpec { star: true, uri: b"*", expires: None, q: None, instance: None, reg_id: None };
    }
    let (uri, hp) = name_addr(s);
    ContactSpec {
        star: false,
        uri,
        expires: param(hp, b"expires").and_then(parse_u32),
        q: param(hp, b"q").and_then(parse_q),
        instance: param(hp, b"+sip.instance").map(|v| v.strip_prefix(b"\"").unwrap_or(v).strip_suffix(b"\"").unwrap_or(v)),
        reg_id: param(hp, b"reg-id").and_then(parse_u32),
    }
}

/// `0.5` → 500, `1` → 1000, `1.000` → 1000 (RFC 3261 qvalue).
pub fn parse_q(v: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(v).ok()?;
    let f: f32 = s.parse().ok()?;
    if !(0.0..=1.0).contains(&f) {
        return None;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "f is finite and in 0.0..=1.0, so the rounded product is in 0..=1000")]
    let q = (f * 1000.0).round() as u16;
    Some(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris() {
        let u = parse_uri(b"sip:alice:pw@Example.COM:5070;transport=tcp;lr?Subject=x").unwrap();
        assert_eq!((u.scheme, u.user, u.host, u.port), (&b"sip"[..], Some(&b"alice"[..]), &b"Example.COM"[..], Some(5070)));
        assert_eq!(u.param(b"transport"), Some(&b"tcp"[..]));
        assert_eq!(u.param(b"lr"), Some(&b""[..]));
        let u = parse_uri(b"sips:[2001:db8::1]:5061").unwrap();
        assert!(u.is_sips() && u.user.is_none() && u.host == b"[2001:db8::1]" && u.port == Some(5061));
        let u = parse_uri(b"sip:df7jal23ls0d.invalid;transport=ws").unwrap();
        assert_eq!((u.host, u.param(b"transport")), (&b"df7jal23ls0d.invalid"[..], Some(&b"ws"[..])));
        assert!(parse_uri(b"nonsense").is_none());
        assert_eq!(crate::util::split_host_port(b"[::1"), (&b"[::1"[..], None));
        assert_eq!(crate::util::split_host_port(b"[::1]x"), (&b"[::1]"[..], None));
        assert_eq!(crate::util::split_host_port(b"h:"), (&b"h"[..], None));
        assert_eq!(crate::util::parse_u32(b"999999999"), Some(999_999_999));
        assert_eq!(crate::util::parse_u32(b"4294967295"), Some(u32::MAX));
        assert_eq!(crate::util::parse_u32(b"4294967296"), None);
        assert_eq!(crate::util::parse_u32(b"00000000001"), None, "more than 10 digits");
        assert_eq!(crate::util::parse_u32(b"1/"), None);
        assert!(parse_uri(b":x").is_none() && parse_uri(b"sip:@").is_none());
    }

    #[test]
    fn contacts() {
        let v = split_list(br#""Doe, John" <sip:j@x;a=b,c>;expires=60;q=0.7, sip:k@y;expires=0 , *"#);
        assert_eq!(v.len(), 3);
        let c = parse_contact(v[0]);
        assert_eq!((c.uri, c.expires, c.q), (&b"sip:j@x;a=b,c"[..], Some(60), Some(700)));
        let c = parse_contact(v[1]);
        assert_eq!((c.uri, c.expires), (&b"sip:k@y"[..], Some(0)));
        assert!(parse_contact(v[2]).star);
        let c = parse_contact(br#"<sip:a@b;ob>;+sip.instance="<urn:uuid:1234>";reg-id=1"#);
        assert_eq!((c.instance, c.reg_id), (Some(&b"<urn:uuid:1234>"[..]), Some(1)));
        assert_eq!(name_addr(b"<sip:bob@x>;tag=99"), (&b"sip:bob@x"[..], &b"tag=99"[..]));
        assert_eq!(name_addr(br#""a<b" <sip:c>"#), (&b"sip:c"[..], &b""[..]));
        assert_eq!(name_addr(b"<sip:open"), (&b"<sip:open"[..], &b""[..]));
        assert_eq!(split_list(br#"<a,b>, "x,<y", z,,"#), [&b"<a,b>"[..], br#""x,<y""#, b"z"]);
        assert_eq!(parse_q(b"1"), Some(1000));
        assert_eq!(parse_q(b"1.5"), None);
        assert_eq!(parse_q(b"NaN"), None);
        assert_eq!(parse_q(b"-0.1"), None);
        assert_eq!(parse_q(b"0.0005"), Some(1));
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;

    #[test]
    fn parse_uri_splits_scheme_user_host_port_and_params() {
        // (input, scheme, user, host, port, params)
        type Case<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>, &'a [u8], Option<u16>, &'a [u8]);
        let cases: &[Case] = &[
            (b"sip:example.com", b"sip", None, b"example.com", None, b""),
            (b"sip:alice@example.com", b"sip", Some(b"alice"), b"example.com", None, b""),
            (b"SIP:alice@example.com:5060", b"SIP", Some(b"alice"), b"example.com", Some(5060), b""),
            (b"sip:alice:secret@h", b"sip", Some(b"alice"), b"h", None, b""),
            (b"sip:+49301234;npdi;rn=+4930@gw.example;user=phone", b"sip", Some(b"+49301234;npdi;rn=+4930"), b"gw.example", None, b"user=phone"),
            (b"sip:h;transport=tcp;lr", b"sip", None, b"h", None, b"transport=tcp;lr"),
            (b"sip:h:5080;maddr=10.0.0.1?Subject=hi&Priority=urgent", b"sip", None, b"h", Some(5080), b"maddr=10.0.0.1"),
            (b"sip:bob@h?Route=%3Csip:x%3E", b"sip", Some(b"bob"), b"h", None, b""),
            (b"sip:[2001:db8::1]", b"sip", None, b"[2001:db8::1]", None, b""),
            (b"sip:bob@[2001:db8::1]:5070;transport=udp", b"sip", Some(b"bob"), b"[2001:db8::1]", Some(5070), b"transport=udp"),
            (b"sips:[::1];lr", b"sips", None, b"[::1]", None, b"lr"),
            (b"tel:+1-201-555-0123;phone-context=example.com", b"tel", None, b"+1-201-555-0123", None, b"phone-context=example.com"),
            (b"  sip:h  ", b"sip", None, b"h", None, b""),
            (b"sip:@h", b"sip", None, b"h", None, b""),
            (b"sip:h:65535", b"sip", None, b"h", Some(65535), b""),
            (b"sip:h:65536", b"sip", None, b"h", None, b""),
            (b"sip:h:0", b"sip", None, b"h", Some(0), b""),
            (b"sip:h:abc", b"sip", None, b"h", None, b""),
        ];
        for &(input, scheme, user, host, port, params) in cases {
            let what = String::from_utf8_lossy(input);
            let u = parse_uri(input).unwrap_or_else(|| panic!("{what}"));
            assert_eq!((u.scheme, u.user, u.host, u.port, u.params), (scheme, user, host, port, params), "{what}");
        }
    }

    #[test]
    fn parse_uri_rejects_missing_scheme_or_host() {
        for bad in [&b""[..], b"example.com", b":h", b"si p:h", b"sip:", b"sip:alice@", b"sip:;lr", b"sip:alice@:5060", b"sip:?x=y"] {
            assert!(parse_uri(bad).is_none(), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn uri_param_lookup_is_case_insensitive_and_trims() {
        let params = b"Transport=TCP; lr ;maddr = 10.0.0.1;;ttl=";
        let cases: &[(&[u8], Option<&[u8]>)] = &[
            (b"transport", Some(b"TCP")),
            (b"TRANSPORT", Some(b"TCP")),
            (b"lr", Some(b"")),
            (b"maddr", Some(b"10.0.0.1")),
            (b"ttl", Some(b"")),
            (b"user", None),
            (b"trans", None),
        ];
        for &(name, want) in cases {
            assert_eq!(param(params, name), want, "{:?}", String::from_utf8_lossy(name));
        }
        assert_eq!(param(b"a=1;a=2", b"a"), Some(&b"1"[..]), "the first occurrence wins");
        assert!(parse_uri(b"sips:h").unwrap().is_sips());
        assert!(parse_uri(b"SIPS:h").unwrap().is_sips());
        assert!(!parse_uri(b"sip:h").unwrap().is_sips());
    }

    #[test]
    fn name_addr_separates_uri_from_header_params() {
        let cases: &[(&[u8], &[u8], &[u8])] = &[
            (b"<sip:a@h>", b"sip:a@h", b""),
            (b"<sip:a@h;lr>;tag=1", b"sip:a@h;lr", b"tag=1"),
            (b"\"Bob\" <sip:b@h> ;tag=2", b"sip:b@h", b"tag=2"),
            (b"Bob <sip:b@h>", b"sip:b@h", b""),
            (b"\"x <y> z\" <sip:c@h>;q=1", b"sip:c@h", b"q=1"),
            (b"sip:a@h;tag=3", b"sip:a@h", b"tag=3"),
            (b"  sip:a@h  ", b"sip:a@h", b""),
            (b"< sip:a@h >", b"sip:a@h", b""),
            (b"<sip:a@h", b"<sip:a@h", b""),
            (b"", b"", b""),
        ];
        for &(input, uri, params) in cases {
            assert_eq!(name_addr(input), (uri, params), "{:?}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn split_list_handles_multiple_values_per_header() {
        let cases: &[(&[u8], &[&[u8]])] = &[
            (b"", &[]),
            (b" , ,", &[]),
            (b"<sip:a>", &[b"<sip:a>"]),
            (b"<sip:a>,<sip:b>", &[b"<sip:a>", b"<sip:b>"]),
            (b"<sip:a;lr>, <sip:b;lr> ,<sip:c>", &[b"<sip:a;lr>", b"<sip:b;lr>", b"<sip:c>"]),
            (b"\"A, B\" <sip:a>, \"C\" <sip:c?x=1,2>", &[b"\"A, B\" <sip:a>", b"\"C\" <sip:c?x=1,2>"]),
            (b"INVITE, ACK,BYE", &[b"INVITE", b"ACK", b"BYE"]),
            (b"\"unterminated, quote", &[b"\"unterminated, quote"]),
            (b"\"a>b\" <sip:x>, <sip:y>", &[b"\"a>b\" <sip:x>", b"<sip:y>"]),
            (b"\"a\\\", b\" <sip:x>, <sip:y>", &[b"\"a\\\", b\" <sip:x>", b"<sip:y>"]),
            (b"\"a\\\\\" <sip:x>, <sip:y>", &[b"\"a\\\\\" <sip:x>", b"<sip:y>"]),
            (b"a\\, b", &[b"a\\", b"b"]),
        ];
        for &(input, want) in cases {
            assert_eq!(split_list(input), want, "{:?}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn parse_q_converts_qvalues_to_thousandths() {
        let cases: &[(&[u8], Option<u16>)] = &[
            (b"0", Some(0)),
            (b"0.0", Some(0)),
            (b"0.001", Some(1)),
            (b"0.1", Some(100)),
            (b"0.5", Some(500)),
            (b"0.75", Some(750)),
            (b"0.999", Some(999)),
            (b"1", Some(1000)),
            (b"1.0", Some(1000)),
            (b"1.000", Some(1000)),
            (b"1.001", None),
            (b"2", None),
            (b"-1", None),
            (b"", None),
            (b"q", None),
            (b"0,5", None),
            (b"inf", None),
            (b"\xff", None),
        ];
        for &(input, want) in cases {
            assert_eq!(parse_q(input), want, "{:?}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn parse_contact_reads_expires_q_instance_and_reg_id() {
        let c = parse_contact(b"\"A\" <sip:a@[2001:db8::5]:5070;transport=tcp>;EXPIRES=3600;q = 0.25;+sip.instance=\"<urn:uuid:x>\";reg-id=2");
        assert_eq!(c.uri, b"sip:a@[2001:db8::5]:5070;transport=tcp");
        assert_eq!((c.star, c.expires, c.q, c.instance, c.reg_id), (false, Some(3600), Some(250), Some(&b"<urn:uuid:x>"[..]), Some(2)));
        let u = parse_uri(c.uri).unwrap();
        assert_eq!((u.host, u.port, u.param(b"transport")), (&b"[2001:db8::5]"[..], Some(5070), Some(&b"tcp"[..])));

        let c = parse_contact(b"<sip:a@h;expires=10>");
        assert_eq!(c.expires, None, "a URI parameter is not the header's expires");
        let c = parse_contact(b"sip:a@h;expires=abc;q=7;reg-id=-1");
        assert_eq!((c.expires, c.q, c.reg_id), (None, None, None), "malformed values are dropped");
        let c = parse_contact(b"  *  ");
        assert!(c.star);
        assert_eq!(c.uri, b"*");
        let c = parse_contact(b"<sip:a@h>;+sip.instance=bare");
        assert_eq!(c.instance, Some(&b"bare"[..]));
    }
}
