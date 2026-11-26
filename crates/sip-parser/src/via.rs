//! Via parsing (only what a proxy needs to route requests/replies).

use crate::util::{split_host_port, split_once, trim, trim_start};

#[derive(Clone, Copy, Debug, Default)]
pub struct Via<'a> {
    /// The whole via-parm, e.g. `SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1`.
    pub raw: &'a [u8],
    pub transport: &'a [u8],
    pub host: &'a [u8],
    pub port: Option<u16>,
    pub branch: Option<&'a [u8]>,
    pub received: Option<&'a [u8]>,
    pub rport: Option<&'a [u8]>,
    /// RFC 5923 `;alias`: the sender offers this connection for reuse.
    pub alias: bool,
}

/// Parses the first via-parm of `s` and returns the remainder after a
/// top-level comma (i.e. the next Via value inside the same header line).
pub fn parse_via(s: &[u8]) -> Option<(Via<'_>, Option<&[u8]>)> {
    let (raw, rest) = match split_once(s, b',') {
        Some((raw, r)) => {
            let r = trim_start(r);
            (raw, (!r.is_empty()).then_some(r))
        }
        None => (s, None),
    };
    let raw = trim(raw);
    let sp = raw.iter().position(|&c| c == b' ' || c == b'\t')?;
    let (proto, after) = raw.split_at_checked(sp)?;
    let after = trim_start(after);
    let transport = proto.rsplit(|&c| c == b'/').next()?;
    let (sent_by, params) = split_once(after, b';').unwrap_or((after, b""));
    let (host, port) = split_host_port(trim(sent_by));
    if host.is_empty() {
        return None;
    }
    let mut v = Via { raw, transport, host, port, ..Default::default() };
    for p in params.split(|&c| c == b';') {
        let p = trim(p);
        let (k, val) = split_once(p, b'=').map_or((p, &b""[..]), |(k, v)| (trim(k), trim(v)));
        if k.eq_ignore_ascii_case(b"branch") {
            v.branch = Some(val);
        } else if k.eq_ignore_ascii_case(b"received") {
            v.received = Some(val);
        } else if k.eq_ignore_ascii_case(b"rport") {
            v.rport = Some(val);
        } else if k.eq_ignore_ascii_case(b"alias") {
            v.alias = true;
        }
    }
    Some((v, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_via_extracts_sent_by_and_params() {
        // (input, transport, host, port, branch, received, rport, alias, rest)
        type Case<'a> = (&'a [u8], &'a [u8], &'a [u8], Option<u16>, Option<&'a [u8]>, Option<&'a [u8]>, Option<&'a [u8]>, bool, Option<&'a [u8]>);
        let cases: &[Case] = &[
            (b"SIP/2.0/UDP 10.0.0.1", b"UDP", b"10.0.0.1", None, None, None, None, false, None),
            (b"SIP/2.0/TCP h.example:5070;branch=z9hG4bK1", b"TCP", b"h.example", Some(5070), Some(b"z9hG4bK1"), None, None, false, None),
            (b"SIP/2.0/TLS [2001:db8::1]:5061;branch=b", b"TLS", b"[2001:db8::1]", Some(5061), Some(b"b"), None, None, false, None),
            (b"SIP/2.0/UDP [::1];rport", b"UDP", b"[::1]", None, None, None, Some(b""), false, None),
            (b"SIP/2.0/UDP h;rport=5062;received=1.2.3.4", b"UDP", b"h", None, None, Some(b"1.2.3.4"), Some(b"5062"), false, None),
            (b"SIP/2.0/WSS h ; BRANCH = x ; Alias", b"WSS", b"h", None, Some(b"x"), None, None, true, None),
            (b"SIP/2.0/UDP\th:1;branch=a", b"UDP", b"h", Some(1), Some(b"a"), None, None, false, None),
            (b"SIP/2.0/UDP a;branch=1, SIP/2.0/TCP b", b"UDP", b"a", None, Some(b"1"), None, None, false, Some(b"SIP/2.0/TCP b")),
            (b"SIP/2.0/UDP a,SIP/2.0/TCP b", b"UDP", b"a", None, None, None, None, false, Some(b"SIP/2.0/TCP b")),
            (b"SIP/2.0/UDP a , ", b"UDP", b"a", None, None, None, None, false, None),
            (b"SIP/2.0/UDP h:99999", b"UDP", b"h", None, None, None, None, false, None),
        ];
        for &(input, transport, host, port, branch, received, rport, alias, rest) in cases {
            let what = String::from_utf8_lossy(input);
            let (v, r) = parse_via(input).unwrap_or_else(|| panic!("{what}"));
            assert_eq!((v.transport, v.host, v.port), (transport, host, port), "{what}");
            assert_eq!((v.branch, v.received, v.rport, v.alias), (branch, received, rport, alias), "{what}");
            assert_eq!(r, rest, "{what}");
        }
    }

    #[test]
    fn parse_via_raw_is_the_trimmed_first_value() {
        let (v, _) = parse_via(b"  SIP/2.0/UDP a;branch=1 , SIP/2.0/UDP b").unwrap();
        assert_eq!(v.raw, b"SIP/2.0/UDP a;branch=1");
    }

    #[test]
    fn parse_via_rejects_values_without_sent_by() {
        for bad in [&b""[..], b"SIP/2.0/UDP", b"SIP/2.0/UDP ", b"SIP/2.0/UDP ;branch=x", b"SIP/2.0/UDP :5060", b"garbage"] {
            assert!(parse_via(bad).is_none(), "{:?}", String::from_utf8_lossy(bad));
        }
    }
}
