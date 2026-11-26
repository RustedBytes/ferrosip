//! Routing, NAT and access-control modules (Kamailio names, one
//! `loadmodule` each): `rr`, `path`, `nathelper`, `dispatcher`,
//! `permissions`, `domain`, `alias_db`, `group`.

use sip_core::{Ctx, Dest, Module, Outbound, Proto};
use sip_parser::uri::{name_addr, split_list};
use sip_parser::{HdrFlags, HdrKind, parse_uri};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

mod acl;
mod dispatcher;
mod nat;
mod rr;
#[cfg(test)]
mod testutil;

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &["rr", "path", "nathelper", "dispatcher", "permissions", "domain", "alias_db", "group"];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "rr" => Arc::new(rr::Rr::default()),
        "path" => Arc::new(rr::PathMod::default()),
        "nathelper" => Arc::new(nat::NatHelper::default()),
        "dispatcher" => Arc::new(dispatcher::Dispatcher::default()),
        "permissions" => Arc::new(acl::Permissions::default()),
        "domain" => Arc::new(acl::Domain::default()),
        "alias_db" => Arc::new(acl::AliasDb::default()),
        "group" => Arc::new(acl::Group::default()),
        _ => return None,
    })
}

/// A cheap thread-safe PRNG (xorshift over a shared counter) — good enough
/// for load balancing; no crypto use.
pub(crate) fn rand_u64() -> u64 {
    static SEED: AtomicU64 = AtomicU64::new(0);
    let mut s = SEED.load(Ordering::Relaxed);
    if s == 0 {
        s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_secs().wrapping_mul(1_000_000_000).wrapping_add(u64::from(d.subsec_nanos())))
            | 1;
    }
    let mut x = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    SEED.store(x, Ordering::Relaxed);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// One element of a comma-separated header list, with its position.
pub(crate) struct ListItem {
    /// Index of the header line in `msg.headers`.
    pub hdr: usize,
    /// The item text (`<sip:x;lr>`), owned.
    pub text: Vec<u8>,
    /// The URI inside it.
    pub uri: Vec<u8>,
}

/// All items of the headers of `kind` (or named `name`), in order.
pub(crate) fn list_items(ctx: &mut Ctx<'_, '_>, kind: HdrKind, name: &[u8]) -> Vec<ListItem> {
    if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
        return vec![];
    }
    let mut out = Vec::new();
    for (i, h) in ctx.msg.headers.iter().enumerate() {
        let hit = if kind == HdrKind::Other { h.name.eq_ignore_ascii_case(name) } else { h.kind == kind };
        if hit {
            for it in split_list(h.body) {
                out.push(ListItem { hdr: i, text: it.to_vec(), uri: name_addr(it).0.to_vec() });
            }
        }
    }
    out
}

/// Is this URI one of our addresses (host is us and, if a port is given,
/// it's one of our listening ports)?
pub(crate) fn uri_is_myself(net: &dyn Outbound, uri: &[u8]) -> bool {
    let Some(u) = parse_uri(uri) else { return false };
    let host = String::from_utf8_lossy(u.host);
    if !sip_core::net::is_myself(net, &host) {
        return false;
    }
    match u.port {
        None => true,
        Some(p) => Proto::ALL.iter().filter_map(|pr| net.advertise(*pr)).any(|a| a.port() == p),
    }
}

/// Private / shared address space (RFC 1918, RFC 6598, loopback is not).
pub(crate) fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            o[0] == 10 || (o[0] == 172 && (16..32).contains(&o[1])) || (o[0] == 192 && o[1] == 168) || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}

pub(crate) fn parse_ip(b: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(b).ok()?.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

/// `ip` within `net/mask`.
pub(crate) fn in_subnet(ip: IpAddr, net: IpAddr, mask: u8) -> bool {
    match (ip, net) {
        // The top `mask` bits (all of them past the width: the shift fails).
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let m = u32::MAX.checked_shr(u32::from(mask)).map_or(u32::MAX, |low| !low);
            u32::from(a) & m == u32::from(b) & m
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let m = u128::MAX.checked_shr(u32::from(mask)).map_or(u128::MAX, |low| !low);
            u128::from(a) & m == u128::from(b) & m
        }
        (IpAddr::V6(a), IpAddr::V4(_)) => a.to_ipv4_mapped().is_some_and(|a| in_subnet(IpAddr::V4(a), net, mask)),
        _ => false,
    }
}

/// `ip`, `ip/mask` → (ip, mask).
pub(crate) fn parse_net(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, mask) = match s.split_once('/') {
        Some((i, m)) => (i, Some(m.trim().parse::<u8>().ok()?)),
        None => (s, None),
    };
    let ip: IpAddr = ip.trim().trim_matches(|c| c == '[' || c == ']').parse().ok()?;
    Some((ip, mask.unwrap_or(if ip.is_ipv4() { 32 } else { 128 })))
}

/// Kamailio protocol numbers (`;alias=ip~port~proto`, `$pr` numbers).
pub(crate) fn proto_num(p: Proto) -> u8 {
    match p {
        Proto::Udp => 1,
        Proto::Tcp => 2,
        Proto::Tls => 3,
        Proto::Ws => 5,
        Proto::Wss => 6,
    }
}

pub(crate) fn proto_from_num(n: u8) -> Option<Proto> {
    Some(match n {
        1 => Proto::Udp,
        2 => Proto::Tcp,
        3 => Proto::Tls,
        5 => Proto::Ws,
        6 => Proto::Wss,
        _ => return None,
    })
}

pub(crate) fn proto_from_name(s: &str) -> Option<Proto> {
    Some(match s.to_ascii_lowercase().as_str() {
        "udp" => Proto::Udp,
        "tcp" => Proto::Tcp,
        "tls" => Proto::Tls,
        "ws" => Proto::Ws,
        "wss" => Proto::Wss,
        _ => return None,
    })
}

/// `%XX` unescaping (URI parameter values).
pub(crate) fn unescape(s: &[u8]) -> Vec<u8> {
    let hex = |c: &u8| char::from(*c).to_digit(16).and_then(|d| u8::try_from(d).ok());
    let mut out = Vec::with_capacity(s.len());
    let mut rest = s;
    while let Some((&c, tail)) = rest.split_first() {
        if c == b'%'
            && let [hi, lo, more @ ..] = tail
            && let (Some(hi), Some(lo)) = (hex(hi), hex(lo))
        {
            out.push(hi << 4 | lo);
            rest = more;
        } else {
            out.push(c);
            rest = tail;
        }
    }
    out
}

/// `want_args`, as an array to destructure: `let [name, value] = args(a)?;`.
pub(crate) fn args<const N: usize>(a: &[sip_core::Arg]) -> Result<&[sip_core::Arg; N], String> {
    <&[sip_core::Arg; N]>::try_from(a).map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

/// Value of a `name=` field in a `;`-separated attribute string.
pub(crate) fn attr<'a>(attrs: &'a str, name: &str) -> Option<&'a str> {
    attrs.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        k.trim().eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

/// `user`, `host` of a URI (owned).
pub(crate) fn user_host(uri: &[u8]) -> Option<(String, String)> {
    let u = parse_uri(uri)?;
    Some((String::from_utf8_lossy(u.user.unwrap_or(b"")).into_owned(), String::from_utf8_lossy(u.host).to_ascii_lowercase()))
}

/// URI of the From / To header.
pub(crate) fn hdr_uri(ctx: &mut Ctx<'_, '_>, kind: HdrKind) -> Option<Vec<u8>> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    ctx.msg.get(kind).map(|h| name_addr(h.body).0.to_vec())
}

/// Resolve a URI to a next hop.
pub(crate) fn uri_dest(uri: &[u8]) -> Option<Dest> {
    sip_core::pvcore::dest_from_uri(uri)
}

/// Load a whole table (`cols` in order) from `db_url`.
pub(crate) fn load_table(db_url: &str, table: &str, cols: &[&str]) -> Result<Vec<Vec<sip_db::DbVal>>, String> {
    let db = sip_db::connect(db_url)?;
    Ok(db.query(table, cols, &[])?.rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets_and_private() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(in_subnet(ip("10.1.2.3"), ip("10.0.0.0"), 8));
        assert!(!in_subnet(ip("11.1.2.3"), ip("10.0.0.0"), 8));
        assert!(in_subnet(ip("1.2.3.4"), ip("0.0.0.0"), 0));
        assert!(in_subnet(ip("2001:db8::1"), ip("2001:db8::"), 32));
        assert!(is_private(ip("192.168.1.1")) && is_private(ip("172.20.0.1")) && is_private(ip("100.64.0.1")));
        assert!(!is_private(ip("8.8.8.8")) && !is_private(ip("127.0.0.1")));
        assert_eq!(parse_net("10.0.0.0/8"), Some((ip("10.0.0.0"), 8)));
        assert_eq!(unescape(b"sip:1.2.3.4:5%3Btransport%3Dtcp"), b"sip:1.2.3.4:5;transport=tcp");
        assert_eq!(attr("weight=50;duid=a", "duid"), Some("a"));
        assert_eq!(unescape(b"%41%4a%"), b"AJ%");
        assert_eq!(unescape(b"%4%zz%+1"), b"%4%zz%+1");
        assert!(in_subnet(ip("10.1.2.3"), ip("10.1.2.3"), 200) && !in_subnet(ip("10.1.2.4"), ip("10.1.2.3"), 32));
        assert!(in_subnet(ip("2001:db8::1"), ip("::"), 0) && !in_subnet(ip("2001:db8::1"), ip("2001:db8::2"), 128));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn subnet_boundaries_and_families() {
        let cases = [
            ("10.255.255.255", "10.0.0.0", 8, true),
            ("11.0.0.0", "10.0.0.0", 8, false),
            ("192.168.1.127", "192.168.1.0", 25, true),
            ("192.168.1.128", "192.168.1.0", 25, false),
            ("192.168.1.1", "192.168.1.0", 31, true),
            ("192.168.1.2", "192.168.1.0", 31, false),
            ("192.168.1.1", "192.168.1.0", 32, false),
            ("::ffff:10.1.2.3", "10.0.0.0", 8, true),
            ("::ffff:11.1.2.3", "10.0.0.0", 8, false),
            ("10.1.2.3", "::ffff:10.0.0.0", 104, false),
            ("2001:db8::1", "10.0.0.0", 0, false),
            ("fe80::1", "fe80::", 10, true),
            ("febf::1", "fe80::", 10, true),
            ("fec0::1", "fe80::", 10, false),
        ];
        for (a, net, mask, want) in cases {
            assert_eq!(in_subnet(ip(a), ip(net), mask), want, "{a} in {net}/{mask}");
        }
    }

    #[test]
    fn private_address_ranges() {
        let cases = [
            ("10.0.0.0", true),
            ("9.255.255.255", false),
            ("172.15.255.255", false),
            ("172.16.0.0", true),
            ("172.31.255.255", true),
            ("172.32.0.0", false),
            ("192.168.0.0", true),
            ("192.169.0.0", false),
            ("100.63.255.255", false),
            ("100.64.0.0", true),
            ("100.127.255.255", true),
            ("100.128.0.0", false),
            ("127.0.0.1", false),
            ("fc00::1", true),
            ("fdff::1", true),
            ("fe80::1", false),
            ("::1", false),
        ];
        for (a, want) in cases {
            assert_eq!(is_private(ip(a)), want, "{a}");
        }
    }

    #[test]
    fn network_and_address_parsing() {
        let cases: &[(&str, Option<(&str, u8)>)] = &[
            ("10.0.0.0/8", Some(("10.0.0.0", 8))),
            (" 10.0.0.1 ", Some(("10.0.0.1", 32))),
            ("10.0.0.0/ 16", Some(("10.0.0.0", 16))),
            ("[2001:db8::]/48", Some(("2001:db8::", 48))),
            ("2001:db8::1", Some(("2001:db8::1", 128))),
            ("10.0.0.0/x", None),
            ("10.0.0.0/300", None),
            ("host.example", None),
            ("", None),
        ];
        for (s, want) in cases {
            assert_eq!(parse_net(s), want.map(|(a, m)| (ip(a), m)), "{s:?}");
        }
        assert_eq!(parse_ip(b"[::1]"), Some(ip("::1")));
        assert_eq!(parse_ip(b"1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse_ip(b"example.com"), None);
        assert_eq!(parse_ip(&[0xff, 0xfe]), None);
    }

    #[test]
    fn kamailio_protocol_numbers_round_trip() {
        for p in Proto::ALL {
            assert_eq!(proto_from_num(proto_num(p)), Some(p));
            assert_eq!(proto_from_name(&p.via_name().to_ascii_lowercase()), Some(p));
        }
        assert_eq!((proto_num(Proto::Udp), proto_num(Proto::Tcp), proto_num(Proto::Tls), proto_num(Proto::Ws), proto_num(Proto::Wss)), (1, 2, 3, 5, 6));
        assert_eq!(proto_from_num(4), None, "SCTP is not supported");
        assert_eq!(proto_from_num(0), None);
        assert_eq!(proto_from_name("TCP"), Some(Proto::Tcp));
        assert_eq!(proto_from_name("sctp"), None);
    }

    #[test]
    fn attribute_and_uri_helpers() {
        assert_eq!(attr("weight=50; DUID = a ;flag", "duid"), Some("a"));
        assert_eq!(attr("weight=50;flag", "flag"), Some(""));
        assert_eq!(attr("weight=50", "maxload"), None);
        assert_eq!(attr("a=1=2", "a"), Some("1=2"));
        assert_eq!(user_host(b"sip:Alice@EXAMPLE.com:5060;x"), Some(("Alice".into(), "example.com".into())));
        assert_eq!(user_host(b"sip:example.com"), Some((String::new(), "example.com".into())));
        assert_eq!(user_host(b"not a uri"), None);
        assert_eq!(args::<2>(&[sip_core::Arg::Int(1)]).unwrap_err(), "expected 2 argument(s), got 1");
        assert!(module("dispatcher").is_some() && module("tm").is_none());
        assert!(NAMES.iter().all(|n| module(n).is_some_and(|m| m.name() == *n)));
    }
}
