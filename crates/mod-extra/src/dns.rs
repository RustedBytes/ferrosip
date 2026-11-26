//! `enum` — E.164 number to URI mapping through DNS NAPTR records
//! (RFC 6116): `enum_query([suffix[, service]])` rewrites the R-URI of an
//! E.164 user (`+4930…`) with the first matching NAPTR rule (flags `u`,
//! service `E2U+sip` by default, ordered by order/preference) applied to
//! the number; `enum_pv_query(number[, suffix[, service]])` does it for a
//! given number; `is_from_user_enum([suffix[, service]])` is 1 when the
//! caller's number maps to one of our own URIs. `i_enum_query` is the same
//! as `enum_query`. Parameters: `domain_suffix` ("e164.arpa."),
//! `service` ("e2u+sip"), `nameserver` (ferrosip: `ip:port`; default the
//! first one in /etc/resolv.conf).
//!
//! The resolver is a minimal DNS-over-UDP client for NAPTR queries.

use crate::ruri_user;
use regex::Regex;
use sip_core::module::{DynStr, rc};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Registry};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

pub use sip_core::dns::Naptr;
use sip_core::dns::{Rdata, T_NAPTR, system_nameserver};

/// NAPTR answers of a DNS response for query `id`.
#[cfg(test)]
fn parse_naptr(p: &[u8], id: u16) -> Option<Vec<Naptr>> {
    let r = sip_core::dns::parse(p, id)?;
    Some(r.answers.into_iter().filter_map(|r| if let Rdata::Naptr(n) = r.data { Some(n) } else { None }).collect())
}

pub fn query_naptr(server: SocketAddr, name: &str, id: u16) -> Option<Vec<Naptr>> {
    let r = sip_core::dns::query(server, name, T_NAPTR, id, Duration::from_secs(2))?;
    Some(r.answers.into_iter().filter_map(|r| if let Rdata::Naptr(n) = r.data { Some(n) } else { None }).collect())
}

/// Apply a NAPTR `!regex!replacement!flags` to `input` (`\1` refs).
pub fn apply_regexp(rx: &str, input: &str) -> Option<String> {
    let d = rx.chars().next()?;
    let parts: Vec<&str> = rx.strip_prefix(d)?.split(d).collect();
    let [pattern, replacement, flags @ ..] = parts.as_slice() else { return None };
    let ci = flags.first().is_some_and(|f| f.contains('i'));
    let re = Regex::new(&format!("{}{pattern}", if ci { "(?i)" } else { "" })).ok()?;
    let caps = re.captures(input)?;
    let mut out = String::new();
    let mut it = replacement.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek().copied() {
                Some(n) if n.is_ascii_digit() => {
                    it.next();
                    out.push_str(caps.get(n.to_digit(10)? as usize).map_or("", |m| m.as_str()));
                }
                Some(n) => {
                    it.next();
                    out.push(n);
                }
                None => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

pub struct Enum {
    suffix: Mutex<String>,
    service: Mutex<String>,
    server: Mutex<Option<SocketAddr>>,
    id: AtomicU16,
}

impl Default for Enum {
    fn default() -> Self {
        Self { suffix: Mutex::new("e164.arpa.".into()), service: Mutex::new("e2u+sip".into()), server: Mutex::new(None), id: AtomicU16::new(0x4242) }
    }
}

impl Enum {
    /// E.164 number → URI.
    fn lookup(&self, number: &str, suffix: Option<String>, service: Option<String>) -> Option<String> {
        let digits = number.strip_prefix('+')?;
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let suffix = suffix.unwrap_or_else(|| lock(&self.suffix).clone());
        let service = service.unwrap_or_else(|| lock(&self.service).clone()).to_ascii_lowercase();
        let name = format!("{}.{}", digits.chars().rev().map(String::from).collect::<Vec<_>>().join("."), suffix.trim_start_matches('.'));
        let server = lock(&self.server).or_else(system_nameserver)?;
        let mut recs = query_naptr(server, &name, self.id.fetch_add(1, Ordering::Relaxed))?;
        recs.retain(|r| {
            let s = r.services.to_ascii_lowercase();
            r.flags.to_ascii_lowercase().contains('u')
                && (s == service || s == "sip+e2u" && service == "e2u+sip" || s.split(':').next() == Some(service.as_str()))
        });
        recs.sort_by_key(|r| (r.order, r.pref));
        recs.iter().find_map(|r| apply_regexp(&r.regexp, number))
    }
}

impl Module for Enum {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("domain_suffix", Ty::Str, "e164.arpa.", "DNS domain the reversed number is looked up under"),
            p("service", Ty::Str, "e2u+sip", "NAPTR service to use"),
            p("nameserver", Ty::Str, "", "DNS server ip[:port] (default: the first one in /etc/resolv.conf)"),
        ])
    }

    fn name(&self) -> &'static str {
        "enum"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "domain_suffix" => *lock(&self.suffix) = v.str()?.into(),
            "service" => *lock(&self.service) = v.str()?.into(),
            "nameserver" => {
                let s = v.str()?;
                *lock(&self.server) = Some(s.parse().or_else(|_| format!("{s}:53").parse()).map_err(|_| format!("enum: bad nameserver {s:?}"))?);
            }
            "tel_uri_params" | "i_enum_suffix" | "branchlabel" | "bl_algorithm" => {}
            _ => return Err(format!("enum: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, hidden, opt, sig};
        const OPT2: &[Param] = &[opt("suffix", Str).eg("\"e164.arpa.\""), opt("service", Str).eg("\"e2u+sip\"")];
        const NUMBER: &[Param] = &[arg("number", Str).eg("\"+4930123\""), opt("suffix", Str).eg("\"e164.arpa.\""), opt("service", Str).eg("\"e2u+sip\"")];
        Some(vec![
            sig("enum_query", "query", OPT2, Ret::Bool, "Rewrite the R-URI of an E.164 user (+4930…) from its ENUM (NAPTR) record"),
            hidden("i_enum_query", "the same as enum.query"),
            sig("enum_pv_query", "query_number", NUMBER, Ret::Bool, "Rewrite the R-URI from the ENUM record of `number` (or a URI's user)"),
            sig("is_from_user_enum", "caller_is_local", OPT2, Ret::Bool, "The caller's number maps (through ENUM) to one of our own URIs"),
        ])
    }

    fn register(self: std::sync::Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let opt2 = |a: &[Arg]| -> Result<(Option<DynStr>, Option<DynStr>), String> {
            if a.len() > 2 {
                return Err("expected [suffix[, service]]".into());
            }
            Ok((a.first().map(Arg::dyn_str).transpose()?, a.get(1).map(Arg::dyn_str).transpose()?))
        };
        for name in ["enum_query", "i_enum_query"] {
            let me = self.clone();
            reg.export("enum", name, opt2, move |ctx: &mut Ctx, (sfx, svc): &(Option<DynStr>, Option<DynStr>)| {
                let (sfx, svc) = (sfx.as_ref().map(|s| s.eval(ctx).into_owned()), svc.as_ref().map(|s| s.eval(ctx).into_owned()));
                let user = ruri_user(ctx);
                match me.lookup(&user, sfx, svc) {
                    Some(u) => {
                        ctx.new_ruri = Some(u.into_bytes());
                        1
                    }
                    None => -1,
                }
            });
        }
        let me = self.clone();
        reg.export(
            "enum",
            "enum_pv_query",
            |a: &[Arg]| -> Result<Vec<DynStr>, String> {
                if a.is_empty() || a.len() > 3 {
                    return Err("expected number[, suffix[, service]]".into());
                }
                a.iter().map(Arg::dyn_str).collect()
            },
            move |ctx: &mut Ctx, a: &Vec<DynStr>| {
                let mut v = a.iter().map(|x| x.eval(ctx).into_owned());
                let Some(number) = v.next() else { return -1 };
                let num = sip_parser::parse_uri(number.as_bytes()).and_then(|u| u.user).map_or(number.clone(), |u| String::from_utf8_lossy(u).into_owned());
                match me.lookup(&num, v.next(), v.next()) {
                    Some(u) => {
                        ctx.new_ruri = Some(u.into_bytes());
                        1
                    }
                    None => -1,
                }
            },
        );
        let me = self.clone();
        reg.export("enum", "is_from_user_enum", opt2, move |ctx: &mut Ctx, (sfx, svc): &(Option<DynStr>, Option<DynStr>)| {
            let (sfx, svc) = (sfx.as_ref().map(|s| s.eval(ctx).into_owned()), svc.as_ref().map(|s| s.eval(ctx).into_owned()));
            let _ = ctx.msg.parse_headers(sip_parser::HdrFlags::EOH);
            let from = ctx.msg.get(sip_parser::HdrKind::From).map(|h| sip_parser::uri::name_addr(h.body).0.to_vec()).unwrap_or_default();
            let Some(user) = sip_parser::parse_uri(&from).and_then(|u| u.user).map(|u| String::from_utf8_lossy(u).into_owned()) else { return -1 };
            match me.lookup(&user, sfx, svc) {
                Some(u) => rc(sip_core::net::is_myself(ctx.net, &u)),
                None => -1,
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naptr() {
        assert_eq!(apply_regexp("!^.*$!sip:info@example.com!", "+4930123").as_deref(), Some("sip:info@example.com"));
        assert_eq!(apply_regexp("!^\\+49(.*)$!sip:\\1@de.example!", "+4930123").as_deref(), Some("sip:30123@de.example"));
        assert_eq!(apply_regexp("!^.*$", "+4930123"), None, "no replacement");
        assert_eq!(apply_regexp("!A!x!i", "a").as_deref(), Some("x"), "case-insensitive flag");
        // A response with one NAPTR answer (name compressed to the question).
        let mut p = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        p.extend_from_slice(&sip_core::dns::qname("1.e164.arpa"));
        p.extend_from_slice(&[0, 35, 0, 1]);
        p.extend_from_slice(&[0xc0, 12, 0, 35, 0, 1, 0, 0, 0, 60]);
        let mut rd = vec![0, 10, 0, 100, 1, b'u', 7];
        rd.extend_from_slice(b"E2U+sip");
        let rx = b"!^.*$!sip:a@b!";
        rd.push(u8::try_from(rx.len()).unwrap());
        rd.extend_from_slice(rx);
        rd.push(0);
        p.extend_from_slice(&u16::try_from(rd.len()).unwrap().to_be_bytes());
        p.extend_from_slice(&rd);
        let r = parse_naptr(&p, 0x1234).unwrap();
        assert_eq!(
            r,
            vec![Naptr { order: 10, pref: 100, flags: "u".into(), services: "E2U+sip".into(), regexp: "!^.*$!sip:a@b!".into(), replacement: String::new() }]
        );
    }
}

#[cfg(test)]
mod regexp_tests {
    use super::*;

    #[test]
    fn apply_regexp_substitutes_backreferences() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            ("!^\\+(.*)$!sip:\\1@gw.example!", "+4930123", Some("sip:4930123@gw.example")),
            ("!^\\+(49)(\\d+)$!sip:\\2@de.example;cc=\\1!", "+4930123", Some("sip:30123@de.example;cc=49")),
            ("!^\\+49(.*)$!tel:+49\\1!", "+4930", Some("tel:+4930")),
            ("!^.*$!<\\0>!", "+1", Some("<+1>")),
            ("!^(.*)$!\\5x!", "+1", Some("x")),
            ("!^.*$!a\\\\b!", "+1", Some("a\\b")),
            ("!^.*$!a\\.b!", "+1", Some("a.b")),
            ("/^\\+1(.*)$/sip:\\1@us.example/", "+1555", Some("sip:555@us.example")),
            ("|^.*$|sip:x@y|", "+1", Some("sip:x@y")),
            ("!^\\+44!sip:uk@x!", "+4930", None),
            ("!A!x!i", "a", Some("x")),
            ("!A!x!", "a", None),
            ("!(!x!", "+1", None),
            ("", "+1", None),
            ("!", "+1", None),
            ("!^.*$", "+1", None),
        ];
        for &(rx, input, want) in cases {
            assert_eq!(apply_regexp(rx, input).as_deref(), want, "{rx:?} on {input:?}");
        }
    }

    #[test]
    fn a_trailing_backslash_is_kept() {
        assert_eq!(apply_regexp("!^.*$!x\\", "+1").as_deref(), Some("x\\"));
    }

    #[test]
    fn lookup_rejects_non_e164_numbers_before_querying() {
        let e = Enum::default();
        *lock(&e.server) = Some("127.0.0.1:9".parse().unwrap());
        for n in ["", "+", "4930123", "+49 30", "+49a", "sip:+4930@x", "++49"] {
            assert_eq!(e.lookup(n, None, None), None, "{n:?}");
        }
    }
}

#[cfg(test)]
mod script_tests {
    use super::*;
    use crate::testutil::{FakeNet, call, fixup, invite, registry, with_ctx};
    use std::net::UdpSocket;
    use std::sync::Arc;

    /// One NAPTR answer: (order, pref, flags, services, regexp).
    type Rec = (u16, u16, &'static str, &'static str, &'static str);

    /// A loopback DNS server answering every query with `recs` (until no
    /// query comes for a while); returns its address.
    fn dns_server(recs: Vec<Rec>) -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let addr = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = s.recv_from(&mut buf) {
                let q = &buf[..n];
                let mut p = q[..2].to_vec();
                p.extend_from_slice(&[0x81, 0x80, 0, 1]);
                p.extend_from_slice(&u16::try_from(recs.len()).unwrap().to_be_bytes());
                p.extend_from_slice(&[0, 0, 0, 0]);
                p.extend_from_slice(&q[12..]);
                for &(order, pref, flags, services, regexp) in &recs {
                    let mut rd = [order.to_be_bytes(), pref.to_be_bytes()].concat();
                    for s in [flags, services, regexp, ""] {
                        rd.push(u8::try_from(s.len()).unwrap());
                        rd.extend_from_slice(s.as_bytes());
                    }
                    p.extend_from_slice(&[0xc0, 12, 0, 35, 0, 1, 0, 0, 0, 60]);
                    p.extend_from_slice(&u16::try_from(rd.len()).unwrap().to_be_bytes());
                    p.extend_from_slice(&rd);
                }
                let _ = s.send_to(&p, from);
            }
        });
        addr
    }

    fn enum_reg(recs: Vec<Rec>) -> sip_core::Registry {
        let e = Enum::default();
        e.set_param("nameserver", &Arg::Str(dns_server(recs).to_string())).unwrap();
        registry(vec![Arc::new(e)])
    }

    #[test]
    fn enum_parameters() {
        let e = Enum::default();
        for ok in ["tel_uri_params", "i_enum_suffix", "branchlabel", "bl_algorithm"] {
            assert!(e.set_param(ok, &Arg::Str("x".into())).is_ok(), "{ok}");
        }
        assert!(e.set_param("nope", &Arg::Str("x".into())).is_err());
        assert!(e.set_param("nameserver", &Arg::Str("not an address".into())).is_err());
        e.set_param("nameserver", &Arg::Str("192.0.2.53".into())).unwrap();
        assert_eq!(*lock(&e.server), Some("192.0.2.53:53".parse().unwrap()), "port 53 by default");
    }

    #[test]
    fn lookup_picks_the_best_matching_rule() {
        let recs = vec![
            (5, 1, "", "E2U+sip", "!^.*$!sip:no-u-flag@x!"),
            (5, 1, "u", "E2U+email", "!^.*$!mailto:x@y!"),
            (20, 1, "U", "sip+E2U", "!^.*$!sip:legacy@x!"),
            (10, 50, "u", "e2u+sip", "!^\\+(.*)$!sip:\\1@best.example!"),
            (10, 60, "u", "E2U+sip", "!^.*$!sip:worse@x!"),
        ];
        let e = Enum::default();
        *lock(&e.server) = Some(dns_server(recs));
        assert_eq!(e.lookup("+4930", None, None).as_deref(), Some("sip:4930@best.example"));
        assert_eq!(e.lookup("+4930", Some("e164.example.".into()), Some("E2U+email".into())).as_deref(), Some("mailto:x@y"));
        assert_eq!(e.lookup("+4930", None, Some("e2u+tel".into())), None, "no rule for the service");
    }

    #[test]
    fn enum_pv_query_takes_a_number_or_a_uri() {
        let reg = enum_reg(vec![(10, 10, "u", "E2U+sip", "!^\\+(.*)$!sip:\\1@gw.example!")]);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "enum_pv_query", &["+4930"]).unwrap(), 1);
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:4930@gw.example"[..]));
            assert_eq!(call(&reg, ctx, "enum_pv_query", &["sip:+1555@h", "e164.arpa.", "E2U+sip"]).unwrap(), 1);
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:1555@gw.example"[..]));
            assert_eq!(call(&reg, ctx, "enum_pv_query", &["4930"]).unwrap(), -1, "not E.164");
        });
        let s = |x: &str| Arg::Str(x.into());
        assert!(fixup(&reg, "enum_pv_query", &[]).is_err());
        assert!(fixup(&reg, "enum_pv_query", &[s("a"), s("b"), s("c"), s("d")]).is_err());
        assert!(fixup(&reg, "enum_query", &[s("a"), s("b"), s("c")]).is_err());
    }

    #[test]
    fn is_from_user_enum_checks_the_callers_mapping_is_ours() {
        let reg = enum_reg(vec![(10, 10, "u", "E2U+sip", "!^\\+49(.*)$!sip:\\1@192.0.2.10!")]);
        let caller = |from: &str| invite("").replace("<sip:alice@a.example>", from);
        let ours = FakeNet(Some("192.0.2.10:5060".parse().unwrap()));
        with_ctx(&caller("<sip:+4930@a.example>"), &ours, |ctx| assert_eq!(call(&reg, ctx, "is_from_user_enum", &[]).unwrap(), 1));
        let other = FakeNet(Some("192.0.2.11:5060".parse().unwrap()));
        with_ctx(&caller("<sip:+4930@a.example>"), &other, |ctx| {
            assert_eq!(call(&reg, ctx, "is_from_user_enum", &["e164.arpa.", "e2u+sip"]).unwrap(), -1, "maps elsewhere");
        });
        with_ctx(&caller("<sip:+1555@a.example>"), &ours, |ctx| assert_eq!(call(&reg, ctx, "is_from_user_enum", &[]).unwrap(), -1, "no match"));
        with_ctx(&caller("<sip:a.example>"), &ours, |ctx| assert_eq!(call(&reg, ctx, "is_from_user_enum", &[]).unwrap(), -1, "no user"));
    }
}
