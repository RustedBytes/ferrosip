//! `nathelper` — signalling-side NAT traversal: detect NATed clients
//! (`nat_uac_test`), rewrite their Contact / SDP to the address the packet
//! really came from, the `;alias` connection-reuse trick
//! (`set_contact_alias` / `handle_ruri_alias`), and keep-alive pings to
//! registered contacts so NAT bindings stay open (usrloc NAT pinging).

use crate::{args, is_private, list_items, parse_ip, proto_from_num, proto_num, rand_u64};
use mod_location::store::Usrloc;
use sip_core::module::{DynStr, rc};
use sip_core::schema::{ParamSpec, Ty, Unit, p, pr};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Dest, Module, Outbound, Proto, Registry, want_args};
use sip_parser::{HdrKind, parse_uri};
use std::io::Write as _;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const PING_BRANCH: &str = "z9hG4bKnhping";

pub struct NatHelper {
    natping_interval: AtomicU64,
    ping_nated_only: AtomicBool,
    nat_bflag: AtomicI64,
    sipping_bflag: AtomicI64,
    sipping_from: Mutex<String>,
    sipping_method: Mutex<String>,
    ul: OnceLock<Arc<Usrloc>>,
}

impl Default for NatHelper {
    fn default() -> Self {
        Self {
            natping_interval: AtomicU64::new(0),
            ping_nated_only: AtomicBool::new(false),
            nat_bflag: AtomicI64::new(-1),
            sipping_bflag: AtomicI64::new(-1),
            sipping_from: Mutex::new("sip:pinger@ferrosip.invalid".into()),
            sipping_method: Mutex::new("OPTIONS".into()),
            ul: OnceLock::new(),
        }
    }
}

/// Position of `host[:port]` of a URI inside the message buffer.
fn hostport_span(buf: &[u8], base: usize, uri: &[u8]) -> Option<(usize, usize)> {
    let u = parse_uri(uri)?;
    let off = (u.host.as_ptr() as usize).checked_sub(uri.as_ptr() as usize)?;
    let s = base.checked_add(off)?;
    let e = s.checked_add(u.host.len())?;
    let (head, tail) = buf.split_at_checked(e)?;
    // `[v6]`: the brackets too.
    let (s, tail) = match (head.get(..s).and_then(<[u8]>::last), tail.split_first()) {
        (Some(b'['), Some((b']', rest))) => (s.checked_sub(1)?, rest),
        _ => (s, tail),
    };
    let port = match tail.split_first() {
        Some((b':', digits)) => digits.iter().take_while(|c| c.is_ascii_digit()).count().checked_add(1)?,
        _ => 0,
    };
    let host_end = buf.len().checked_sub(tail.len())?;
    Some((s, host_end.checked_add(port)?))
}

/// The first Contact URI and its offset in the buffer.
fn first_contact(ctx: &mut Ctx<'_, '_>) -> Option<(usize, Vec<u8>)> {
    let items = list_items(ctx, HdrKind::Contact, b"");
    let it = items.into_iter().next()?;
    if it.uri.is_empty() || it.uri == b"*" {
        return None;
    }
    // Find the item in its header line to get the absolute offset.
    let h = ctx.msg.headers.get(it.hdr)?;
    let pos = h.start.checked_add(memfind(ctx.msg.buf.get(h.start..h.end)?, &it.uri)?)?;
    Some((pos, it.uri))
}

fn memfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len().max(1)).position(|w| w == needle)
}

fn host_port(d: &Dest) -> String {
    match d.addr.ip() {
        IpAddr::V6(ip) => format!("[{ip}]:{}", d.addr.port()),
        ip => format!("{ip}:{}", d.addr.port()),
    }
}

fn sdp_ip(line: &str) -> Option<IpAddr> {
    // c=IN IP4 1.2.3.4  /  o=- 1 1 IN IP4 1.2.3.4
    line.split_whitespace().last().and_then(|s| s.split('/').next()).and_then(|s| s.parse().ok())
}

impl NatHelper {
    fn nat_uac_test(ctx: &mut Ctx<'_, '_>, flags: i64) -> bool {
        let src = ctx.src.addr;
        let contact = first_contact(ctx).map(|c| c.1);
        let chost = contact.as_deref().and_then(parse_uri).map(|u| (parse_ip(u.host), u.port.unwrap_or(5060)));
        let via = ctx.msg.via1.map(|v| (parse_ip(v.host), v.port.unwrap_or(5060)));
        // 1: Contact has a private address.
        if flags & 1 != 0 && chost.is_some_and(|(ip, _)| ip.is_some_and(is_private)) {
            return true;
        }
        // 2: the Via sent-by address isn't where the request came from.
        if flags & 2 != 0 && via.is_some_and(|(ip, _)| ip != Some(src.ip())) {
            return true;
        }
        // 4: the top Via has a private address.
        if flags & 4 != 0 && via.is_some_and(|(ip, _)| ip.is_some_and(is_private)) {
            return true;
        }
        // 8: SDP connection address is private.
        if flags & 8 != 0 {
            let body = ctx.body();
            let s = String::from_utf8_lossy(&body);
            if s.lines().filter(|l| l.starts_with("c=")).any(|l| sdp_ip(l).is_some_and(is_private)) {
                return true;
            }
        }
        // 16: the Via port differs from the source port.
        if flags & 16 != 0 && via.is_some_and(|(_, p)| p != src.port()) {
            return true;
        }
        // 32: the source address itself is private.
        if flags & 32 != 0 && is_private(src.ip()) {
            return true;
        }
        // 64: WebSocket client.
        if flags & 64 != 0 && ctx.src.proto.is_ws() {
            return true;
        }
        // 128: the Contact port differs from the source port.
        if flags & 128 != 0 && chost.is_some_and(|(_, p)| p != src.port()) {
            return true;
        }
        // 256: the SDP connection address differs from the source address.
        if flags & 256 != 0 {
            let body = ctx.body();
            let s = String::from_utf8_lossy(&body);
            if s.lines().filter(|l| l.starts_with("c=")).any(|l| sdp_ip(l).is_some_and(|ip| ip != src.ip())) {
                return true;
            }
        }
        false
    }

    /// Contact host:port → the source address of the request.
    fn fix_nated_contact(ctx: &mut Ctx<'_, '_>) -> i32 {
        let Some((pos, uri)) = first_contact(ctx) else { return -1 };
        let Some((s, e)) = hostport_span(ctx.msg.buf, pos, &uri) else { return -1 };
        ctx.lumps.replace(s, e.saturating_sub(s), host_port(&ctx.src).into_bytes());
        1
    }

    /// `;alias=ip~port~proto` on the Contact URI (so requests to it can be
    /// sent back over the same NAT binding / connection).
    fn set_contact_alias(ctx: &mut Ctx<'_, '_>, d: Dest) -> i32 {
        let Some((pos, uri)) = first_contact(ctx) else { return -1 };
        if parse_uri(&uri).is_some_and(|u| u.param(b"alias").is_some()) {
            return 1;
        }
        let Some((_, e)) = hostport_span(ctx.msg.buf, pos, &uri) else { return -1 };
        let ip = match d.addr.ip() {
            IpAddr::V6(ip) => format!("[{ip}]"),
            ip => ip.to_string(),
        };
        // Insert after the URI's parameters (before `>` / header params).
        let uri_end = pos.saturating_add(uri.len());
        let at = uri_end.max(e);
        ctx.lumps.insert(at, format!(";alias={ip}~{}~{}", d.addr.port(), proto_num(d.proto)).into_bytes());
        1
    }

    /// R-URI `;alias=ip~port~proto` → `$du`, and remove it from the R-URI.
    fn handle_ruri_alias(ctx: &mut Ctx<'_, '_>) -> i32 {
        let ruri = ctx.ruri().to_vec();
        let Some(u) = parse_uri(&ruri) else { return -1 };
        let Some(alias) = u.param(b"alias") else { return 2 };
        let s = String::from_utf8_lossy(alias).into_owned();
        let mut it = s.split('~');
        let (Some(ip), Some(port), proto) = (it.next(), it.next(), it.next()) else { return -1 };
        let (Ok(ip), Ok(port)) = (ip.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>(), port.parse::<u16>()) else { return -1 };
        let proto = proto.and_then(|p| p.parse::<u8>().ok()).and_then(proto_from_num).unwrap_or(Proto::Udp);
        ctx.dst = Some(Dest::new(proto, (ip, port).into()));
        // Drop the alias parameter from the R-URI.
        let params: Vec<&[u8]> = u.params.split(|&c| c == b';').filter(|p| !p.is_empty() && !p.starts_with(b"alias=")).collect();
        // The R-URI up to its parameters, without the `;` before them.
        let Some(base) = (u.params.as_ptr() as usize).checked_sub(ruri.as_ptr() as usize).and_then(|end| ruri.get(..end.saturating_sub(1))) else {
            return -1;
        };
        let mut new = base.to_vec();
        for p in params {
            new.push(b';');
            new.extend_from_slice(p);
        }
        ctx.new_ruri = Some(new);
        1
    }

    /// `;received="sip:ip:port;transport=x"` as Contact header parameter
    /// (or, with `uri_param`, inside the URI).
    fn add_rcv_param(ctx: &mut Ctx<'_, '_>, uri_param: bool) -> i32 {
        let Some((pos, uri)) = first_contact(ctx) else { return -1 };
        let mut r = sip_core::pvcore::dest_to_uri(&ctx.src);
        let at = if uri_param {
            r = r.replace(';', "%3B").replace('=', "%3D");
            pos.saturating_add(uri.len())
        } else {
            r = format!("\"{r}\"");
            // After the closing `>` if present.
            let buf = &ctx.msg.buf;
            let e = pos.saturating_add(uri.len());
            if buf.get(e) == Some(&b'>') { e.saturating_add(1) } else { e }
        };
        ctx.lumps.insert(at, format!(";received={r}").into_bytes());
        1
    }

    /// fix_nated_sdp(flags[, ip]): 1 add `a=direction:active`, 2 rewrite
    /// `c=` addresses, 8 rewrite the `o=` address.
    fn fix_nated_sdp(ctx: &mut Ctx<'_, '_>, flags: i64, ip: Option<String>) -> i32 {
        let body = ctx.body();
        if body.is_empty() {
            return -1;
        }
        let ip = ip.unwrap_or_else(|| ctx.src.addr.ip().to_string());
        let fam = if ip.contains(':') { "IP6" } else { "IP4" };
        let text = String::from_utf8_lossy(&body).into_owned();
        let mut out = String::with_capacity(text.len().saturating_add(32));
        let mut added = false;
        for line in text.split_inclusive('\n') {
            let l = line.trim_end_matches(['\r', '\n']);
            if flags & 2 != 0 && l.starts_with("c=") {
                out.push_str(&format!("c=IN {fam} {ip}\r\n"));
            } else if flags & 8 != 0 && l.starts_with("o=") {
                let mut f: Vec<&str> = l.split_whitespace().collect();
                // o=<user> <sess-id> <sess-version> IN <addrtype> <address>
                if let [_, _, _, _, addrtype, .., address] = f.as_mut_slice() {
                    *addrtype = fam;
                    *address = &ip;
                }
                out.push_str(&f.join(" "));
                out.push_str("\r\n");
            } else {
                out.push_str(line);
            }
            if flags & 1 != 0 && !added && l.starts_with("c=") {
                out.push_str("a=direction:active\r\n");
                added = true;
            }
        }
        ctx.set_body(out.into_bytes(), None);
        1
    }

    fn ping_once(&self, net: &dyn Outbound) {
        let Some(ul) = self.ul.get() else { return };
        let only_nated = self.ping_nated_only.load(Ordering::Relaxed);
        let nat = self.nat_bflag.load(Ordering::Relaxed);
        let sip = self.sipping_bflag.load(Ordering::Relaxed);
        let bit = |f: i64| if f >= 0 { 1u32 << f } else { 0 };
        let (nat, sip) = (bit(nat), bit(sip));
        let mut targets = Vec::new();
        ul.for_each_contact(|_, c| {
            if only_nated && c.cflags & nat == 0 {
                return;
            }
            targets.push((c.received, c.uri.clone(), sip != 0 && c.cflags & sip != 0));
        });
        let from = lock(&self.sipping_from).clone();
        let method = lock(&self.sipping_method).clone();
        for (dst, uri, sipping) in targets {
            if sipping {
                let adv = net.advertise(dst.proto).unwrap_or(dst.addr);
                let uri = String::from_utf8_lossy(&uri);
                let mut m = Vec::with_capacity(400);
                let n = rand_u64();
                let _ = write!(
                    m,
                    "{method} {uri} SIP/2.0\r\nVia: SIP/2.0/{} {adv};branch={PING_BRANCH}{n:x}\r\nFrom: <{from}>;tag={:x}\r\nTo: <{uri}>\r\n\
Call-ID: nhping-{n:x}\r\nCSeq: 1 {method}\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
                    dst.proto.via_name(),
                    n >> 16
                );
                let _ = net.send(&dst, &m);
            } else if dst.proto.is_stream() {
                let _ = net.send(&dst, b"\r\n\r\n");
            } else {
                let _ = net.send(&dst, &[0, 0, 0, 0]);
            }
            sip_core::stats::inc(sip_core::stats::counter("nathelper", "pings_sent"));
        }
    }
}

impl Module for NatHelper {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("natping_interval", Ty::Duration(Unit::Sec), "0s", "NAT keep-alive interval for registered contacts (0: off)"),
            pr("ping_nated_only", Ty::Bool, "false", "Ping only contacts flagged as behind NAT"),
            p("nat_bflag", Ty::Int { min: -1, max: 63 }, "-1", "Branch flag marking contacts behind NAT"),
            p("sipping_bflag", Ty::Int { min: -1, max: 63 }, "-1", "Branch flag: ping with SIP OPTIONS instead of UDP"),
            p("sipping_from", Ty::Str, "sip:pinger@ferrosip.invalid", "From URI of SIP pings"),
            p("sipping_method", Ty::Str, "OPTIONS", "Method of SIP pings"),
        ])
    }

    fn name(&self) -> &'static str {
        "nathelper"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, opt_or, sig};
        const FLAGS: &[Param] = &[opt_or("flags", Int, "19")];
        const ALIAS: &[Param] = &[opt("ip", Str).eg("\"192.0.2.1\""), opt("port", Int).eg("5060"), opt("proto", Str).eg("\"udp\"")];
        const SDP: &[Param] = &[arg("flags", Int).eg("3"), opt("ip", Str).eg("\"192.0.2.1\"")];
        const IP: &[Param] = &[arg("ip", Str).eg("\"10.0.0.1\"")];
        const ROUTE_REPLY: u8 = ctx::ROUTE | ctx::REPLY;
        Some(vec![
            sig("nat_uac_test", "is_behind", FLAGS, Ret::Bool, "The sender is behind NAT, by the tests in `flags` (1 private Contact, 2 Via ≠ source, 4 private Via, 8 private SDP, 16 Via port ≠ source port, 32 private source)")
                .allowed(ROUTE_REPLY),
            sig("fix_nated_contact", "fix_contact", &[], Ret::Bool, "Rewrite the Contact host:port to the source address").allowed(ROUTE_REPLY),
            sig("fix_nated_register", "fix_register", &[], Ret::Bool, "Keep a REGISTER's source address for its contact (registrar always does)")
                .allowed(ctx::REQUEST),
            sig("set_contact_alias", "set_contact_alias", ALIAS, Ret::Bool, "Add `;alias=ip~port~proto` (the source address, or this one) to the Contact URI")
                .allowed(ROUTE_REPLY),
            sig("add_contact_alias", "add_contact_alias", ALIAS, Ret::Bool, "Add `;alias=ip~port~proto` (the source address, or this one) to the Contact URI")
                .allowed(ROUTE_REPLY),
            sig("handle_ruri_alias", "handle_ruri_alias", &[], Ret::Bool, "Send to the R-URI's `;alias` address (as $du) and drop the parameter"),
            sig("add_rcv_param", "add_received", &[], Ret::Bool, "Add the source address as `;received` to the Contact header").allowed(ctx::REQUEST),
            sig("add_rcv_param", "add_received_uri", &[], Ret::Bool, "Add the source address as `;received` to the Contact URI")
                .fixed(&["1"])
                .allowed(ctx::REQUEST),
            sig("fix_nated_sdp", "fix_sdp", SDP, Ret::Bool, "Rewrite SDP addresses to the source (or `ip`): flags 1 a=direction:active, 2 c=, 8 o=")
                .allowed(ROUTE_REPLY),
            sig("is_rfc1918", "is_private", IP, Ret::Bool, "The IP address is private (RFC 1918 and the like)").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "natping_interval" => self.natping_interval.store(u64::try_from(v.int()?).unwrap_or(0), Ordering::Relaxed),
            "ping_nated_only" => self.ping_nated_only.store(v.int()? != 0, Ordering::Relaxed),
            "nat_bflag" => self.nat_bflag.store(v.int()?, Ordering::Relaxed),
            "sipping_bflag" => self.sipping_bflag.store(v.int()?, Ordering::Relaxed),
            "sipping_from" => *lock(&self.sipping_from) = v.str()?.to_string(),
            "sipping_method" => *lock(&self.sipping_method) = v.str()?.to_string(),
            // Accepted for compatibility: registrar always records the source.
            "received_avp" | "natping_processes" | "natping_socket" | "force_socket" | "keepalive_timeout" | "udpping_from_path" => {}
            _ => return Err(format!("nathelper: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        if let Some(ul) = reg.api::<Usrloc>() {
            let _ = self.ul.set(ul);
        } else if self.natping_interval.load(Ordering::Relaxed) > 0 {
            return Err("nathelper: natping_interval needs usrloc loaded first".into());
        }
        let m = "nathelper";
        reg.export(
            m,
            "nat_uac_test",
            |a: &[Arg]| {
                let [f] = args(a)?;
                f.dyn_int()
            },
            |ctx: &mut Ctx, f: &sip_core::module::DynInt| {
                let f = f.eval(ctx).unwrap_or(0);
                rc(NatHelper::nat_uac_test(ctx, f))
            },
        );
        reg.export(m, "fix_nated_contact", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| NatHelper::fix_nated_contact(ctx));
        // registrar always saves the source address/connection of a
        // REGISTER, which is what Kamailio's received_avp achieves.
        reg.export(m, "fix_nated_register", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| rc(ctx.msg.method() == Some(sip_parser::Method::Register)));
        let alias_fix = |a: &[Arg]| -> Result<Vec<DynStr>, String> {
            if !(a.is_empty() || a.len() == 3) {
                return Err("expected no arguments or (ip, port, proto)".into());
            }
            a.iter().map(Arg::dyn_str).collect()
        };
        let alias = |ctx: &mut Ctx, a: &Vec<DynStr>| {
            // None or three: checked at fixup.
            let [ip, port, proto] = a.as_slice() else {
                let d = ctx.src;
                return NatHelper::set_contact_alias(ctx, d);
            };
            let (ip, port, proto) = (ip.eval(ctx).into_owned(), port.eval(ctx).into_owned(), proto.eval(ctx).into_owned());
            match (ip.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>(), port.parse::<u16>(), crate::proto_from_name(&proto)) {
                (Ok(ip), Ok(port), Some(p)) => NatHelper::set_contact_alias(ctx, Dest::new(p, (ip, port).into())),
                _ => -1,
            }
        };
        reg.export(m, "set_contact_alias", alias_fix, alias);
        reg.export(m, "add_contact_alias", alias_fix, alias);
        reg.export(m, "handle_ruri_alias", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| NatHelper::handle_ruri_alias(ctx));
        reg.export(
            m,
            "add_rcv_param",
            |a: &[Arg]| -> Result<bool, String> {
                match a {
                    [] => Ok(false),
                    [in_uri] => Ok(in_uri.int()? != 0),
                    _ => Err("expected at most 1 argument".into()),
                }
            },
            |ctx: &mut Ctx, &u: &bool| NatHelper::add_rcv_param(ctx, u),
        );
        reg.export(
            m,
            "fix_nated_sdp",
            |a: &[Arg]| -> Result<(sip_core::module::DynInt, Option<DynStr>), String> {
                match a {
                    [flags] => Ok((flags.dyn_int()?, None)),
                    [flags, ip] => Ok((flags.dyn_int()?, Some(ip.dyn_str()?))),
                    _ => Err("expected flags[, ip]".into()),
                }
            },
            |ctx: &mut Ctx, (f, ip): &(sip_core::module::DynInt, Option<DynStr>)| {
                let f = f.eval(ctx).unwrap_or(0);
                let ip = ip.as_ref().map(|i| i.eval(ctx).into_owned());
                NatHelper::fix_nated_sdp(ctx, f, ip)
            },
        );
        reg.export(
            m,
            "is_rfc1918",
            |a: &[Arg]| {
                let [ip] = args(a)?;
                ip.dyn_str()
            },
            |ctx: &mut Ctx, ip: &DynStr| rc(ip.eval(ctx).trim().parse::<IpAddr>().is_ok_and(is_private)),
        );
        Ok(())
    }

    /// Replies to our SIP pings end here.
    fn on_reply(&self, ctx: &mut Ctx<'_, '_>) -> bool {
        ctx.msg.via1.and_then(|v| v.branch).is_some_and(|b| b.starts_with(PING_BRANCH.as_bytes()))
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let every = self.natping_interval.load(Ordering::Relaxed);
        if every == 0 || self.ul.get().is_none() {
            return Ok(());
        }
        std::thread::Builder::new()
            .name("nathelper-ping".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(every));
                    self.ping_once(&*net);
                }
            })
            .map_err(|e| format!("cannot start the nathelper pinger thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_spans() {
        let span = |buf: &[u8], uri: &[u8]| {
            let base = memfind(buf, uri).unwrap();
            hostport_span(buf, base, uri).map(|(s, e)| String::from_utf8_lossy(&buf[s..e]).into_owned())
        };
        assert_eq!(span(b"Contact: <sip:a@10.0.0.1:5060;x>", b"sip:a@10.0.0.1:5060;x").as_deref(), Some("10.0.0.1:5060"));
        assert_eq!(span(b"Contact: <sip:a@[::1]:5070>", b"sip:a@[::1]:5070").as_deref(), Some("[::1]:5070"));
        assert_eq!(span(b"Contact: sip:host", b"sip:host").as_deref(), Some("host"));
        assert_eq!(span(b"Contact: <sip:a@h:>", b"sip:a@h:").as_deref(), Some("h:"));
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;
    use crate::testutil::{FakeNet, rendered, udp, with_ctx};

    fn msg(contact: &str, via: &str, body: &str) -> String {
        let ctype = if body.is_empty() { String::new() } else { "Content-Type: application/sdp\n".into() };
        let contact = if contact.is_empty() { String::new() } else { format!("Contact: {contact}\n") };
        format!(
            "INVITE sip:bob@b.example SIP/2.0\nVia: SIP/2.0/UDP {via};branch=z9hG4bK1\nFrom: <sip:a@a.example>;tag=1\nTo: <sip:bob@b.example>\n\
Call-ID: c\nCSeq: 1 INVITE\n{contact}{ctype}Content-Length: {}\n\n{body}",
            body.replace('\n', "\r\n").len()
        )
    }

    const SDP_PRIV: &str = "v=0\no=- 1 1 IN IP4 10.0.0.5\ns=-\nc=IN IP4 10.0.0.5\nt=0 0\nm=audio 4000 RTP/AVP 0\n";
    const SDP_PUB: &str = "v=0\no=- 1 1 IN IP4 203.0.113.7\ns=-\nc=IN IP4 203.0.113.7/127\nt=0 0\nm=audio 4000 RTP/AVP 0\n";

    #[test]
    fn nat_uac_test_each_flag() {
        let net = FakeNet(vec![]);
        let src = udp("203.0.113.7:5060");
        let pub_c = "<sip:a@203.0.113.7:5060>";
        let priv_c = "<sip:a@10.0.0.5:5060>";
        // (flag, contact, via, body, source, behind NAT)
        let cases: &[(i64, &str, &str, &str, Dest, bool)] = &[
            (1, priv_c, "203.0.113.7", "", src, true),
            (1, pub_c, "203.0.113.7", "", src, false),
            (1, "*", "203.0.113.7", "", src, false),
            (1, "", "203.0.113.7", "", src, false),
            (2, pub_c, "198.51.100.1", "", src, true),
            (2, pub_c, "203.0.113.7:5080", "", src, false),
            (4, pub_c, "192.168.1.2", "", src, true),
            (4, pub_c, "172.32.0.1", "", src, false),
            (8, pub_c, "203.0.113.7", SDP_PRIV, src, true),
            (8, pub_c, "203.0.113.7", SDP_PUB, src, false),
            (16, pub_c, "203.0.113.7", "", src, false),
            (16, pub_c, "203.0.113.7:5080", "", src, true),
            (16, pub_c, "203.0.113.7", "", udp("203.0.113.7:40000"), true),
            (32, pub_c, "203.0.113.7", "", udp("100.64.1.1:5060"), true),
            (32, pub_c, "203.0.113.7", "", src, false),
            (64, pub_c, "203.0.113.7", "", Dest::new(Proto::Ws, "203.0.113.7:5060".parse().unwrap()), true),
            (64, pub_c, "203.0.113.7", "", Dest::new(Proto::Tcp, "203.0.113.7:5060".parse().unwrap()), false),
            (128, "<sip:a@203.0.113.7>", "203.0.113.7", "", src, false),
            (128, "<sip:a@203.0.113.7:5070>", "203.0.113.7", "", src, true),
            (256, pub_c, "203.0.113.7", SDP_PUB, src, false),
            (256, pub_c, "203.0.113.7", SDP_PRIV, src, true),
            (0, priv_c, "10.0.0.5:9", SDP_PRIV, udp("10.0.0.6:1"), false),
            (19, pub_c, "203.0.113.7", "", src, false),
            (19, pub_c, "203.0.113.7:1", "", src, true),
        ];
        for (i, (flags, contact, via, body, src, want)) in cases.iter().enumerate() {
            let got = with_ctx(&msg(contact, via, body), *src, &net, |ctx| NatHelper::nat_uac_test(ctx, *flags));
            assert_eq!(got, *want, "case {i}: flags {flags}, contact {contact:?}, via {via}");
        }
    }

    fn contact_line(out: &str) -> String {
        out.lines().find(|l| l.starts_with("Contact:")).unwrap_or_default().to_string()
    }

    #[test]
    fn fix_nated_contact_rewrites_host_and_port() {
        let net = FakeNet(vec![]);
        let cases = [
            ("<sip:alice@10.0.0.5:5060;transport=udp>;expires=60", udp("203.0.113.7:40000"), "<sip:alice@203.0.113.7:40000;transport=udp>;expires=60"),
            ("\"A\" <sip:alice@10.0.0.5>", udp("203.0.113.7:40000"), "\"A\" <sip:alice@203.0.113.7:40000>"),
            ("sip:10.0.0.5:5062", udp("203.0.113.7:1"), "sip:203.0.113.7:1"),
            ("<sip:alice@[fd00::5]:5060>", udp("[2001:db8::7]:5070"), "<sip:alice@[2001:db8::7]:5070>"),
            ("<sip:alice@10.0.0.5:5060>, <sip:alice@10.0.0.6:5060>", udp("203.0.113.7:9"), "<sip:alice@203.0.113.7:9>, <sip:alice@10.0.0.6:5060>"),
        ];
        for (contact, src, want) in cases {
            let out = with_ctx(&msg(contact, "10.0.0.5", ""), src, &net, |ctx| {
                assert_eq!(NatHelper::fix_nated_contact(ctx), 1, "{contact}");
                rendered(ctx)
            });
            assert_eq!(contact_line(&out), format!("Contact: {want}"));
        }
        for contact in ["*", ""] {
            assert_eq!(with_ctx(&msg(contact, "10.0.0.5", ""), udp("203.0.113.7:1"), &net, NatHelper::fix_nated_contact), -1, "{contact:?}");
        }
    }

    #[test]
    fn set_contact_alias_appends_to_the_uri() {
        let net = FakeNet(vec![]);
        let tcp = Dest::new(Proto::Tcp, "203.0.113.7:40000".parse().unwrap());
        let cases = [
            ("<sip:alice@10.0.0.5:5060;transport=tcp>;expires=60", tcp, "<sip:alice@10.0.0.5:5060;transport=tcp;alias=203.0.113.7~40000~2>;expires=60"),
            ("<sip:alice@10.0.0.5>", udp("[2001:db8::7]:5070"), "<sip:alice@10.0.0.5;alias=[2001:db8::7]~5070~1>"),
            ("<sip:alice@10.0.0.5;alias=1.2.3.4~5~1>", tcp, "<sip:alice@10.0.0.5;alias=1.2.3.4~5~1>"),
        ];
        for (contact, d, want) in cases {
            let out = with_ctx(&msg(contact, "10.0.0.5", ""), udp("203.0.113.7:40000"), &net, |ctx| {
                assert_eq!(NatHelper::set_contact_alias(ctx, d), 1, "{contact}");
                rendered(ctx)
            });
            assert_eq!(contact_line(&out), format!("Contact: {want}"));
        }
        assert_eq!(with_ctx(&msg("*", "10.0.0.5", ""), udp("203.0.113.7:1"), &net, |ctx| NatHelper::set_contact_alias(ctx, tcp)), -1);
    }

    #[test]
    fn handle_ruri_alias_sets_dst_and_strips_the_parameter() {
        let net = FakeNet(vec![]);
        let run = |ruri: &str| {
            let m = msg("", "10.0.0.5", "").replace("INVITE sip:bob@b.example SIP", &format!("INVITE {ruri} SIP"));
            with_ctx(&m, udp("203.0.113.7:1"), &net, |ctx| {
                let rc = NatHelper::handle_ruri_alias(ctx);
                (rc, ctx.dst.map(|d| (d.proto, d.addr.to_string())), ctx.new_ruri.clone().map(|u| String::from_utf8(u).unwrap()))
            })
        };
        // (R-URI, code, $du, new R-URI)
        type Case<'a> = (&'a str, i32, Option<(Proto, &'a str)>, Option<&'a str>);
        let cases: &[Case] = &[
            (
                "sip:bob@10.0.0.5:5060;alias=203.0.113.7~40000~2;transport=tcp",
                1,
                Some((Proto::Tcp, "203.0.113.7:40000")),
                Some("sip:bob@10.0.0.5:5060;transport=tcp"),
            ),
            ("sip:bob@h;alias=203.0.113.7~5060~1", 1, Some((Proto::Udp, "203.0.113.7:5060")), Some("sip:bob@h")),
            ("sip:bob@h;alias=203.0.113.7~5060", 1, Some((Proto::Udp, "203.0.113.7:5060")), Some("sip:bob@h")),
            ("sip:bob@h;lr;alias=[2001:db8::7]~5070~6", 1, Some((Proto::Wss, "[2001:db8::7]:5070")), Some("sip:bob@h;lr")),
            ("sip:bob@h;alias=203.0.113.7~5060~99", 1, Some((Proto::Udp, "203.0.113.7:5060")), Some("sip:bob@h")),
            ("sip:bob@h;transport=tcp", 2, None, None),
            ("sip:bob@h;alias=203.0.113.7", -1, None, None),
            ("sip:bob@h;alias=bogus~5060~1", -1, None, None),
            ("sip:bob@h;alias=203.0.113.7~70000~1", -1, None, None),
        ];
        for (ruri, rc, dst, new) in cases {
            let want = (*rc, dst.map(|(p, a)| (p, a.to_string())), new.map(String::from));
            assert_eq!(run(ruri), want, "{ruri}");
        }
    }

    #[test]
    fn add_rcv_param_as_header_or_uri_parameter() {
        let net = FakeNet(vec![]);
        let tcp = Dest::new(Proto::Tcp, "203.0.113.7:40000".parse().unwrap());
        let cases = [
            ("<sip:a@10.0.0.5>;expires=60", false, udp("203.0.113.7:1"), "<sip:a@10.0.0.5>;received=\"sip:203.0.113.7:1\";expires=60"),
            ("<sip:a@10.0.0.5>", false, tcp, "<sip:a@10.0.0.5>;received=\"sip:203.0.113.7:40000;transport=tcp\""),
            ("<sip:a@10.0.0.5>", true, tcp, "<sip:a@10.0.0.5;received=sip:203.0.113.7:40000%3Btransport%3Dtcp>"),
            ("sip:a@10.0.0.5", false, udp("203.0.113.7:1"), "sip:a@10.0.0.5;received=\"sip:203.0.113.7:1\""),
        ];
        for (contact, in_uri, src, want) in cases {
            let out = with_ctx(&msg(contact, "10.0.0.5", ""), src, &net, |ctx| {
                assert_eq!(NatHelper::add_rcv_param(ctx, in_uri), 1);
                rendered(ctx)
            });
            assert_eq!(contact_line(&out), format!("Contact: {want}"), "{contact} in_uri={in_uri}");
        }
    }

    #[test]
    fn fix_nated_sdp_flags() {
        let net = FakeNet(vec![]);
        let run = |flags: i64, ip: Option<&str>| {
            with_ctx(&msg("", "10.0.0.5", SDP_PRIV), udp("203.0.113.7:1"), &net, |ctx| {
                assert_eq!(NatHelper::fix_nated_sdp(ctx, flags, ip.map(String::from)), 1);
                String::from_utf8(ctx.body()).unwrap()
            })
        };
        assert_eq!(run(2, None), "v=0\r\no=- 1 1 IN IP4 10.0.0.5\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n");
        assert_eq!(run(8, Some("2001:db8::9")), "v=0\r\no=- 1 1 IN IP6 2001:db8::9\r\ns=-\r\nc=IN IP4 10.0.0.5\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n");
        assert_eq!(
            run(11, None),
            "v=0\r\no=- 1 1 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\na=direction:active\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"
        );
        assert_eq!(with_ctx(&msg("", "10.0.0.5", ""), udp("203.0.113.7:1"), &net, |ctx| NatHelper::fix_nated_sdp(ctx, 2, None)), -1, "no body");
    }

    #[test]
    fn sdp_connection_address() {
        let cases = [
            ("c=IN IP4 10.0.0.5", Some("10.0.0.5")),
            ("c=IN IP4 224.2.1.1/127/3", Some("224.2.1.1")),
            ("c=IN IP6 2001:db8::1", Some("2001:db8::1")),
            ("o=- 1 1 IN IP4 192.0.2.1", Some("192.0.2.1")),
            ("c=IN IP4 host.example", None),
            ("c=", None),
        ];
        for (line, want) in cases {
            assert_eq!(sdp_ip(line), want.map(|s| s.parse().unwrap()), "{line}");
        }
    }

    #[test]
    fn replies_to_our_pings_are_consumed() {
        let net = FakeNet(vec![]);
        let reply = |branch: &str| {
            format!(
                "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 192.0.2.1;branch={branch}\nFrom: <sip:a@x>;tag=1\nTo: <sip:b@x>;tag=2\nCall-ID: c\nCSeq: 1 OPTIONS\nContent-Length: 0\n\n"
            )
        };
        let nh = NatHelper::default();
        // The core has parsed the Via of a reply by the time modules see it.
        let consumed = |r: String| {
            with_ctx(&r, udp("203.0.113.7:1"), &net, |ctx| {
                ctx.msg.parse_headers(sip_parser::HdrFlags::EOH).unwrap();
                nh.on_reply(ctx)
            })
        };
        assert!(consumed(reply("z9hG4bKnhping1a2b")));
        assert!(!consumed(reply("z9hG4bKother")));
    }
}
