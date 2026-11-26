//! `topoh` / `topos` — topology hiding.
//!
//! Every message ferrosip sends goes through a send filter
//! (`sip_core::net::set_send_filter`):
//! * requests: the Via headers of the previous hops are removed and carried
//!   in a parameter of our own Via (`vparam_name`, default `th`), so the
//!   next hop sees only us; replies get them back before tm forwards them;
//! * requests and replies: every Contact URI becomes
//!   `sip:<mask_ip>:<port>;<uparam_name>=<token>` (default `line`), so
//!   in-dialog requests come to us and are sent on to the real contact.
//!
//! `topoh` puts the hidden data into the token itself (XOR with
//! `mask_key`, base64url — obfuscation, as in Kamailio, not encryption);
//! `topos` keeps it on the proxy (in memory, `storage_ttl`, default
//! 12 h) and puts only a random id on the wire.
//!
//! * Record-Route: in requests, the URIs of other proxies become
//!   `sip:<mask_ip>:<port>;lr;<uparam_name>=<token>` too; a received
//!   request gets its Route URIs back, and a received reply its
//!   Record-Route URIs, before routing (a receive filter), so in-dialog
//!   requests still go through them.
//!
//! Not done: Call-ID masking (`mask_callid=1` is refused).

use crate::{b64, rand_u64, unb64};
use bumpalo::Bump;
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Dest, Lumps, Module, Outbound, Proto, Registry, ShardedMap};
use sip_parser::uri::{name_addr, split_list};
use sip_parser::{HdrFlags, HdrKind, Msg, parse_uri};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub struct Topo {
    stateful: bool,
    key: Mutex<String>,
    mask_ip: Mutex<Option<String>>,
    vparam: Mutex<String>,
    uparam: Mutex<String>,
    ttl: AtomicU64,
    store: ShardedMap<String, (Vec<u8>, u64)>,
    net: OnceLock<Arc<dyn Outbound>>,
}

impl Topo {
    pub fn new(stateful: bool) -> Self {
        Self {
            stateful,
            key: Mutex::new("aL9.n8~Hm]Z".into()),
            mask_ip: Mutex::new(None),
            vparam: Mutex::new("th".into()),
            uparam: Mutex::new("line".into()),
            ttl: AtomicU64::new(43200),
            store: ShardedMap::new(64),
            net: OnceLock::new(),
        }
    }

    fn keystream(&self, len: usize) -> Vec<u8> {
        let key = lock(&self.key).clone();
        let mut x = sip_core::fx_hash(key.as_bytes()) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // Bits 24..32 of the state.
                x.to_le_bytes()[3]
            })
            .collect()
    }

    fn encode(&self, data: &[u8]) -> String {
        if self.stateful {
            let id = format!("{:016x}", rand_u64());
            self.store.insert(id.clone(), (data.to_vec(), unix_secs().saturating_add(self.ttl.load(Ordering::Relaxed))));
            id
        } else {
            let ks = self.keystream(data.len());
            b64(&data.iter().zip(ks).map(|(a, b)| a ^ b).collect::<Vec<_>>())
        }
    }

    fn decode(&self, tok: &str) -> Option<Vec<u8>> {
        if self.stateful {
            self.store.get_cloned(tok).map(|v| v.0)
        } else {
            let raw = unb64(tok)?;
            let ks = self.keystream(raw.len());
            Some(raw.iter().zip(ks).map(|(a, b)| a ^ b).collect())
        }
    }

    fn host_for(&self, dst: &Dest) -> Option<String> {
        let adv = self.net.get()?.advertise(dst.proto)?;
        let ip = lock(&self.mask_ip).clone().unwrap_or_else(|| adv.ip().to_string());
        let ip = if ip.contains(':') && !ip.starts_with('[') { format!("[{ip}]") } else { ip };
        let t = match dst.proto {
            Proto::Udp => "",
            Proto::Tcp => ";transport=tcp",
            Proto::Tls => ";transport=tls",
            Proto::Ws => ";transport=ws",
            Proto::Wss => ";transport=wss",
        };
        Some(format!("{ip}:{}{t}", adv.port()))
    }

    /// The outgoing-message filter.
    fn filter(&self, dst: &Dest, data: &[u8]) -> Option<Vec<u8>> {
        let arena = Bump::new();
        let mut m = Msg::parse(data, &arena).ok()?;
        m.parse_headers(HdrFlags::EOH).ok()?;
        let mut lumps = Lumps::default();
        let mut changed = false;
        let uparam = lock(&self.uparam).clone();
        if m.is_request() {
            // Our Via is the first line; the rest go into a parameter of it.
            let vias: Vec<(usize, usize)> = m.headers.iter().filter(|h| h.kind == HdrKind::Via).map(|h| (h.start, h.end)).collect();
            // (tm puts its Via on a line of its own.)
            if let [(_, e0), rest @ ..] = vias.as_slice()
                && !rest.is_empty()
                && m.via1_next.is_none()
            {
                let mut hidden = Vec::new();
                for &(s, e) in rest {
                    hidden.extend_from_slice(data.get(s..e).unwrap_or_default());
                }
                let tok = self.encode(&hidden);
                let vp = lock(&self.vparam).clone();
                // Before our Via line's CRLF.
                lumps.insert(e0.saturating_sub(2), format!(";{vp}={tok}").into_bytes());
                for &(s, e) in rest {
                    lumps.delete(s, e.saturating_sub(s));
                }
                changed = true;
            }
        }
        // Record-Route of other proxies → us (requests: the next hop is the
        // other side; replies give it back unmasked, see `unmask`).
        if m.is_request()
            && let Some(host) = self.host_for(dst)
        {
            let net = self.net.get();
            for h in m.headers.iter().filter(|h| h.kind == HdrKind::RecordRoute) {
                for item in split_list(h.body) {
                    let uri = name_addr(item).0;
                    let Some(p) = parse_uri(uri) else { continue };
                    let ours = net.is_some_and(|n| {
                        sip_core::net::is_myself(&**n, &String::from_utf8_lossy(p.host))
                            && p.port.is_none_or(|port| Proto::ALL.iter().filter_map(|pr| n.advertise(*pr)).any(|a| a.port() == port))
                    });
                    if p.param(uparam.as_bytes()).is_some() || ours {
                        continue;
                    }
                    let scheme = String::from_utf8_lossy(p.scheme).into_owned();
                    let tok = self.encode(uri);
                    lumps.replace(m.offset_of(uri), uri.len(), format!("{scheme}:{host};lr;{uparam}={tok}").into_bytes());
                    changed = true;
                }
            }
        }
        // Contacts → us.
        if let Some(host) = self.host_for(dst) {
            for h in m.headers.iter().filter(|h| h.kind == HdrKind::Contact) {
                for item in split_list(h.body) {
                    let uri = name_addr(item).0;
                    if uri == b"*" || parse_uri(uri).is_some_and(|u| u.param(uparam.as_bytes()).is_some()) {
                        continue;
                    }
                    let Some(p) = parse_uri(uri) else { continue };
                    let scheme = String::from_utf8_lossy(p.scheme).into_owned();
                    let tok = self.encode(uri);
                    let at = m.offset_of(uri);
                    lumps.replace(at, uri.len(), format!("{scheme}:{host};{uparam}={tok}").into_bytes());
                    changed = true;
                }
            }
        }
        if !changed {
            return None;
        }
        let mut out = Vec::with_capacity(data.len().saturating_add(128));
        lumps.apply(data, &mut out);
        // Fix Content-Length? Bodies are untouched, so no.
        Some(out)
    }

    /// The receive filter: the masked URIs of a request's Route headers or
    /// a reply's Record-Route headers back to the real ones.
    fn unmask(&self, data: &[u8]) -> Option<Vec<u8>> {
        let uparam = lock(&self.uparam).clone();
        let needle = format!(";{uparam}=");
        if !data.windows(needle.len()).any(|w| w == needle.as_bytes()) {
            return None;
        }
        let arena = Bump::new();
        let mut m = Msg::parse(data, &arena).ok()?;
        m.parse_headers(HdrFlags::EOH).ok()?;
        let kind = if m.is_request() { HdrKind::Route } else { HdrKind::RecordRoute };
        let mut lumps = Lumps::default();
        let mut changed = false;
        for h in m.headers.iter().filter(|h| h.kind == kind) {
            for item in split_list(h.body) {
                let uri = name_addr(item).0;
                let Some(tok) = parse_uri(uri).and_then(|u| u.param(uparam.as_bytes()).map(|t| String::from_utf8_lossy(t).into_owned())) else { continue };
                let Some(orig) = self.decode(&tok) else { continue };
                lumps.replace(m.offset_of(uri), uri.len(), orig);
                changed = true;
            }
        }
        if !changed {
            return None;
        }
        let mut out = Vec::with_capacity(data.len());
        lumps.apply(data, &mut out);
        Some(out)
    }

    fn on_request(&self, ctx: &mut Ctx<'_, '_>) {
        let uparam = lock(&self.uparam).clone();
        let ruri = ctx.ruri().to_vec();
        let Some(u) = parse_uri(&ruri) else { return };
        let Some(tok) = u.param(uparam.as_bytes()) else { return };
        let host = String::from_utf8_lossy(u.host).into_owned();
        let ours = lock(&self.mask_ip).as_deref().is_some_and(|m| m.trim_matches(|c| c == '[' || c == ']') == host.trim_matches(|c| c == '[' || c == ']'))
            || sip_core::net::is_myself(ctx.net, &host);
        if !ours {
            return;
        }
        if let Some(orig) = self.decode(&String::from_utf8_lossy(tok)) {
            ctx.new_ruri = Some(orig);
        }
    }

    fn on_reply(&self, ctx: &mut Ctx<'_, '_>) {
        let vp = lock(&self.vparam).clone();
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return;
        }
        let Some(v) = ctx.msg.via1 else { return };
        let Some(params) = v.raw.splitn(2, |&c| c == b';').nth(1) else { return };
        let Some(tok) = sip_parser::uri::param(params, vp.as_bytes()).map(|t| String::from_utf8_lossy(t).into_owned()) else { return };
        let Some(hidden) = self.decode(&tok) else { return };
        let Some(end) = ctx.msg.via1_hdr.and_then(|hi| ctx.msg.headers.get(hi)).map(|h| h.end) else { return };
        ctx.lumps.insert(end, hidden);
    }
}

impl Module for Topo {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("mask_key", Ty::Str, "aL9.n8~Hm]Z", "Key that obfuscates the hidden data (topoh)"),
            p("mask_ip", Ty::Str, "", "Host put into masked Contact URIs (default: our address)"),
            p("vparam_name", Ty::Str, "th", "Via parameter that carries the hidden Via headers"),
            p("uparam_name", Ty::Str, "line", "Contact URI parameter that carries the hidden contact"),
            p("storage_ttl", Ty::Duration(Unit::Sec), "12h", "How long topos keeps the hidden data (at least 60s)"),
            p("dialog_expire", Ty::Duration(Unit::Sec), "12h", "Same as storage_ttl"),
        ])
    }

    fn name(&self) -> &'static str {
        if self.stateful { "topos" } else { "topoh" }
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "mask_key" => *lock(&self.key) = v.str()?.into(),
            "mask_ip" => *lock(&self.mask_ip) = Some(v.str()?.into()),
            "vparam_name" => *lock(&self.vparam) = v.str()?.into(),
            "uparam_name" => *lock(&self.uparam) = v.str()?.into(),
            "storage_ttl" | "dialog_expire" => self.ttl.store(u64::try_from(v.int()?).unwrap_or(0).max(60), Ordering::Relaxed),
            "mask_callid" if v.int()? != 0 => return Err(format!("{}: mask_callid is not supported", self.name())),
            "mask_callid" | "uparam_prefix" | "vparam_prefix" | "callid_prefix" | "sanity_checks" | "uri_prefix_checks" | "event_callback" | "event_mode"
            | "use_mode" | "db_url" | "storage" | "clean_interval" | "branch_expire" => {}
            _ => return Err(format!("{}: unknown parameter {name:?}", self.name())),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, _reg: &mut Registry) -> Result<(), String> {
        let me = self.clone();
        sip_core::net::set_send_filter(Arc::new(move |d, m| me.filter(d, m)))?;
        let me = self.clone();
        sip_core::net::set_recv_filter(Arc::new(move |_, m| me.unmask(m)))
    }

    fn observes(&self) -> bool {
        true
    }

    fn observe_request(&self, ctx: &mut Ctx<'_, '_>) {
        self.on_request(ctx);
    }

    fn observe_reply(&self, ctx: &mut Ctx<'_, '_>) {
        self.on_reply(ctx);
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        if self.stateful {
            std::thread::Builder::new()
                .name("topos-gc".into())
                .spawn(move || {
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(30));
                        let t = unix_secs();
                        self.store.retain(|_, v| v.1 > t);
                    }
                })
                .map_err(|e| format!("cannot start the topos gc thread: {e}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_roundtrip() {
        for stateful in [false, true] {
            let t = Topo::new(stateful);
            let tok = t.encode(b"Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\n");
            assert!(!tok.contains(';') && !tok.contains('='));
            assert_eq!(t.decode(&tok).unwrap(), b"Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\n");
        }
    }

    #[test]
    fn route_and_record_route_are_unmasked() {
        let t = Topo::new(false);
        let tok = t.encode(b"sip:10.1.1.1;lr");
        let req = format!(
            "BYE sip:a@x SIP/2.0\r\nVia: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bK1\r\nRoute: <sip:9.9.9.9;lr>, <sip:5.5.5.5:5060;lr;line={tok}>\r\nCall-ID: c\r\nContent-Length: 0\r\n\r\n"
        );
        let out = String::from_utf8(t.unmask(req.as_bytes()).unwrap()).unwrap();
        assert!(out.contains("Route: <sip:9.9.9.9;lr>, <sip:10.1.1.1;lr>\r\n"), "{out}");
        let rep = format!(
            "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bK1\r\nRecord-Route: <sip:5.5.5.5;lr;line={tok}>\r\nCall-ID: c\r\nContent-Length: 0\r\n\r\n"
        );
        let out = String::from_utf8(t.unmask(rep.as_bytes()).unwrap()).unwrap();
        assert!(out.contains("Record-Route: <sip:10.1.1.1;lr>\r\n"), "{out}");
        assert!(t.unmask(b"OPTIONS sip:a@x SIP/2.0\r\nContent-Length: 0\r\n\r\n").is_none());
    }

    use crate::testutil::{FakeNet, crlf, rendered, udp, with_ctx};

    /// A topoh/topos instance that advertises 192.0.2.10:5060.
    fn topo(stateful: bool) -> Topo {
        let t = Topo::new(stateful);
        let _ = t.net.set(Arc::new(FakeNet(Some("192.0.2.10:5060".parse().unwrap()))));
        t
    }

    /// The value of `;name=` in `line`.
    fn token<'a>(line: &'a str, name: &str) -> &'a str {
        let (_, rest) = line.split_once(&format!(";{name}=")).unwrap_or_else(|| panic!("no {name} in {line}"));
        rest.split([';', '>', '\r', ',']).next().unwrap()
    }

    fn line<'a>(msg: &'a str, prefix: &str) -> &'a str {
        msg.split("\r\n").find(|l| l.starts_with(prefix)).unwrap_or_else(|| panic!("no {prefix} in {msg}"))
    }

    const HIDDEN: &str = "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKa;rport\r\nVia: SIP/2.0/TCP 10.0.0.2;branch=z9hG4bKb\r\n";

    fn invite() -> String {
        crlf(
            "INVITE sip:bob@198.51.100.1 SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKus\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKa;rport\nVia: SIP/2.0/TCP 10.0.0.2;branch=z9hG4bKb\nFrom: <sip:a@x>;tag=1\nTo: <sip:bob@x>\n\
Call-ID: c\nCSeq: 1 INVITE\nContact: \"A\" <sip:a@10.0.0.1:5060;transport=udp>;expires=60\nRecord-Route: <sip:10.9.9.9;lr>, <sip:192.0.2.10;lr>\n\
Content-Length: 0\n\n",
        )
    }

    #[test]
    fn topo_request_hides_vias_contact_and_record_route_and_they_come_back() {
        for stateful in [false, true] {
            let t = topo(stateful);
            let out = String::from_utf8(t.filter(&udp("198.51.100.1:5060"), invite().as_bytes()).unwrap()).unwrap();
            assert_eq!(out.matches("Via:").count(), 1, "{out}");
            let via = line(&out, "Via:");
            assert!(via.starts_with("Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKus;th="), "{via}");
            assert_eq!(t.decode(token(via, "th")).unwrap(), HIDDEN.as_bytes(), "stateful {stateful}");
            let contact = line(&out, "Contact:");
            let ctok = token(contact, "line");
            assert_eq!(contact, format!("Contact: \"A\" <sip:192.0.2.10:5060;line={ctok}>;expires=60"));
            assert_eq!(t.decode(ctok).unwrap(), b"sip:a@10.0.0.1:5060;transport=udp");
            let rr = line(&out, "Record-Route:");
            let rtok = token(rr, "line");
            assert_eq!(rr, format!("Record-Route: <sip:192.0.2.10:5060;lr;line={rtok}>, <sip:192.0.2.10;lr>"), "our own entry stays");
            assert_eq!(t.decode(rtok).unwrap(), b"sip:10.9.9.9;lr");

            // The reply to it gets the hidden Vias back under ours.
            let reply =
                crlf(&format!("SIP/2.0 200 OK\n{via}\nFrom: <sip:a@x>;tag=1\nTo: <sip:bob@x>;tag=2\nCall-ID: c\nCSeq: 1 INVITE\nContent-Length: 0\n\n"));
            let net = FakeNet(None);
            let back = with_ctx(&reply, udp("198.51.100.1:5060"), &net, |ctx| {
                t.on_reply(ctx);
                rendered(ctx)
            });
            assert!(back.contains(&format!("{via}\r\n{HIDDEN}From:")), "{back}");

            // An in-dialog request to the masked Contact goes to the real one.
            let us = FakeNet(Some("192.0.2.10:5060".parse().unwrap()));
            let bye = crlf(&format!(
                "BYE sip:192.0.2.10:5060;line={ctok} SIP/2.0\nVia: SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK2\nFrom: <sip:bob@x>;tag=2\n\
To: <sip:a@x>;tag=1\nCall-ID: c\nCSeq: 2 BYE\nContent-Length: 0\n\n"
            ));
            let ruri = with_ctx(&bye, udp("198.51.100.1:5060"), &us, |ctx| {
                t.on_request(ctx);
                ctx.new_ruri.clone()
            });
            assert_eq!(ruri.as_deref(), Some(&b"sip:a@10.0.0.1:5060;transport=udp"[..]));
            let elsewhere = bye.replace("sip:192.0.2.10:5060;line=", "sip:203.0.113.9;line=");
            let ruri = with_ctx(&elsewhere, udp("198.51.100.1:5060"), &us, |ctx| {
                t.on_request(ctx);
                ctx.new_ruri.clone()
            });
            assert_eq!(ruri, None, "not our host: left alone");

            // Its Route through the masked Record-Route is unmasked on receipt.
            let routed = bye.replace("Content-Length", &format!("Route: <sip:192.0.2.10:5060;lr;line={rtok}>\r\nContent-Length"));
            let un = String::from_utf8(t.unmask(routed.as_bytes()).unwrap()).unwrap();
            assert!(un.contains("Route: <sip:10.9.9.9;lr>\r\n"), "{un}");
        }
    }

    #[test]
    fn topo_masked_host_follows_mask_ip_and_transport() {
        let t = topo(false);
        let msg = crlf(
            "OPTIONS sip:b@x SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.10;branch=z9hG4bK1\nFrom: <sip:a@x>;tag=1\nTo: <sip:b@x>\nCall-ID: c\nCSeq: 1 OPTIONS\nContact: <sip:a@10.0.0.1>\nContent-Length: 0\n\n",
        );
        let contact = |t: &Topo, d: Dest| {
            let out = String::from_utf8(t.filter(&d, msg.as_bytes()).unwrap()).unwrap();
            let l = line(&out, "Contact:").to_string();
            l.split(";line=").next().unwrap().to_string()
        };
        assert_eq!(contact(&t, udp("198.51.100.1:5060")), "Contact: <sip:192.0.2.10:5060");
        assert_eq!(contact(&t, Dest::new(Proto::Tcp, "198.51.100.1:5060".parse().unwrap())), "Contact: <sip:192.0.2.10:5060;transport=tcp");
        assert_eq!(contact(&t, Dest::new(Proto::Wss, "198.51.100.1:443".parse().unwrap())), "Contact: <sip:192.0.2.10:5060;transport=wss");
        assert_eq!(contact(&t, Dest::new(Proto::Tls, "198.51.100.1:5061".parse().unwrap())), "Contact: <sip:192.0.2.10:5060;transport=tls");
        assert_eq!(contact(&t, Dest::new(Proto::Ws, "198.51.100.1:80".parse().unwrap())), "Contact: <sip:192.0.2.10:5060;transport=ws");
        t.set_param("mask_ip", &Arg::Str("2001:db8::1".into())).unwrap();
        assert_eq!(contact(&t, udp("198.51.100.1:5060")), "Contact: <sip:[2001:db8::1]:5060");
        t.set_param("uparam_name", &Arg::Str("tok".into())).unwrap();
        let out = String::from_utf8(t.filter(&udp("198.51.100.1:5060"), msg.as_bytes()).unwrap()).unwrap();
        assert!(line(&out, "Contact:").contains(";tok="), "{out}");
    }

    #[test]
    fn topo_leaves_alone_what_it_cannot_or_need_not_mask() {
        let t = topo(false);
        let plain = |contact: &str| {
            crlf(&format!(
                "OPTIONS sip:b@x SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.10;branch=z9hG4bK1\nFrom: <sip:a@x>;tag=1\nTo: <sip:b@x>\nCall-ID: c\nCSeq: 1 OPTIONS\n{contact}Content-Length: 0\n\n"
            ))
        };
        assert!(t.filter(&udp("198.51.100.1:5060"), plain("").as_bytes()).is_none(), "one Via, no Contact");
        assert!(t.filter(&udp("198.51.100.1:5060"), plain("Contact: *\n").as_bytes()).is_none());
        assert!(t.filter(&udp("198.51.100.1:5060"), plain("Contact: <sip:192.0.2.10:5060;line=abc>\n").as_bytes()).is_none(), "already masked");
        // A reply keeps its Vias; only the Contact is masked.
        let reply = crlf(
            "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 192.0.2.10;branch=z9hG4bK1\nVia: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK2\nFrom: <sip:a@x>;tag=1\n\
To: <sip:b@x>;tag=2\nCall-ID: c\nCSeq: 1 INVITE\nContact: <sip:b@10.0.0.7>\nRecord-Route: <sip:10.9.9.9;lr>\nContent-Length: 0\n\n",
        );
        let out = String::from_utf8(t.filter(&udp("198.51.100.1:5060"), reply.as_bytes()).unwrap()).unwrap();
        assert_eq!(out.matches("Via:").count(), 2);
        assert!(out.contains("Record-Route: <sip:10.9.9.9;lr>\r\n"), "a reply's Record-Route is not masked: {out}");
        assert!(line(&out, "Contact:").starts_with("Contact: <sip:192.0.2.10:5060;line="));
        // Without a network (before spawn) only the Vias can be hidden.
        let bare = Topo::new(false);
        let out = String::from_utf8(bare.filter(&udp("198.51.100.1:5060"), invite().as_bytes()).unwrap()).unwrap();
        assert!(out.contains("Contact: \"A\" <sip:a@10.0.0.1:5060;transport=udp>") && out.matches("Via:").count() == 1, "{out}");
        // A Via line with two values is not ours alone: left as is.
        let two = invite().replace("branch=z9hG4bKus\r\nVia:", "branch=z9hG4bKus,");
        let out = String::from_utf8(t.filter(&udp("198.51.100.1:5060"), two.as_bytes()).unwrap()).unwrap();
        assert!(!out.contains(";th="), "{out}");
    }

    #[test]
    fn topo_tokens_depend_on_key_and_unknown_tokens_fail() {
        let a = Topo::new(false);
        let b = Topo::new(false);
        b.set_param("mask_key", &Arg::Str("other".into())).unwrap();
        let tok = a.encode(b"sip:secret@10.0.0.1");
        assert_ne!(b.decode(&tok).unwrap(), b"sip:secret@10.0.0.1");
        assert_ne!(tok, b.encode(b"sip:secret@10.0.0.1"));
        assert_eq!(a.encode(b"x"), a.encode(b"x"), "topoh: deterministic");
        assert_eq!(a.decode("!!"), None);
        let s = Topo::new(true);
        assert_eq!(s.decode(&a.encode(b"x")), None, "topos: not stored here");
        assert_ne!(s.encode(b"x"), s.encode(b"x"), "topos: a new id each time");
        assert_eq!(a.encode(b"").len(), 0);
    }

    #[test]
    fn topo_parameters() {
        let t = Topo::new(true);
        assert!(t.set_param("mask_callid", &Arg::Int(1)).is_err());
        assert!(t.set_param("mask_callid", &Arg::Int(0)).is_ok());
        t.set_param("storage_ttl", &Arg::Int(5)).unwrap();
        assert_eq!(t.ttl.load(Ordering::Relaxed), 60, "at least 60s");
        t.set_param("dialog_expire", &Arg::Int(-5)).unwrap();
        assert_eq!(t.ttl.load(Ordering::Relaxed), 60);
        assert!(t.set_param("bogus", &Arg::Int(1)).unwrap_err().starts_with("topos:"));
        assert_eq!((Topo::new(false).name(), t.name()), ("topoh", "topos"));
    }

    #[test]
    fn topo_ignores_tokens_it_cannot_decode() {
        let t = topo(true);
        let us = FakeNet(Some("192.0.2.10:5060".parse().unwrap()));
        let bye = crlf(
            "BYE sip:192.0.2.10:5060;line=0123456789abcdef SIP/2.0\nVia: SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK2\nFrom: <sip:bob@x>;tag=2\n\
To: <sip:a@x>;tag=1\nCall-ID: c\nCSeq: 2 BYE\nContent-Length: 0\n\n",
        );
        let ruri = with_ctx(&bye, udp("198.51.100.1:5060"), &us, |ctx| {
            t.on_request(ctx);
            ctx.new_ruri.clone()
        });
        assert_eq!(ruri, None, "an unknown (expired) topos id leaves the R-URI alone");
        let reply = |via: &str| {
            crlf(&format!("SIP/2.0 200 OK\n{via}\nFrom: <sip:a@x>;tag=1\nTo: <sip:bob@x>;tag=2\nCall-ID: c\nCSeq: 1 INVITE\nContent-Length: 0\n\n"))
        };
        for via in [
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKus;th=0123456789abcdef",
            "Via: SIP/2.0/UDP 192.0.2.10:5060",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKus",
        ] {
            let msg = reply(via);
            let out = with_ctx(&msg, udp("198.51.100.1:5060"), &us, |ctx| {
                t.on_reply(ctx);
                rendered(ctx)
            });
            assert_eq!(out, msg, "{via}");
        }
        // A header line without a colon: the headers do not parse.
        let broken = crlf("SIP/2.0 200 OK\nVia: SIP/2.0/UDP 192.0.2.10;th=x\nno colon here\nContent-Length: 0\n\n");
        let out = with_ctx(&broken, udp("198.51.100.1:5060"), &us, |ctx| {
            t.on_reply(ctx);
            rendered(ctx)
        });
        assert_eq!(out, broken);
    }
}
