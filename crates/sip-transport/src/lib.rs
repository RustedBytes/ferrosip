//! Transports: UDP workers, TCP/TLS/WS/WSS (tcp_main + readers), and `Net`, the
//! send-side API (`Outbound`) shared by every thread.
#![forbid(unsafe_code)]
// An ignored Result here is a decision: say why (`#[allow]` + reason).
#![warn(clippy::let_underscore_must_use)]

pub mod tcp;
pub mod tls;
pub mod udp;
pub mod ws;

pub use tcp::{ConnInfo, TcpOpts, TcpService};
pub use tls::TlsFiles;

use bumpalo::Bump;
use mio::net::TcpListener;
use sip_core::{Ctx, Dest, Handler, Lumps, Outbound, Proto};
use sip_parser::Msg;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Per-thread scratch space reused for every message.
#[derive(Default)]
pub(crate) struct Scratch {
    arena: Bump,
    lumps: Lumps,
    out: Vec<u8>,
    /// Where a stamped Via and its message are built (reused: no
    /// allocation per message once it has grown).
    via: Vec<u8>,
    stamped: Vec<u8>,
}

/// Parse one complete message and run the handler on it. Shared by the UDP
/// workers and the TCP readers — the routing logic never knows the transport
/// except through `ctx.src.proto`.
///
/// Everything (parsing included) runs inside `sip_core::panic::catch`: a bug
/// triggered by one message drops that message, never the worker thread
/// (Kamailio gets this isolation from separate processes).
pub(crate) fn dispatch(pkt: &[u8], src: Dest, net: &dyn Outbound, udp: Option<&UdpSocket>, handler: &dyn Handler, s: &mut Scratch, worker: usize) {
    if sip_core::panic::catch(|| dispatch_one(pkt, src, net, udp, handler, s, worker)).is_err() {
        sip_core::elog!("worker {worker}: panic while handling message from {src}; dropped");
    }
}

fn dispatch_one(pkt: &[u8], src: Dest, net: &dyn Outbound, udp: Option<&UdpSocket>, handler: &dyn Handler, s: &mut Scratch, worker: usize) {
    if pkt.iter().all(u8::is_ascii_whitespace) {
        return; // keep-alive
    }
    s.arena.reset(); // frees all of the previous message's allocations at once
    s.lumps.clear();
    let pkt: &[u8] = match sip_core::net::recv_filtered(&src, pkt) {
        Some(v) => s.arena.alloc_slice_copy(&v),
        None => pkt,
    };
    let Ok(mut msg) = Msg::parse(pkt, &s.arena) else {
        sip_core::stats::inc(core_stats().2);
        return;
    };
    let mut via_stamp = None;
    // RFC 3261 §18.2.1 / RFC 3581 §4: stamp the top Via with where the
    // request really came from. Done on the buffer itself, so the relayed
    // request, every local reply and the transaction's copy all carry it.
    if msg.is_request()
        && msg.parse_headers(sip_parser::HdrFlags::VIA).is_ok()
        && let Some(v) = msg.via1
        && let Some(start) = stamp_via(pkt, &v, src.addr, &mut s.via, &mut s.stamped)
    {
        via_stamp = Some(sip_core::module::ViaStamp { start, stamped_len: s.via.len(), orig: s.arena.alloc_slice_copy(v.raw) });
        let buf: &[u8] = s.arena.alloc_slice_copy(&s.stamped);
        let Ok(m) = Msg::parse(buf, &s.arena) else {
            sip_core::stats::inc(core_stats().2);
            return;
        };
        msg = m;
    }
    sip_core::stats::inc(if msg.is_request() { core_stats().0 } else { core_stats().1 });
    let draining = sip_core::shutdown::draining() && sip_core::shutdown::starts_new_work(&mut msg);
    // RFC 5923: `Via: …;alias` on a request over a stream offers the
    // connection for requests to the Via sent-by port (opt-in, as in
    // Kamailio). The alias is always the connection's own source IP: the Via
    // host is peer-controlled, and trusting it would let any client capture
    // requests meant for another address (§5: the alias must not be
    // usable to impersonate another host).
    if let (Some(id), true) = (src.conn, src.proto.is_stream() && !src.proto.is_ws() && msg.is_request() && net.accepts_aliases())
        && msg.parse_headers(sip_parser::HdrFlags::VIA).is_ok()
        && let Some(v) = msg.via1.filter(|v| v.alias)
    {
        let port = v.port.unwrap_or(if src.proto.is_tls() { 5061 } else { 5060 });
        net.add_alias(id, SocketAddr::new(src.addr.ip(), port));
    }
    let mut ctx = Ctx {
        msg: &mut msg,
        lumps: &mut s.lumps,
        out: &mut s.out,
        net,
        udp,
        src,
        worker,
        last_error: None,
        new_ruri: None,
        dst: None,
        rc: 1,
        ruri_q: None,
        branches: Vec::new(),
        ext: Vec::new(),
        answered: false,
        via_stamp,
    };
    if draining {
        // Graceful shutdown: no new transactions or dialogs; the sender
        // retries elsewhere or after the restart.
        let retry = format!("Retry-After: {}\r\n", sip_core::shutdown::RETRY_AFTER_SECS);
        #[allow(clippy::let_underscore_must_use, reason = "the request is refused either way; send failures are counted")]
        let _ = ctx.reply_with(503, "Service Unavailable", retry.as_bytes());
        return;
    }
    handler.handle(&mut ctx);
}

/// `pkt` with its top Via (`v`, parsed from `pkt`) given `received=` when
/// the sent-by host isn't the source IP, and `rport=`/`received=` when the
/// sender asked for rport (RFC 3581), built in `out`; the new Via is left
/// in `via`. Returns where the Via starts; None: nothing to change.
fn stamp_via(pkt: &[u8], v: &sip_parser::Via<'_>, src: SocketAddr, via: &mut Vec<u8>, out: &mut Vec<u8>) -> Option<usize> {
    let host = v.host.strip_prefix(b"[").and_then(|h| h.strip_suffix(b"]")).unwrap_or(v.host);
    let same_host = std::str::from_utf8(host).ok().and_then(|h| h.parse::<IpAddr>().ok()) == Some(src.ip());
    let rport = v.rport.is_some();
    let received_ok = v.received.is_some_and(|r| std::str::from_utf8(r).ok().and_then(|r| r.parse::<IpAddr>().ok()) == Some(src.ip()));
    let rport_ok = !rport || v.rport.is_some_and(|p| p == src.port().to_string().as_bytes());
    let want_received = !same_host || rport;
    if (!want_received || received_ok) && rport_ok {
        return None;
    }
    let start = (v.raw.as_ptr() as usize).checked_sub(pkt.as_ptr() as usize)?;
    let (before, from_via) = pkt.split_at_checked(start)?;
    let after = from_via.get(v.raw.len()..)?;
    let (head, params) = sip_parser::util::split_once(v.raw, b';').unwrap_or((v.raw, b""));
    via.clear();
    via.extend_from_slice(head);
    for p in params.split(|&c| c == b';') {
        let name = p.split(|&c| c == b'=').next().unwrap_or(p);
        let name = name.trim_ascii();
        if name.is_empty() || name.eq_ignore_ascii_case(b"received") || name.eq_ignore_ascii_case(b"rport") {
            continue;
        }
        via.push(b';');
        via.extend_from_slice(p);
    }
    if want_received {
        #[allow(clippy::let_underscore_must_use, reason = "writing into memory can't fail")]
        let _ = write!(via, ";received={}", src.ip());
    }
    if rport {
        #[allow(clippy::let_underscore_must_use, reason = "writing into memory can't fail")]
        let _ = write!(via, ";rport={}", src.port());
    }
    out.clear();
    out.extend_from_slice(before);
    out.extend_from_slice(via);
    out.extend_from_slice(after);
    Some(start)
}

/// Load the TLS certificates, keys and profiles the configuration names
/// (None: no TLS), and check every TLS listener has a certificate. Used at
/// startup and by `ferrosip check`.
pub fn load_tls(cfg: &Config) -> Result<Option<tls::TlsConfig>, String> {
    let need_tls_server = cfg.listen.iter().any(|l| l.proto.is_tls());
    let have_tls_files = cfg.tls.cert.is_some()
        || cfg.tls.key.is_some()
        || cfg.tls.ca.is_some()
        || !cfg.tls.sni.is_empty()
        || cfg.tls.profile.is_some()
        || cfg.tls.profile_text.is_some();
    let tls = if need_tls_server || have_tls_files { Some(tls::load(&cfg.tls, need_tls_server)?) } else { None };
    for l in cfg.listen.iter().filter(|l| l.proto.is_tls()) {
        if tls.as_ref().and_then(|t| t.server_for(Some(l.addr))).is_none() {
            return Err(format!("{}:{}: no certificate (--tls-cert, or a [server:{}] profile)", l.proto.via_name().to_lowercase(), l.addr, l.addr));
        }
    }
    Ok(tls)
}

type CoreStats = (&'static std::sync::atomic::AtomicI64, &'static std::sync::atomic::AtomicI64, &'static std::sync::atomic::AtomicI64);

fn core_stats() -> &'static CoreStats {
    static S: std::sync::OnceLock<CoreStats> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        use sip_core::stats::counter;
        (counter("core", "rcv_requests"), counter("core", "rcv_replies"), counter("core", "bad_msgs"))
    })
}

/// Sends over any transport; implements `Outbound` for modules and timers.
pub struct Net {
    udp: Option<UdpSocket>,
    tcp: Arc<TcpService>,
    advertise: [Option<SocketAddr>; 5],
}

impl Net {
    pub fn tcp(&self) -> &TcpService {
        &self.tcp
    }
}

impl Outbound for Net {
    fn send(&self, dst: &Dest, data: &[u8]) -> io::Result<()> {
        let data = &*sip_core::net::filtered(dst, data);
        let r = match dst.proto {
            Proto::Udp => match self.udp.as_ref() {
                Some(s) => s.send_to(data, dst.addr).map(|_| ()),
                None => Err(io::Error::other("no UDP listener")),
            },
            _ => self.tcp.send(dst, data),
        };
        // Every send through the transport is counted (and logged) here.
        sip_core::net::note_send(dst, r)
    }

    fn accepts_aliases(&self) -> bool {
        self.tcp.accepts_aliases()
    }

    fn add_alias(&self, conn: sip_core::ConnId, addr: SocketAddr) {
        self.tcp.add_alias(conn, addr)
    }

    fn conn_to(&self, dst: &Dest) -> Option<sip_core::ConnId> {
        if dst.proto == Proto::Udp {
            return None;
        }
        self.tcp.conn_to(dst)
    }

    fn advertise(&self, proto: Proto) -> Option<SocketAddr> {
        // No listener for this transport (e.g. outbound-only TLS): replies
        // come back on the same connection, any of our addresses will do.
        self.advertise.get(proto.index()).copied().flatten().or_else(|| self.advertise.iter().flatten().next().copied())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Listen {
    pub proto: Proto,
    pub addr: SocketAddr,
    /// Address to put in Via/Contact for this protocol instead of the bind
    /// address (ferrosip.toml `[[listen]] advertise`).
    pub advertise: Option<SocketAddr>,
}

impl Listen {
    /// `udp:`, `tcp:`, `tls:`, `ws:`, `wss:` + `ip:port` (bare `ip:port` = UDP).
    pub fn parse(s: &str) -> Result<Self, String> {
        let d = Dest::parse(s)?;
        Ok(Self { proto: d.proto, addr: d.addr, advertise: None })
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: Vec<Listen>,
    pub udp_workers: usize,
    pub tcp: TcpOpts,
    pub tls: TlsFiles,
    /// Advertise this IP in Via instead of the bind address (`advertise` in Kamailio).
    pub advertise_ip: Option<IpAddr>,
}

pub fn start(cfg: &Config, handler: Arc<dyn Handler>) -> Result<(Arc<Net>, Vec<JoinHandle<()>>), String> {
    let mut advertise = [None; 5];
    let adv = |a: SocketAddr| SocketAddr::new(cfg.advertise_ip.unwrap_or(a.ip()), a.port());

    let mut udp_socks = Vec::new();
    let mut tcp_listeners = Vec::new();
    for l in &cfg.listen {
        if let Some(slot) = advertise.get_mut(l.proto.index()) {
            slot.get_or_insert(l.advertise.unwrap_or_else(|| adv(l.addr)));
        }
        match l.proto {
            Proto::Udp => {
                for _ in 0..cfg.udp_workers.max(1) {
                    udp_socks.push(udp::bind_reuseport(l.addr, 8 << 20).map_err(|e| format!("bind udp:{}: {e}", l.addr))?);
                }
            }
            p => {
                let tl = TcpListener::bind(l.addr).map_err(|e| format!("bind {}:{}: {e}", p.via_name().to_lowercase(), l.addr))?;
                tcp_listeners.push((tl, p));
            }
        }
    }

    let tls = load_tls(cfg)?;
    let tcp = TcpService::new(cfg.tcp.clone(), tls).map_err(|e| format!("tcp init: {e}"))?;
    let t = tcp.clone();
    sip_core::stats::gauge("tcp", "active_connections", move || i64::try_from(t.active_connections()).unwrap_or(i64::MAX));

    let udp_send = match udp_socks.first() {
        Some(s) => Some(s.try_clone().map_err(|e| e.to_string())?),
        None => None,
    };
    let net = Arc::new(Net { udp: udp_send, tcp: tcp.clone(), advertise });
    let n_udp = udp_socks.len();
    let mut handles = udp::run_workers(udp_socks, net.clone(), handler.clone())?;
    handles.extend(tcp.start(tcp_listeners, net.clone(), handler, n_udp)?);
    Ok((net, handles))
}

#[cfg(test)]
mod via_tests {
    use super::*;

    fn stamp(req: &str, src: &str) -> Option<String> {
        let arena = Bump::new();
        let mut m = Msg::parse(req.as_bytes(), &arena).unwrap();
        m.parse_headers(sip_parser::HdrFlags::VIA).unwrap();
        let (mut via, mut out) = (Vec::new(), Vec::new());
        stamp_via(req.as_bytes(), &m.via1.unwrap(), src.parse().unwrap(), &mut via, &mut out).map(|_| String::from_utf8(out).unwrap())
    }

    const REQ: &str = "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP {VIA}\r\nVia: SIP/2.0/UDP 10.9.9.9;branch=z9hG4bKx\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:a@b>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";

    fn req(via: &str) -> String {
        REQ.replace("{VIA}", via)
    }

    #[test]
    fn a_via_matching_the_source_is_left_alone() {
        assert_eq!(stamp(&req("192.0.2.1:5060;branch=z9hG4bK1"), "192.0.2.1:7000"), None);
    }

    #[test]
    fn a_different_host_gets_received() {
        let out = stamp(&req("10.0.0.5:5060;branch=z9hG4bK1"), "192.0.2.1:7000").unwrap();
        assert!(out.contains("Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK1;received=192.0.2.1\r\n"), "{out}");
        assert!(out.contains("Via: SIP/2.0/UDP 10.9.9.9;branch=z9hG4bKx\r\n"));
    }

    #[test]
    fn rport_gets_the_port_and_received() {
        let out = stamp(&req("192.0.2.1:5060;rport;branch=z9hG4bK1"), "192.0.2.1:7000").unwrap();
        assert!(out.contains("Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1;received=192.0.2.1;rport=7000\r\n"), "{out}");
        // Stamped once: a second pass changes nothing.
        assert_eq!(stamp(&out, "192.0.2.1:7000"), None);
    }

    #[test]
    fn a_forged_received_is_replaced() {
        let out = stamp(&req("10.0.0.5;received=203.0.113.9;branch=z9hG4bK1"), "192.0.2.1:7000").unwrap();
        assert!(out.contains("10.0.0.5;branch=z9hG4bK1;received=192.0.2.1\r\n"), "{out}");
        assert!(!out.contains("203.0.113.9"));
    }

    #[test]
    fn ipv6_hosts_compare_without_brackets() {
        assert_eq!(stamp(&req("[2001:db8::1]:5060;branch=z9hG4bK1"), "[2001:db8::1]:7000"), None);
    }
}

#[cfg(test)]
mod via_table_tests {
    use super::*;

    fn stamp(via_line: &str, src: &str) -> Option<String> {
        let req = format!("OPTIONS sip:a@b SIP/2.0\r\n{via_line}\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:a@b>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n");
        let arena = Bump::new();
        let mut m = Msg::parse(req.as_bytes(), &arena).unwrap();
        m.parse_headers(sip_parser::HdrFlags::VIA).unwrap();
        let v = m.via1.unwrap();
        let (mut via, mut out) = (Vec::new(), Vec::new());
        let start = stamp_via(req.as_bytes(), &v, src.parse().unwrap(), &mut via, &mut out)?;
        let out = String::from_utf8(out).unwrap();
        assert_eq!(start, req.find(std::str::from_utf8(v.raw).unwrap()).unwrap(), "start points at the Via value");
        assert!(out.contains(std::str::from_utf8(&via).unwrap()), "the returned Via is the one in the message");
        Some(out.lines().nth(1).unwrap().to_string())
    }

    #[test]
    fn received_and_rport_table() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            // Already right: nothing to do.
            ("Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1", "192.0.2.1:5060", None),
            ("Via: SIP/2.0/UDP host.example;received=192.0.2.1;branch=z9hG4bK1", "192.0.2.1:5060", None),
            ("Via: SIP/2.0/UDP 192.0.2.1;rport=7000;received=192.0.2.1;branch=z9hG4bK1", "192.0.2.1:7000", None),
            ("Via: SIP/2.0/UDP [2001:db8::1];branch=z9hG4bK1", "[2001:db8::1]:5060", None),
            ("Via: SIP/2.0/UDP [2001:DB8:0::1];branch=z9hG4bK1", "[2001:db8::1]:5060", None),
            // A host name always gets received=.
            (
                "Via: SIP/2.0/UDP host.example:5060;branch=z9hG4bK1",
                "192.0.2.1:5060",
                Some("Via: SIP/2.0/UDP host.example:5060;branch=z9hG4bK1;received=192.0.2.1"),
            ),
            // IPv6 source: received= carries the address without brackets.
            (
                "Via: SIP/2.0/TCP [2001:db8::1]:5060;branch=z9hG4bK1",
                "[2001:db8::2]:5070",
                Some("Via: SIP/2.0/TCP [2001:db8::1]:5060;branch=z9hG4bK1;received=2001:db8::2"),
            ),
            (
                "Via: SIP/2.0/UDP [2001:db8::1];rport;branch=z9hG4bK1",
                "[2001:db8::1]:5999",
                Some("Via: SIP/2.0/UDP [2001:db8::1];branch=z9hG4bK1;received=2001:db8::1;rport=5999"),
            ),
            // A stale rport value is replaced.
            (
                "Via: SIP/2.0/UDP 192.0.2.1;rport=1;branch=z9hG4bK1",
                "192.0.2.1:7000",
                Some("Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1;received=192.0.2.1;rport=7000"),
            ),
            // Parameter names in any case are replaced, other params kept as written.
            (
                "Via: SIP/2.0/UDP 10.0.0.1;Branch=z9hG4bK1;RPort;Received=10.0.0.1;x=Y",
                "192.0.2.1:7000",
                Some("Via: SIP/2.0/UDP 10.0.0.1;Branch=z9hG4bK1;x=Y;received=192.0.2.1;rport=7000"),
            ),
            // Only the first Via value of a comma-separated header changes.
            (
                "Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1, SIP/2.0/UDP 10.0.0.2;branch=z9hG4bK2",
                "192.0.2.1:7000",
                Some("Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1;received=192.0.2.1, SIP/2.0/UDP 10.0.0.2;branch=z9hG4bK2"),
            ),
            // Compact header name.
            ("v: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1", "192.0.2.1:7000", Some("v: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1;received=192.0.2.1")),
        ];
        for (via, src, want) in cases {
            assert_eq!(stamp(via, src).as_deref(), *want, "{via} from {src}");
        }
    }

    #[derive(Default)]
    struct AliasNet {
        accept: bool,
        added: std::sync::Mutex<Vec<(sip_core::ConnId, SocketAddr)>>,
    }

    impl Outbound for AliasNet {
        fn send(&self, _: &Dest, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
        fn accepts_aliases(&self) -> bool {
            self.accept
        }
        fn add_alias(&self, conn: sip_core::ConnId, addr: SocketAddr) {
            self.added.lock().unwrap().push((conn, addr));
        }
    }

    struct Seen(std::sync::Mutex<Vec<String>>);

    impl Handler for Seen {
        fn handle(&self, ctx: &mut Ctx<'_, '_>) {
            ctx.msg.parse_headers(sip_parser::HdrFlags::EOH).unwrap();
            let top = ctx.msg.headers.iter().find(|h| h.kind == sip_parser::HdrKind::Via).map(|h| String::from_utf8_lossy(h.body).into_owned());
            self.0.lock().unwrap().push(top.unwrap_or_default());
        }
    }

    fn run(via: &str, src: Dest, accept: bool) -> (Vec<(sip_core::ConnId, SocketAddr)>, Vec<String>) {
        let req = format!(
            "OPTIONS sip:a@b SIP/2.0\r\nVia: {via}\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:a@b>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        );
        let net = AliasNet { accept, ..AliasNet::default() };
        let seen = Seen(std::sync::Mutex::new(Vec::new()));
        let mut s = Scratch::default();
        dispatch(req.as_bytes(), src, &net, None, &seen, &mut s, 0);
        (net.added.into_inner().unwrap(), seen.0.into_inner().unwrap())
    }

    fn conn(proto: Proto, addr: &str, id: u64) -> Dest {
        let mut d = Dest::new(proto, addr.parse().unwrap());
        d.conn = Some(id);
        d
    }

    #[test]
    fn via_alias_registers_the_source_ip_and_sent_by_port() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        // (top Via, source, aliases enabled, aliases added)
        type Case = (&'static str, Dest, bool, &'static [(u64, &'static str)]);
        let cases: &[Case] = &[
            ("SIP/2.0/TCP 192.0.2.1:5080;branch=z9hG4bK1;alias", conn(Proto::Tcp, "192.0.2.1:40000", 3), true, &[(3, "192.0.2.1:5080")]),
            // The Via host is not trusted: the alias is the connection's own IP.
            ("SIP/2.0/TCP 203.0.113.9:5080;branch=z9hG4bK1;alias", conn(Proto::Tcp, "192.0.2.1:40000", 3), true, &[(3, "192.0.2.1:5080")]),
            ("SIP/2.0/TLS host.example;branch=z9hG4bK1;alias", conn(Proto::Tls, "192.0.2.1:40000", 4), true, &[(4, "192.0.2.1:5061")]),
            ("SIP/2.0/TCP h;branch=z9hG4bK1;alias", conn(Proto::Tcp, "[2001:db8::7]:40000", 5), true, &[(5, "[2001:db8::7]:5060")]),
            ("SIP/2.0/TCP 192.0.2.1:5080;branch=z9hG4bK1;alias", conn(Proto::Tcp, "192.0.2.1:40000", 3), false, &[]),
            ("SIP/2.0/TCP 192.0.2.1:5080;branch=z9hG4bK1", conn(Proto::Tcp, "192.0.2.1:40000", 3), true, &[]),
            ("SIP/2.0/WS h;branch=z9hG4bK1;alias", conn(Proto::Ws, "192.0.2.1:40000", 6), true, &[]),
            ("SIP/2.0/UDP 192.0.2.1:5080;branch=z9hG4bK1;alias", Dest::new(Proto::Udp, sa("192.0.2.1:5060")), true, &[]),
        ];
        for (via, src, accept, want) in cases {
            let (added, seen) = run(via, *src, *accept);
            let want: Vec<_> = want.iter().map(|(id, a)| (*id, sa(a))).collect();
            assert_eq!(added, want, "{via} from {src} (aliases on: {accept})");
            assert_eq!(seen.len(), 1, "the request is still handled");
        }
    }

    #[test]
    fn dispatch_stamps_the_via_the_handler_sees_and_skips_keepalives() {
        let (_, seen) = run("SIP/2.0/UDP 10.0.0.1;rport;branch=z9hG4bK1", Dest::new(Proto::Udp, "192.0.2.1:7000".parse().unwrap()), false);
        assert_eq!(seen, ["SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1;received=192.0.2.1;rport=7000"]);
        let seen = Seen(std::sync::Mutex::new(Vec::new()));
        let mut s = Scratch::default();
        for ka in [&b"\r\n\r\n"[..], b"\r\n", b" "] {
            dispatch(ka, Dest::new(Proto::Udp, "192.0.2.1:7000".parse().unwrap()), &AliasNet::default(), None, &seen, &mut s, 0);
        }
        assert!(seen.0.lock().unwrap().is_empty(), "keep-alives reach no route");
    }
}

#[cfg(test)]
mod send_error_tests {
    use super::*;

    #[test]
    fn failed_sends_are_counted_once() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = TcpService::new(TcpOpts::default(), None).unwrap();
        let net = Net { udp: Some(udp), tcp, advertise: [None; 5] };
        let c = sip_core::net::send_errors();
        let before = c.load(std::sync::atomic::Ordering::Relaxed);
        // An IPv4 socket cannot send to an IPv6 address.
        let v6 = Dest { proto: Proto::Udp, addr: "[::1]:5060".parse().unwrap(), conn: None, no_connect: false };
        assert!(net.send(&v6, b"x").is_err());
        // No open connection and dialling is not allowed.
        let tcp = Dest { proto: Proto::Tcp, addr: "127.0.0.1:9".parse().unwrap(), conn: None, no_connect: true };
        assert!(net.send(&tcp, b"x").is_err());
        let ok = Dest { proto: Proto::Udp, addr: "127.0.0.1:9".parse().unwrap(), conn: None, no_connect: false };
        assert!(net.send(&ok, b"x").is_ok());
        assert_eq!(c.load(std::sync::atomic::Ordering::Relaxed) - before, 2);
    }
}

#[cfg(test)]
mod dispatch_error_tests {
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;

    struct NullNet;

    impl Outbound for NullNet {
        fn send(&self, _: &Dest, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    struct Panics(std::sync::atomic::AtomicUsize);

    impl Handler for Panics {
        fn handle(&self, _: &mut Ctx<'_, '_>) {
            self.0.fetch_add(1, Relaxed);
            panic!("handler bug");
        }
    }

    const OPTIONS: &[u8] = b"OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:a@b>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";

    #[test]
    fn a_panicking_handler_drops_only_that_message() {
        let h = Panics(0.into());
        let mut s = Scratch::default();
        let src = Dest::new(Proto::Udp, "192.0.2.1:5060".parse().unwrap());
        dispatch(OPTIONS, src, &NullNet, None, &h, &mut s, 0);
        dispatch(OPTIONS, src, &NullNet, None, &h, &mut s, 0);
        assert_eq!(h.0.load(Relaxed), 2, "the worker survives and handles the next message");
    }

    #[test]
    fn unparsable_messages_are_counted_and_reach_no_route() {
        let h = Panics(0.into());
        let mut s = Scratch::default();
        let bad = core_stats().2;
        let before = bad.load(Relaxed);
        dispatch(b"this is not SIP\r\n\r\n", Dest::new(Proto::Udp, "192.0.2.1:5060".parse().unwrap()), &NullNet, None, &h, &mut s, 0);
        assert_eq!(h.0.load(Relaxed), 0);
        assert!(bad.load(Relaxed) > before, "core.bad_msgs counts it");
    }

    fn config(listen: &[&str], tls: TlsFiles) -> Config {
        Config { listen: listen.iter().map(|l| Listen::parse(l).unwrap()).collect(), udp_workers: 1, tcp: TcpOpts::default(), tls, advertise_ip: None }
    }

    #[test]
    fn a_tls_listener_without_a_certificate_of_its_own_is_refused() {
        let (c, k) = tls::test_pki::own();
        let profile = format!("[server:127.0.0.1:5062]\ncertificate = {}\nprivate_key = {}\n", c.display(), k.display());
        let tls = TlsFiles { profile_text: Some(profile), ..TlsFiles::default() };
        let ok = load_tls(&config(&["tls:127.0.0.1:5062"], tls.clone())).unwrap().unwrap();
        assert!(ok.server_by_local.contains_key(&"127.0.0.1:5062".parse().unwrap()));
        let e = load_tls(&config(&["tls:127.0.0.1:5062", "tls:127.0.0.1:5061"], tls)).err().unwrap_or_default();
        assert_eq!(e, "tls:127.0.0.1:5061: no certificate (--tls-cert, or a [server:127.0.0.1:5061] profile)");
        assert!(load_tls(&config(&["udp:127.0.0.1:5060"], TlsFiles::default())).unwrap().is_none(), "no TLS, nothing loaded");
    }

    #[test]
    fn start_reports_a_udp_address_in_use() {
        // Bound without SO_REUSEPORT: the workers' sockets can't share it.
        let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let e = start(&config(&[&format!("udp:{addr}")], TlsFiles::default()), Arc::new(Panics(0.into()))).err().unwrap_or_default();
        assert!(e.starts_with(&format!("bind udp:{addr}: ")), "{e}");
    }

    #[test]
    fn net_without_a_udp_listener() {
        let net = Net {
            udp: None,
            tcp: TcpService::new(TcpOpts::default(), None).unwrap(),
            advertise: [None, Some("192.0.2.9:5060".parse().unwrap()), None, None, None],
        };
        let udp = Dest::new(Proto::Udp, "127.0.0.1:9".parse().unwrap());
        assert_eq!(net.send(&udp, b"x").unwrap_err().to_string(), "no UDP listener");
        assert_eq!(net.conn_to(&udp), None, "UDP has no connections");
        assert_eq!(net.conn_to(&Dest::new(Proto::Tcp, "127.0.0.1:9".parse().unwrap())), None);
        assert_eq!(net.advertise(Proto::Udp), Some("192.0.2.9:5060".parse().unwrap()), "any listener's address will do");
        assert!(!net.accepts_aliases());
    }
}
