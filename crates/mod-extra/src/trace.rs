//! `siptrace` — copies of SIP traffic to a HEP (v3) capture server such as
//! Homer. The Kamailio configs from Homer's wiki work as they are:
//!
//! - `sip_trace([dst[, correlation_id[, mode]]])` traces the current
//!   message to `dst` (`sip:host:port`, default `duplicate_uri`) and, with
//!   mode `t` (transaction) or `d` (dialog), every later message of the
//!   same Call-ID, received and sent (t: until the transaction is done,
//!   ~32 s after the last traced message, 180 s for INVITE; d: 12 h).
//!   `sip_trace_mode("m"|"t"|"d")` sets the mode for `sip_trace()` without one.
//! - `trace_flag` (Kamailio 4.x style `setflag(22)`): a request carrying the
//!   flag when ferrosip first sends something for it (t_relay, a reply) is
//!   traced as a transaction, with no `sip_trace()` call needed.
//! - `hlog([correlation_id,] message)` sends a HEP log record.
//!
//! Parameters:
//! - `duplicate_uri`: the collector, `sip:host:port`;
//! - `hep_mode_on` (1; 0 sends plain SIP copies instead of HEP);
//! - `hep_version` (3 only), `hep_capture_id` (1), `auth_key`;
//! - `trace_on` (1), `trace_flag`;
//! - `send_sock_addr`: the source IP of the HEP packets (the port is
//!   picked by the OS: SIP listeners own theirs).
//!
//! RPC `siptrace.status on|off|check`. Over UDP only. There is no database
//! storage (`trace_to_database=1` logs a note).

use sip_core::module::DynStr;
use sip_core::schema::{ParamSpec, Ty, UINT, p};
use sip_core::serde_json::json;
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Dest, Module, Outbound, Registry, ShardedMap};
use sip_parser::HdrKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Per-message trace mode set by `sip_trace_mode()`.
struct Mode(char);

/// This received message was already sent to the collector.
struct InTraced;

/// A call being traced.
#[derive(Clone)]
struct Traced {
    until: u64,
    correlation: String,
    /// Collector for this call.
    to: SocketAddr,
    /// Transaction mode: extended while messages keep flowing.
    txn: bool,
}

pub struct SipTrace {
    dst: Mutex<Option<String>>,
    collector: OnceLock<SocketAddr>,
    capture_id: AtomicU32,
    auth_key: Mutex<Option<String>>,
    on: AtomicBool,
    /// HEP encapsulation (`hep_mode_on`); off: plain SIP copies.
    hep: AtomicBool,
    /// `trace_flag` (-1: none).
    flag: AtomicI64,
    send_from: Mutex<Option<IpAddr>>,
    sock: OnceLock<UdpSocket>,
    /// Traced Call-IDs.
    calls: ShardedMap<String, Traced>,
    net: OnceLock<Arc<dyn Outbound>>,
}

impl Default for SipTrace {
    fn default() -> Self {
        Self {
            dst: Mutex::new(None),
            collector: OnceLock::new(),
            capture_id: AtomicU32::new(1),
            auth_key: Mutex::new(None),
            on: AtomicBool::new(true),
            hep: AtomicBool::new(true),
            flag: AtomicI64::new(-1),
            send_from: Mutex::new(None),
            sock: OnceLock::new(),
            calls: ShardedMap::new(16),
            net: OnceLock::new(),
        }
    }
}

/// One HEP chunk; `None` if `payload` is too long for its 16-bit length.
fn chunk(out: &mut Vec<u8>, ty: u16, payload: &[u8]) -> Option<()> {
    let len = u16::try_from(payload.len().checked_add(6)?).ok()?;
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Some(())
}

/// Metadata of a HEP record.
pub struct Hep<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub tcp: bool,
    /// 1 SIP, 100 log.
    pub proto_type: u8,
    pub capture_id: u32,
    pub auth: Option<&'a str>,
    pub correlation: Option<&'a str>,
}

/// A HEPv3 packet; `None` if it would not fit HEP's 16-bit lengths
/// (a payload of more than about 64 KB).
pub fn hep3(h: &Hep<'_>, payload: &[u8]) -> Option<Vec<u8>> {
    let Hep { src, dst, tcp, proto_type, capture_id, auth, correlation } = *h;
    let mut c = Vec::with_capacity(payload.len().saturating_add(128));
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            chunk(&mut c, 1, &[2])?;
            chunk(&mut c, 3, &s.octets())?;
            chunk(&mut c, 4, &d.octets())?;
        }
        (s, d) => {
            let v6 = |ip: IpAddr| match ip {
                IpAddr::V4(v) => v.to_ipv6_mapped().octets(),
                IpAddr::V6(v) => v.octets(),
            };
            chunk(&mut c, 1, &[10])?;
            chunk(&mut c, 5, &v6(s))?;
            chunk(&mut c, 6, &v6(d))?;
        }
    }
    chunk(&mut c, 2, &[if tcp { 6 } else { 17 }])?;
    chunk(&mut c, 7, &src.port().to_be_bytes())?;
    chunk(&mut c, 8, &dst.port().to_be_bytes())?;
    // HEP's 32-bit seconds (good until 2106).
    chunk(&mut c, 9, &u32::try_from(ts.as_secs()).unwrap_or(u32::MAX).to_be_bytes())?;
    chunk(&mut c, 10, &ts.subsec_micros().to_be_bytes())?;
    chunk(&mut c, 11, &[proto_type])?;
    chunk(&mut c, 12, &capture_id.to_be_bytes())?;
    if let Some(a) = auth {
        chunk(&mut c, 14, a.as_bytes())?;
    }
    if let Some(cid) = correlation {
        chunk(&mut c, 17, cid.as_bytes())?;
    }
    chunk(&mut c, 15, payload)?;
    let total = u16::try_from(c.len().checked_add(6)?).ok()?;
    let mut out = Vec::with_capacity(usize::from(total));
    out.extend_from_slice(b"HEP3");
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&c);
    Some(out)
}

/// The value of the first header `name` (or its compact form) in a raw message.
fn header_of(data: &[u8], name: &str, compact: &str) -> Option<String> {
    let head = data.windows(4).position(|w| w == b"\r\n\r\n").and_then(|end| data.get(..end)).unwrap_or(data);
    std::str::from_utf8(head).ok()?.split("\r\n").skip(1).find_map(|l| {
        let (n, v) = l.split_once(':')?;
        let n = n.trim();
        (n.eq_ignore_ascii_case(name) || (!compact.is_empty() && n.eq_ignore_ascii_case(compact))).then(|| v.trim().to_string())
    })
}

fn callid_of(data: &[u8]) -> Option<String> {
    header_of(data, "call-id", "i")
}

/// `sip_trace()` arguments: collector, correlation id, mode.
type TraceArgs = (Option<SocketAddr>, Option<DynStr>, Option<char>);

/// What a record describes (besides its payload).
struct Rec<'a> {
    src: SocketAddr,
    dst: SocketAddr,
    tcp: bool,
    /// 1 SIP, 100 log.
    proto_type: u8,
    correlation: Option<&'a str>,
}

/// A `sip:host:port` (or `udp:host:port`) collector address.
fn collector_addr(uri: &str) -> Result<SocketAddr, String> {
    sip_core::pvcore::dest_from_uri(uri.as_bytes())
        .or_else(|| Dest::parse(uri).ok())
        .map(|d| d.addr)
        .ok_or_else(|| format!("siptrace: bad collector address {uri:?} (sip:host:port)"))
}

/// Transaction-mode lifetime: INVITE transactions can ring for minutes.
fn txn_ttl(data: &[u8]) -> u64 {
    if header_of(data, "cseq", "").is_some_and(|c| c.split_whitespace().nth(1).is_some_and(|m| m.eq_ignore_ascii_case("INVITE"))) { 180 } else { 32 }
}

impl SipTrace {
    /// Send one record to the collector `to`. `r.src`/`r.dst` are the
    /// addresses of the traced packet.
    fn send(&self, to: SocketAddr, r: Rec<'_>, payload: &[u8]) {
        let Rec { src, dst, tcp, proto_type, correlation } = r;
        if !self.on.load(Ordering::Relaxed) {
            return;
        }
        let Some(sock) = self.sock.get() else { return };
        if !self.hep.load(Ordering::Relaxed) {
            // Plain duplicates: SIP only (no HEP log records).
            if proto_type == 1 {
                let _ = sock.send_to(payload, to);
            }
            return;
        }
        let auth = lock(&self.auth_key).clone();
        let h = Hep { src, dst, tcp, proto_type, capture_id: self.capture_id.load(Ordering::Relaxed), auth: auth.as_deref(), correlation };
        // Too big for HEP's 16-bit lengths: not sent, rather than sent with
        // wrapped lengths.
        if let Some(p) = hep3(&h, payload) {
            let _ = sock.send_to(&p, to);
        }
    }

    fn default_to(&self) -> Option<SocketAddr> {
        self.collector.get().copied()
    }

    fn our_addr(&self, d: &Dest) -> SocketAddr {
        self.net.get().and_then(|n| n.advertise(d.proto)).unwrap_or(SocketAddr::from(([127, 0, 0, 1], 5060)))
    }

    fn flagged(&self, ctx: &Ctx<'_, '_>) -> bool {
        let f = self.flag.load(Ordering::Relaxed);
        (0..64).contains(&f) && ctx.ext::<sip_core::TxnVars>().is_some_and(|t| t.flags & (1u64 << f) != 0)
    }

    /// Send the received message (once) and start tracing its call.
    fn trace_ctx(&self, ctx: &mut Ctx<'_, '_>, mode: char, correlation: Option<String>, to: Option<SocketAddr>) -> i32 {
        let Some(to) = to.or_else(|| self.default_to()) else { return -1 };
        let _ = ctx.msg.parse_headers(sip_parser::HdrFlags::EOH);
        let callid = ctx.msg.get(HdrKind::CallId).map(|h| String::from_utf8_lossy(h.body).into_owned()).unwrap_or_default();
        let corr = correlation.unwrap_or_else(|| callid.clone());
        if ctx.ext::<InTraced>().is_none() {
            let src = ctx.src;
            self.send(
                to,
                Rec { src: src.addr, dst: self.our_addr(&src), tcp: src.proto.is_stream(), proto_type: 1, correlation: Some(&corr) },
                &ctx.received(),
            );
            ctx.ext.push(Box::new(InTraced));
        }
        // With the trace flag set, at least the transaction is traced.
        let mode = if mode == 'm' && self.flagged(ctx) { 't' } else { mode };
        let ttl = match mode {
            't' => txn_ttl(ctx.msg.buf),
            'd' => 43200,
            _ => 0,
        };
        if ttl > 0 && !callid.is_empty() {
            self.calls.insert(callid, Traced { until: unix_secs().saturating_add(ttl), correlation: corr, to, txn: mode == 't' });
        }
        1
    }

    /// `trace_flag`: called before anything is sent for a message.
    fn on_ctx_send(&self, ctx: &Ctx<'_, '_>) {
        if !self.on.load(Ordering::Relaxed) || !ctx.msg.is_request() || !self.flagged(ctx) {
            return;
        }
        let Some(to) = self.default_to() else { return };
        let Some(cid) = callid_of(ctx.msg.buf) else { return };
        if self.calls.get_cloned(cid.as_str()).is_some_and(|t| t.until >= unix_secs()) {
            return;
        }
        if ctx.ext::<InTraced>().is_none() {
            let src = ctx.src;
            self.send(to, Rec { src: src.addr, dst: self.our_addr(&src), tcp: src.proto.is_stream(), proto_type: 1, correlation: Some(&cid) }, &ctx.received());
        }
        self.calls.insert(cid.clone(), Traced { until: unix_secs().saturating_add(txn_ttl(ctx.msg.buf)), correlation: cid, to, txn: true });
    }

    /// The trace entry of a message's call, if it is being traced (and
    /// extended, in transaction mode).
    fn traced(&self, data: &[u8]) -> Option<Traced> {
        if self.calls.is_empty() {
            return None;
        }
        let cid = callid_of(data)?;
        let mut t = self.calls.get_cloned(cid.as_str())?;
        let n = unix_secs();
        if t.until < n {
            self.calls.remove(cid.as_str());
            return None;
        }
        let extended = n.saturating_add(32);
        if t.txn && t.until < extended {
            t.until = extended;
            self.calls.insert(cid, t.clone());
        }
        Some(t)
    }

    /// Outgoing messages of traced calls.
    fn tap(&self, dst: &Dest, data: &[u8]) {
        if let Some(t) = self.traced(data) {
            self.send(t.to, Rec { src: self.our_addr(dst), dst: dst.addr, tcp: dst.proto.is_stream(), proto_type: 1, correlation: Some(&t.correlation) }, data);
        }
    }
}

impl Module for SipTrace {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("duplicate_uri", Ty::Str, "", "Where traced messages go, e.g. \"sip:10.0.0.5:9060\" (HEP collector)"),
            p("hep_mode_on", Ty::Bool, "true", "Send HEPv3 (HOMER) instead of SIP"),
            p("hep_capture_id", UINT, "1", "HEP capture agent id"),
            p("auth_key", Ty::Str, "", "HEP authentication key"),
            p("trace_on", Ty::Bool, "true", "Tracing on at start"),
            p("trace_flag", Ty::Int { min: 0, max: 63 }, "", "Flag that marks a transaction for tracing (default: none)"),
            p("send_sock_addr", Ty::Str, "", "Local address to send from"),
        ])
    }

    fn name(&self) -> &'static str {
        "siptrace"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "duplicate_uri" => *lock(&self.dst) = Some(v.str()?.into()),
            "hep_capture_id" => {
                let id = u32::try_from(v.int()?.max(0)).map_err(|_| "siptrace: hep_capture_id out of range".to_string())?;
                self.capture_id.store(id, Ordering::Relaxed);
            }
            "auth_key" => *lock(&self.auth_key) = Some(v.str()?.into()),
            "trace_on" => self.on.store(v.int()? != 0, Ordering::Relaxed),
            "hep_mode_on" => self.hep.store(v.int()? != 0, Ordering::Relaxed),
            "hep_version" if v.int()? != 3 => return Err("siptrace: only hep_version 3 is supported".into()),
            "hep_version" => {}
            "trace_flag" => {
                let f = v.int()?;
                if !(0..64).contains(&f) {
                    return Err(format!("siptrace: trace_flag {f} out of range 0..63"));
                }
                self.flag.store(f, Ordering::Relaxed);
            }
            "send_sock_addr" => {
                let a = collector_addr(v.str()?)?;
                *lock(&self.send_from) = Some(a.ip());
            }
            "trace_to_database" => {
                if v.int()? != 0 {
                    sip_core::elog!("ferrosip: note: siptrace: trace_to_database: no database storage here, HEP to duplicate_uri only");
                }
            }
            "db_url"
            | "table"
            | "trace_mode"
            | "xheaders_write"
            | "xheaders_read"
            | "force_send_sock"
            | "send_sock_name"
            | "trace_local_ip"
            | "trace_sl_acks"
            | "trace_init_mode"
            | "trace_dialog_ack"
            | "trace_dialog_spiral"
            | "trace_delayed"
            | "hep_vendor_id" => sip_core::module::param_no_effect("siptrace", name),
            _ => return Err(format!("siptrace: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const MODES: &[&str] = &["message", "transaction", "dialog"];
        const TRACE: &[Param] = &[opt("to", Uri).lit().eg("\"sip:127.0.0.1:9060\""), opt("correlation_id", Str), opt("mode", Enum(MODES))];
        const MODE: &[Param] = &[arg("mode", Enum(MODES))];
        const LOG: &[Param] = &[arg("message", Str)];
        const LOG_ID: &[Param] = &[arg("correlation_id", Str), arg("message", Str)];
        Some(vec![
            sig(
                "sip_trace",
                "capture",
                TRACE,
                Ret::Void,
                "Send this message to the HEP collector (`to`, default duplicate_uri), and with mode transaction/dialog the rest of it",
            )
            .allowed(ctx::ANY),
            sig("sip_trace_mode", "set_mode", MODE, Ret::Void, "The mode of trace.capture() calls that give none").allowed(ctx::ANY),
            sig("hlog", "log", LOG, Ret::Void, "Send a HEP log record (correlated by Call-ID)").allowed(ctx::ANY),
            sig("hlog", "log_with_id", LOG_ID, Ret::Void, "Send a HEP log record with this correlation id").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let uri = lock(&self.dst).clone().ok_or("siptrace: duplicate_uri is required")?;
        let to = collector_addr(&uri)?;
        let _ = self.collector.set(to);
        // From send_sock_addr's IP, with a port of the OS's choosing (the
        // SIP listeners own theirs).
        let from: SocketAddr = match *lock(&self.send_from) {
            Some(ip) => SocketAddr::new(ip, 0),
            None if to.is_ipv4() => SocketAddr::from(([0, 0, 0, 0], 0)),
            None => SocketAddr::from(([0u16; 8], 0)),
        };
        let _ = self.sock.set(UdpSocket::bind(from).map_err(|e| format!("siptrace: send_sock_addr {from}: {e}"))?);
        let me = self.clone();
        sip_core::net::add_send_tap(Arc::new(move |d, m| me.tap(d, m)));
        if self.flag.load(Ordering::Relaxed) >= 0 {
            let me = self.clone();
            sip_core::module::add_ctx_send_hook(Arc::new(move |ctx| me.on_ctx_send(ctx)));
        }
        let m = "siptrace";
        let me = self.clone();
        reg.export(
            m,
            "sip_trace",
            |a: &[Arg]| -> Result<TraceArgs, String> {
                if a.len() > 3 {
                    return Err("sip_trace([dst[, correlation_id[, mode]]])".into());
                }
                let to = match a.first() {
                    Some(d) => {
                        let s = d.str().map_err(|_| "sip_trace(dst): the collector must be a constant sip:host:port".to_string())?;
                        if s.is_empty() || s == "$null" { None } else { Some(collector_addr(s)?) }
                    }
                    None => None,
                };
                let mode = match a.get(2) {
                    Some(m) => match m.str()?.chars().next() {
                        Some(c @ ('m' | 't' | 'd' | 'M' | 'T' | 'D')) => Some(c.to_ascii_lowercase()),
                        _ => return Err("sip_trace: mode must be m, t or d".into()),
                    },
                    None => None,
                };
                Ok((to, a.get(1).map(Arg::dyn_str).transpose()?, mode))
            },
            move |ctx: &mut Ctx, (to, corr, mode): &TraceArgs| {
                let mode = mode.or_else(|| ctx.ext::<Mode>().map(|m| m.0)).unwrap_or('m');
                let corr = corr.as_ref().map(|c| c.eval(ctx).into_owned()).filter(|c| !c.is_empty());
                me.trace_ctx(ctx, mode, corr, *to)
            },
        );
        reg.export(
            m,
            "sip_trace_mode",
            |a: &[Arg]| {
                let [mode] = crate::fixed_args(a)?;
                match mode.str()?.chars().next() {
                    Some(c @ ('m' | 't' | 'd' | 'M' | 'T' | 'D')) => Ok(c.to_ascii_lowercase()),
                    _ => Err("mode must be m, t or d".into()),
                }
            },
            |ctx: &mut Ctx, &c: &char| {
                ctx.ext.retain(|e| !e.is::<Mode>());
                ctx.ext.push(Box::new(Mode(c)));
                1
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "hlog",
            |a: &[Arg]| -> Result<(Option<DynStr>, DynStr), String> {
                match a {
                    [text] => Ok((None, text.dyn_str()?)),
                    [corr, text] => Ok((Some(corr.dyn_str()?), text.dyn_str()?)),
                    _ => Err("expected [correlation_id,] message".into()),
                }
            },
            move |ctx: &mut Ctx, (corr, text): &(Option<DynStr>, DynStr)| {
                let corr = match corr {
                    Some(c) => c.eval(ctx).into_owned(),
                    None => {
                        let _ = ctx.msg.parse_headers(sip_parser::HdrFlags::EOH);
                        ctx.msg.get(HdrKind::CallId).map(|h| String::from_utf8_lossy(h.body).into_owned()).unwrap_or_default()
                    }
                };
                let t = text.eval(ctx).into_owned();
                let Some(to) = me.default_to() else { return -1 };
                let src = me.our_addr(&ctx.src);
                me.send(to, Rec { src, dst: to, tcp: false, proto_type: 100, correlation: Some(&corr) }, t.as_bytes());
                1
            },
        );
        let me = self.clone();
        reg.rpc.add("siptrace.status", "siptrace.status on|off|check", move |p| {
            match sip_core::rpc::str_param(p, 0)?.as_str() {
                "on" => me.on.store(true, Ordering::Relaxed),
                "off" => me.on.store(false, Ordering::Relaxed),
                "check" => {}
                x => return Err(format!("unknown argument {x:?}")),
            }
            Ok(json!(if me.on.load(Ordering::Relaxed) { "enabled" } else { "disabled" }))
        });
        Ok(())
    }

    fn observes(&self) -> bool {
        true
    }

    /// Received requests of traced calls (before the script).
    fn observe_request(&self, ctx: &mut Ctx<'_, '_>) {
        self.observe_in(ctx);
    }

    /// Received replies of traced calls.
    fn observe_reply(&self, ctx: &mut Ctx<'_, '_>) {
        self.observe_in(ctx);
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        std::thread::Builder::new()
            .name("siptrace-gc".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(10));
                    let t = unix_secs();
                    self.calls.retain(|_, v| v.until >= t);
                }
            })
            .map_err(|e| format!("cannot start the siptrace gc thread: {e}"))?;
        Ok(())
    }
}

impl SipTrace {
    fn observe_in(&self, ctx: &mut Ctx<'_, '_>) {
        let Some(t) = self.traced(ctx.msg.buf) else { return };
        let src = ctx.src;
        self.send(
            t.to,
            Rec { src: src.addr, dst: self.our_addr(&src), tcp: src.proto.is_stream(), proto_type: 1, correlation: Some(&t.correlation) },
            ctx.msg.buf,
        );
        ctx.ext.push(Box::new(InTraced));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_ttl() {
        let inv = b"INVITE sip:a@b SIP/2.0\r\ni: abc\r\nCSeq: 42 INVITE\r\n\r\nbody";
        assert_eq!(callid_of(inv).as_deref(), Some("abc"));
        assert_eq!(txn_ttl(inv), 180);
        assert_eq!(txn_ttl(b"SIP/2.0 180 Ringing\r\nCSeq: 7 invite\r\n\r\n"), 180, "replies too, by CSeq");
        assert_eq!(txn_ttl(b"MESSAGE sip:a@b SIP/2.0\r\nCSeq: 1 MESSAGE\r\n\r\n"), 32);
        assert!(collector_addr("sip:127.0.0.1:9060").is_ok());
        assert!(collector_addr("nonsense:").is_err());
    }

    #[test]
    fn hep3_layout() {
        let h = Hep {
            src: "10.0.0.1:5060".parse().unwrap(),
            dst: "10.0.0.2:5080".parse().unwrap(),
            tcp: false,
            proto_type: 1,
            capture_id: 22,
            auth: None,
            correlation: Some("cid"),
        };
        let p = hep3(&h, b"SIP").unwrap();
        assert_eq!(&p[..4], b"HEP3");
        assert_eq!(u16::from_be_bytes([p[4], p[5]]) as usize, p.len());
        assert!(p.windows(3).any(|w| w == b"cid") && p.ends_with(b"SIP"));
        // The lengths are 16 bits: a bigger record is refused, not wrapped.
        let big = hep3(&h, &[b'x'; 65_000]).unwrap();
        assert_eq!(usize::from(u16::from_be_bytes([big[4], big[5]])), big.len());
        assert!(hep3(&h, &[b'x'; 70_000]).is_none());
    }
}

#[cfg(test)]
mod hep_tests {
    use super::*;

    /// The chunks of a HEP3 packet as (type, payload); checks the framing.
    fn chunks(p: &[u8]) -> Vec<(u16, Vec<u8>)> {
        assert_eq!(&p[..4], b"HEP3");
        assert_eq!(usize::from(u16::from_be_bytes([p[4], p[5]])), p.len(), "total length");
        let mut out = Vec::new();
        let mut rest = &p[6..];
        while !rest.is_empty() {
            assert_eq!(&rest[..2], &[0, 0], "vendor 0 (generic)");
            let ty = u16::from_be_bytes([rest[2], rest[3]]);
            let len = usize::from(u16::from_be_bytes([rest[4], rest[5]]));
            assert!(len >= 6 && len <= rest.len(), "chunk {ty} length {len}");
            out.push((ty, rest[6..len].to_vec()));
            rest = &rest[len..];
        }
        out
    }

    fn hep<'a>(src: &str, dst: &str) -> Hep<'a> {
        Hep { src: src.parse().unwrap(), dst: dst.parse().unwrap(), tcp: false, proto_type: 1, capture_id: 0x0102_0304, auth: None, correlation: None }
    }

    #[test]
    fn chunk_header_is_vendor_type_and_length() {
        let mut out = Vec::new();
        chunk(&mut out, 0x0f, b"abc").unwrap();
        assert_eq!(out, [0, 0, 0, 0x0f, 0, 9, b'a', b'b', b'c']);
        let mut out = Vec::new();
        assert!(chunk(&mut out, 15, &[0; 65_529]).is_some(), "6 + 65529 = 65535 fits");
        assert!(chunk(&mut vec![], 15, &[0; 65_530]).is_none());
        assert_eq!(&out[4..6], &[0xff, 0xff]);
    }

    #[test]
    fn hep3_ipv4_record_has_the_exact_chunks() {
        let h = Hep { tcp: true, auth: Some("key"), correlation: Some("cid-1"), ..hep("192.0.2.1:5060", "198.51.100.7:5080") };
        let p = hep3(&h, b"INVITE").unwrap();
        // Everything before the timestamp, byte for byte.
        let head: &[u8] = &[
            b'H', b'E', b'P', b'3', 0, 0, // total length (checked below)
            0, 0, 0, 1, 0, 7, 2, // IP family: AF_INET
            0, 0, 0, 3, 0, 10, 192, 0, 2, 1, // source IPv4
            0, 0, 0, 4, 0, 10, 198, 51, 100, 7, // destination IPv4
            0, 0, 0, 2, 0, 7, 6, // IP protocol: TCP
            0, 0, 0, 7, 0, 8, 0x13, 0xc4, // source port 5060
            0, 0, 0, 8, 0, 8, 0x13, 0xd8, // destination port 5080
        ];
        assert_eq!(&p[6..head.len()], &head[6..]);
        let c = chunks(&p);
        let types: Vec<u16> = c.iter().map(|x| x.0).collect();
        assert_eq!(types, [1, 3, 4, 2, 7, 8, 9, 10, 11, 12, 14, 17, 15]);
        assert_eq!(c[6].1.len(), 4, "seconds: 32 bits");
        assert_eq!(c[7].1.len(), 4, "microseconds: 32 bits");
        assert!(u32::from_be_bytes(c[7].1[..].try_into().unwrap()) < 1_000_000);
        assert!(u32::from_be_bytes(c[6].1[..].try_into().unwrap()) > 1_600_000_000, "a current unix time");
        assert_eq!(c[8].1, [1], "proto type SIP");
        assert_eq!(c[9].1, [1, 2, 3, 4], "capture id, big endian");
        assert_eq!(c[10].1, b"key");
        assert_eq!(c[11].1, b"cid-1");
        assert_eq!(c[12].1, b"INVITE");
        assert_eq!(p.len(), 6 + 7 + 10 + 10 + 7 + 8 + 8 + 10 + 10 + 7 + 10 + 9 + 11 + 12);
    }

    #[test]
    fn hep3_uses_ipv6_chunks_when_either_side_is_ipv6() {
        let p = hep3(&Hep { proto_type: 100, ..hep("[2001:db8::1]:5060", "[2001:db8::2]:9060") }, b"log").unwrap();
        let c = chunks(&p);
        assert_eq!(c.iter().map(|x| x.0).collect::<Vec<_>>(), [1, 5, 6, 2, 7, 8, 9, 10, 11, 12, 15]);
        assert_eq!(c[0].1, [10], "AF_INET6");
        assert_eq!(c[1].1, "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(c[3].1, [17], "UDP");
        assert_eq!(c[8].1, [100], "proto type log");

        let c = chunks(&hep3(&hep("10.0.0.1:1", "[::1]:2"), b"").unwrap());
        assert_eq!(c[0].1, [10]);
        assert_eq!(c[1].1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1], "IPv4 source as v4-mapped");
        assert_eq!(c[2].1, std::net::Ipv6Addr::LOCALHOST.octets());
        assert_eq!(c.last().unwrap(), &(15, vec![]), "an empty payload is still a chunk");
    }

    #[test]
    fn hep3_total_length_limit_is_exact() {
        let h = Hep { correlation: Some("c"), ..hep("10.0.0.1:5060", "10.0.0.2:5060") };
        let overhead = hep3(&h, b"").unwrap().len();
        let max = 65_535 - overhead;
        let p = hep3(&h, &vec![b'x'; max]).unwrap();
        assert_eq!(p.len(), 65_535);
        assert_eq!(&p[4..6], &[0xff, 0xff]);
        assert!(hep3(&h, &vec![b'x'; max + 1]).is_none());
    }

    #[test]
    fn header_of_matches_full_and_compact_names_in_the_head_only() {
        let msg = b"INVITE sip:a@b SIP/2.0\r\nCALL-ID :  x1 \r\nCSeq: 2 BYE\r\n\r\nCall-ID: body";
        assert_eq!(header_of(msg, "call-id", "i").as_deref(), Some("x1"));
        assert_eq!(header_of(b"SIP/2.0 200 OK\r\ni: c2\r\n\r\n", "call-id", "i").as_deref(), Some("c2"));
        assert_eq!(header_of(b"SIP/2.0 200 OK\r\nI: c3\r\n\r\n", "call-id", "i").as_deref(), Some("c3"), "compact names are case-insensitive too");
        assert_eq!(header_of(b"OPTIONS sip:a SIP/2.0\r\nTo: x\r\n\r\ni: body", "call-id", "i"), None);
        assert_eq!(header_of(b"call-id: first-line\r\nX: y\r\n\r\n", "call-id", "i"), None, "the first line is skipped");
        assert_eq!(header_of(b"OPTIONS sip:a SIP/2.0\r\nCall-ID: no-end", "call-id", "i").as_deref(), Some("no-end"));
        assert_eq!(txn_ttl(b"OPTIONS sip:a SIP/2.0\r\nCSeq: 1\r\n\r\n"), 32, "CSeq without a method");
        assert_eq!(txn_ttl(b"OPTIONS sip:a SIP/2.0\r\n\r\n"), 32);
    }
}

#[cfg(test)]
mod send_tests {
    use super::*;
    use crate::testutil::{FakeNet, arg, call, fixup, invite, registry, rpc, src, with_ctx};
    use sip_core::serde_json::json;

    /// A loopback collector: what it received so far, without waiting
    /// (loopback UDP is delivered by the time `send_to` returns).
    struct Collector(UdpSocket);

    impl Collector {
        fn new() -> Self {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.set_nonblocking(true).unwrap();
            Self(s)
        }
        fn addr(&self) -> SocketAddr {
            self.0.local_addr().unwrap()
        }
        fn packets(&self) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            let mut buf = vec![0u8; 70_000];
            while let Ok(n) = self.0.recv(&mut buf) {
                out.push(buf[..n].to_vec());
            }
            out
        }
    }

    /// A SipTrace that sends to `c` from a loopback socket (no register()).
    fn tracer(c: &Collector) -> SipTrace {
        let t = SipTrace::default();
        t.sock.set(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
        t.collector.set(c.addr()).unwrap();
        t
    }

    fn rec(proto_type: u8) -> Rec<'static> {
        Rec { src: src().addr, dst: "192.0.2.2:5060".parse().unwrap(), tcp: false, proto_type, correlation: Some("corr") }
    }

    fn has(p: &[u8], needle: &[u8]) -> bool {
        p.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn send_respects_trace_on_and_hep_mode() {
        let c = Collector::new();
        let t = tracer(&c);
        t.on.store(false, Ordering::Relaxed);
        t.send(c.addr(), rec(1), b"INVITE");
        assert!(c.packets().is_empty(), "tracing off");
        t.on.store(true, Ordering::Relaxed);
        *lock(&t.auth_key) = Some("secret".into());
        t.send(c.addr(), rec(1), b"INVITE");
        let p = c.packets();
        assert_eq!(p.len(), 1);
        assert!(p[0].starts_with(b"HEP3") && has(&p[0], b"secret") && has(&p[0], b"corr") && p[0].ends_with(b"INVITE"));
        t.send(c.addr(), rec(1), &[b'x'; 70_000]);
        assert!(c.packets().is_empty(), "too big for HEP: not sent");
        t.hep.store(false, Ordering::Relaxed);
        t.send(c.addr(), rec(1), b"INVITE");
        t.send(c.addr(), rec(100), b"a log line");
        assert_eq!(c.packets(), [b"INVITE".to_vec()], "plain copies: SIP only, no log records");
    }

    #[test]
    fn traced_expires_and_extends_transaction_entries() {
        let c = Collector::new();
        let t = tracer(&c);
        let msg = |cid: &str| format!("SIP/2.0 200 OK\r\nCall-ID: {cid}\r\n\r\n");
        let entry = |until: u64, txn: bool| Traced { until, correlation: "x".into(), to: c.addr(), txn };
        assert!(t.traced(msg("a").as_bytes()).is_none(), "nothing traced");
        let now = unix_secs();
        t.calls.insert("old".into(), entry(now.saturating_sub(1), true));
        t.calls.insert("txn".into(), entry(now, true));
        t.calls.insert("dlg".into(), entry(now.saturating_add(5), false));
        assert!(t.traced(msg("old").as_bytes()).is_none());
        assert!(t.calls.get_cloned("old").is_none(), "an expired entry is dropped");
        assert!(t.traced(b"SIP/2.0 200 OK\r\n\r\n").is_none(), "no Call-ID");
        assert!(t.traced(msg("txn").as_bytes()).unwrap().until >= now.saturating_add(32), "transaction mode: extended");
        assert!(t.calls.get_cloned("txn").unwrap().until >= now.saturating_add(32));
        assert_eq!(t.traced(msg("dlg").as_bytes()).unwrap().until, now.saturating_add(5), "dialog mode: not extended");
        // Outgoing messages of traced calls are copied, from our address to theirs.
        let to = Dest::new(sip_core::Proto::Tcp, "192.0.2.7:5060".parse().unwrap());
        t.tap(&to, msg("dlg").as_bytes());
        t.tap(&to, msg("other").as_bytes());
        let p = c.packets();
        assert_eq!(p.len(), 1);
        assert!(has(&p[0], &[192, 0, 2, 7]) && has(&p[0], &[0, 0, 0, 2, 0, 7, 6]), "destination address, TCP");
    }

    #[test]
    fn trace_ctx_modes_set_how_long_a_call_is_traced() {
        let c = Collector::new();
        let t = tracer(&c);
        let net = FakeNet(Some("192.0.2.100:5060".parse().unwrap()));
        let now = unix_secs();
        with_ctx(&invite(""), &net, |ctx| {
            assert_eq!(t.trace_ctx(ctx, 'd', Some("my-corr".into()), None), 1);
            assert_eq!(t.trace_ctx(ctx, 'm', None, None), 1, "the received message is sent once");
        });
        let e = t.calls.get_cloned("cid-1").unwrap();
        assert!(e.until >= now.saturating_add(43200) && !e.txn && e.correlation == "my-corr");
        assert_eq!(c.packets().len(), 1);
        // Message mode with the trace flag set: the transaction is traced.
        t.flag.store(5, Ordering::Relaxed);
        with_ctx(&invite("").replace("cid-1", "cid-2"), &net, |ctx| {
            ctx.ext_mut::<sip_core::TxnVars>().flags |= 1 << 5;
            assert_eq!(t.trace_ctx(ctx, 'm', None, None), 1);
        });
        let e = t.calls.get_cloned("cid-2").unwrap();
        assert!(e.txn && e.until >= now.saturating_add(180) && e.correlation == "cid-2");
        with_ctx(&invite("").replace("cid-1", "cid-3"), &net, |ctx| assert_eq!(t.trace_ctx(ctx, 'm', None, None), 1));
        assert!(t.calls.get_cloned("cid-3").is_none(), "message mode alone traces nothing later");
        let lonely = SipTrace::default();
        with_ctx(&invite(""), &net, |ctx| assert_eq!(lonely.trace_ctx(ctx, 'm', None, None), -1, "no collector"));
    }

    #[test]
    fn parameters_are_checked() {
        let t = SipTrace::default();
        let i = Arg::Int;
        assert!(t.set_param("hep_version", &i(3)).is_ok());
        assert!(t.set_param("hep_version", &i(2)).is_err());
        assert!(t.set_param("trace_flag", &i(64)).is_err());
        assert!(t.set_param("trace_flag", &i(-1)).is_err());
        assert!(t.set_param("trace_flag", &i(63)).is_ok());
        assert!(t.set_param("hep_capture_id", &i(i64::from(u32::MAX) + 1)).is_err());
        assert!(t.set_param("hep_capture_id", &i(-5)).is_ok(), "negative: 0");
        assert_eq!(t.capture_id.load(Ordering::Relaxed), 0);
        assert!(t.set_param("trace_to_database", &i(1)).is_ok());
        assert!(t.set_param("trace_to_database", &i(0)).is_ok());
        assert!(t.set_param("db_url", &Arg::Str("mysql://x".into())).is_ok());
        assert!(t.set_param("send_sock_addr", &Arg::Str("nonsense:".into())).is_err());
        assert!(t.set_param("nope", &i(1)).is_err());
        let err = Arc::new(SipTrace::default()).register(&mut Registry::default()).err().unwrap();
        assert!(err.contains("duplicate_uri"), "{err}");
    }

    /// A registered siptrace sending from 127.0.0.1 to `c`.
    fn registered(c: &Collector) -> Registry {
        let t = SipTrace::default();
        t.set_param("duplicate_uri", &Arg::Str(format!("sip:{}", c.addr()))).unwrap();
        t.set_param("send_sock_addr", &Arg::Str("sip:127.0.0.1:5060".into())).unwrap();
        registry(vec![Arc::new(t)])
    }

    #[test]
    fn script_functions_check_their_arguments() {
        let c = Collector::new();
        let reg = registered(&c);
        let s = |x: &str| Arg::Str(x.into());
        assert!(fixup(&reg, "sip_trace", &[s(""), s(""), s("m"), s("x")]).is_err(), "at most 3");
        assert!(fixup(&reg, "sip_trace", &[s(""), s(""), s("x")]).is_err(), "bad mode");
        assert!(fixup(&reg, "sip_trace", &[arg(&reg, "sip:$rd:9060")]).is_err(), "the collector must be constant");
        assert!(fixup(&reg, "sip_trace", &[s("$null"), s(""), s("T")]).is_ok());
        assert!(fixup(&reg, "sip_trace_mode", &[s("x")]).is_err());
        assert!(fixup(&reg, "sip_trace_mode", &[s("")]).is_err());
        assert!(fixup(&reg, "hlog", &[]).is_err());
        assert!(fixup(&reg, "hlog", &[s("a"), s("b"), s("c")]).is_err());
    }

    #[test]
    fn sip_trace_mode_applies_to_sip_trace_without_a_mode() {
        let c = Collector::new();
        let reg = registered(&c);
        with_ctx(&invite("").replace("cid-1", "send-tests-mode"), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "sip_trace_mode", &["m"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "sip_trace_mode", &["D"]).unwrap(), 1, "the last call wins");
            assert_eq!(call(&reg, ctx, "sip_trace", &[]).unwrap(), 1);
        });
        let p = c.packets();
        assert_eq!(p.len(), 1);
        assert!(has(&p[0], b"send-tests-mode"));
    }

    #[test]
    fn hlog_sends_a_log_record_correlated_by_call_id_or_the_given_id() {
        let c = Collector::new();
        let reg = registered(&c);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "hlog", &["hello"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "hlog", &["id-9", "bye"]).unwrap(), 1);
        });
        let p = c.packets();
        assert_eq!(p.len(), 2);
        // Chunk 11 (protocol type) is 100: a log.
        assert!(has(&p[0], &[0, 0, 0, 11, 0, 7, 100]));
        assert!(has(&p[0], b"cid-1") && p[0].ends_with(b"hello"));
        assert!(has(&p[1], b"id-9") && p[1].ends_with(b"bye"));
    }

    #[test]
    fn status_rpc_turns_tracing_on_and_off() {
        let c = Collector::new();
        let reg = registered(&c);
        assert_eq!(rpc(&reg, "siptrace.status", json!(["check"])).unwrap(), json!("enabled"));
        assert_eq!(rpc(&reg, "siptrace.status", json!(["off"])).unwrap(), json!("disabled"));
        with_ctx(&invite(""), &FakeNet(None), |ctx| assert_eq!(call(&reg, ctx, "hlog", &["x"]).unwrap(), 1));
        assert!(c.packets().is_empty(), "off: nothing sent");
        assert_eq!(rpc(&reg, "siptrace.status", json!(["check"])).unwrap(), json!("disabled"));
        assert_eq!(rpc(&reg, "siptrace.status", json!(["on"])).unwrap(), json!("enabled"));
        assert!(rpc(&reg, "siptrace.status", json!(["maybe"])).is_err());
        assert!(rpc(&reg, "siptrace.status", json!([])).is_err());
    }
}
