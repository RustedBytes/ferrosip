//! Transport-neutral addressing and the send-side API modules use.
//!
//! Kamailio equivalent: `struct dest_info` (proto + address + optional
//! connection id) and `msg_send()`, which picks UDP sendto, an existing TCP
//! connection, or opens a new one.

use crate::sync::{lock, read, write};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};

/// Host names behind configured destinations, so outbound TLS can verify the
/// server certificate by name (not just by IP). Filled by `Dest::parse`.
fn tls_names() -> &'static Mutex<HashMap<SocketAddr, String>> {
    static NAMES: OnceLock<Mutex<HashMap<SocketAddr, String>>> = OnceLock::new();
    NAMES.get_or_init(Default::default)
}

/// The configured host name for `addr`, if it was given by name.
/// Remember the TLS server name to verify for `addr` (RFC 5922: the URI's domain).
pub fn set_tls_name(addr: SocketAddr, name: &str) {
    lock(tls_names()).insert(addr, name.to_string());
}

pub fn tls_name_for(addr: &SocketAddr) -> Option<String> {
    lock(tls_names()).get(addr).cloned()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    Udp,
    Tcp,
    Tls,
    /// SIP over WebSocket (RFC 7118), plain.
    Ws,
    /// SIP over WebSocket over TLS.
    Wss,
}

impl Proto {
    pub const ALL: [Proto; 5] = [Proto::Udp, Proto::Tcp, Proto::Tls, Proto::Ws, Proto::Wss];
}

impl Proto {
    pub fn via_name(self) -> &'static str {
        match self {
            Proto::Udp => "UDP",
            Proto::Tcp => "TCP",
            Proto::Tls => "TLS",
            Proto::Ws => "WS",
            Proto::Wss => "WSS",
        }
    }
    /// Runs over a TLS session (TLS and WSS).
    pub fn is_tls(self) -> bool {
        matches!(self, Proto::Tls | Proto::Wss)
    }
    /// SIP messages are carried in WebSocket frames (WS and WSS).
    pub fn is_ws(self) -> bool {
        matches!(self, Proto::Ws | Proto::Wss)
    }
    /// Reliable transports: no SIP-level retransmissions (RFC 3261 §17.1.1.2).
    pub fn is_stream(self) -> bool {
        !matches!(self, Proto::Udp)
    }
    pub fn index(self) -> usize {
        self as usize
    }
}

pub type ConnId = u64;

/// Where a message came from / goes to.
#[derive(Clone, Copy, Debug)]
pub struct Dest {
    pub proto: Proto,
    pub addr: SocketAddr,
    /// For replies: the exact connection the request arrived on.
    pub conn: Option<ConnId>,
    /// Stream protocols: send only over an open connection, never dial
    /// (`set_reply_no_connect()`). Not part of equality.
    pub no_connect: bool,
}

impl PartialEq for Dest {
    fn eq(&self, o: &Self) -> bool {
        self.proto == o.proto && self.addr == o.addr && self.conn == o.conn
    }
}

impl Eq for Dest {}

impl Dest {
    pub fn new(proto: Proto, addr: SocketAddr) -> Self {
        Self { proto, addr, conn: None, no_connect: false }
    }

    /// `"host:port"` (UDP), `"udp:…"`, `"tcp:…"`, `"tls:…"`, `"ws:…"`, `"wss:…"`. Resolved once.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (proto, hp) = match s.split_once(':') {
            Some((p, rest)) if p.eq_ignore_ascii_case("udp") => (Proto::Udp, rest),
            Some((p, rest)) if p.eq_ignore_ascii_case("tcp") => (Proto::Tcp, rest),
            Some((p, rest)) if p.eq_ignore_ascii_case("tls") => (Proto::Tls, rest),
            Some((p, rest)) if p.eq_ignore_ascii_case("ws") => (Proto::Ws, rest),
            Some((p, rest)) if p.eq_ignore_ascii_case("wss") => (Proto::Wss, rest),
            _ => (Proto::Udp, s),
        };
        let addrs: Vec<SocketAddr> = hp.to_socket_addrs().map_err(|e| format!("{s}: {e}"))?.collect();
        // Prefer IPv4 when a name resolves to both (listeners are usually v4).
        let addr = addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).copied().ok_or_else(|| format!("{s}: no address"))?;
        let host = hp.rsplit_once(':').map_or(hp, |(h, _)| h).trim_matches(|c| c == '[' || c == ']');
        if host.parse::<IpAddr>().is_err() {
            lock(tls_names()).insert(addr, host.to_string());
        }
        Ok(Self::new(proto, addr))
    }
}

impl fmt::Display for Dest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.proto.via_name().to_ascii_lowercase(), self.addr)?;
        if let Some(c) = self.conn {
            write!(f, "#{c}")?;
        }
        Ok(())
    }
}

/// Connection life-cycle notifications from the transport layer, delivered
/// to every module (Kamailio: tcp `event_route[tcp:closed]`, usrloc's
/// `handle_lost_tcp`, tm's reaction to send failures).
#[derive(Clone, Copy, Debug)]
pub enum TransportEvent {
    Closed {
        /// The connection (proto, peer address, id).
        conn: Dest,
        /// We dialled it (vs. accepted it).
        outbound: bool,
        /// It ever became usable (TCP connected / TLS handshake done).
        established: bool,
    },
}

/// Implemented by the transport layer; shared by every worker and helper thread.
pub trait Outbound: Send + Sync {
    /// Send one complete SIP message. For stream protocols this reuses
    /// `dst.conn`, else any connection to `dst.addr`, else connects (async).
    fn send(&self, dst: &Dest, data: &[u8]) -> io::Result<()>;
    /// Address to put in our Via for `proto`.
    fn advertise(&self, proto: Proto) -> Option<SocketAddr>;
    /// RFC 5923 connection reuse is enabled (`--tcp-accept-aliases`).
    fn accepts_aliases(&self) -> bool {
        false
    }
    /// Route future requests for `addr` over connection `conn` (RFC 5923).
    fn add_alias(&self, _conn: ConnId, _addr: SocketAddr) {}
    /// The open stream connection a send to `dst` would use now (`None` for
    /// UDP or when a send would have to dial).
    fn conn_to(&self, _dst: &Dest) -> Option<ConnId> {
        None
    }
}

/// Rewrites every outgoing SIP message (topology hiding): returns the
/// bytes to send instead, or `None` to send as is.
pub type SendFilter = std::sync::Arc<dyn Fn(&Dest, &[u8]) -> Option<Vec<u8>> + Send + Sync>;

fn send_filter_cell() -> &'static OnceLock<SendFilter> {
    static F: OnceLock<SendFilter> = OnceLock::new();
    &F
}

/// Install the (single) outgoing-message filter. Fails if one is set.
pub fn set_send_filter(f: SendFilter) -> Result<(), String> {
    send_filter_cell().set(f).map_err(|_| "a send filter (topoh/topos) is already installed".to_string())
}

fn recv_filter_cell() -> &'static OnceLock<SendFilter> {
    static F: OnceLock<SendFilter> = OnceLock::new();
    &F
}

/// Install the (single) incoming-message filter: it may rewrite a message
/// before it is parsed and routed (topoh unmasks Route/Record-Route).
pub fn set_recv_filter(f: SendFilter) -> Result<(), String> {
    recv_filter_cell().set(f).map_err(|_| "a receive filter (topoh/topos) is already installed".to_string())
}

/// `data` (from `src`) after the receive filter; None: unchanged.
pub fn recv_filtered(src: &Dest, data: &[u8]) -> Option<Vec<u8>> {
    recv_filter_cell().get().and_then(|f| f(src, data))
}

/// Sees every outgoing SIP message after filtering (siptrace).
pub type SendTap = std::sync::Arc<dyn Fn(&Dest, &[u8]) + Send + Sync>;

static HAS_TAPS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn taps() -> &'static std::sync::RwLock<Vec<SendTap>> {
    static T: OnceLock<std::sync::RwLock<Vec<SendTap>>> = OnceLock::new();
    T.get_or_init(Default::default)
}

pub fn add_send_tap(t: SendTap) {
    write(taps()).push(t);
    HAS_TAPS.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Apply the send filter, if any (and show the result to the taps).
#[inline]
pub fn filtered<'a>(dst: &Dest, data: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
    let out = match send_filter_cell().get().and_then(|f| f(dst, data)) {
        Some(v) => std::borrow::Cow::Owned(v),
        None => std::borrow::Cow::Borrowed(data),
    };
    if HAS_TAPS.load(std::sync::atomic::Ordering::Relaxed) {
        for t in read(taps()).iter() {
            t(dst, &out);
        }
    }
    out
}

/// `core:send_errors`: messages a transport refused to send.
pub fn send_errors() -> &'static std::sync::atomic::AtomicI64 {
    static C: OnceLock<&'static std::sync::atomic::AtomicI64> = OnceLock::new();
    C.get_or_init(|| crate::stats::counter("core", "send_errors"))
}

/// `r` is the result of handing one message for `dst` to the transport:
/// count a failure in `core:send_errors` and log it, at most one line per
/// second (the lines skipped in between are counted in the next one).
/// Called once per send by the layer that touches the socket.
#[inline]
pub fn note_send(dst: &Dest, r: io::Result<()>) -> io::Result<()> {
    if let Err(e) = &r {
        send_failed(dst, e);
    }
    r
}

#[cold]
fn send_failed(dst: &Dest, e: &io::Error) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    static LAST_MS: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    crate::stats::inc(send_errors());
    // +1000 so the first failure is logged.
    let now = u64::try_from(START.get_or_init(std::time::Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX).saturating_add(1000);
    let last = LAST_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) < 1000 || LAST_MS.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let n = SUPPRESSED.swap(0, Ordering::Relaxed);
    let more = if n > 0 { format!(" ({n} more send errors suppressed)") } else { String::new() };
    crate::log::log(crate::log::L_ERR, &format!("send to {dst} failed: {e}{more}"));
}

/// Host names/IPs that are "us" besides our listen addresses (Kamailio's
/// `alias=` core parameter; the domain module adds its local domains).
fn aliases() -> &'static std::sync::RwLock<std::collections::HashSet<String>> {
    static A: OnceLock<std::sync::RwLock<std::collections::HashSet<String>>> = OnceLock::new();
    A.get_or_init(Default::default)
}

pub fn add_alias(host: &str) {
    write(aliases()).insert(host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase());
}

/// `X == myself`: is `host` (an IP, a host name, or a SIP URI) one of ours?
pub fn is_myself(net: &dyn Outbound, host: &str) -> bool {
    let h = match sip_parser::parse_uri(host.as_bytes()) {
        Some(u) => String::from_utf8_lossy(u.host).into_owned(),
        None => host.to_string(),
    };
    let h = h.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    if read(aliases()).contains(&h) {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => Proto::ALL.iter().filter_map(|p| net.advertise(*p)).any(|a| a.ip() == ip),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_parse_forms() {
        let cases: &[(&str, Option<(Proto, &str)>)] = &[
            ("192.0.2.1:5060", Some((Proto::Udp, "192.0.2.1:5060"))),
            ("udp:192.0.2.1:5070", Some((Proto::Udp, "192.0.2.1:5070"))),
            ("TCP:192.0.2.1:5070", Some((Proto::Tcp, "192.0.2.1:5070"))),
            ("tls:192.0.2.1:5061", Some((Proto::Tls, "192.0.2.1:5061"))),
            ("ws:192.0.2.1:80", Some((Proto::Ws, "192.0.2.1:80"))),
            ("Wss:192.0.2.1:443", Some((Proto::Wss, "192.0.2.1:443"))),
            ("[2001:db8::1]:5060", Some((Proto::Udp, "[2001:db8::1]:5060"))),
            ("tcp:[2001:db8::1]:5060", Some((Proto::Tcp, "[2001:db8::1]:5060"))),
            ("192.0.2.1", None),
            ("tcp:192.0.2.1", None),
            ("sctp:192.0.2.1:5060", None),
            ("192.0.2.1:99999", None),
            ("", None),
        ];
        for (s, want) in cases {
            let got = Dest::parse(s).ok().map(|d| (d.proto, d.addr.to_string()));
            assert_eq!(got, want.map(|(p, a)| (p, a.to_string())), "{s:?}");
        }
    }

    #[test]
    fn dest_display_and_equality() {
        let mut d = Dest::new(Proto::Tls, "[2001:db8::1]:5061".parse().unwrap());
        assert_eq!(d.to_string(), "tls:[2001:db8::1]:5061");
        d.conn = Some(12);
        assert_eq!(d.to_string(), "tls:[2001:db8::1]:5061#12");
        let mut e = d;
        e.no_connect = true;
        assert_eq!(d, e, "no_connect is not part of equality");
        e.conn = None;
        assert_ne!(d, e, "the connection id is");
        let shown = Dest::new(Proto::Ws, "192.0.2.1:80".parse().unwrap()).to_string();
        assert_eq!(Dest::parse(&shown).unwrap(), Dest::new(Proto::Ws, "192.0.2.1:80".parse().unwrap()), "Display parses back");
    }

    #[test]
    fn proto_properties() {
        // (proto, via name, tls, ws, stream)
        let cases = [
            (Proto::Udp, "UDP", false, false, false),
            (Proto::Tcp, "TCP", false, false, true),
            (Proto::Tls, "TLS", true, false, true),
            (Proto::Ws, "WS", false, true, true),
            (Proto::Wss, "WSS", true, true, true),
        ];
        for (i, (p, name, tls, ws, stream)) in cases.into_iter().enumerate() {
            assert_eq!((p.via_name(), p.is_tls(), p.is_ws(), p.is_stream(), p.index()), (name, tls, ws, stream, i), "{p:?}");
            assert_eq!(Proto::ALL[i], p);
        }
    }

    struct Net;
    impl Outbound for Net {
        fn send(&self, _: &Dest, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn advertise(&self, p: Proto) -> Option<SocketAddr> {
            match p {
                Proto::Udp => Some("192.0.2.50:5060".parse().unwrap()),
                Proto::Tls => Some("[2001:db8::50]:5061".parse().unwrap()),
                _ => None,
            }
        }
    }

    #[test]
    fn is_myself_matches_listeners_and_aliases() {
        add_alias("[Net-Test-Alias.Example]");
        let cases: &[(&str, bool)] = &[
            ("192.0.2.50", true),
            ("sip:u@192.0.2.50:5070;transport=tcp", true),
            ("2001:db8::50", true),
            ("[2001:db8::50]", true),
            ("sip:[2001:db8::50]", true),
            ("192.0.2.51", false),
            ("net-test-alias.example", true),
            ("sips:x@NET-TEST-ALIAS.example", true),
            ("other.example", false),
            ("", false),
        ];
        for (h, want) in cases {
            assert_eq!(is_myself(&Net, h), *want, "{h:?}");
        }
    }
}
