//! TCP/TLS transport modelled on Kamailio's tcp_main.c / tcp_read.c.
//!
//! ```text
//!              accept()                        Arc<Conn> + wake
//!  listeners ──────────► tcp-main ─────────────────────────────┐
//!                         (least-loaded reader, max_connections)│
//!                                                               ▼
//!  any thread ── send() ──► conn table ──► direct write   tcp-reader-0..N
//!  (workers, tm timer)      by_id/by_addr  (per-conn lock)  epoll (edge-trig.)
//!                              │           would-block →    read → frame by
//!                              │           queue (wq_max)   Content-Length →
//!                              └─ miss → non-blocking       Handler; flush
//!                                 connect, adopt by reader  queues on EPOLLOUT;
//!                                                           idle-timeout sweep
//! ```
//!
//! Differences from Kamailio, all consequences of threads vs processes:
//! * Kamailio passes fds between tcp_main and reader *processes* over unix
//!   sockets and hands idle connections back to tcp_main. Threads share
//!   memory, so a connection stays pinned to one reader for its lifetime and
//!   only an `Arc<Conn>` is handed over (once).
//! * The connection table is a sharded map instead of a hash in shm guarded by
//!   a global TCP lock.
//!
//! WebSocket (WS/WSS, RFC 7118) is a layer on the same connections: the reader
//! runs the HTTP upgrade, then de-frames instead of Content-Length framing, and
//! `write()` prepends a frame header. Outbound `ws:`/`wss:` connections are
//! WebSocket clients: `connect()` sends the Upgrade, and SIP messages queue
//! until the 101 arrives (frames masked, RFC 6455 §5.3).

use crate::tls::TlsConfig;
use crate::ws::{self, Handshake, Parsed, WsOpts, op};
use crate::{Scratch, dispatch};
use mio::net::{TcpListener, TcpStream};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token, Waker};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, Connection, ServerConnection};
use sip_core::limit::{KeyedLimiter, Limiter, Permit};
use sip_core::sync::lock;
use sip_core::{ConnId, Dest, Handler, Outbound, Proto, ShardedMap, TransportEvent};
use sip_parser::{Frame, stream_frame};
use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const WAKER: Token = Token(usize::MAX);
/// Smaller messages are sent uncompressed even with permessage-deflate
/// (allowed per message by RFC 7692; saves CPU where it can't pay off).
const WS_DEFLATE_MIN: usize = 128;

/// Kamailio core parameters of the same names.
#[derive(Clone, Debug)]
pub struct TcpOpts {
    /// `tcp_children`
    pub readers: usize,
    /// `tcp_max_connections`
    pub max_connections: usize,
    /// `tcp_connection_lifetime`: idle connections are closed after this.
    pub connection_lifetime: Duration,
    /// `tcp_conn_wq_max`: per-connection write-queue limit; exceeding it closes.
    pub conn_wq_max: usize,
    /// Maximum size of one SIP message on a stream.
    pub max_msg_size: usize,
    /// WebSocket listener options (Origin allow-list, permessage-deflate).
    pub ws: WsOpts,
    /// `tcp_connect_timeout`: an outbound connection (incl. TLS handshake)
    /// not usable after this is closed and its transactions failed with 477.
    pub connect_timeout: Duration,
    /// `tcp_keepalive` + `tcp_keepidle`: kernel keep-alive probes after this idle time.
    pub keepalive: Option<Duration>,
    /// `tcp_accept_aliases`: honour Via `;alias` (RFC 5923) on incoming requests.
    pub accept_aliases: bool,
    /// `tcp_accept_iplimit`: inbound connections per source IP (0 = no limit).
    pub accept_iplimit: usize,
}

impl Default for TcpOpts {
    fn default() -> Self {
        Self {
            readers: 2,
            max_connections: 4096,
            connection_lifetime: Duration::from_secs(120),
            conn_wq_max: 256 * 1024,
            max_msg_size: 64 * 1024,
            ws: WsOpts::default(),
            connect_timeout: Duration::from_secs(10),
            keepalive: None,
            accept_aliases: false,
            accept_iplimit: 1024,
        }
    }
}

/// One open stream connection, as `TcpService::connections` reports it.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    pub id: ConnId,
    pub proto: Proto,
    pub peer: SocketAddr,
    pub local: Option<SocketAddr>,
    /// We dialled it.
    pub outbound: bool,
    /// Handshake / WebSocket upgrade done.
    pub established: bool,
    pub age_ms: u64,
    pub idle_ms: u64,
    /// RFC 5923 aliases published for it.
    pub aliases: Vec<SocketAddr>,
    pub tls_version: Option<String>,
    /// TLS server name the client asked for.
    pub sni: Option<String>,
}

enum ConnIo {
    /// Pending bytes not yet accepted by the kernel.
    Plain(Vec<u8>),
    /// rustls keeps its own outgoing buffer (bounded by `set_buffer_limit`).
    Tls(Box<Connection>),
}

pub struct Conn {
    pub id: ConnId,
    pub proto: Proto,
    pub peer: SocketAddr,
    stream: TcpStream,
    /// Write side for plain TCP; whole session for TLS (reads need it too).
    io: Mutex<ConnIo>,
    last_active: AtomicU64,
    closed: AtomicBool,
    /// WS/WSS: set once the 101 has been sent; frames may only flow after it.
    ws_open: AtomicBool,
    /// permessage-deflate negotiated: compress outgoing messages.
    ws_deflate: AtomicBool,
    /// We dialled it.
    outbound: bool,
    /// Usable: TCP connected, TLS handshake finished, and for WS/WSS the
    /// upgrade done (101 sent or received). Until then the connection is
    /// bound by tcp_connect_timeout, inbound too: a peer that connects and
    /// never completes its handshake can't hold a slot for the idle lifetime.
    established: AtomicBool,
    created: u64,
    /// RFC 5923 aliases published for this connection.
    aliases: Mutex<Vec<SocketAddr>>,
    reader: usize,
    /// Outbound WS/WSS: our Sec-WebSocket-Key (frames we send are masked).
    ws_key: Option<String>,
    /// Outbound WS/WSS: SIP messages queued until the 101 arrives.
    ws_pending: Mutex<Vec<Vec<u8>>>,
}

impl Conn {
    fn io(&self) -> MutexGuard<'_, ConnIo> {
        lock(&self.io)
    }
}

struct ReaderHandle {
    tx: Sender<Arc<Conn>>,
    waker: Waker,
    load: AtomicUsize,
}

pub struct TcpService {
    opts: TcpOpts,
    tls: Option<TlsConfig>,
    by_id: ShardedMap<ConnId, Arc<Conn>>,
    by_addr: ShardedMap<(Proto, SocketAddr), ConnId>,
    readers: Vec<ReaderHandle>,
    pending: Mutex<Vec<(Poll, Receiver<Arc<Conn>>)>>,
    next_id: AtomicU64,
    /// `tcp_max_connections`: inbound and outbound share one budget.
    slots: Limiter,
    /// `tcp_accept_iplimit`: inbound connections per source IP.
    per_ip: KeyedLimiter<IpAddr>,
    epoch: Instant,
}

/// A fresh frame mask (RFC 6455 §5.3: unpredictable).
fn mask() -> [u8; 4] {
    let mut m = [0u8; 4];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut m).is_err() {
        sip_core::elog!("ws: no system randomness for a frame mask");
    }
    m
}

fn would_block(e: &io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::NotConnected)
}

/// Write as much as the kernel takes right now; returns bytes written.
fn write_some(mut s: &TcpStream, buf: &[u8]) -> io::Result<usize> {
    let mut rest = buf;
    while !rest.is_empty() {
        match s.write(rest) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(n) => rest = rest.get(n..).unwrap_or_default(),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if would_block(&e) => break,
            Err(e) => return Err(e),
        }
    }
    // Written: what is no longer left (`rest` is a suffix of `buf`).
    Ok(buf.len().saturating_sub(rest.len()))
}

/// Grow `buf` by up to `n` bytes that `read` fills in; keeps only the bytes
/// `read` reports and returns its result.
fn read_into_tail(buf: &mut Vec<u8>, n: usize, read: impl FnOnce(&mut [u8]) -> io::Result<usize>) -> io::Result<usize> {
    let len = buf.len();
    buf.resize(len.saturating_add(n), 0);
    let r = read(buf.get_mut(len..).unwrap_or_default());
    buf.truncate(len.saturating_add(*r.as_ref().unwrap_or(&0)));
    r
}

fn flush_tls(mut s: &TcpStream, sess: &mut Connection) -> io::Result<()> {
    while sess.wants_write() {
        match sess.write_tls(&mut s) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if would_block(&e) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn flush(conn: &Conn) -> io::Result<()> {
    match &mut *conn.io() {
        ConnIo::Plain(wq) => {
            let n = write_some(&conn.stream, wq)?;
            wq.drain(..n);
            Ok(())
        }
        ConnIo::Tls(sess) => flush_tls(&conn.stream, sess),
    }
}

/// Read what's available into `rbuf` (plaintext for TLS), stopping once it
/// holds `cap` bytes so one sender can't grow it without bound or hold a
/// TLS session lock for an entire flood.
fn read_available(conn: &Conn, rbuf: &mut Vec<u8>, cap: usize) -> io::Result<ReadEnd> {
    let mut s = &conn.stream;
    if !conn.proto.is_tls() {
        loop {
            if rbuf.len() >= cap {
                return Ok(ReadEnd::Full);
            }
            match read_into_tail(rbuf, 16 * 1024, |b| s.read(b)) {
                Ok(0) => return Ok(ReadEnd::Eof),
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(ReadEnd::Drained),
                Err(e) => return Err(e),
            }
        }
    }
    let mut io = conn.io();
    let ConnIo::Tls(sess) = &mut *io else { return Err(io::Error::other("TLS connection without a TLS session")) };
    let (mut eof, mut full) = (false, false);
    loop {
        if rbuf.len() >= cap {
            full = true;
            break;
        }
        match sess.read_tls(&mut s) {
            Ok(0) => eof = true,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
        let st = sess.process_new_packets().map_err(|e| {
            #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
            let _ = flush_tls(&conn.stream, sess); // try to send the alert
            io::Error::new(ErrorKind::InvalidData, e)
        })?;
        let n = st.plaintext_bytes_to_read();
        if n > 0 {
            read_into_tail(rbuf, n, |b| sess.reader().read_exact(b).map(|()| b.len()))?;
        }
        if eof || st.peer_has_closed() {
            eof = true;
            break;
        }
    }
    // Handshake replies, and application data queued before the handshake
    // finished, become sendable here.
    flush_tls(&conn.stream, sess)?;
    Ok(if eof {
        ReadEnd::Eof
    } else if full {
        ReadEnd::Full
    } else {
        ReadEnd::Drained
    })
}

/// How a `read_available` call ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadEnd {
    /// Everything the kernel had was read.
    Drained,
    /// The peer closed its side.
    Eof,
    /// The buffer reached its cap with data still waiting: process, then
    /// read again (edge-triggered polling needs the socket drained).
    Full,
}

struct Local {
    conn: Arc<Conn>,
    rbuf: Vec<u8>,
    start: usize,
    ws: Option<WsLocal>,
}

/// Reader-side WebSocket state.
#[derive(Default)]
struct WsLocal {
    open: bool,
    /// Reassembly buffer for a fragmented message and its opcode (0 = none).
    frag: Vec<u8>,
    frag_op: u8,
    frag_rsv1: bool,
    /// permessage-deflate state for client→server messages.
    inflater: Option<ws::Inflater>,
    inflated: Vec<u8>,
    /// A keep-alive ping is outstanding.
    pinged: bool,
}

impl TcpService {
    pub fn new(opts: TcpOpts, tls: Option<TlsConfig>) -> io::Result<Arc<Self>> {
        let mut readers = Vec::new();
        let mut pending = Vec::new();
        for _ in 0..opts.readers.max(1) {
            let poll = Poll::new()?;
            let waker = Waker::new(poll.registry(), WAKER)?;
            let (tx, rx) = mpsc::channel();
            readers.push(ReaderHandle { tx, waker, load: AtomicUsize::new(0) });
            pending.push((poll, rx));
        }
        let (slots, per_ip) = (Limiter::new(opts.max_connections), KeyedLimiter::new(opts.accept_iplimit));
        Ok(Arc::new(Self {
            opts,
            tls,
            by_id: ShardedMap::new(256),
            by_addr: ShardedMap::new(256),
            readers,
            pending: Mutex::new(pending),
            next_id: AtomicU64::new(1),
            slots,
            per_ip,
            epoch: Instant::now(),
        }))
    }

    /// Graceful shutdown, last step: send TLS close_notify (best effort,
    /// non-blocking) and close every connection.
    pub fn close_all(&self) {
        let mut all = Vec::new();
        self.by_id.for_each_mut(|_, c| all.push(c.clone()));
        for conn in all {
            self.kill(&conn);
            if let ConnIo::Tls(sess) = &mut *conn.io() {
                sess.send_close_notify();
                #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
                let _ = flush_tls(&conn.stream, sess);
            }
            #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
            let _ = conn.stream.shutdown(Shutdown::Both);
        }
    }

    /// A snapshot of every open stream connection (for `core.connections`).
    /// TLS details come from connections whose session isn't busy right now
    /// (never blocks a sender).
    pub fn connections(&self) -> Vec<ConnInfo> {
        let mut all = Vec::new();
        self.by_id.for_each_mut(|_, c| all.push(c.clone()));
        let now = self.now();
        let mut out: Vec<ConnInfo> = all
            .iter()
            .map(|c| {
                let (tls_version, sni) = match c.io.try_lock().as_deref() {
                    Ok(ConnIo::Tls(sess)) => {
                        let v = sess.protocol_version().map(|v| format!("{v:?}"));
                        let sni = match &**sess {
                            Connection::Server(s) => s.server_name().map(str::to_string),
                            Connection::Client(_) => None,
                        };
                        (v, sni)
                    }
                    _ => (None, None),
                };
                ConnInfo {
                    id: c.id,
                    proto: c.proto,
                    peer: c.peer,
                    local: c.stream.local_addr().ok(),
                    outbound: c.outbound,
                    established: c.established.load(Ordering::Relaxed),
                    age_ms: now.saturating_sub(c.created),
                    idle_ms: now.saturating_sub(c.last_active.load(Ordering::Relaxed)),
                    aliases: c.aliases.lock().map(|a| a.clone()).unwrap_or_default(),
                    tls_version,
                    sni,
                }
            })
            .collect();
        out.sort_by_key(|c| c.id);
        out
    }

    /// Configured limits (for `core.connections`).
    pub fn limits(&self) -> (usize, usize, Duration) {
        (self.opts.max_connections, self.opts.accept_iplimit, self.opts.connection_lifetime)
    }

    pub fn active_connections(&self) -> usize {
        self.slots.in_use()
    }

    /// Milliseconds since start (connection timestamps).
    fn now(&self) -> u64 {
        millis(self.epoch.elapsed())
    }

    fn tune(&self, s: &TcpStream) {
        #[allow(clippy::let_underscore_must_use, reason = "best effort: the socket works without it")]
        let _ = s.set_nodelay(true);
        if let Some(idle) = self.opts.keepalive {
            let ka =
                socket2::TcpKeepalive::new().with_time(idle).with_interval(idle.checked_div(3).unwrap_or_default().max(Duration::from_secs(1))).with_retries(3);
            #[allow(clippy::let_underscore_must_use, reason = "best effort: the socket works without it")]
            let _ = socket2::SockRef::from(s).set_tcp_keepalive(&ka);
        }
    }

    fn new_conn(&self, stream: TcpStream, peer: SocketAddr, proto: Proto, io: ConnIo, outbound: bool) -> Arc<Conn> {
        let reader = self.readers.iter().enumerate().min_by_key(|(_, r)| r.load.load(Ordering::Relaxed)).map_or(0, |(i, _)| i);
        Arc::new(Conn {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            proto,
            peer,
            stream,
            io: Mutex::new(io),
            last_active: AtomicU64::new(self.now()),
            closed: AtomicBool::new(false),
            ws_open: AtomicBool::new(false),
            ws_deflate: AtomicBool::new(false),
            outbound,
            established: AtomicBool::new(!outbound && !proto.is_tls() && !proto.is_ws()),
            created: self.now(),
            aliases: Mutex::new(Vec::new()),
            reader,
            ws_key: None,
            ws_pending: Mutex::new(Vec::new()),
        })
    }

    /// Claim one of the `tcp_max_connections` slots (atomic: concurrent
    /// accepts and connects can't overshoot). Given back on drop unless
    /// `adopt` keeps it for a live connection (then `release` frees it).
    fn reserve(&self) -> Option<Permit<'_>> {
        self.slots.try_acquire()
    }

    /// Publish in the shared table and hand to the owning reader. On failure
    /// (the reader is gone) the connection is killed and its slot, source-IP
    /// unit and reader load are given back, so a dead reader can't leak the
    /// connection budget.
    fn adopt(&self, conn: &Arc<Conn>, slot: Permit<'_>, ip: Option<IpUnit<'_>>) {
        let Some(r) = self.readers.get(conn.reader) else {
            self.kill(conn);
            return;
        };
        r.load.fetch_add(1, Ordering::Relaxed);
        self.by_id.insert(conn.id, conn.clone());
        self.by_addr.insert((conn.proto, conn.peer), conn.id);
        if r.tx.send(conn.clone()).is_err() || r.waker.wake().is_err() {
            self.kill(conn);
            r.load.fetch_sub(1, Ordering::Relaxed);
            return; // `slot` and `ip` drop: both counts go back down
        }
        slot.keep();
        if let Some(ip) = ip {
            ip.keep();
        }
    }

    fn accepted(&self, stream: TcpStream, peer: SocketAddr, proto: Proto) {
        if sip_core::shutdown::draining() {
            return; // shutting down: no new connections (dropping closes it)
        }
        // Per source IP first, so one host can't fill the global budget.
        let Some(ip) = IpUnit::acquire(&self.per_ip, peer.ip()) else {
            sip_core::stats::inc(tcp_stats().rejected_iplimit);
            reject_log(self.opts.max_connections, peer, Some(self.opts.accept_iplimit));
            return;
        };
        let Some(slot) = self.reserve() else {
            sip_core::stats::inc(tcp_stats().rejected);
            reject_log(self.opts.max_connections, peer, None);
            return; // dropping the stream closes it (and `ip` gives its unit back)
        };
        sip_core::stats::inc(tcp_stats().accepted);
        self.tune(&stream);
        let io = match proto {
            p if p.is_tls() => {
                let Some(cfg) = self.tls.as_ref().and_then(|t| t.server_for(stream.local_addr().ok())) else { return };
                match ServerConnection::new(cfg) {
                    Ok(mut c) => {
                        c.set_buffer_limit(Some(self.opts.conn_wq_max));
                        ConnIo::Tls(Box::new(c.into()))
                    }
                    Err(e) => {
                        sip_core::elog!("tls: {e}");
                        return;
                    }
                }
            }
            _ => ConnIo::Plain(Vec::new()),
        };
        let conn = self.new_conn(stream, peer, proto, io, false);
        self.adopt(&conn, slot, Some(ip));
    }

    /// Asynchronous connect (Kamailio `tcp_async`): returns immediately; data
    /// written before the handshake completes is queued and flushed by the
    /// owning reader on EPOLLOUT.
    fn connect(&self, proto: Proto, addr: SocketAddr) -> io::Result<Arc<Conn>> {
        let slot = self.reserve().ok_or_else(|| io::Error::other("tcp_max_connections reached"))?;
        let io = match proto {
            Proto::Tcp | Proto::Ws => ConnIo::Plain(Vec::new()),
            Proto::Tls | Proto::Wss => {
                let (cfg, profile_name) = self.tls.as_ref().and_then(|t| t.client_for(&addr)).ok_or_else(|| io::Error::other("outbound TLS needs --tls-ca"))?;
                // Verify by the profile's server_name, else by host name if the
                // destination was configured by name, else by IP.
                let name = match profile_name.or_else(|| sip_core::net::tls_name_for(&addr)) {
                    Some(n) => ServerName::try_from(n).map_err(io::Error::other)?,
                    None => ServerName::from(addr.ip()),
                };
                let mut c = ClientConnection::new(cfg, name).map_err(io::Error::other)?;
                c.set_buffer_limit(Some(self.opts.conn_wq_max));
                ConnIo::Tls(Box::new(c.into()))
            }
            Proto::Udp => return Err(io::Error::other("not a stream protocol")),
        };
        let stream = TcpStream::connect(addr)?;
        self.tune(&stream);
        let mut conn = self.new_conn(stream, addr, proto, io, true);
        if proto.is_ws() {
            // We are the WebSocket client: send the upgrade first; SIP
            // messages wait for the 101 (see process_ws).
            let mut k = [0u8; 16];
            if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut k).is_err() {
                sip_core::elog!("ws: no system randomness for a Sec-WebSocket-Key");
            }
            let key = ws::base64(&k);
            let host = sip_core::net::tls_name_for(&addr).map_or_else(|| addr.to_string(), |n| format!("{n}:{}", addr.port()));
            let req = ws::client_request(&host, "/", &key);
            let Some(fresh) = Arc::get_mut(&mut conn) else { return Err(io::Error::other("new connection already shared")) };
            fresh.ws_key = Some(key);
            self.adopt(&conn, slot, None);
            self.write_parts(&conn, &[req.as_bytes()])?;
            return Ok(conn);
        }
        self.adopt(&conn, slot, None);
        Ok(conn)
    }

    /// The open connection a send to `dst` would use right now.
    pub fn conn_to(&self, dst: &Dest) -> Option<ConnId> {
        self.lookup(dst).map(|c| c.id)
    }

    fn lookup(&self, dst: &Dest) -> Option<Arc<Conn>> {
        let ok = |c: &Arc<Conn>| c.proto == dst.proto && !c.closed.load(Ordering::Acquire);
        if let Some(c) = dst.conn.and_then(|id| self.by_id.get_cloned(&id)).filter(ok) {
            return Some(c);
        }
        let id = self.by_addr.get_cloned(&(dst.proto, dst.addr))?;
        self.by_id.get_cloned(&id).filter(ok)
    }

    /// Send a complete message from any thread.
    pub fn send(&self, dst: &Dest, data: &[u8]) -> io::Result<()> {
        let conn = match self.lookup(dst) {
            Some(c) => c,
            None if dst.no_connect => return Err(io::Error::new(ErrorKind::NotConnected, "connection closed and set_reply_no_connect() is on")),
            None => self.connect(dst.proto, dst.addr)?,
        };
        self.write(&conn, data)
    }

    /// Send one SIP message: raw on TCP/TLS, as one WebSocket frame on WS/WSS.
    fn write(&self, conn: &Arc<Conn>, data: &[u8]) -> io::Result<()> {
        if !conn.proto.is_ws() {
            return self.write_parts(conn, &[data]);
        }
        if !conn.ws_open.load(Ordering::Acquire) {
            if conn.ws_key.is_some() {
                // Our own connection, upgrade in progress: send after the 101.
                let mut q = lock(&conn.ws_pending);
                if !conn.ws_open.load(Ordering::Acquire) {
                    // Bounded like any write queue (tcp_conn_wq_max).
                    if q.iter().map(Vec::len).sum::<usize>().saturating_add(data.len()) > self.opts.conn_wq_max {
                        return Err(io::Error::other("WebSocket upgrade pending and the queue is full"));
                    }
                    q.push(data.to_vec());
                    return Ok(());
                }
            } else {
                return Err(io::Error::new(ErrorKind::NotConnected, "WebSocket handshake not complete"));
            }
        }
        // RFC 7118 §5: text frames must be UTF-8; anything else goes as binary.
        let opcode = if std::str::from_utf8(data).is_ok() { op::TEXT } else { op::BINARY };
        if conn.ws_key.is_some() {
            // Client → server frames are masked (RFC 6455 §5.3).
            let mut f = Vec::with_capacity(data.len().saturating_add(14));
            ws::encode(true, opcode, data, Some(mask()), &mut f);
            return self.write_parts(conn, &[&f]);
        }
        if conn.ws_deflate.load(Ordering::Acquire) && data.len() >= WS_DEFLATE_MIN {
            let sent = ws::with_deflated(data, |z| {
                let h = ws::frame_header(true, opcode, z.len(), None).compressed();
                self.write_parts(conn, &[h.as_bytes(), z])
            });
            if let Some(r) = sent {
                return r;
            }
            // The compressor failed: an uncompressed frame is valid too.
        }
        let h = ws::frame_header(true, opcode, data.len(), None);
        self.write_parts(conn, &[h.as_bytes(), data]) // header + payload, no copy
    }

    fn ws_control(&self, conn: &Arc<Conn>, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if conn.ws_key.is_some() {
            let mut f = Vec::with_capacity(payload.len().saturating_add(14));
            ws::encode(true, opcode, payload, Some(mask()), &mut f);
            return self.write_parts(conn, &[&f]);
        }
        let h = ws::frame_header(true, opcode, payload.len(), None);
        self.write_parts(conn, &[h.as_bytes(), payload])
    }

    /// Write `parts` back to back under the connection lock, so concurrent
    /// senders never interleave (a frame header and its payload stay together).
    fn write_parts(&self, conn: &Arc<Conn>, parts: &[&[u8]]) -> io::Result<()> {
        if conn.closed.load(Ordering::Acquire) {
            return Err(ErrorKind::NotConnected.into());
        }
        let r = match &mut *conn.io() {
            ConnIo::Plain(wq) => parts.iter().try_for_each(|&p| {
                // Fast path: nothing queued → write directly from this thread.
                let n = if wq.is_empty() { write_some(&conn.stream, p)? } else { 0 };
                let rest = p.get(n..).unwrap_or_default();
                if wq.len().saturating_add(rest.len()) > self.opts.conn_wq_max {
                    return Err(io::Error::other("tcp_conn_wq_max exceeded"));
                }
                wq.extend_from_slice(rest);
                Ok(())
            }),
            ConnIo::Tls(sess) => parts.iter().try_for_each(|p| sess.writer().write_all(p)).and_then(|_| flush_tls(&conn.stream, sess)),
        };
        match r {
            Ok(()) => {
                conn.last_active.store(self.now(), Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.kill(conn);
                Err(e)
            }
        }
    }

    /// Mark dead and unpublish (any thread). The owner releases the fd.
    fn kill(&self, conn: &Conn) {
        if !conn.closed.swap(true, Ordering::AcqRel) {
            self.by_id.remove(&conn.id);
            self.by_addr.remove_if(&(conn.proto, conn.peer), |&id| id == conn.id);
            for a in lock(&conn.aliases).drain(..) {
                self.by_addr.remove_if(&(conn.proto, a), |&id| id == conn.id);
            }
        }
    }

    /// RFC 5923: requests to `addr` may reuse connection `id` (opt-in).
    pub fn add_alias(&self, id: ConnId, addr: SocketAddr) {
        if !self.opts.accept_aliases {
            return;
        }
        let Some(conn) = self.by_id.get_cloned(&id) else { return };
        let mut al = lock(&conn.aliases);
        // kill() sets `closed` before draining the aliases under this lock:
        // checking it here means a racing kill can't leave a by_addr entry
        // pointing at a dead connection.
        if conn.closed.load(Ordering::Acquire) {
            return;
        }
        if addr != conn.peer && !al.contains(&addr) && al.len() < 8 {
            al.push(addr);
            self.by_addr.insert((conn.proto, addr), id);
        }
    }

    pub fn accepts_aliases(&self) -> bool {
        self.opts.accept_aliases
    }

    /// Owner-only: release and tell the modules (tm fails transactions on a
    /// connection that never came up; usrloc drops contacts on lost conns).
    fn close(&self, conn: &Conn, reg: &Registry, handler: &dyn Handler) {
        self.release(conn, reg);
        let ev = TransportEvent::Closed {
            conn: Dest { proto: conn.proto, addr: conn.peer, conn: Some(conn.id), no_connect: false },
            outbound: conn.outbound,
            established: conn.established.load(Ordering::Acquire),
        };
        if sip_core::panic::catch(|| handler.transport_event(&ev)).is_err() {
            sip_core::elog!("tcp: panic in a module's handler for the close of {}", conn.peer);
        }
    }

    /// Owner-only: deregister and close.
    fn release(&self, conn: &Conn, reg: &Registry) {
        self.kill(conn);
        let fd = conn.stream.as_raw_fd();
        #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
        let _ = reg.deregister(&mut SourceFd(&fd));
        if let ConnIo::Tls(sess) = &mut *conn.io() {
            sess.send_close_notify();
            #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
            let _ = flush_tls(&conn.stream, sess);
        }
        #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
        let _ = conn.stream.shutdown(Shutdown::Both);
        self.slots.release();
        if !conn.outbound {
            self.per_ip.release(&conn.peer.ip());
        }
        if let Some(r) = self.readers.get(conn.reader) {
            r.load.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn start(
        self: &Arc<Self>,
        mut listeners: Vec<(TcpListener, Proto)>,
        net: Arc<dyn Outbound>,
        handler: Arc<dyn Handler>,
        worker_base: usize,
    ) -> Result<Vec<JoinHandle<()>>, String> {
        let pending = std::mem::take(&mut *lock(&self.pending));
        let mut hs = Vec::new();
        for (i, (poll, rx)) in pending.into_iter().enumerate() {
            let (svc, net, h) = (self.clone(), net.clone(), handler.clone());
            hs.push(
                thread::Builder::new()
                    .name(format!("tcp-reader-{i}"))
                    .spawn(move || svc.reader_loop(poll, rx, net, h, worker_base.saturating_add(i)))
                    .map_err(|e| format!("cannot start TCP reader thread {i}: {e}"))?,
            );
        }
        if !listeners.is_empty() {
            let poll = Poll::new().map_err(|e| format!("cannot create the TCP accept poller: {e}"))?;
            for (i, (l, proto)) in listeners.iter_mut().enumerate() {
                poll.registry().register(l, Token(i), Interest::READABLE).map_err(|e| format!("cannot register the {proto:?} listener: {e}"))?;
            }
            let svc = self.clone();
            hs.push(
                thread::Builder::new()
                    .name("tcp-main".into())
                    .spawn(move || svc.main_loop(poll, listeners))
                    .map_err(|e| format!("cannot start the TCP accept thread: {e}"))?,
            );
        }
        Ok(hs)
    }

    fn main_loop(self: Arc<Self>, mut poll: Poll, listeners: Vec<(TcpListener, Proto)>) {
        let mut events = Events::with_capacity(64);
        loop {
            // With a timeout, so a listener that hit EMFILE (and lost its edge)
            // is retried at least once a second.
            if let Err(e) = poll.poll(&mut events, Some(Duration::from_secs(1)))
                && e.kind() != ErrorKind::Interrupted
            {
                sip_core::elog!("tcp-main: poll: {e}");
            }
            for (l, proto) in &listeners {
                loop {
                    match l.accept() {
                        Ok((s, peer)) => self.accepted(s, peer, *proto),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == ErrorKind::Interrupted => {}
                        Err(e) => {
                            sip_core::elog!("tcp-main: accept: {e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    fn reader_loop(self: Arc<Self>, mut poll: Poll, rx: Receiver<Arc<Conn>>, net: Arc<dyn Outbound>, handler: Arc<dyn Handler>, worker: usize) {
        let mut conns: HashMap<ConnId, Local> = HashMap::new();
        let mut events = Events::with_capacity(1024);
        let mut scratch = Scratch::default();
        let mut dead = Vec::new();
        let mut last_sweep = Instant::now();
        let lifetime = millis(self.opts.connection_lifetime);
        let connect_timeout = millis(self.opts.connect_timeout);
        loop {
            if let Err(e) = poll.poll(&mut events, Some(Duration::from_millis(250))) {
                if e.kind() != ErrorKind::Interrupted {
                    sip_core::elog!("tcp-reader: poll: {e}");
                }
                continue;
            }
            for ev in events.iter() {
                if ev.token() == WAKER {
                    while let Ok(c) = rx.try_recv() {
                        let fd = c.stream.as_raw_fd();
                        // Edge-triggered, always interested in both directions:
                        // EPOLLOUT fires whenever a full socket drains, which is
                        // exactly when queued data (from any thread) can go out.
                        // Ids that don't fit a token (32-bit hosts) can't be polled.
                        let r = match usize::try_from(c.id) {
                            Ok(t) if Token(t) != WAKER => poll.registry().register(&mut SourceFd(&fd), Token(t), Interest::READABLE | Interest::WRITABLE),
                            _ => Err(io::Error::other("connection id out of token range")),
                        };
                        if r.is_err() {
                            self.close(&c, poll.registry(), &*handler);
                            continue;
                        }
                        let ws = c.proto.is_ws().then(WsLocal::default);
                        conns.insert(c.id, Local { conn: c, rbuf: Vec::new(), start: 0, ws });
                    }
                    continue;
                }
                let id = ev.token().0 as ConnId;
                let Some(l) = conns.get_mut(&id) else { continue };
                let mut close = ev.is_error() || l.conn.closed.load(Ordering::Acquire);
                if !close && ev.is_writable() {
                    close = matches!(l.conn.stream.take_error(), Ok(Some(_)) | Err(_)) || flush(&l.conn).is_err();
                    if !close && !l.conn.proto.is_tls() && !l.conn.proto.is_ws() {
                        l.conn.established.store(true, Ordering::Release); // TCP connect completed
                    }
                }
                if !close && (ev.is_readable() || ev.is_read_closed()) {
                    close = self.read_and_process(l, &*net, &*handler, &mut scratch, worker);
                }
                if !close
                    && l.conn.proto.is_tls()
                    && !l.conn.proto.is_ws()
                    && !l.conn.established.load(Ordering::Relaxed)
                    && let ConnIo::Tls(sess) = &*l.conn.io()
                    && !sess.is_handshaking()
                {
                    l.conn.established.store(true, Ordering::Release);
                }
                if close {
                    dead.push(id);
                }
            }
            if last_sweep.elapsed() >= Duration::from_millis(250) {
                last_sweep = Instant::now();
                let now = self.now();
                for (id, l) in conns.iter_mut() {
                    let idle = now.saturating_sub(l.conn.last_active.load(Ordering::Relaxed));
                    let never_up = !l.conn.established.load(Ordering::Acquire) && now.saturating_sub(l.conn.created) >= connect_timeout;
                    if l.conn.closed.load(Ordering::Acquire) || idle >= lifetime || never_up {
                        dead.push(*id);
                    } else if let Some(w) = l.ws.as_mut().filter(|w| w.open && !w.pinged && idle >= lifetime / 2) {
                        // Kamailio websocket keepalive_mechanism=1: ping idle
                        // clients; the pong counts as activity.
                        w.pinged = true;
                        #[allow(clippy::let_underscore_must_use, reason = "a failed write closes the connection")]
                        let _ = self.ws_control(&l.conn, op::PING, b"");
                    }
                }
            }
            for id in dead.drain(..) {
                if let Some(l) = conns.remove(&id) {
                    self.close(&l.conn, poll.registry(), &*handler);
                }
            }
        }
    }

    /// Drain the socket in capped chunks, running complete messages after each
    /// chunk. Returns true when the connection must close: EOF, a read error
    /// (bytes read before it are still processed), a framing error, a panic,
    /// or a single message that outgrows the buffer cap.
    fn read_and_process(&self, l: &mut Local, net: &dyn Outbound, handler: &dyn Handler, s: &mut Scratch, worker: usize) -> bool {
        let cap = self.opts.max_msg_size.saturating_add(64 * 1024);
        loop {
            let read = read_available(&l.conn, &mut l.rbuf, cap);
            if let Some(w) = &mut l.ws {
                w.pinged = false;
            }
            // A panic in framing, a handshake hook or the script closes this
            // connection, not the reader (which owns many others).
            let ok = sip_core::panic::catch(|| self.process(l, net, handler, s, worker)).unwrap_or_else(|_| {
                sip_core::elog!("tcp: panic while processing {}; closing it", l.conn.peer);
                false
            });
            // Only complete messages count as activity: a peer trickling one
            // never-ending message still hits tcp_connection_lifetime.
            if l.rbuf.is_empty() {
                l.conn.last_active.store(self.now(), Ordering::Relaxed);
            }
            match read {
                _ if !ok => return true,
                Ok(ReadEnd::Drained) => return false,
                Ok(ReadEnd::Eof) | Err(_) => return true,
                Ok(ReadEnd::Full) if l.rbuf.len() >= cap => {
                    sip_core::elog!("tcp: closing {}: more than {cap} bytes without a complete message", l.conn.peer);
                    return true;
                }
                Ok(ReadEnd::Full) => {}
            }
        }
    }

    /// Split the stream into messages and run them. false = close connection.
    fn process(&self, l: &mut Local, net: &dyn Outbound, handler: &dyn Handler, s: &mut Scratch, worker: usize) -> bool {
        let src = Dest { proto: l.conn.proto, addr: l.conn.peer, conn: Some(l.conn.id), no_connect: false };
        let ok = if l.ws.is_some() {
            self.process_ws(l, src, net, handler, s, worker)
        } else {
            loop {
                let unread = l.rbuf.get(l.start..).unwrap_or_default();
                match stream_frame(unread, self.opts.max_msg_size) {
                    Frame::Incomplete => break true,
                    Frame::Keepalive { len, ping } => {
                        l.start = l.start.saturating_add(len);
                        if ping && self.write(&l.conn, b"\r\n").is_err() {
                            break false;
                        }
                    }
                    Frame::Message(n) => {
                        dispatch(unread.get(..n).unwrap_or_default(), src, net, None, handler, s, worker);
                        l.start = l.start.saturating_add(n);
                    }
                    Frame::Error(e) => {
                        sip_core::elog!("tcp: closing {}: {e}", src);
                        break false;
                    }
                }
            }
        };
        if l.start == l.rbuf.len() {
            l.rbuf.clear();
            l.start = 0;
            if l.rbuf.capacity() > 64 * 1024 {
                l.rbuf.shrink_to(16 * 1024);
            }
        } else if l.start > 0 {
            l.rbuf.drain(..l.start);
            l.start = 0;
        }
        ok
    }

    /// WebSocket: opening handshake, then one SIP message per WS message.
    fn process_ws(&self, l: &mut Local, src: Dest, net: &dyn Outbound, handler: &dyn Handler, s: &mut Scratch, worker: usize) -> bool {
        let max = self.opts.max_msg_size;
        let fail = |conn: &Arc<Conn>, code: u16, why: &str| {
            sip_core::elog!("ws: closing {src}: {why}");
            #[allow(clippy::let_underscore_must_use, reason = "a failed write closes the connection")]
            let _ = self.ws_control(conn, op::CLOSE, &code.to_be_bytes());
            false
        };
        loop {
            let Some(w) = l.ws.as_mut() else { return false };
            if !w.open {
                if let Some(key) = &l.conn.ws_key {
                    match ws::client_handshake(l.rbuf.get(l.start..).unwrap_or_default(), key) {
                        ws::ClientHandshake::Incomplete => return true,
                        ws::ClientHandshake::Failed(why) => {
                            sip_core::elog!("ws: upgrade to {src} failed: {why}");
                            return false;
                        }
                        ws::ClientHandshake::Open { len } => {
                            w.open = true;
                            l.conn.established.store(true, Ordering::Release);
                            l.start = l.start.saturating_add(len);
                            let queued = {
                                let mut q = lock(&l.conn.ws_pending);
                                l.conn.ws_open.store(true, Ordering::Release);
                                std::mem::take(&mut *q)
                            };
                            for m in queued {
                                if self.write(&l.conn, &m).is_err() {
                                    return false;
                                }
                            }
                            continue;
                        }
                    }
                }
                let unread = l.rbuf.get(l.start..).unwrap_or_default();
                match ws::server_handshake(unread, &self.opts.ws) {
                    Handshake::Incomplete => return true,
                    Handshake::Reject { response } => {
                        sip_core::elog!("ws: rejecting upgrade from {src}: {}", response.lines().next().unwrap_or(""));
                        #[allow(clippy::let_underscore_must_use, reason = "a failed write closes the connection")]
                        let _ = self.write_parts(&l.conn, &[response.as_bytes()]);
                        return false;
                    }
                    Handshake::Accept { len, response, deflate } => {
                        if !handler.ws_handshake(net, unread.get(..len).unwrap_or_default(), src) {
                            sip_core::elog!("ws: upgrade from {src} refused by event_route[websocket:handshake]");
                            #[allow(clippy::let_underscore_must_use, reason = "a failed write closes the connection")]
                            let _ = self.write_parts(&l.conn, &[ws::HOOK_FORBIDDEN.as_bytes()]);
                            return false;
                        }
                        if self.write_parts(&l.conn, &[response.as_bytes()]).is_err() {
                            return false;
                        }
                        w.inflater = deflate.map(ws::Inflater::new);
                        l.conn.ws_deflate.store(deflate.is_some(), Ordering::Release);
                        l.conn.ws_open.store(true, Ordering::Release);
                        l.conn.established.store(true, Ordering::Release);
                        w.open = true;
                        l.start = l.start.saturating_add(len);
                        continue;
                    }
                }
            }
            let client = l.conn.ws_key.is_some();
            let unread = l.rbuf.get_mut(l.start..).unwrap_or_default();
            let f = match ws::parse_frame(unread, max, !client, w.inflater.is_some()) {
                Parsed::Incomplete => return true,
                Parsed::Error(code, why) => return fail(&l.conn, code, why),
                Parsed::Frame(f) => f,
            };
            let payload = f.payload(unread);
            match f.opcode {
                op::PING => {
                    if self.ws_control(&l.conn, op::PONG, payload).is_err() {
                        return false;
                    }
                }
                op::PONG => {}
                op::CLOSE => {
                    // Echo the status code, then close (RFC 6455 §5.5.1).
                    let code = payload.get(..2).unwrap_or(&ws::close::NORMAL.to_be_bytes()).to_vec();
                    #[allow(clippy::let_underscore_must_use, reason = "a failed write closes the connection")]
                    let _ = self.ws_control(&l.conn, op::CLOSE, &code);
                    return false;
                }
                op::TEXT | op::BINARY if w.frag_op != 0 => {
                    return fail(&l.conn, ws::close::PROTOCOL_ERROR, "new message inside a fragmented one")
                }
                // Unfragmented (the common case): the unmasked payload is
                // parsed straight out of the read buffer, zero-copy (unless
                // it was compressed).
                op::TEXT | op::BINARY if f.fin => {
                    match complete_message(payload, f.opcode, f.rsv1, w.inflater.as_mut(), &mut w.inflated, max) {
                        Ok(m) => dispatch(m, src, net, None, handler, s, worker),
                        Err((code, why)) => return fail(&l.conn, code, why),
                    }
                }
                op::TEXT | op::BINARY => {
                    w.frag.clear();
                    w.frag.extend_from_slice(payload);
                    w.frag_op = f.opcode;
                    w.frag_rsv1 = f.rsv1;
                }
                _ /* CONT */ => {
                    if w.frag_op == 0 {
                        return fail(&l.conn, ws::close::PROTOCOL_ERROR, "continuation without a message");
                    }
                    if w.frag.len().saturating_add(payload.len()) > max {
                        return fail(&l.conn, ws::close::TOO_BIG, "fragmented message too big");
                    }
                    w.frag.extend_from_slice(payload);
                    if f.fin {
                        match complete_message(&w.frag, w.frag_op, w.frag_rsv1, w.inflater.as_mut(), &mut w.inflated, max) {
                            Ok(m) => dispatch(m, src, net, None, handler, s, worker),
                            Err((code, why)) => return fail(&l.conn, code, why),
                        }
                        w.frag_op = 0;
                        w.frag.clear();
                    }
                }
            }
            l.start = l.start.saturating_add(f.frame_len());
        }
    }
}

/// Decompress (if RSV1) and validate one complete WebSocket message.
fn complete_message<'b>(
    data: &'b [u8],
    opcode: u8,
    compressed: bool,
    inflater: Option<&mut ws::Inflater>,
    inflated: &'b mut Vec<u8>,
    max: usize,
) -> Result<&'b [u8], (u16, &'static str)> {
    let msg: &'b [u8] = match (compressed, inflater) {
        (true, Some(inf)) => {
            inf.inflate(data, max, inflated)?;
            inflated
        }
        (true, None) => return Err((ws::close::PROTOCOL_ERROR, "compressed frame without permessage-deflate")),
        (false, _) => data,
    };
    // RFC 6455 §8.1: a TEXT message that isn't UTF-8 fails the connection.
    if opcode == op::TEXT && std::str::from_utf8(msg).is_err() {
        return Err((ws::close::INVALID_DATA, "TEXT message is not valid UTF-8"));
    }
    Ok(msg)
}

/// One inbound connection's unit of its source IP's budget
/// (`tcp_accept_iplimit`); given back on drop unless kept by `adopt`.
struct IpUnit<'a> {
    lim: &'a KeyedLimiter<IpAddr>,
    ip: IpAddr,
}

impl<'a> IpUnit<'a> {
    fn acquire(lim: &'a KeyedLimiter<IpAddr>, ip: IpAddr) -> Option<Self> {
        // `then`, not `then_some`: the guard must only exist if a unit was
        // taken (an eagerly built guard would release one on drop).
        lim.try_acquire(&ip).then(|| Self { lim, ip })
    }

    /// Now owned by the connection; `release` gives it back on close.
    fn keep(self) {
        // Skip `Drop` (which would release the unit); only borrows inside.
        let _kept = std::mem::ManuallyDrop::new(self);
    }
}

impl Drop for IpUnit<'_> {
    fn drop(&mut self) {
        self.lim.release(&self.ip);
    }
}

struct TcpStats {
    accepted: &'static std::sync::atomic::AtomicI64,
    rejected: &'static std::sync::atomic::AtomicI64,
    rejected_iplimit: &'static std::sync::atomic::AtomicI64,
}

fn tcp_stats() -> &'static TcpStats {
    static S: std::sync::OnceLock<TcpStats> = std::sync::OnceLock::new();
    S.get_or_init(|| TcpStats {
        accepted: sip_core::stats::counter("tcp", "accepted"),
        rejected: sip_core::stats::counter("tcp", "rejected"),
        rejected_iplimit: sip_core::stats::counter("tcp", "rejected_iplimit"),
    })
}

/// "max_connections reached" at most once a second (a connection flood
/// would otherwise flood the log too), with the number rejected meanwhile.
/// A duration in whole milliseconds, saturating.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn reject_log(max: usize, peer: SocketAddr, per_ip: Option<usize>) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    static SKIPPED: AtomicU64 = AtomicU64::new(0);
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let now = millis(EPOCH.get_or_init(Instant::now).elapsed()).saturating_add(1000);
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) < 1000 || LAST.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() {
        SKIPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let why = match per_ip {
        Some(n) => format!("accept_iplimit ({n} per address)"),
        None => format!("max_connections ({max})"),
    };
    match SKIPPED.swap(0, Ordering::Relaxed) {
        0 => sip_core::elog!("tcp: {why} reached, rejecting {peer}"),
        n => sip_core::elog!("tcp: {why} reached, rejecting {peer} ({n} more rejected since the last message)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_ip_unit_releases_nothing() {
        // Regression: the guard was built eagerly (`then_some`) and its Drop
        // gave back a unit on every refusal, letting one extra connection in.
        let lim = KeyedLimiter::new(1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let held = IpUnit::acquire(&lim, ip).expect("first");
        assert!(IpUnit::acquire(&lim, ip).is_none(), "at the limit");
        assert_eq!(lim.in_use(&ip), 1, "a refusal must not release the held unit");
        drop(held);
        assert_eq!(lim.in_use(&ip), 0);
    }

    #[test]
    fn connection_slots_are_reserved_atomically_and_given_back() {
        let t = TcpService::new(TcpOpts { max_connections: 2, ..TcpOpts::default() }, None).unwrap();
        let a = t.reserve().expect("first slot");
        let b = t.reserve().expect("second slot");
        assert!(t.reserve().is_none(), "limit reached");
        assert_eq!(t.active_connections(), 2);
        drop(a); // an early return before adopt() gives the slot back
        assert_eq!(t.active_connections(), 1);
        b.keep(); // adopted: stays counted until release()
        let c = t.reserve().expect("freed slot is reusable");
        assert_eq!(t.active_connections(), 2);
        drop(c);
        assert_eq!(t.active_connections(), 1);
    }

    #[test]
    fn slots_never_overshoot_under_concurrency() {
        let t = TcpService::new(TcpOpts { max_connections: 64, ..TcpOpts::default() }, None).unwrap();
        let got: usize = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        let mut n = 0;
                        for _ in 0..100 {
                            if let Some(slot) = t.reserve() {
                                slot.keep();
                                n += 1;
                            }
                        }
                        n
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(got, 64);
        assert_eq!(t.active_connections(), 64);
    }

    /// A plain TCP connection to a loopback listener, published in `t` as if
    /// accepted from `peer`.
    fn fake_conn(t: &TcpService, l: &std::net::TcpListener, proto: Proto, peer: &str) -> Arc<Conn> {
        let s = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let conn = t.new_conn(TcpStream::from_std(s), peer.parse().unwrap(), proto, ConnIo::Plain(Vec::new()), false);
        t.adopt(&conn, t.reserve().unwrap(), None);
        conn
    }

    fn to(proto: Proto, addr: &str) -> Dest {
        Dest::new(proto, addr.parse().unwrap())
    }

    #[test]
    fn aliases_route_to_their_connection_until_it_dies() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let t = TcpService::new(TcpOpts { accept_aliases: true, ..TcpOpts::default() }, None).unwrap();
        let c = fake_conn(&t, &l, Proto::Tcp, "192.0.2.1:40000");
        assert_eq!(t.conn_to(&to(Proto::Tcp, "192.0.2.1:40000")), Some(c.id), "by peer address");
        assert_eq!(t.conn_to(&to(Proto::Tcp, "192.0.2.1:5060")), None);
        t.add_alias(c.id, "192.0.2.1:5060".parse().unwrap());
        assert_eq!(t.conn_to(&to(Proto::Tcp, "192.0.2.1:5060")), Some(c.id), "by alias");
        assert_eq!(t.conn_to(&to(Proto::Tls, "192.0.2.1:5060")), None, "per transport");
        t.add_alias(c.id, "192.0.2.1:40000".parse().unwrap()); // the peer itself
        t.add_alias(c.id, "192.0.2.1:5060".parse().unwrap()); // again
        t.add_alias(9999, "192.0.2.1:6000".parse().unwrap()); // no such connection
        assert_eq!(t.conn_to(&to(Proto::Tcp, "192.0.2.1:6000")), None);
        let info = t.connections();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].aliases, ["192.0.2.1:5060".parse::<SocketAddr>().unwrap()], "no duplicates, not the peer");
        for port in 6001..6020 {
            t.add_alias(c.id, SocketAddr::new("192.0.2.1".parse().unwrap(), port));
        }
        assert_eq!(t.connections()[0].aliases.len(), 8, "at most 8 aliases per connection");
        t.kill(&c);
        for a in ["192.0.2.1:40000", "192.0.2.1:5060", "192.0.2.1:6001"] {
            assert_eq!(t.conn_to(&to(Proto::Tcp, a)), None, "{a} after the connection died");
        }
        t.add_alias(c.id, "192.0.2.1:7000".parse().unwrap());
        assert_eq!(t.conn_to(&to(Proto::Tcp, "192.0.2.1:7000")), None, "no alias for a dead connection");
    }

    #[test]
    fn aliases_are_ignored_unless_enabled() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let t = TcpService::new(TcpOpts::default(), None).unwrap();
        assert!(!t.accepts_aliases());
        let c = fake_conn(&t, &l, Proto::Tcp, "192.0.2.1:40000");
        t.add_alias(c.id, "192.0.2.1:5060".parse().unwrap());
        assert_eq!(t.conn_to(&to(Proto::Tcp, "192.0.2.1:5060")), None);
        assert!(t.connections()[0].aliases.is_empty());
    }

    #[test]
    fn lookup_by_connection_id_and_address() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let t = TcpService::new(TcpOpts { accept_aliases: true, ..TcpOpts::default() }, None).unwrap();
        let old = fake_conn(&t, &l, Proto::Tcp, "192.0.2.1:40000");
        let new = fake_conn(&t, &l, Proto::Tcp, "192.0.2.1:40000");
        let tls = fake_conn(&t, &l, Proto::Tls, "192.0.2.2:5061");
        assert!(old.id < new.id && new.id < tls.id, "ids increase");
        let mut d = to(Proto::Tcp, "192.0.2.1:40000");
        assert_eq!(t.conn_to(&d), Some(new.id), "the newest connection to an address wins");
        d.conn = Some(old.id);
        assert_eq!(t.conn_to(&d), Some(old.id), "an explicit connection id wins");
        d.conn = Some(tls.id);
        assert_eq!(t.conn_to(&d), Some(new.id), "an id of another transport falls back to the address");
        t.kill(&old);
        assert_eq!(t.conn_to(&to(Proto::Tcp, "192.0.2.1:40000")), Some(new.id), "killing the old one keeps the newer mapping");
        d.conn = Some(old.id);
        assert_eq!(t.conn_to(&d), Some(new.id), "a dead id falls back to the address");
        assert_eq!(t.conn_to(&to(Proto::Udp, "192.0.2.1:40000")), None);
        let ids: Vec<ConnId> = t.connections().iter().map(|c| c.id).collect();
        assert_eq!(ids, [new.id, tls.id], "sorted by id, dead ones gone");
    }

    #[test]
    fn complete_message_checks() {
        let mut inflated = Vec::new();
        assert_eq!(complete_message(b"OPTIONS", op::TEXT, false, None, &mut inflated, 100), Ok(&b"OPTIONS"[..]));
        assert_eq!(complete_message(&[0xff, 0xfe], op::BINARY, false, None, &mut inflated, 100), Ok(&[0xff, 0xfe][..]), "binary need not be UTF-8");
        assert_eq!(
            complete_message(&[0xff, 0xfe], op::TEXT, false, None, &mut inflated, 100),
            Err((ws::close::INVALID_DATA, "TEXT message is not valid UTF-8"))
        );
        assert_eq!(complete_message(b"x", op::TEXT, true, None, &mut inflated, 100).unwrap_err().0, ws::close::PROTOCOL_ERROR, "RSV1 without deflate");
        let mut inf = ws::Inflater::new(ws::Deflate { client_no_context_takeover: false });
        let z = ws::with_deflated("héllo".as_bytes(), <[u8]>::to_vec).unwrap();
        let mut inflated = Vec::new();
        assert_eq!(complete_message(&z, op::TEXT, true, Some(&mut inf), &mut inflated, 100), Ok("héllo".as_bytes()));
        let mut inflated = Vec::new();
        assert_eq!(
            complete_message(b"plain", op::TEXT, false, Some(&mut inf), &mut inflated, 100),
            Ok(&b"plain"[..]),
            "uncompressed frames on a deflate connection"
        );
        let z = ws::with_deflated(&[0xff; 10], <[u8]>::to_vec).unwrap();
        let mut inflated = Vec::new();
        assert_eq!(complete_message(&z, op::TEXT, true, Some(&mut inf), &mut inflated, 100).unwrap_err().0, ws::close::INVALID_DATA, "checked after inflating");
    }
}

/// The read, framing and WebSocket paths, driven synchronously on loopback
/// connections (no reader thread) unless a test says otherwise.
#[cfg(test)]
mod io_tests {
    use super::*;
    use sip_core::Ctx;

    struct NullNet;

    impl Outbound for NullNet {
        fn send(&self, _: &Dest, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    /// Records messages and close events; can refuse or panic on the
    /// WebSocket handshake hook and panic on close events.
    #[derive(Default)]
    struct Rec {
        msgs: Mutex<Vec<String>>,
        closed: Mutex<Option<Sender<TransportEvent>>>,
        panic_in_ws_hook: bool,
        panic_on_close: bool,
    }

    impl Handler for Rec {
        fn handle(&self, ctx: &mut Ctx<'_, '_>) {
            lock(&self.msgs).push(String::from_utf8_lossy(ctx.msg.buf).into_owned());
        }
        fn transport_event(&self, ev: &TransportEvent) {
            assert!(!self.panic_on_close, "module bug");
            if let Some(tx) = &*lock(&self.closed) {
                tx.send(*ev).unwrap();
            }
        }
        fn ws_handshake(&self, _: &dyn Outbound, _: &[u8], _: Dest) -> bool {
            assert!(!self.panic_in_ws_hook, "hook bug");
            true
        }
    }

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n\r\n";
    const OPTIONS: &str = "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/WS 127.0.0.1;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:a@b>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";

    /// A connection published in `t` (ours: the accepted end, non-blocking)
    /// and the peer's end (blocking, 5 s read timeout).
    fn pair(t: &TcpService, proto: Proto, io: ConnIo, outbound: bool, ws_key: Option<&str>) -> (Local, std::net::TcpStream) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (ours, from) = l.accept().unwrap();
        ours.set_nonblocking(true).unwrap();
        let mut conn = t.new_conn(TcpStream::from_std(ours), from, proto, io, outbound);
        Arc::get_mut(&mut conn).unwrap().ws_key = ws_key.map(str::to_string);
        t.adopt(&conn, t.reserve().unwrap(), None);
        let ws = proto.is_ws().then(WsLocal::default);
        (Local { conn, rbuf: Vec::new(), start: 0, ws }, peer)
    }

    fn plain(t: &TcpService, proto: Proto) -> (Local, std::net::TcpStream) {
        pair(t, proto, ConnIo::Plain(Vec::new()), false, None)
    }

    /// Append `bytes` as if read from the socket and process them; false = close.
    fn feed(t: &TcpService, l: &mut Local, h: &Rec, bytes: &[u8]) -> bool {
        l.rbuf.extend_from_slice(bytes);
        t.process(l, &NullNet, h, &mut Scratch::default(), 0)
    }

    fn read_n(peer: &mut std::net::TcpStream, n: usize) -> Vec<u8> {
        let mut b = vec![0; n];
        peer.read_exact(&mut b).unwrap();
        b
    }

    /// An HTTP head, up to and including the blank line.
    fn read_head(peer: &mut std::net::TcpStream) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.extend(read_n(peer, 1));
        }
        String::from_utf8(head).unwrap()
    }

    /// Block until our end of the connection has something to read.
    fn wait_readable(s: &TcpStream) {
        let mut poll = Poll::new().unwrap();
        let fd = s.as_raw_fd();
        poll.registry().register(&mut SourceFd(&fd), Token(0), Interest::READABLE).unwrap();
        let mut events = Events::with_capacity(4);
        poll.poll(&mut events, Some(Duration::from_secs(5))).unwrap();
        assert!(!events.is_empty(), "nothing to read within 5 s");
        poll.registry().deregister(&mut SourceFd(&fd)).unwrap();
    }

    fn masked(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        ws::encode(fin, opcode, payload, Some([1, 2, 3, 4]), &mut f);
        f
    }

    /// An inbound WebSocket connection past its upgrade.
    fn ws_open(t: &TcpService, h: &Rec) -> (Local, std::net::TcpStream) {
        let (mut l, mut peer) = plain(t, Proto::Ws);
        assert!(feed(t, &mut l, h, UPGRADE.as_bytes()));
        assert!(read_head(&mut peer).starts_with("HTTP/1.1 101 "));
        (l, peer)
    }

    #[test]
    fn websocket_fragmentation_errors_close_with_a_status_code() {
        let t = TcpService::new(TcpOpts { max_msg_size: 200, ..TcpOpts::default() }, None).unwrap();
        let h = Rec::default();
        let cases: &[(&str, Vec<Vec<u8>>, u16)] = &[
            ("continuation without a message", vec![masked(true, op::CONT, b"x")], ws::close::PROTOCOL_ERROR),
            ("a new message inside a fragmented one", vec![masked(false, op::TEXT, b"a"), masked(true, op::TEXT, b"b")], ws::close::PROTOCOL_ERROR),
            ("fragments adding up past max_msg_size", vec![masked(false, op::TEXT, &[b'a'; 150]), masked(true, op::CONT, &[b'a'; 51])], ws::close::TOO_BIG),
            ("a reassembled TEXT message that isn't UTF-8", vec![masked(false, op::TEXT, &[0xc3]), masked(true, op::CONT, &[0x28])], ws::close::INVALID_DATA),
        ];
        for (what, frames, code) in cases {
            let (mut l, mut peer) = ws_open(&t, &h);
            let (last, first) = frames.split_last().unwrap();
            for f in first {
                assert!(feed(&t, &mut l, &h, f), "{what}: the first frames are fine");
            }
            assert!(!feed(&t, &mut l, &h, last), "{what}: closes");
            let [a, b] = code.to_be_bytes();
            assert_eq!(read_n(&mut peer, 4), [0x88, 2, a, b], "{what}: a CLOSE frame with the status code");
        }
        assert!(lock(&h.msgs).is_empty());
        // The same fragments within the limits make one message.
        let (mut l, _peer) = ws_open(&t, &h);
        let (a, b) = OPTIONS.as_bytes().split_at(10);
        assert!(feed(&t, &mut l, &h, &[masked(false, op::TEXT, a), masked(false, op::CONT, &b[..5]), masked(true, op::CONT, &b[5..])].concat()));
        assert_eq!(*lock(&h.msgs), [OPTIONS]);
    }

    #[test]
    fn writes_to_a_dead_or_unready_websocket_fail() {
        let t = TcpService::new(TcpOpts::default(), None).unwrap();
        let h = Rec::default();
        let (l, _peer) = plain(&t, Proto::Ws);
        assert_eq!(t.write(&l.conn, b"OPTIONS").unwrap_err().kind(), ErrorKind::NotConnected, "inbound, before the upgrade");
        // The 101 can't be sent: the upgrade fails.
        let (mut l, _peer) = plain(&t, Proto::Ws);
        t.kill(&l.conn);
        assert!(!feed(&t, &mut l, &h, UPGRADE.as_bytes()));
        // A PING whose PONG can't be sent closes the connection.
        let (mut l, _peer) = ws_open(&t, &h);
        t.kill(&l.conn);
        assert!(!feed(&t, &mut l, &h, &masked(true, op::PING, b"p")));
        assert_eq!(t.write(&l.conn, b"x").unwrap_err().kind(), ErrorKind::NotConnected, "a dead connection takes no writes");
    }

    #[test]
    fn a_panicking_handshake_hook_closes_only_that_connection() {
        let t = TcpService::new(TcpOpts::default(), None).unwrap();
        let h = Rec { panic_in_ws_hook: true, ..Rec::default() };
        let (mut l, mut peer) = plain(&t, Proto::Ws);
        peer.write_all(UPGRADE.as_bytes()).unwrap();
        wait_readable(&l.conn.stream);
        assert!(t.read_and_process(&mut l, &NullNet, &h, &mut Scratch::default(), 0), "close");
        assert!(!l.conn.ws_open.load(Ordering::Acquire));
    }

    fn switching_protocols() -> String {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: sip\r\n\r\n",
            ws::accept_key(KEY)
        )
    }

    #[test]
    fn outbound_websocket_queues_until_the_101() {
        let t = TcpService::new(TcpOpts { conn_wq_max: 64, ..TcpOpts::default() }, None).unwrap();
        let h = Rec::default();
        let client = |t: &TcpService| pair(t, Proto::Ws, ConnIo::Plain(Vec::new()), true, Some(KEY));
        let (mut l, mut peer) = client(&t);
        t.write(&l.conn, b"OPTIONS").unwrap();
        assert!(t.write(&l.conn, &[b'x'; 58]).is_err(), "the queue is bounded by tcp_conn_wq_max");
        assert!(feed(&t, &mut l, &h, switching_protocols().as_bytes()));
        assert!(l.conn.established.load(Ordering::Acquire));
        let mut f = read_n(&mut peer, 13);
        let Parsed::Frame(hdr) = ws::parse_frame(&mut f, 100, true, false) else { panic!("not a masked frame: {f:?}") };
        assert_eq!(hdr.payload(&f), b"OPTIONS", "the queued message goes out masked");
        // A server that refuses the upgrade.
        let (mut l, _peer) = client(&t);
        assert!(!feed(&t, &mut l, &h, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"));
        // The queued messages can't be sent after the 101.
        let (mut l, _peer) = client(&t);
        t.write(&l.conn, b"OPTIONS").unwrap();
        t.kill(&l.conn);
        assert!(!feed(&t, &mut l, &h, switching_protocols().as_bytes()));
    }

    #[test]
    fn crlf_ping_gets_a_pong_unless_the_connection_is_dead() {
        let t = TcpService::new(TcpOpts::default(), None).unwrap();
        let h = Rec::default();
        let (mut l, mut peer) = plain(&t, Proto::Tcp);
        assert!(feed(&t, &mut l, &h, b"\r\n\r\n"));
        assert_eq!(read_n(&mut peer, 2), b"\r\n");
        t.kill(&l.conn);
        assert!(!feed(&t, &mut l, &h, b"\r\n\r\n"));
    }

    #[test]
    fn a_reset_connection_is_a_read_error() {
        let t = TcpService::new(TcpOpts::default(), None).unwrap();
        let (l, peer) = plain(&t, Proto::Tcp);
        socket2::SockRef::from(&peer).set_linger(Some(Duration::ZERO)).unwrap();
        drop(peer); // RST
        wait_readable(&l.conn.stream);
        assert_eq!(read_available(&l.conn, &mut Vec::new(), 1024).err().map(|e| e.kind()), Some(ErrorKind::ConnectionReset));
    }

    #[test]
    fn tls_reads_stop_at_the_cap_and_connections_show_version_and_sni() {
        use crate::tls::test_pki::{handshake, pki};
        let cfg = crate::tls::load(&pki(), true).unwrap();
        let t = TcpService::new(TcpOpts::default(), Some(cfg.clone())).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let mut cli: Connection = ClientConnection::new(cfg.client.clone().unwrap(), name.clone()).unwrap().into();
        let mut srv: Connection = ServerConnection::new(cfg.server.clone().unwrap()).unwrap().into();
        handshake(&mut cli, &mut srv).unwrap();
        let (l, mut peer) = pair(&t, Proto::Tls, ConnIo::Tls(Box::new(srv)), false, None);
        let dialled: Connection = ClientConnection::new(cfg.client.clone().unwrap(), name).unwrap().into();
        let (_out, _peer2) = pair(&t, Proto::Tls, ConnIo::Tls(Box::new(dialled)), true, None);
        let info = t.connections();
        assert_eq!((info[0].tls_version.as_deref(), info[0].sni.as_deref()), (Some("TLSv1_3"), Some("localhost")));
        assert_eq!((info[1].tls_version.as_deref(), info[1].sni.as_deref(), info[1].outbound), (None, None, true), "no SNI on our own client side");

        cli.writer().write_all(&[b'a'; 100]).unwrap();
        while cli.wants_write() {
            cli.write_tls(&mut peer).unwrap();
        }
        wait_readable(&l.conn.stream);
        let mut rbuf = Vec::new();
        assert!(read_available(&l.conn, &mut rbuf, 1).unwrap() == ReadEnd::Full, "stops at the cap");
        assert_eq!(rbuf, [b'a'; 100], "a whole record is decrypted");
        assert!(read_available(&l.conn, &mut rbuf, 1024).unwrap() == ReadEnd::Drained);

        socket2::SockRef::from(&peer).set_linger(Some(Duration::ZERO)).unwrap();
        drop(peer); // RST
        wait_readable(&l.conn.stream);
        assert_eq!(read_available(&l.conn, &mut rbuf, 1024).err().map(|e| e.kind()), Some(ErrorKind::ConnectionReset));
    }

    #[test]
    fn adopting_with_its_reader_gone_gives_everything_back() {
        let t = TcpService::new(TcpOpts { readers: 1, ..TcpOpts::default() }, None).unwrap();
        drop(std::mem::take(&mut *lock(&t.pending))); // the reader's receiving end
        let (l, _peer) = plain(&t, Proto::Tcp);
        assert!(l.conn.closed.load(Ordering::Acquire));
        assert_eq!(t.active_connections(), 0, "slot given back");
        assert!(t.connections().is_empty(), "not published");
        assert_eq!(t.readers[0].load.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_panicking_close_handler_still_releases_the_connection() {
        let t = TcpService::new(TcpOpts::default(), None).unwrap();
        let (l, _peer) = plain(&t, Proto::Tcp);
        assert_eq!(t.active_connections(), 1);
        let poll = Poll::new().unwrap();
        t.close(&l.conn, poll.registry(), &Rec { panic_on_close: true, ..Rec::default() });
        assert_eq!(t.active_connections(), 0);
        assert!(t.connections().is_empty());
    }

    #[test]
    fn connect_refusals() {
        let t = TcpService::new(TcpOpts::default(), None).unwrap();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(t.connect(Proto::Udp, addr).err().map(|e| e.to_string()).as_deref(), Some("not a stream protocol"));
        assert_eq!(t.connect(Proto::Tls, addr).err().map(|e| e.to_string()).as_deref(), Some("outbound TLS needs --tls-ca"));
        assert_eq!(t.active_connections(), 0, "refused connects keep no slot");
        let full = TcpService::new(TcpOpts { max_connections: 0, ..TcpOpts::default() }, None).unwrap();
        assert_eq!(full.connect(Proto::Tcp, addr).err().map(|e| e.to_string()).as_deref(), Some("tcp_max_connections reached"));
    }

    #[test]
    fn the_reader_closes_unpollable_and_finished_connections() {
        let t = TcpService::new(TcpOpts { readers: 1, ..TcpOpts::default() }, None).unwrap();
        let (tx, rx) = mpsc::channel();
        let h = Arc::new(Rec { closed: Mutex::new(Some(tx)), ..Rec::default() });
        // The reader thread runs until the test binary exits.
        t.start(Vec::new(), Arc::new(NullNet), h, 0).unwrap();
        let closed = |id: ConnId| match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            TransportEvent::Closed { conn, established, .. } => {
                assert_eq!(conn.conn, Some(id));
                established
            }
        };
        // An id that collides with the waker's token can't be registered.
        t.next_id.store(u64::try_from(usize::MAX).unwrap(), Ordering::Relaxed);
        let (l, _peer) = plain(&t, Proto::Tcp);
        assert!(closed(l.conn.id), "an inbound TCP connection is established from the start");
        // A peer that hangs up.
        let (l, peer) = plain(&t, Proto::Tcp);
        assert_eq!(l.conn.id, 0, "ids wrap");
        drop(peer);
        closed(l.conn.id);
        assert_eq!(t.active_connections(), 0);
    }
}
