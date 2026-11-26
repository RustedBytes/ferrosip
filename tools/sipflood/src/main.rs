//! sipflood — load generator + dummy UAS for benchmarking ferrosip over
//! UDP, TCP and TLS.
//!
//!   sipflood uas   udp:127.0.0.1:5070                     # answers 200 to everything
//!   sipflood uas   tls:127.0.0.1:5072 --cert c.pem --key k.pem
//!   sipflood bench tcp:127.0.0.1:5060 200000 [window] [METHOD] [ruri-user] [--ca ca.pem]
//!   sipflood bench ws:127.0.0.1:8080  200000 …          # SIP over WebSocket client
#![allow(clippy::unwrap_used, reason = "a command-line tool: a failed unwrap ends it with a message, which is what it should do")]

use bumpalo::Bump;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use sip_core::reply::build_reply;
use sip_core::{Dest, Proto};
use sip_parser::{Frame, HdrFlags, Method, Msg, stream_frame};
use sip_transport::TlsFiles;
use sip_transport::tls::{self, TlsConfig};
use sip_transport::ws;
use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};
use std::{env, process, thread};

const MAX: usize = 1 << 20;

/// Ends the run with a message (a CLI tool has nothing better to do).
fn die(what: impl std::fmt::Display, e: impl std::fmt::Display) -> ! {
    eprintln!("sipflood: {what}: {e}");
    process::exit(1)
}

/// Builds the 200 OK for one request (nothing for ACK / replies).
fn answer(pkt: &[u8], arena: &mut Bump, out: &mut Vec<u8>) {
    arena.reset();
    let Ok(mut m) = Msg::parse(pkt, arena) else { return };
    if m.is_request() && m.method() != Some(Method::Ack) {
        let _ = build_reply(&mut m, 200, "OK", out);
    }
}

fn serve_stream(mut s: impl Read + Write) {
    let (mut rbuf, mut tmp, mut out, mut arena) = (Vec::new(), vec![0u8; 65536], Vec::new(), Bump::new());
    loop {
        loop {
            match stream_frame(&rbuf, MAX) {
                Frame::Message(n) => {
                    answer(rbuf.get(..n).unwrap_or_default(), &mut arena, &mut out);
                    rbuf.drain(..n);
                }
                Frame::Keepalive { len, ping } => {
                    if ping {
                        out.extend_from_slice(b"\r\n");
                    }
                    rbuf.drain(..len);
                }
                Frame::Incomplete => break,
                Frame::Error(_) => return,
            }
        }
        // One write per read: replies to pipelined requests are batched.
        if !out.is_empty() {
            if s.write_all(&out).and_then(|_| s.flush()).is_err() {
                return;
            }
            out.clear();
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => rbuf.extend_from_slice(tmp.get(..n).unwrap_or_default()),
        }
    }
}

fn uas(at: Dest, tls: Option<TlsConfig>) {
    eprintln!("uas on {at}");
    if at.proto == Proto::Udp {
        let sock = UdpSocket::bind(at.addr).unwrap_or_else(|e| die(format_args!("bind {}", at.addr), e));
        let _ = socket2::SockRef::from(&sock).set_recv_buffer_size(8 << 20);
        let (mut buf, mut out, mut arena) = (vec![0u8; 65535], Vec::new(), Bump::new());
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf) else { continue };
            out.clear();
            answer(buf.get(..n).unwrap_or_default(), &mut arena, &mut out);
            if !out.is_empty() {
                let _ = sock.send_to(&out, src);
            }
        }
    }
    let server = tls.and_then(|t| t.server);
    if at.proto == Proto::Tls && server.is_none() {
        eprintln!("tls uas needs --cert and --key");
        process::exit(2);
    }
    for s in TcpListener::bind(at.addr).unwrap_or_else(|e| die(format_args!("bind {}", at.addr), e)).incoming().flatten() {
        let _ = s.set_nodelay(true);
        let server = server.clone();
        thread::spawn(move || match (at.proto, server) {
            (Proto::Tls, Some(cfg)) => serve_stream(StreamOwned::new(ServerConnection::new(cfg).unwrap(), s)),
            _ => serve_stream(s),
        });
    }
}

trait Rw: Read + Write {}
impl<T: Read + Write> Rw for T {}

enum Client {
    Udp(UdpSocket, SocketAddr),
    /// `ws`: Some(mask PRNG state) when SIP is carried in WebSocket frames.
    Stream {
        s: Box<dyn Rw>,
        rbuf: Vec<u8>,
        wbuf: Vec<u8>,
        ws: Option<u32>,
        inflater: Option<ws::Inflater>,
    },
}

/// `--ws-deflate`: offer permessage-deflate (both sides without context takeover).
static WS_DEFLATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Client side of the WebSocket opening handshake (blocking).
/// Returns whether permessage-deflate was accepted.
fn ws_handshake(s: &mut dyn Rw, host: SocketAddr, rbuf: &mut Vec<u8>) -> io::Result<bool> {
    let key = ws::base64(&std::process::id().to_be_bytes().repeat(4));
    let ext =
        if WS_DEFLATE.load(std::sync::atomic::Ordering::Relaxed) { "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover\r\n" } else { "" };
    write!(
        s,
        "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n{ext}\r\n"
    )?;
    s.flush()?;
    let end = loop {
        if let Some(i) = rbuf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i.saturating_add(4); // the head with its blank line
        }
        let mut tmp = [0u8; 4096];
        match s.read(&mut tmp)? {
            0 => return Err(ErrorKind::UnexpectedEof.into()),
            n => rbuf.extend_from_slice(tmp.get(..n).unwrap_or_default()),
        }
    };
    let head = String::from_utf8_lossy(rbuf.get(..end).unwrap_or_default()).to_string();
    rbuf.drain(..end);
    if !head.starts_with("HTTP/1.1 101") || !head.contains(&ws::accept_key(&key)) {
        return Err(io::Error::other(format!("upgrade refused: {}", head.lines().next().unwrap_or(""))));
    }
    Ok(head.contains("permessage-deflate"))
}

impl Client {
    fn connect(dst: &Dest, tls: Option<TlsConfig>) -> io::Result<(Self, SocketAddr)> {
        let timeout = Some(Duration::from_millis(200));
        if dst.proto == Proto::Udp {
            let sock = UdpSocket::bind("127.0.0.1:0")?;
            let _ = socket2::SockRef::from(&sock).set_recv_buffer_size(8 << 20);
            sock.set_read_timeout(timeout)?;
            let me = sock.local_addr()?;
            return Ok((Client::Udp(sock, dst.addr), me));
        }
        let mut tcp = TcpStream::connect(dst.addr)?;
        tcp.set_nodelay(true)?;
        let me = tcp.local_addr()?;
        let handle = tcp.try_clone()?; // to set the read timeout after the handshakes
        let mut s: Box<dyn Rw> = if dst.proto.is_tls() {
            let cfg = tls.and_then(|t| t.client).ok_or_else(|| io::Error::other("tls bench needs --ca"))?;
            let mut c = ClientConnection::new(cfg, ServerName::from(dst.addr.ip())).map_err(io::Error::other)?;
            while c.is_handshaking() {
                c.complete_io(&mut tcp)?; // blocking handshake before the read timeout is set
            }
            Box::new(StreamOwned::new(c, tcp))
        } else {
            Box::new(tcp)
        };
        let mut rbuf = Vec::new();
        let (mut ws, mut inflater) = (None, None);
        if dst.proto.is_ws() {
            if ws_handshake(&mut *s, dst.addr, &mut rbuf)? {
                // Server always resets per message; so do we (offered above).
                inflater = Some(ws::Inflater::new(ws::Deflate { client_no_context_takeover: true }));
            }
            ws = Some(0x9e37_79b9 ^ process::id());
        }
        handle.set_read_timeout(timeout)?;
        Ok((Client::Stream { s, rbuf, wbuf: Vec::new(), ws, inflater }, me))
    }

    fn queue(&mut self, m: &[u8]) -> io::Result<()> {
        match self {
            Client::Udp(s, dst) => s.send_to(m, *dst).map(|_| ()),
            Client::Stream { wbuf, ws: Some(st), inflater, .. } => {
                // Clients must mask every frame (RFC 6455 §5.3).
                *st ^= *st << 13;
                *st ^= *st >> 17;
                *st ^= *st << 5;
                let deflated = inflater.is_some()
                    && ws::with_deflated(m, |z| {
                        let at = wbuf.len();
                        ws::encode(true, ws::op::TEXT, z, Some(st.to_ne_bytes()), wbuf);
                        if let Some(b0) = wbuf.get_mut(at) {
                            *b0 |= 0x40; // RSV1
                        }
                    })
                    .is_some();
                if !deflated {
                    ws::encode(true, ws::op::TEXT, m, Some(st.to_ne_bytes()), wbuf);
                }
                Ok(())
            }
            Client::Stream { wbuf, .. } => {
                wbuf.extend_from_slice(m);
                Ok(())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Client::Udp(..) => Ok(()),
            Client::Stream { s, wbuf, .. } => {
                s.write_all(wbuf)?;
                wbuf.clear();
                s.flush()
            }
        }
    }

    /// One message into `out`; Ok(false) on read timeout.
    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        out.clear();
        match self {
            Client::Udp(s, _) => {
                out.resize(65535, 0);
                match s.recv_from(out) {
                    Ok((n, _)) => {
                        out.truncate(n);
                        Ok(true)
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(false),
                    Err(e) => Err(e),
                }
            }
            Client::Stream { s, rbuf, ws, inflater, .. } => loop {
                let frame = if ws.is_some() {
                    match ws::parse_frame(rbuf, MAX, false, inflater.is_some()) {
                        ws::Parsed::Frame(f) => {
                            let data = f.fin && matches!(f.opcode, ws::op::TEXT | ws::op::BINARY);
                            let payload = f.payload(rbuf);
                            match inflater.as_mut().filter(|_| data && f.rsv1) {
                                Some(inf) => inf.inflate(payload, MAX, out).map_err(|(_, e)| io::Error::other(e))?,
                                None if data => out.extend_from_slice(payload),
                                None => {}
                            }
                            rbuf.drain(..f.frame_len());
                            if data {
                                return Ok(true);
                            }
                            continue; // pings/pongs: ignored by the bench client
                        }
                        ws::Parsed::Error(_, e) => Frame::Error(e),
                        ws::Parsed::Incomplete => Frame::Incomplete,
                    }
                } else {
                    stream_frame(rbuf, MAX)
                };
                match frame {
                    Frame::Message(n) => {
                        out.extend_from_slice(rbuf.get(..n).unwrap_or_default());
                        rbuf.drain(..n);
                        return Ok(true);
                    }
                    Frame::Keepalive { len, .. } => {
                        rbuf.drain(..len);
                    }
                    Frame::Error(e) => return Err(io::Error::other(e)),
                    Frame::Incomplete => {
                        let mut tmp = [0u8; 65536];
                        match s.read(&mut tmp) {
                            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                            Ok(n) => rbuf.extend_from_slice(tmp.get(..n).unwrap_or_default()),
                            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(false),
                            Err(e) => return Err(e),
                        }
                    }
                }
            },
        }
    }
}

fn bench(target: Dest, total: u64, window: u64, method: &str, user: &str, tls: Option<TlsConfig>) {
    let (mut client, me) = Client::connect(&target, tls).unwrap_or_else(|e| {
        eprintln!("connect {target}: {e}");
        process::exit(1)
    });
    let via = target.proto.via_name();
    // Unique per run: branches must never repeat (RFC 3261 §8.1.1.7), or the
    // proxy rightly treats them as retransmissions of still-live transactions.
    let run = format!("{:x}{:x}", process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros());
    let prefix = format!("z9hG4bK{run}.");
    let (mut buf, mut req, mut arena) = (Vec::with_capacity(65535), Vec::with_capacity(512), Bump::new());
    let mut inflight: HashMap<u64, Instant> = HashMap::new();
    let mut lat = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
    let (mut sent, mut ok, mut other, mut lost) = (0u64, 0u64, 0u64, 0u64);
    let t0 = Instant::now();
    while ok.saturating_add(other).saturating_add(lost) < total {
        let refill = sent < total && (inflight.len() as u64) < window;
        while sent < total && (inflight.len() as u64) < window {
            req.clear();
            // REGISTER: one AoR + Contact per request ({user}{n}), so the
            // registrar's location table grows to `total` bindings.
            let (to_user, reg) = if method == "REGISTER" {
                (format!("{user}{sent}"), format!("Contact: <sip:{user}{sent}@{me}>\r\nExpires: 3600\r\n"))
            } else {
                (user.to_string(), String::new())
            };
            let _ = write!(
                req,
                "{method} sip:{to_user}@{} SIP/2.0\r\n\
                 Via: SIP/2.0/{via} {me};branch={prefix}{sent}\r\n\
                 Max-Forwards: 70\r\n\
                 From: <sip:flood@{me}>;tag=f{sent}\r\n\
                 To: <sip:{to_user}@{}>\r\n\
                 Call-ID: {run}-{sent}@{me}\r\n\
                 CSeq: 1 {method}\r\n\
                 User-Agent: sipflood\r\n\
                 {reg}Content-Length: 0\r\n\r\n",
                target.addr, target.addr
            );
            client.queue(&req).unwrap_or_else(|e| die("send", e));
            inflight.insert(sent, Instant::now());
            sent = sent.saturating_add(1);
        }
        if refill {
            client.flush().unwrap_or_else(|e| die("flush", e));
        }
        match client.recv(&mut buf) {
            Ok(true) => {
                arena.reset();
                let Ok(mut m) = Msg::parse(&buf, &arena) else { continue };
                let Some(code) = m.status() else { continue };
                if code < 200 || m.parse_headers(HdrFlags::VIA).is_err() {
                    continue;
                }
                let id = m.via1.and_then(|v| v.branch).and_then(|b| b.strip_prefix(prefix.as_bytes()));
                let id = id.and_then(|b| std::str::from_utf8(b).ok()?.parse::<u64>().ok());
                if let Some(t) = id.and_then(|id| inflight.remove(&id)) {
                    lat.push(t.elapsed());
                    let counter = if code == 200 { &mut ok } else { &mut other };
                    *counter = counter.saturating_add(1);
                }
            }
            Ok(false) => {
                // Anything outstanding for >2s counts as lost.
                let now = Instant::now();
                let before = inflight.len();
                inflight.retain(|_, t| now.saturating_duration_since(*t) < Duration::from_secs(2));
                lost = lost.saturating_add(before.saturating_sub(inflight.len()) as u64);
            }
            Err(e) => {
                eprintln!("connection error: {e}");
                lost = lost.saturating_add(inflight.len() as u64).saturating_add(total.saturating_sub(sent));
                break;
            }
        }
    }
    let el = t0.elapsed();
    lat.sort();
    let p = |permille: usize| lat.get((lat.len().saturating_mul(permille) / 1000).min(lat.len().saturating_sub(1))).copied().unwrap_or_default();
    println!(
        "{total} {method} over {via} in {:.2}s → {:.0} req/s | 200: {ok}, other: {other}, lost: {lost} | p50 {:?} p99 {:?}",
        el.as_secs_f64(),
        total as f64 / el.as_secs_f64(),
        p(500),
        p(990)
    );
}

fn main() {
    // Options (anywhere) out, positional arguments in `a`.
    let mut a: Vec<String> = Vec::new();
    let mut files = TlsFiles::default();
    let mut args = env::args();
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--cert" => &mut files.cert,
            "--key" => &mut files.key,
            "--ca" => &mut files.ca,
            "--ws-deflate" => {
                WS_DEFLATE.store(true, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
            _ => {
                a.push(arg);
                continue;
            }
        };
        *slot = args.next().map(Into::into);
    }
    let tls = (files.cert.is_some() || files.ca.is_some()).then(|| tls::load(&files, false).unwrap_or_else(|e| die("tls", e)));
    let dest = |s: Option<&String>, d: &str| Dest::parse(s.map_or(d, |s| s)).unwrap_or_else(|e| die("destination", e));
    match a.get(1).map(String::as_str) {
        Some("uas") => uas(dest(a.get(2), "udp:127.0.0.1:5070"), tls),
        Some("bench") => {
            let total = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(100_000);
            let window = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(200);
            let method = a.get(5).map_or("OPTIONS", |s| s);
            let user = a.get(6).map_or("bench", |s| s);
            bench(dest(a.get(2), "udp:127.0.0.1:5060"), total, window, method, user, tls)
        }
        _ => {
            eprintln!(
                "usage: sipflood uas <proto:ip:port> [--cert C --key K]\n       \
                 sipflood bench <proto:ip:port> [total] [window] [METHOD] [ruri-user] [--ca CA]"
            );
            process::exit(2);
        }
    }
}
