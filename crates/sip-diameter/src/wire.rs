//! The byte streams Diameter runs over: TCP, TLS over TCP (RFC 6733 §13,
//! TLS from the first byte as on port 5658, via rustls) and SCTP (a
//! one-to-one `SOCK_STREAM` socket, which reads and writes like TCP).
//!
//! A connection is split into a reader (owned by the peer's reader
//! thread) and a writer (shared, behind a lock). For TLS both halves share
//! the rustls state: the reader waits for ciphertext without holding the
//! lock, then feeds it in; every socket write happens under the lock.

use sip_core::sync::lock;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The transport of a peer or an acceptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Proto {
    #[default]
    Tcp,
    Tls,
    Sctp,
}

impl Proto {
    pub fn parse(s: &str) -> Result<Proto, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "tcp" => Ok(Proto::Tcp),
            "tls" => Ok(Proto::Tls),
            "sctp" => Ok(Proto::Sctp),
            o => Err(format!("unknown Diameter transport {o:?} (tcp, tls or sctp)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Tls => "tls",
            Proto::Sctp => "sctp",
        }
    }

    /// RFC 6733 §11.2: 3868 for TCP and SCTP, 5658 for TLS/TCP.
    pub fn default_port(self) -> u16 {
        if self == Proto::Tls { 5658 } else { 3868 }
    }
}

/// IPPROTO_SCTP.
const IPPROTO_SCTP: i32 = 132;

fn sctp_socket(addr: &SocketAddr) -> io::Result<socket2::Socket> {
    socket2::Socket::new(socket2::Domain::for_address(*addr), socket2::Type::STREAM, Some(socket2::Protocol::from(IPPROTO_SCTP))).map_err(|e| {
        if e.raw_os_error() == Some(93) || e.kind() == io::ErrorKind::Unsupported {
            io::Error::new(e.kind(), format!("SCTP is not supported by this kernel ({e})"))
        } else {
            e
        }
    })
}

/// Connect a stream socket (TCP or SCTP) to `addr`.
pub fn connect(proto: Proto, addr: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    if proto == Proto::Sctp {
        let s = sctp_socket(addr)?;
        s.connect_timeout(&(*addr).into(), timeout)?;
        // One-to-one style: reads and writes like a TCP stream.
        return Ok(s.into());
    }
    let s = TcpStream::connect_timeout(addr, timeout)?;
    #[allow(clippy::let_underscore_must_use, reason = "best effort: the socket works without it")]
    let _ = s.set_nodelay(true);
    Ok(s)
}

/// Listen on `addr` (TCP or SCTP).
pub fn listen(proto: Proto, addr: &str) -> io::Result<TcpListener> {
    if proto != Proto::Sctp {
        return TcpListener::bind(addr);
    }
    let a: SocketAddr = addr.parse().map_err(|_| io::Error::other(format!("bad address {addr}")))?;
    let s = sctp_socket(&a)?;
    s.set_reuse_address(true)?;
    s.bind(&a.into())?;
    s.listen(64)?;
    Ok(s.into())
}

/// The TLS configurations of a peer manager.
#[derive(Clone, Default)]
pub struct Tls {
    pub client: Option<Arc<rustls::ClientConfig>>,
    pub server: Option<Arc<rustls::ServerConfig>>,
}

pub(crate) struct TlsState {
    conn: rustls::Connection,
    sock: TcpStream,
}

impl TlsState {
    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }
}

/// The sending half (shared by every writer of the connection).
pub(crate) enum Writer {
    Plain(Mutex<TcpStream>),
    Tls(Arc<Mutex<TlsState>>),
}

impl Writer {
    pub fn write_all(&self, b: &[u8]) -> io::Result<()> {
        match self {
            Writer::Plain(s) => lock(s).write_all(b),
            Writer::Tls(t) => {
                let mut t = lock(t);
                // rustls buffers a bounded amount of plaintext: write it out
                // as it is encrypted.
                let mut rest = b;
                while !rest.is_empty() {
                    let n = t.conn.writer().write(rest)?;
                    t.flush()?;
                    if n == 0 {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "TLS connection refuses data"));
                    }
                    rest = rest.get(n..).unwrap_or_default();
                }
                t.flush()
            }
        }
    }
}

/// The receiving half.
pub struct Reader {
    sock: TcpStream,
    tls: Option<Arc<Mutex<TlsState>>>,
    /// Ciphertext read from the socket and not yet taken by rustls.
    pending: Vec<u8>,
}

impl Reader {
    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(d)
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }
    pub fn shutdown(&self) {
        if let Some(t) = &self.tls {
            let mut t = lock(t);
            t.conn.send_close_notify();
            #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
            let _ = t.flush();
        }
        #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
        let _ = self.sock.shutdown(std::net::Shutdown::Both);
    }
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(t) = self.tls.clone() else { return self.sock.read(buf) };
        loop {
            {
                let mut st = lock(&t);
                match st.conn.reader().read(buf) {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                if !self.pending.is_empty() {
                    // Only fed while no plaintext is waiting, so rustls
                    // always has room for it.
                    let mut rd = &self.pending[..];
                    let n = st.conn.read_tls(&mut rd)?;
                    self.pending.drain(..n);
                    let res = st.conn.process_new_packets();
                    // Alerts, handshake messages, key updates.
                    #[allow(clippy::let_underscore_must_use, reason = "closing anyway")]
                    let _ = st.flush();
                    res.map_err(io::Error::other)?;
                    continue;
                }
            }
            // Wait for ciphertext without the lock: writers go on meanwhile.
            let mut tmp = [0u8; 16 * 1024];
            let n = self.sock.read(&mut tmp)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TLS peer closed the connection"));
            }
            self.pending.extend_from_slice(tmp.get(..n).unwrap_or_default());
        }
    }
}

/// A connected stream after the handshake (if any): its two halves.
pub fn split(sock: TcpStream, tls: Option<rustls::Connection>) -> io::Result<(Reader, Writer)> {
    match tls {
        None => {
            let w = sock.try_clone()?;
            Ok((Reader { sock, tls: None, pending: Vec::new() }, Writer::Plain(Mutex::new(w))))
        }
        Some(conn) => {
            let st = Arc::new(Mutex::new(TlsState { conn, sock: sock.try_clone()? }));
            Ok((Reader { sock, tls: Some(st.clone()), pending: Vec::new() }, Writer::Tls(st)))
        }
    }
}

/// Client handshake: verify the server as `name` (the peer's FQDN).
pub fn client_handshake(cfg: &Arc<rustls::ClientConfig>, name: &str, sock: &mut TcpStream) -> io::Result<rustls::Connection> {
    let sn = rustls::pki_types::ServerName::try_from(name.to_string()).map_err(|e| io::Error::other(format!("TLS server name {name:?}: {e}")))?;
    let mut c = rustls::ClientConnection::new(cfg.clone(), sn).map_err(io::Error::other)?;
    while c.is_handshaking() {
        c.complete_io(sock)?;
    }
    Ok(c.into())
}

/// Server handshake on an accepted connection.
pub fn server_handshake(cfg: &Arc<rustls::ServerConfig>, sock: &mut TcpStream) -> io::Result<rustls::Connection> {
    let mut c = rustls::ServerConnection::new(cfg.clone()).map_err(io::Error::other)?;
    while c.is_handshaking() {
        c.complete_io(sock)?;
    }
    Ok(c.into())
}
