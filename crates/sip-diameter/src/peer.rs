//! Diameter peers over TCP (RFC 6733 §5): the peer state machine
//! reduced to what a SIP server needs — connect, CER/CEA, Open, DWR/DWA
//! watchdog, DPR/DPA, reconnect after `tc` seconds — plus an acceptor for
//! incoming peers, request routing (Destination-Host, then realm, then the
//! default route, then any open peer) and synchronous requests with a
//! transaction timeout.

use crate::codes::*;
use crate::watchdog::{self, Watchdog};
use crate::wire::{self, Proto, Reader, Writer};
use crate::{Avp, DiameterError, Msg};
use sip_core::sync::{lock, read, write};
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default)]
pub struct PeerCfg {
    pub fqdn: String,
    pub realm: String,
    /// Where to connect (default: the FQDN).
    pub host: String,
    pub port: u16,
    /// TCP, TLS (the server verified as `fqdn`) or SCTP.
    pub proto: Proto,
}

/// A route to a peer (`<Route>` in a `<Realm>`, or `<DefaultRoute>`):
/// lower metrics are tried first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub fqdn: String,
    pub metric: u32,
}

/// Certificates for Diameter over TLS (PEM files, as for SIP TLS).
#[derive(Clone, Debug, Default)]
pub struct TlsCfg {
    /// Our certificate chain: the acceptor's server certificate, and the
    /// client certificate presented to TLS peers (optional there).
    pub certificate: Option<std::path::PathBuf>,
    pub private_key: Option<std::path::PathBuf>,
    /// CAs that verify the TLS peers we connect to (required for them),
    /// and incoming clients when `require_certificate` is set.
    pub ca_list: Option<std::path::PathBuf>,
    /// The TLS acceptor asks for and verifies a client certificate.
    pub require_certificate: bool,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub identity: String,
    pub realm: String,
    pub vendor_id: VendorId,
    pub product: String,
    pub peers: Vec<PeerCfg>,
    /// Acceptors (`ip:port`), each on its transport.
    pub listen: Vec<(Proto, String)>,
    /// (vendor or 0, application id)
    pub auth_apps: Vec<(VendorId, AppId)>,
    pub acct_apps: Vec<(VendorId, AppId)>,
    /// Reconnect interval (s).
    pub tc: u64,
    /// Watchdog interval (s).
    pub tw: u64,
    pub timeout: Duration,
    /// `<DefaultRoute>`s: for realms without a route table.
    pub default_routes: Vec<Route>,
    /// `<Realm name>` → its `<Route>`s.
    pub realm_routes: Vec<(String, Vec<Route>)>,
    pub tls: TlsCfg,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            identity: "ferrosip.localdomain".into(),
            realm: "localdomain".into(),
            vendor_id: VENDOR_3GPP,
            product: "ferrosip".into(),
            peers: vec![],
            listen: vec![],
            auth_apps: vec![],
            acct_apps: vec![],
            tc: 30,
            tw: 30,
            timeout: Duration::from_secs(5),
            default_routes: vec![],
            realm_routes: vec![],
            tls: TlsCfg::default(),
        }
    }
}

/// Answers incoming requests of one (application, command).
pub type Handler = Arc<dyn Fn(&Msg) -> Option<Msg> + Send + Sync>;

struct Conn {
    /// Our configured FQDN for it, or its Origin-Host for accepted peers.
    name: String,
    realm: String,
    origin_host: String,
    proto: Proto,
    writer: Arc<Writer>,
    watchdog: Mutex<Watchdog>,
    /// When routing last chose it (cdp's `last_selected`): equal-metric
    /// routes go to the least recently chosen peer.
    last_selected: Mutex<Option<Instant>>,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub fqdn: String,
    pub realm: String,
    pub state: &'static str,
    pub origin_host: String,
    pub proto: Proto,
}

/// What a request with an answer pending is waiting in.
enum Waiter {
    /// `request()`: a thread blocked on the channel.
    Chan(mpsc::Sender<Msg>),
    /// `request_cb()`: called with the answer, or with an error once the
    /// deadline has passed (by the watchdog). No deadline: a timeout too
    /// large for the clock never expires.
    Cb(AnswerFn, Option<Instant>),
}

/// Completion of `request_cb`: the answer, or why there is none. Runs on
/// the connection's reader (or the watchdog) thread: it must not block.
pub type AnswerFn = Box<dyn FnOnce(Result<Msg, DiameterError>) + Send>;

pub struct Peers {
    pub cfg: Config,
    conns: Mutex<Vec<Arc<Conn>>>,
    pending: Mutex<HashMap<u32, Waiter>>,
    handlers: RwLock<HashMap<(AppId, CmdCode), Handler>>,
    /// Requests no handler takes (`ims_diameter_server`).
    fallback: RwLock<Option<Handler>>,
    tls: wire::Tls,
    hbh: AtomicU32,
    e2e: AtomicU32,
    session: AtomicU64,
    state_id: u32,
    /// Inbound connections being served (bounded by `MAX_INBOUND`).
    inbound: AtomicUsize,
}

/// Most inbound Diameter connections served at once: each costs a thread,
/// and the acceptor has no authentication beyond the CER.
const MAX_INBOUND: usize = 64;

/// Auth or accounting application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppKind {
    Auth,
    Acct,
}

/// The applications a CER/CEA advertises (RFC 6733 §5.3): Auth- and
/// Acct-Application-Id, alone or inside Vendor-Specific-Application-Id.
fn advertised_apps(m: &Msg) -> Vec<(AppKind, AppId)> {
    let mut v = Vec::new();
    let mut take = |a: &Avp| {
        let kind = match a.code {
            _ if a.vendor.is_some() => return,
            AUTH_APPLICATION_ID => AppKind::Auth,
            ACCT_APPLICATION_ID => AppKind::Acct,
            _ => return,
        };
        if let Some(id) = a.as_u32() {
            v.push((kind, AppId(id)));
        }
    };
    for a in &m.avps {
        if a.code == VENDOR_SPECIFIC_APPLICATION_ID && a.vendor.is_none() {
            a.group_avps().iter().for_each(&mut take);
        } else {
            take(a);
        }
    }
    v
}

/// The applications both sides support, by kind and id (the Vendor-Id of a
/// Vendor-Specific-Application-Id is informational). The Relay id on one
/// side stands for every application of the other. Empty: no common
/// application (5010).
fn common_apps(cfg: &Config, m: &Msg) -> Vec<(AppKind, AppId)> {
    let ours: Vec<(AppKind, AppId)> =
        cfg.auth_apps.iter().map(|&(_, a)| (AppKind::Auth, a)).chain(cfg.acct_apps.iter().map(|&(_, a)| (AppKind::Acct, a))).collect();
    let theirs = advertised_apps(m);
    let relay = |v: &[(AppKind, AppId)]| v.iter().any(|&(_, a)| a == APP_RELAY);
    if relay(&theirs) {
        ours
    } else if relay(&ours) {
        theirs
    } else {
        ours.into_iter().filter(|a| theirs.contains(a)).collect()
    }
}

fn read_msg(s: &mut impl Read) -> std::io::Result<Msg> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h)?;
    let len = Msg::frame_len(&h).ok_or_else(|| std::io::Error::other("not Diameter"))?;
    if !(20..=1 << 20).contains(&len) {
        return Err(std::io::Error::other("bad Diameter length"));
    }
    let mut b = vec![0u8; len];
    let (head, body) = b.split_first_chunk_mut::<4>().ok_or_else(|| std::io::Error::other("bad Diameter length"))?;
    *head = h;
    s.read_exact(body)?;
    Msg::decode(&b).ok_or_else(|| std::io::Error::other("bad Diameter message"))
}

impl Peers {
    /// A peer manager; panics on a bad TLS setup (tests only: see
    /// [`Peers::try_new`]).
    #[cfg(test)]
    pub(crate) fn new(cfg: Config) -> Arc<Self> {
        Self::try_new(cfg).unwrap_or_else(|e| panic!("diameter: {e}"))
    }

    /// A peer manager, with the TLS certificates loaded when a peer or an
    /// acceptor uses TLS.
    pub fn try_new(cfg: Config) -> Result<Arc<Self>, String> {
        let tls = load_tls(&cfg)?;
        #[allow(clippy::cast_possible_truncation, reason = "the clock's low 32 bits seed the ids and Origin-State-Id (wraps in 2106)")]
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map_or(1, |d| d.as_secs()) as u32;
        Ok(Arc::new(Self {
            cfg,
            conns: Mutex::new(vec![]),
            pending: Mutex::new(HashMap::new()),
            handlers: RwLock::new(HashMap::new()),
            fallback: RwLock::new(None),
            tls,
            hbh: AtomicU32::new(t.rotate_left(12)),
            e2e: AtomicU32::new(t << 20),
            session: AtomicU64::new(1),
            state_id: t,
            inbound: AtomicUsize::new(0),
        }))
    }

    /// `identity;high;low` (RFC 6733 §8.8).
    pub fn session_id(&self, tag: &str) -> String {
        let n = self.session.fetch_add(1, Ordering::Relaxed);
        format!("{};{};{n};{tag}", self.cfg.identity, self.state_id)
    }

    pub fn add_handler(&self, app: AppId, cmd: CmdCode, h: Handler) {
        write(&self.handlers).insert((app, cmd), h);
    }

    /// Answer the requests no `add_handler` handler takes (instead of 3001).
    pub fn set_fallback_handler(&self, h: Handler) {
        *write(&self.fallback) = Some(h);
    }

    /// The realm we know a peer by: from its CEA/CER, else the config.
    pub fn peer_realm(&self, fqdn: &str) -> Option<String> {
        let conns = lock(&self.conns);
        conns
            .iter()
            .find(|c| c.name == fqdn || c.origin_host == fqdn)
            .map(|c| c.realm.clone())
            .or_else(|| self.cfg.peers.iter().find(|p| p.fqdn == fqdn).map(|p| p.realm.clone()))
            .filter(|r| !r.is_empty())
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        let conns = lock(&self.conns);
        let mut v: Vec<PeerInfo> = self
            .cfg
            .peers
            .iter()
            .map(|p| {
                let c = conns.iter().find(|c| c.name == p.fqdn);
                PeerInfo {
                    fqdn: p.fqdn.clone(),
                    realm: p.realm.clone(),
                    state: match c {
                        Some(c) if !lock(&c.watchdog).usable() => "Suspect",
                        Some(_) => "I_Open",
                        None => "Closed",
                    },
                    origin_host: c.map(|c| c.origin_host.clone()).unwrap_or_default(),
                    proto: p.proto,
                }
            })
            .collect();
        for c in conns.iter().filter(|c| !self.cfg.peers.iter().any(|p| p.fqdn == c.name)) {
            let state = if lock(&c.watchdog).usable() { "R_Open" } else { "Suspect" };
            v.push(PeerInfo { fqdn: c.name.clone(), realm: c.realm.clone(), state, origin_host: c.origin_host.clone(), proto: c.proto });
        }
        v
    }

    fn caps(&self, local: Option<IpAddr>) -> Vec<Avp> {
        let mut v = vec![
            Avp::str(ORIGIN_HOST, None, &self.cfg.identity),
            Avp::str(ORIGIN_REALM, None, &self.cfg.realm),
            Avp::addr(HOST_IP_ADDRESS, local.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            Avp::u32(VENDOR_ID, None, self.cfg.vendor_id.get()),
            Avp::str(PRODUCT_NAME, None, &self.cfg.product).optional(),
            Avp::u32(ORIGIN_STATE_ID, None, self.state_id),
            Avp::u32(SUPPORTED_VENDOR_ID, None, VENDOR_3GPP.get()),
        ];
        for &(vendor, app) in &self.cfg.auth_apps {
            v.push(if vendor == VendorId(0) {
                Avp::u32(AUTH_APPLICATION_ID, None, app.get())
            } else {
                Avp::group(VENDOR_SPECIFIC_APPLICATION_ID, None, vec![Avp::u32(VENDOR_ID, None, vendor.get()), Avp::u32(AUTH_APPLICATION_ID, None, app.get())])
            });
        }
        for &(vendor, app) in &self.cfg.acct_apps {
            v.push(if vendor == VendorId(0) {
                Avp::u32(ACCT_APPLICATION_ID, None, app.get())
            } else {
                Avp::group(VENDOR_SPECIFIC_APPLICATION_ID, None, vec![Avp::u32(VENDOR_ID, None, vendor.get()), Avp::u32(ACCT_APPLICATION_ID, None, app.get())])
            });
        }
        v.push(Avp::u32(FIRMWARE_REVISION, None, 1).optional());
        v
    }

    fn next_ids(&self) -> (u32, u32) {
        (self.hbh.fetch_add(1, Ordering::Relaxed), self.e2e.fetch_add(1, Ordering::Relaxed))
    }

    fn write(w: &Writer, m: &Msg) -> std::io::Result<()> {
        let b = m.try_encode().map_err(|e| {
            sip_core::log::log(sip_core::log::L_ERR, &format!("diameter: not sent: {e}"));
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        })?;
        w.write_all(&b)
    }

    /// Serve an open connection until it fails.
    fn reader(self: &Arc<Self>, conn: Arc<Conn>, mut s: Reader) {
        // The watchdog sends a DWR every Tw seconds of silence, and a live
        // peer answers it: three intervals without a byte means the peer is
        // gone (RFC 3539 §3.4), so the connection is dropped from the pick
        // list instead of being written to forever.
        #[allow(clippy::let_underscore_must_use, reason = "best effort: the socket works without it")]
        let _ = s.set_read_timeout(Some(lock(&conn.watchdog).silence_limit()));
        while let Ok(m) = read_msg(&mut s) {
            lock(&conn.watchdog).received(Instant::now());
            if !m.is_request() {
                let w = lock(&self.pending).remove(&m.hbh);
                match w {
                    Some(Waiter::Chan(tx)) => drop(tx.send(m)),
                    Some(Waiter::Cb(cb, _)) => cb(Ok(m)),
                    None => {}
                }
                continue;
            }
            let base = |res: ResultCode| -> Msg {
                let mut a = m.answer();
                if let Some(sid) = m.get(SESSION_ID, None) {
                    a.add(sid.clone());
                }
                a.add(Avp::u32(RESULT_CODE, None, res.get())).add(Avp::str(ORIGIN_HOST, None, &self.cfg.identity)).add(Avp::str(
                    ORIGIN_REALM,
                    None,
                    &self.cfg.realm,
                ));
                a
            };
            match m.cmd {
                CMD_DW => {
                    let a = base(DIAMETER_SUCCESS).with(Avp::u32(ORIGIN_STATE_ID, None, self.state_id));
                    #[allow(clippy::let_underscore_must_use, reason = "a dead connection is noticed (and closed) by its reader")]
                    let _ = Self::write(&conn.writer, &a);
                }
                CMD_DP => {
                    #[allow(clippy::let_underscore_must_use, reason = "a dead connection is noticed (and closed) by its reader")]
                    let _ = Self::write(&conn.writer, &base(DIAMETER_SUCCESS));
                    break;
                }
                CMD_CE => {
                    let mut a = m.answer();
                    a.add(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get()));
                    a.avps.extend(self.caps(s.local_addr().ok().map(|x| x.ip())));
                    #[allow(clippy::let_underscore_must_use, reason = "a dead connection is noticed (and closed) by its reader")]
                    let _ = Self::write(&conn.writer, &a);
                }
                cmd => {
                    let h = read(&self.handlers).get(&(m.app, cmd)).cloned();
                    if h.is_none()
                        && let Some(f) = read(&self.fallback).clone()
                    {
                        // The fallback (a script) may itself send requests
                        // and wait for answers this thread reads: run it on
                        // a thread of its own.
                        let (w, failed) = (conn.writer.clone(), base(DIAMETER_UNABLE_TO_COMPLY));
                        let spawned = std::thread::Builder::new().name("diameter-request".into()).spawn(move || {
                            sip_core::panic::expendable();
                            let ans = sip_core::panic::catch(|| f(&m)).unwrap_or_else(|_| {
                                sip_core::elog!("diameter: panic answering command {cmd}");
                                Some(failed)
                            });
                            if let Some(a) = ans {
                                #[allow(clippy::let_underscore_must_use, reason = "a dead connection is noticed (and closed) by its reader")]
                                let _ = Self::write(&w, &a);
                            }
                        });
                        if spawned.is_err() {
                            sip_core::elog!("diameter: no thread to answer command {cmd}");
                        }
                        continue;
                    }
                    let ans = match h {
                        // A handler bug answers DIAMETER_UNABLE_TO_COMPLY
                        // instead of killing this peer's reader.
                        Some(h) => sip_core::panic::catch(|| h(&m)).unwrap_or_else(|_| {
                            sip_core::elog!("diameter: panic in the handler for command {cmd}");
                            Some(base(DIAMETER_UNABLE_TO_COMPLY))
                        }),
                        None => Some(base(DIAMETER_COMMAND_UNSUPPORTED)),
                    };
                    if let Some(a) = ans {
                        #[allow(clippy::let_underscore_must_use, reason = "a dead connection is noticed (and closed) by its reader")]
                        let _ = Self::write(&conn.writer, &a);
                    }
                }
            }
        }
        lock(&self.conns).retain(|c| !Arc::ptr_eq(c, &conn));
        s.shutdown();
    }

    fn connect_once(self: &Arc<Self>, p: &PeerCfg) -> std::io::Result<()> {
        let addr: SocketAddr = (p.host.as_str(), p.port).to_socket_addrs()?.next().ok_or_else(|| std::io::Error::other("no address"))?;
        let mut sock = wire::connect(p.proto, &addr, Duration::from_secs(5))?;
        sock.set_read_timeout(Some(Duration::from_secs(5)))?;
        let tls = match p.proto {
            Proto::Tls => {
                let cfg = self.tls.client.as_ref().ok_or_else(|| std::io::Error::other("no TLS client configuration"))?;
                Some(wire::client_handshake(cfg, &p.fqdn, &mut sock).map_err(|e| std::io::Error::other(format!("TLS: {e}")))?)
            }
            _ => None,
        };
        let local = sock.local_addr().ok().map(|a| a.ip());
        let (mut rd, w) = wire::split(sock, tls)?;
        let (hbh, e2e) = self.next_ids();
        let mut cer = Msg::request(CMD_CE, APP_COMMON);
        cer.flags = crate::FLAG_R;
        cer.hbh = hbh;
        cer.e2e = e2e;
        cer.avps = self.caps(local);
        Self::write(&w, &cer)?;
        let cea = read_msg(&mut rd)?;
        if cea.cmd != CMD_CE || cea.result() != Some(DIAMETER_SUCCESS) {
            return Err(std::io::Error::other(format!("CEA from {} refused: {:?}", p.fqdn, cea.result())));
        }
        if common_apps(&self.cfg, &cea).is_empty() {
            rd.shutdown();
            return Err(std::io::Error::other(format!("{} supports none of our applications", p.fqdn)));
        }
        let conn = Arc::new(Conn {
            name: p.fqdn.clone(),
            realm: cea.str(ORIGIN_REALM).unwrap_or_else(|| p.realm.clone()),
            origin_host: cea.str(ORIGIN_HOST).unwrap_or_default(),
            proto: p.proto,
            writer: Arc::new(w),
            watchdog: Mutex::new(Watchdog::new(Duration::from_secs(self.cfg.tw), Instant::now())),
            last_selected: Mutex::new(None),
        });
        lock(&self.conns).push(conn.clone());
        self.reader(conn, rd);
        Ok(())
    }

    fn accept(self: &Arc<Self>, proto: Proto, mut sock: TcpStream) {
        #[allow(clippy::let_underscore_must_use, reason = "best effort: the socket works without it")]
        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
        let tls = match (proto, &self.tls.server) {
            (Proto::Tls, Some(cfg)) => match wire::server_handshake(cfg, &mut sock) {
                Ok(c) => Some(c),
                Err(e) => {
                    sip_core::elog!("cdp: TLS handshake with {:?}: {e}", sock.peer_addr().ok());
                    return;
                }
            },
            (Proto::Tls, None) => return,
            _ => None,
        };
        let local = sock.local_addr().ok().map(|x| x.ip());
        let Ok((mut rd, w)) = wire::split(sock, tls) else { return };
        let Ok(cer) = read_msg(&mut rd) else { return };
        if cer.cmd != CMD_CE || !cer.is_request() {
            return;
        }
        // RFC 6733 §5.3: without an application in common the CER is
        // refused and the connection closed.
        let common = !common_apps(&self.cfg, &cer).is_empty();
        let mut a = cer.answer();
        a.add(Avp::u32(RESULT_CODE, None, if common { DIAMETER_SUCCESS } else { DIAMETER_NO_COMMON_APPLICATION }.get()));
        a.avps.extend(self.caps(local));
        if Self::write(&w, &a).is_err() || !common {
            if !common {
                sip_core::elog!("cdp: {:?} supports none of our applications; refused", cer.str(ORIGIN_HOST).unwrap_or_default());
            }
            rd.shutdown();
            return;
        }
        let origin = cer.str(ORIGIN_HOST).unwrap_or_default();
        let conn = Arc::new(Conn {
            name: origin.clone(),
            realm: cer.str(ORIGIN_REALM).unwrap_or_default(),
            origin_host: origin,
            proto,
            writer: Arc::new(w),
            watchdog: Mutex::new(Watchdog::new(Duration::from_secs(self.cfg.tw), Instant::now())),
            last_selected: Mutex::new(None),
        });
        lock(&self.conns).push(conn.clone());
        self.reader(conn, rd);
    }

    /// Start connector, acceptor and watchdog threads.
    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        for p in self.cfg.peers.clone() {
            let me = self.clone();
            let name = p.fqdn.clone();
            std::thread::Builder::new()
                .name(format!("diameter-{}", p.fqdn))
                .spawn(move || {
                    loop {
                        if let Err(e) = me.connect_once(&p) {
                            sip_core::elog!("cdp: peer {}: {e}", p.fqdn);
                        }
                        std::thread::sleep(Duration::from_secs(me.cfg.tc.max(1)));
                    }
                })
                .map_err(|e| format!("cannot start the thread for peer {name}: {e}"))?;
        }
        for (proto, addr) in self.cfg.listen.clone() {
            match wire::listen(proto, &addr) {
                Ok(l) => {
                    let me = self.clone();
                    std::thread::Builder::new()
                        .name(format!("diameter-acceptor-{}", proto.as_str()))
                        .spawn(move || {
                            for s in l.incoming().flatten() {
                                if me.inbound.fetch_add(1, Ordering::AcqRel) >= MAX_INBOUND {
                                    me.inbound.fetch_sub(1, Ordering::AcqRel);
                                    sip_core::elog!("cdp: {MAX_INBOUND} inbound connections already open; refusing another");
                                    continue; // dropping `s` closes it
                                }
                                let m = me.clone();
                                let spawned = std::thread::Builder::new().name("diameter-in".into()).spawn(move || {
                                    sip_core::panic::expendable();
                                    struct Done<'a>(&'a AtomicUsize);
                                    impl Drop for Done<'_> {
                                        fn drop(&mut self) {
                                            self.0.fetch_sub(1, Ordering::AcqRel);
                                        }
                                    }
                                    let _done = Done(&m.inbound);
                                    m.accept(proto, s)
                                });
                                // The connection is dropped (closed).
                                if let Err(e) = spawned {
                                    me.inbound.fetch_sub(1, Ordering::AcqRel);
                                    sip_core::log::log(sip_core::log::L_ERR, &format!("cdp: no thread for an inbound connection: {e}"));
                                }
                            }
                        })
                        .map_err(|e| format!("cannot start the acceptor thread for {addr}: {e}"))?;
                }
                Err(e) => sip_core::elog!("cdp: cannot listen on {}:{addr}: {e}", proto.as_str()),
            }
        }
        let me = self.clone();
        std::thread::Builder::new()
            .name("diameter-watchdog".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    me.expire_callbacks();
                    let conns = lock(&me.conns).clone();
                    for c in conns {
                        let action = lock(&c.watchdog).tick(Instant::now());
                        match action {
                            watchdog::Action::Nothing => {}
                            watchdog::Action::SendDwr => {
                                let (hbh, e2e) = me.next_ids();
                                let mut dwr = Msg::request(CMD_DW, APP_COMMON);
                                dwr.flags = crate::FLAG_R;
                                dwr.hbh = hbh;
                                dwr.e2e = e2e;
                                dwr.add(Avp::str(ORIGIN_HOST, None, &me.cfg.identity)).add(Avp::str(ORIGIN_REALM, None, &me.cfg.realm)).add(Avp::u32(
                                    ORIGIN_STATE_ID,
                                    None,
                                    me.state_id,
                                ));
                                #[allow(clippy::let_underscore_must_use, reason = "a dead connection is noticed (and closed) by its reader")]
                                let _ = Self::write(&c.writer, &dwr);
                            }
                            watchdog::Action::Suspect => sip_core::elog!("cdp: peer {} is not answering; routing around it", c.name),
                            // Off the pick list now; the reader's own
                            // timeout (the same silence) closes the socket.
                            watchdog::Action::Close => {
                                sip_core::elog!("cdp: peer {} is down; closing", c.name);
                                lock(&me.conns).retain(|x| !Arc::ptr_eq(x, &c));
                            }
                        }
                    }
                }
            })
            .map_err(|e| format!("cannot start the watchdog thread: {e}"))?;
        Ok(())
    }

    /// The connection for a request (cdp's routing): the Destination-Host
    /// peer when it is open; else the destination realm's `<Route>`s, lowest
    /// metric first, skipping peers that are not open, open peers sharing
    /// that metric taking turns (least recently chosen); for a realm without
    /// a route table, a peer in that realm; then the `<DefaultRoute>`s by
    /// metric; then any open peer.
    fn pick(&self, realm: &str, host: Option<&str>) -> Option<Arc<Conn>> {
        // A SUSPECT peer (unanswered watchdog) gets no new requests.
        let conns: Vec<Arc<Conn>> = lock(&self.conns).iter().filter(|c| lock(&c.watchdog).usable()).cloned().collect();
        if let Some(h) = host
            && let Some(c) = conns.iter().find(|c| c.name == h || c.origin_host == h)
        {
            return Some(c.clone());
        }
        // cdp's get_first_connected_route(): the open peers sharing the
        // lowest metric are balanced, the least recently chosen one wins.
        let by_routes = |routes: &[Route]| -> Option<Arc<Conn>> {
            let open: Vec<(u32, &Arc<Conn>)> =
                routes.iter().filter_map(|r| conns.iter().find(|c| c.name == r.fqdn || c.origin_host == r.fqdn).map(|c| (r.metric, c))).collect();
            let best = open.iter().map(|(m, _)| *m).min()?;
            let c = open.iter().filter(|(m, _)| *m == best).map(|(_, c)| *c).min_by_key(|c| *lock(&c.last_selected))?;
            *lock(&c.last_selected) = Some(Instant::now());
            Some(c.clone())
        };
        match self.cfg.realm_routes.iter().find(|(r, _)| r.eq_ignore_ascii_case(realm)) {
            Some((_, routes)) => {
                if let Some(c) = by_routes(routes) {
                    return Some(c);
                }
            }
            None => {
                if let Some(c) = conns.iter().find(|c| c.realm == realm || self.cfg.peers.iter().any(|p| p.fqdn == c.name && p.realm == realm)) {
                    return Some(c.clone());
                }
            }
        }
        if let Some(c) = by_routes(&self.cfg.default_routes) {
            return Some(c);
        }
        conns.first().cloned()
    }

    /// Fill in the routing AVPs and ids of a request; the connection to use.
    fn prepare(&self, m: &mut Msg, dest_realm: &str, dest_host: Option<&str>) -> Result<Arc<Conn>, DiameterError> {
        let conn = self.pick(dest_realm, dest_host).ok_or_else(|| DiameterError::NoRoute { realm: dest_realm.to_string() })?;
        if m.get(ORIGIN_HOST, None).is_none() {
            m.add(Avp::str(ORIGIN_HOST, None, &self.cfg.identity));
        }
        if m.get(ORIGIN_REALM, None).is_none() {
            m.add(Avp::str(ORIGIN_REALM, None, &self.cfg.realm));
        }
        if m.get(DESTINATION_REALM, None).is_none() {
            m.add(Avp::str(DESTINATION_REALM, None, dest_realm));
        }
        if let (Some(h), None) = (dest_host, m.get(DESTINATION_HOST, None)) {
            m.add(Avp::str(DESTINATION_HOST, None, h));
        }
        let (hbh, e2e) = self.next_ids();
        m.hbh = hbh;
        m.e2e = e2e;
        m.flags |= crate::FLAG_R;
        Ok(conn)
    }

    /// Send a request and wait for its answer. Adds Origin-Host/-Realm and
    /// Destination-Realm/-Host when missing.
    pub fn request(&self, mut m: Msg, dest_realm: &str, dest_host: Option<&str>) -> Result<Msg, DiameterError> {
        let conn = self.prepare(&mut m, dest_realm, dest_host)?;
        let b = encode(&m)?;
        let hbh = m.hbh;
        let (tx, rx) = mpsc::channel();
        lock(&self.pending).insert(hbh, Waiter::Chan(tx));
        if let Err(err) = conn.writer.write_all(&b) {
            lock(&self.pending).remove(&hbh);
            return Err(DiameterError::Send { peer: conn.name.clone(), err });
        }
        match rx.recv_timeout(self.cfg.timeout) {
            Ok(a) => Ok(a),
            Err(_) => {
                lock(&self.pending).remove(&hbh);
                Err(DiameterError::Timeout { peer: Some(conn.name.clone()) })
            }
        }
    }

    /// Send a request without blocking: `cb` gets the answer, or an error
    /// when it can't be sent or no answer comes within the cdp timeout
    /// (checked every second by the watchdog). `cb` runs on a Diameter
    /// thread and must hand any real work elsewhere.
    pub fn request_cb(&self, mut m: Msg, dest_realm: &str, dest_host: Option<&str>, cb: AnswerFn) {
        let (conn, b) = match self.prepare(&mut m, dest_realm, dest_host).and_then(|c| Ok((c, encode(&m)?))) {
            Ok(x) => x,
            Err(e) => return cb(Err(e)),
        };
        let hbh = m.hbh;
        lock(&self.pending).insert(hbh, Waiter::Cb(cb, Instant::now().checked_add(self.cfg.timeout)));
        if let Err(err) = conn.writer.write_all(&b) {
            let w = lock(&self.pending).remove(&hbh);
            if let Some(Waiter::Cb(cb, _)) = w {
                cb(Err(DiameterError::Send { peer: conn.name.clone(), err }));
            }
        }
    }

    /// Call the callbacks whose answer didn't come in time.
    fn expire_callbacks(&self) {
        let now = Instant::now();
        let late: Vec<AnswerFn> = {
            let mut p = lock(&self.pending);
            let ids: Vec<u32> = p.iter().filter(|(_, w)| matches!(w, Waiter::Cb(_, Some(d)) if *d <= now)).map(|(k, _)| *k).collect();
            ids.into_iter()
                .filter_map(|k| match p.remove(&k) {
                    Some(Waiter::Cb(cb, _)) => Some(cb),
                    _ => None,
                })
                .collect()
        };
        for cb in late {
            cb(Err(DiameterError::Timeout { peer: None }));
        }
    }

    /// Send a request without waiting (answers are dropped).
    pub fn send(&self, m: Msg, dest_realm: &str) -> Result<(), DiameterError> {
        let conn = self.pick(dest_realm, None).ok_or_else(|| DiameterError::NoRoute { realm: dest_realm.to_string() })?;
        let mut m = m;
        let (hbh, e2e) = self.next_ids();
        m.hbh = hbh;
        m.e2e = e2e;
        let b = encode(&m)?;
        conn.writer.write_all(&b).map_err(|err| DiameterError::Send { peer: conn.name.clone(), err })
    }
}

/// A request's bytes, logged when it can't be encoded.
fn encode(m: &Msg) -> Result<Vec<u8>, DiameterError> {
    m.try_encode().map_err(|e| {
        sip_core::log::log(sip_core::log::L_ERR, &format!("diameter: not sent: {e}"));
        DiameterError::Encode(e)
    })
}

/// The rustls configurations the TLS peers and acceptors need, built by
/// the SIP TLS loader (same PEM handling, ring provider, verification).
fn load_tls(cfg: &Config) -> Result<wire::Tls, String> {
    let client = cfg.peers.iter().any(|p| p.proto == Proto::Tls);
    let server = cfg.listen.iter().any(|(p, _)| *p == Proto::Tls);
    if !client && !server {
        return Ok(wire::Tls::default());
    }
    let t = &cfg.tls;
    if server && (t.certificate.is_none() || t.private_key.is_none()) {
        return Err("a Diameter TLS acceptor needs a certificate and private_key".into());
    }
    if client && t.ca_list.is_none() {
        return Err("Diameter TLS peers need ca_list (their certificates are verified)".into());
    }
    let files = sip_transport::TlsFiles {
        cert: t.certificate.clone(),
        key: t.private_key.clone(),
        ca: t.ca_list.clone(),
        verify_client: t.require_certificate,
        ..Default::default()
    };
    let loaded = sip_transport::tls::load(&files, server).map_err(|e| format!("Diameter TLS: {e}"))?;
    Ok(wire::Tls { client: if client { loaded.client } else { None }, server: if server { loaded.server } else { None } })
}

/// Minimal reading of Kamailio's cdp XML configuration
/// (`<DiameterPeer FQDN Realm …><Peer …/><Acceptor …/><Auth …/><Acct …/>
/// <Realm name><Route FQDN metric/></Realm><DefaultRoute FQDN metric/>`).
/// Attribute `host` (ferrosip) sets the address to connect to; `proto`
/// on `<Peer>` / `<Acceptor>` picks tcp (default), tls or sctp; `<TLS
/// certificate private_key ca_list require_certificate/>` holds the TLS
/// files.
pub fn parse_xml_config(xml: &str) -> Result<Config, String> {
    fn attrs(tag: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        let mut rest = tag;
        while let Some((before, after)) = rest.split_once('=') {
            let key = before.split_whitespace().last().unwrap_or("").to_string();
            let mut chars = after.trim_start().chars();
            let Some(q) = chars.next() else { break };
            if q != '"' && q != '\'' {
                break;
            }
            let Some((value, tail)) = chars.as_str().split_once(q) else { break };
            m.insert(key.to_ascii_lowercase(), value.to_string());
            rest = tail;
        }
        m
    }
    fn tags<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
        let mut v = Vec::new();
        let pat = format!("<{name}");
        let mut rest = xml;
        while let Some((_, after)) = rest.split_once(pat.as_str()) {
            if !after.starts_with(|c: char| c.is_whitespace() || c == '>' || c == '/') {
                rest = after;
                continue;
            }
            let (tag, tail) = after.split_at(after.find('>').unwrap_or(after.len()));
            v.push(tag);
            rest = tail;
        }
        v
    }
    // Drop comments.
    let mut clean = String::new();
    let mut rest = xml;
    while let Some(p) = rest.find("<!--") {
        let (before, comment) = rest.split_at(p);
        clean.push_str(before);
        rest = comment.split_once("-->").map_or("", |(_, after)| after);
    }
    clean.push_str(rest);
    let root = tags(&clean, "DiameterPeer").first().map(|t| attrs(t)).ok_or("cdp config: no <DiameterPeer>")?;
    let mut cfg = Config::default();
    let get = |m: &HashMap<String, String>, k: &str| m.get(k).cloned();
    cfg.identity = get(&root, "fqdn").ok_or("cdp config: DiameterPeer FQDN missing")?;
    cfg.realm = get(&root, "realm").ok_or("cdp config: DiameterPeer Realm missing")?;
    if let Some(v) = get(&root, "vendor_id").and_then(|v| v.parse().ok()) {
        cfg.vendor_id = VendorId(v);
    }
    if let Some(p) = get(&root, "product_name") {
        cfg.product = p;
    }
    if let Some(t) = get(&root, "tc").and_then(|v| v.parse().ok()) {
        cfg.tc = t;
    }
    if let Some(t) = get(&root, "transactiontimeout").and_then(|v| v.parse::<u64>().ok()) {
        cfg.timeout = Duration::from_secs(t.max(1));
    }
    let route = |t: &str| -> Result<Route, String> {
        let a = attrs(t);
        Ok(Route { fqdn: get(&a, "fqdn").ok_or("cdp config: Route without FQDN")?, metric: get(&a, "metric").and_then(|m| m.trim().parse().ok()).unwrap_or(0) })
    };
    // <Realm name="…"><Route …/></Realm>: taken out before the rest is read.
    let mut rest = clean.as_str();
    let mut outside = String::new();
    while let Some(p) = rest
        .find("<Realm")
        .filter(|&p| rest.get(p..).and_then(|t| t.strip_prefix("<Realm")).is_some_and(|t| t.starts_with(|c: char| c.is_whitespace() || c == '>')))
    {
        let (before, realm) = rest.split_at(p);
        outside.push_str(before);
        // `realm` starts with `<Realm`; split it at the `>` closing the open tag.
        let (open, after_open) = realm.split_once('>').ok_or("cdp config: unterminated <Realm")?;
        let name = get(&attrs(open.strip_prefix("<Realm").unwrap_or(open)), "name").ok_or("cdp config: Realm without name")?;
        let routes = if open.ends_with('/') {
            rest = after_open;
            vec![]
        } else {
            let (body, after_close) = after_open.split_once("</Realm>").ok_or("cdp config: <Realm> without </Realm>")?;
            rest = after_close;
            tags(body, "Route").into_iter().map(route).collect::<Result<Vec<_>, _>>()?
        };
        cfg.realm_routes.push((name, routes));
    }
    outside.push_str(rest);
    let clean = outside;
    for t in tags(&clean, "Peer") {
        let a = attrs(t);
        let fqdn = get(&a, "fqdn").ok_or("cdp config: Peer without FQDN")?;
        let proto = Proto::parse(&get(&a, "proto").unwrap_or_default()).map_err(|e| format!("cdp config: Peer {fqdn}: {e}"))?;
        cfg.peers.push(PeerCfg {
            host: get(&a, "host").unwrap_or_else(|| fqdn.clone()),
            realm: get(&a, "realm").unwrap_or_default(),
            port: get(&a, "port").and_then(|p| p.parse().ok()).unwrap_or(proto.default_port()),
            fqdn,
            proto,
        });
    }
    for t in tags(&clean, "Acceptor") {
        let a = attrs(t);
        let proto = Proto::parse(&get(&a, "proto").unwrap_or_default()).map_err(|e| format!("cdp config: Acceptor: {e}"))?;
        let bind = get(&a, "bind").unwrap_or_else(|| "0.0.0.0".into());
        let port = get(&a, "port").unwrap_or_else(|| proto.default_port().to_string());
        cfg.listen.push((proto, if bind.contains(':') && !bind.starts_with('[') { format!("[{bind}]:{port}") } else { format!("{bind}:{port}") }));
    }
    for (tag, list) in [("Auth", &mut cfg.auth_apps), ("Acct", &mut cfg.acct_apps)] {
        for t in tags(&clean, tag) {
            let a = attrs(t);
            if let Some(id) = get(&a, "id").and_then(|v| v.parse().ok()) {
                list.push((VendorId(get(&a, "vendor").and_then(|v| v.parse().ok()).unwrap_or(0)), AppId(id)));
            }
        }
    }
    cfg.default_routes = tags(&clean, "DefaultRoute").into_iter().map(route).collect::<Result<Vec<_>, _>>()?;
    if let Some(a) = tags(&clean, "TLS").first().map(|t| attrs(t)) {
        let path = |k: &str| get(&a, k).filter(|v| !v.is_empty()).map(std::path::PathBuf::from);
        cfg.tls = TlsCfg {
            certificate: path("certificate"),
            private_key: path("private_key"),
            ca_list: path("ca_list"),
            require_certificate: get(&a, "require_certificate").is_some_and(|v| matches!(v.trim(), "1" | "yes" | "true")),
        };
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What both ends of the test connections support (as mod-ims does).
    fn cx() -> Vec<(VendorId, AppId)> {
        vec![(VENDOR_3GPP, APP_CX)]
    }

    /// N distinct ports that are free right now (the OS picks them), so
    /// tests never collide with each other or with another run.
    fn free_ports<const N: usize>() -> [u16; N] {
        let held: Vec<std::net::TcpListener> = (0..N).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        std::array::from_fn(|i| held[i].local_addr().unwrap().port())
    }

    #[test]
    fn read_msg_takes_one_frame_and_refuses_bad_lengths() {
        let m = Msg::request(CMD_DW, APP_COMMON).with(Avp::str(ORIGIN_HOST, None, "a"));
        let b = m.encode();
        let mut two = b.clone();
        two.extend_from_slice(&b);
        let mut cur = std::io::Cursor::new(two);
        assert_eq!(read_msg(&mut cur).unwrap(), m);
        assert_eq!(read_msg(&mut cur).unwrap(), m);
        assert!(read_msg(&mut cur).is_err(), "end of stream");
        // (bytes, why they are refused)
        let cases: &[(&[u8], &str)] = &[
            (&[2, 0, 0, 20], "not version 1"),
            (&[1, 0, 0, 19], "length under the header"),
            (&[1, 0x10, 0, 1], "over 1 MiB"),
            (&[1, 0, 0, 24, 0x80, 0, 1, 24], "cut short"),
        ];
        for (bytes, why) in cases {
            assert!(read_msg(&mut std::io::Cursor::new(bytes.to_vec())).is_err(), "{why}");
        }
        // A frame whose AVPs don't parse.
        let mut bad = b.clone();
        bad[27] = 200;
        assert!(read_msg(&mut std::io::Cursor::new(bad)).is_err());
        // Exactly 1 MiB is allowed.
        let big = Msg::request(CMD_DW, APP_COMMON).with(Avp::new(USER_NAME, None, vec![0; (1 << 20) - 28]));
        let bb = big.encode();
        assert_eq!(bb.len(), 1 << 20);
        assert_eq!(read_msg(&mut std::io::Cursor::new(bb)).unwrap(), big);
    }

    #[test]
    fn capabilities_list_the_configured_applications() {
        let p = Peers::try_new(Config {
            identity: "scscf.t".into(),
            realm: "t".into(),
            auth_apps: vec![(VENDOR_3GPP, APP_CX), (VendorId(0), APP_CC)],
            acct_apps: vec![(VendorId(0), AppId(3)), (VendorId(5535), AppId(9))],
            ..Default::default()
        })
        .unwrap();
        let caps = p.caps(Some("192.0.2.7".parse().unwrap()));
        assert_eq!(crate::find(&caps, ORIGIN_HOST, None).unwrap().as_str(), "scscf.t");
        assert_eq!(crate::find(&caps, ORIGIN_REALM, None).unwrap().as_str(), "t");
        assert_eq!(crate::find(&caps, HOST_IP_ADDRESS, None).unwrap().data, [0, 1, 192, 0, 2, 7]);
        assert_eq!(crate::find(&caps, VENDOR_ID, None).unwrap().as_u32(), Some(10415));
        assert_eq!(crate::find(&caps, AUTH_APPLICATION_ID, None).unwrap().as_u32(), Some(APP_CC.get()));
        assert_eq!(crate::find(&caps, ACCT_APPLICATION_ID, None).unwrap().as_u32(), Some(3));
        let vsai: Vec<(Option<u32>, Option<u32>, Option<u32>)> = caps
            .iter()
            .filter(|a| a.code == VENDOR_SPECIFIC_APPLICATION_ID)
            .map(|a| {
                let g = a.group_avps();
                let u = |c| crate::find(&g, c, None).and_then(Avp::as_u32);
                (u(VENDOR_ID), u(AUTH_APPLICATION_ID), u(ACCT_APPLICATION_ID))
            })
            .collect();
        assert_eq!(vsai, [(Some(10415), Some(APP_CX.get()), None), (Some(5535), None, Some(9))]);
        // Product-Name and Firmware-Revision are not mandatory.
        assert_eq!(crate::find(&caps, PRODUCT_NAME, None).unwrap().flags & crate::FLAG_M, 0);
        assert_eq!(crate::find(&caps, FIRMWARE_REVISION, None).unwrap().flags & crate::FLAG_M, 0);
        // Without a local address: 127.0.0.1.
        assert_eq!(crate::find(&p.caps(None), HOST_IP_ADDRESS, None).unwrap().data, [0, 1, 127, 0, 0, 1]);
    }

    #[test]
    fn session_ids_are_identity_state_counter_tag() {
        let p = Peers::try_new(Config { identity: "pcscf.t".into(), ..Default::default() }).unwrap();
        let a = p.session_id("rx");
        let b = p.session_id("rx");
        let pa: Vec<&str> = a.split(';').collect();
        let pb: Vec<&str> = b.split(';').collect();
        assert_eq!((pa.len(), pa[0], pa[3]), (4, "pcscf.t", "rx"), "{a}");
        assert_eq!(pa[1], pb[1], "same state id");
        assert_eq!(pb[2].parse::<u64>().unwrap(), pa[2].parse::<u64>().unwrap() + 1);
    }

    #[test]
    fn xml_config_defaults_and_attribute_forms() {
        let c =
            parse_xml_config(r#"<DiameterPeer FQDN = 'a.t'  Realm="t" Product_Name="X" TransactionTimeout="0"><Peer FQDN="hss.t"/><Acceptor/></DiameterPeer>"#)
                .unwrap();
        assert_eq!((c.identity.as_str(), c.realm.as_str(), c.product.as_str()), ("a.t", "t", "X"));
        assert_eq!(c.timeout, Duration::from_secs(1), "a zero timeout is raised to 1 s");
        assert_eq!((c.tc, c.vendor_id), (30, VENDOR_3GPP));
        let p = &c.peers[0];
        assert_eq!((p.host.as_str(), p.port, p.realm.as_str(), p.proto), ("hss.t", 3868, "", Proto::Tcp));
        assert_eq!(c.listen, vec![(Proto::Tcp, "0.0.0.0:3868".to_string())]);
        // Unparsable numbers keep the defaults; an Auth without id is skipped.
        let c = parse_xml_config(
            r#"<DiameterPeer FQDN="a" Realm="t" Tc="x" Vendor_Id="-1"><Peer FQDN="h" port="99999"/><Auth vendor="1"/><Acct id="3"/></DiameterPeer>"#,
        )
        .unwrap();
        assert_eq!((c.tc, c.vendor_id, c.peers[0].port), (30, VENDOR_3GPP, 3868));
        assert!(c.auth_apps.is_empty());
        assert_eq!(c.acct_apps, vec![(VendorId(0), AppId(3))]);
        // Commented-out peers are ignored; '=' inside a value is kept.
        let c = parse_xml_config(r#"<DiameterPeer FQDN="a" Realm="t"><!-- <Peer FQDN="old"/> --><Peer FQDN="new" host="h=1"/></DiameterPeer>"#).unwrap();
        assert_eq!(c.peers.iter().map(|p| (p.fqdn.as_str(), p.host.as_str())).collect::<Vec<_>>(), [("new", "h=1")]);
        // Elements whose names only start like a known one are not it.
        let c = parse_xml_config(r#"<DiameterPeer FQDN="a" Realm="t"><PeerX FQDN="x"/><AuthZ id="1"/></DiameterPeer>"#).unwrap();
        assert!(c.peers.is_empty() && c.auth_apps.is_empty());
        // Required pieces.
        let errs = [
            ("<Peer FQDN=\"a\"/>", "no <DiameterPeer>"),
            ("<DiameterPeer Realm=\"t\"/>", "FQDN missing"),
            ("<DiameterPeer FQDN=\"a\"/>", "Realm missing"),
            ("<DiameterPeer FQDN=\"a\" Realm=\"t\"><Peer host=\"h\"/></DiameterPeer>", "Peer without FQDN"),
            ("<DiameterPeer FQDN=\"a\" Realm=\"t\"><DefaultRoute metric=\"1\"/></DiameterPeer>", "Route without FQDN"),
            ("<DiameterPeer FQDN=\"a\" Realm=\"t\"><Realm><Route FQDN=\"x\"/></Realm></DiameterPeer>", "Realm without name"),
        ];
        for (x, want) in errs {
            let e = parse_xml_config(x).unwrap_err();
            assert!(e.contains(want), "{x}: {e}");
        }
        // TLS flags: only 1 / yes / true require a certificate; empty paths are unset.
        for (v, want) in [("1", true), ("yes", true), ("true", true), ("0", false), ("no", false), ("", false)] {
            let c = parse_xml_config(&format!(r#"<DiameterPeer FQDN="a" Realm="t"><TLS certificate="" require_certificate="{v}"/></DiameterPeer>"#)).unwrap();
            assert_eq!(c.tls.require_certificate, want, "require_certificate={v:?}");
            assert!(c.tls.certificate.is_none());
        }
    }

    #[test]
    fn transports_parse_and_default_ports() {
        let cases = [("", Some(Proto::Tcp)), (" TCP ", Some(Proto::Tcp)), ("tls", Some(Proto::Tls)), ("Sctp", Some(Proto::Sctp)), ("udp", None)];
        for (s, want) in cases {
            assert_eq!(Proto::parse(s).ok(), want, "{s:?}");
        }
        for p in [Proto::Tcp, Proto::Tls, Proto::Sctp] {
            assert_eq!(Proto::parse(p.as_str()), Ok(p));
        }
        assert_eq!((Proto::Tcp.default_port(), Proto::Tls.default_port(), Proto::Sctp.default_port()), (3868, 5658, 3868));
    }

    #[test]
    fn xml_config() {
        let x = r#"<?xml version="1.0"?><!-- c --><DiameterPeer FQDN="scscf.ims.test" Realm="ims.test" Vendor_Id="10415" Tc="5">
            <Peer FQDN="hss.ims.test" Realm="ims.test" port="3869" host="127.0.0.1"/>
            <Acceptor port="3870" bind="127.0.0.1"/>
            <Auth id="16777216" vendor="10415"/><Auth id="4" vendor="0"/>
            <DefaultRoute FQDN="hss.ims.test" metric="10"/></DiameterPeer>"#;
        let c = parse_xml_config(x).unwrap();
        assert_eq!((c.identity.as_str(), c.realm.as_str(), c.tc), ("scscf.ims.test", "ims.test", 5));
        assert_eq!(c.peers.len(), 1);
        assert_eq!((c.peers[0].host.as_str(), c.peers[0].port), ("127.0.0.1", 3869));
        assert_eq!(c.listen, vec![(Proto::Tcp, "127.0.0.1:3870".to_string())]);
        assert_eq!(c.auth_apps, vec![(VENDOR_3GPP, APP_CX), (VendorId(0), APP_CC)]);
        assert_eq!(c.default_routes, vec![Route { fqdn: "hss.ims.test".into(), metric: 10 }]);
        assert!(c.realm_routes.is_empty());
        assert_eq!(c.peers[0].proto, Proto::Tcp);
    }

    #[test]
    fn xml_config_transports_and_realms() {
        let x = r#"<DiameterPeer FQDN="scscf.ims.test" Realm="ims.test">
            <Peer FQDN="hss1.ims.test" Realm="ims.test" proto="tls"/>
            <Peer FQDN="hss2.ims.test" Realm="ims.test" port="3870" proto="SCTP"/>
            <Acceptor port="3868" bind="127.0.0.1"/>
            <Acceptor bind="::1" proto="tls"/>
            <Acceptor port="3869" bind="127.0.0.1" proto="sctp"/>
            <TLS certificate="/etc/c.pem" private_key="/etc/k.pem" ca_list="/etc/ca.pem" require_certificate="1"/>
            <Realm name="ims.test">
                <Route FQDN="hss2.ims.test" metric="20"/>
                <Route FQDN="hss1.ims.test" metric="10"/>
            </Realm>
            <Realm name="other.test"><Route FQDN="hss1.ims.test"/></Realm>
            <Realm name="empty.test"/>
            <DefaultRoute FQDN="hss1.ims.test" metric="5"/><DefaultRoute FQDN="hss2.ims.test" metric="1"/>
        </DiameterPeer>"#;
        let c = parse_xml_config(x).unwrap();
        assert_eq!((c.peers[0].proto, c.peers[0].port), (Proto::Tls, 5658));
        assert_eq!((c.peers[1].proto, c.peers[1].port), (Proto::Sctp, 3870));
        assert_eq!(c.listen, vec![(Proto::Tcp, "127.0.0.1:3868".into()), (Proto::Tls, "[::1]:5658".into()), (Proto::Sctp, "127.0.0.1:3869".into())]);
        assert_eq!(c.tls.ca_list.as_deref(), Some(std::path::Path::new("/etc/ca.pem")));
        assert!(c.tls.require_certificate);
        let r = |f: &str, m: u32| Route { fqdn: f.into(), metric: m };
        assert_eq!(
            c.realm_routes,
            vec![
                ("ims.test".into(), vec![r("hss2.ims.test", 20), r("hss1.ims.test", 10)]),
                ("other.test".into(), vec![r("hss1.ims.test", 0)]),
                ("empty.test".into(), vec![]),
            ]
        );
        assert_eq!(c.default_routes, vec![r("hss1.ims.test", 5), r("hss2.ims.test", 1)]);
        assert!(parse_xml_config(r#"<DiameterPeer FQDN="a" Realm="b"><Peer FQDN="x" proto="udp"/></DiameterPeer>"#).is_err());
        // Non-ASCII text and cut-off markup are errors or values, never a panic.
        let u = parse_xml_config("<!-- é --><DiameterPeer FQDN=\"hé.test\" Realm='ü'><Realm name=\"ä\"><Route FQDN=\"ö\"/></Realm><!-- ü").unwrap();
        assert_eq!((u.identity.as_str(), u.realm.as_str()), ("hé.test", "ü"));
        assert_eq!(u.realm_routes, vec![("ä".into(), vec![Route { fqdn: "ö".into(), metric: 0 }])]);
        assert!(parse_xml_config("<DiameterPeer FQDN=\"é\" Realm=\"ü\"><Realm name=\"ä\">").is_err());
        assert!(parse_xml_config("<DiameterPeer FQDN=\"é").is_err());
        // TLS without the files it needs.
        let mut bad = c.clone();
        bad.tls = TlsCfg::default();
        assert!(Peers::try_new(bad).is_err());
    }

    #[test]
    fn realm_routes_pick_by_metric() {
        let [p0, p1, p2] = free_ports::<3>();
        // Three servers; the client routes realm "r" by metric, skipping
        // the one that is down, and falls back to the default route.
        let mut srvs = vec![];
        for (i, port) in [(1, p1), (2, p2)] {
            let s = Peers::new(Config {
                auth_apps: cx(),
                identity: format!("p{i}.t"),
                realm: "t".into(),
                listen: vec![(Proto::Tcp, format!("127.0.0.1:{port}"))],
                ..Default::default()
            });
            s.add_handler(
                APP_CX,
                CMD_MAR,
                Arc::new(move |m: &Msg| {
                    let mut a = m.answer();
                    a.add(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get())).add(Avp::str(ORIGIN_HOST, None, &format!("p{i}.t")));
                    Some(a)
                }),
            );
            s.start().unwrap();
            srvs.push(s);
        }
        std::thread::sleep(Duration::from_millis(100));
        let peer = |f: &str, port| PeerCfg { fqdn: f.into(), realm: "t".into(), host: "127.0.0.1".into(), port, ..Default::default() };
        let r = |f: &str, m: u32| Route { fqdn: f.into(), metric: m };
        let cli = Peers::new(Config {
            auth_apps: cx(),
            identity: "c.t".into(),
            realm: "t".into(),
            // p0 is never up.
            peers: vec![peer("p0.t", p0), peer("p1.t", p1), peer("p2.t", p2)],
            realm_routes: vec![
                ("r".into(), vec![r("p1.t", 20), r("p0.t", 1), r("p2.t", 10)]),
                ("s".into(), vec![r("p0.t", 1)]),
                ("u".into(), vec![r("p1.t", 5), r("p2.t", 5), r("p0.t", 5)]),
            ],
            default_routes: vec![r("p2.t", 9), r("p1.t", 3)],
            tc: 1,
            ..Default::default()
        });
        cli.start().unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        while cli.peers().iter().filter(|p| p.state == "I_Open").count() < 2 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        let who = |realm: &str, host: Option<&str>| cli.request(Msg::request(CMD_MAR, APP_CX), realm, host).unwrap().str(ORIGIN_HOST).unwrap();
        assert_eq!(who("r", None), "p2.t"); // p0 (1) down, p2 (10) before p1 (20)
        assert_eq!(who("r", Some("p1.t")), "p1.t"); // Destination-Host wins
        assert_eq!(who("s", None), "p1.t"); // no open route: default routes, p1 (3) first
        assert!(["p1.t", "p2.t"].contains(&who("t", None).as_str())); // no table: a peer of the realm
        assert_eq!(who("elsewhere", None), "p1.t"); // nobody in that realm: default routes
        // Equal metrics take turns (least recently chosen first).
        let (a, b) = (who("u", None), who("u", None));
        assert!(a != b && ["p1.t", "p2.t"].contains(&a.as_str()) && ["p1.t", "p2.t"].contains(&b.as_str()), "{a} {b}");
        // p2 stops answering the watchdog: SUSPECT, routed around; any
        // traffic from it makes it the first choice again.
        let p2 = lock(&cli.conns).iter().find(|c| c.name == "p2.t").cloned().unwrap();
        let later = |s| Instant::now().checked_add(Duration::from_secs(s)).unwrap();
        assert_eq!(lock(&p2.watchdog).tick(later(31)), watchdog::Action::SendDwr);
        assert_eq!(lock(&p2.watchdog).tick(later(62)), watchdog::Action::Suspect);
        assert_eq!(cli.peers().iter().find(|p| p.fqdn == "p2.t").unwrap().state, "Suspect");
        assert_eq!(who("r", None), "p1.t");
        assert_eq!(who("u", None), "p1.t");
        lock(&p2.watchdog).received(Instant::now());
        assert_eq!(who("r", None), "p2.t");
    }

    #[test]
    fn common_applications() {
        let cfg = |auth: &[u32], acct: &[u32]| Config {
            auth_apps: auth.iter().map(|&a| (VENDOR_3GPP, AppId(a))).collect(),
            acct_apps: acct.iter().map(|&a| (VendorId(0), AppId(a))).collect(),
            ..Default::default()
        };
        let auth = |a: u32| Avp::u32(AUTH_APPLICATION_ID, None, a);
        let acct = |a: u32| Avp::u32(ACCT_APPLICATION_ID, None, a);
        let vsai = |v: u32, inner: Avp| Avp::group(VENDOR_SPECIFIC_APPLICATION_ID, None, vec![Avp::u32(VENDOR_ID, None, v), inner]);
        let cer = |avps: Vec<Avp>| Msg { avps, ..Msg::request(CMD_CE, APP_COMMON) };
        let relay = APP_RELAY.get();
        let (cx, rx, cc) = (APP_CX.get(), APP_RX.get(), APP_CC.get());
        // (our auth, our acct, their AVPs, the common applications)
        type Case = (Vec<u32>, Vec<u32>, Vec<Avp>, Vec<(AppKind, u32)>);
        let cases: Vec<Case> = vec![
            (vec![cx], vec![], vec![auth(cx)], vec![(AppKind::Auth, cx)]),
            (vec![cx], vec![], vec![vsai(10415, auth(cx))], vec![(AppKind::Auth, cx)]),
            (vec![cx], vec![], vec![vsai(5535, auth(cx))], vec![(AppKind::Auth, cx)]),
            (vec![cx, rx], vec![], vec![auth(rx), auth(cc)], vec![(AppKind::Auth, rx)]),
            (vec![cx], vec![], vec![auth(rx)], vec![]),
            (vec![cx], vec![], vec![], vec![]),
            (vec![], vec![], vec![auth(cx)], vec![]),
            // Auth and accounting are different applications.
            (vec![cc], vec![], vec![acct(cc)], vec![]),
            (vec![], vec![3], vec![acct(3), vsai(10415, acct(3))], vec![(AppKind::Acct, 3)]),
            // Relay stands for everything on the other side.
            (vec![cx, rx], vec![3], vec![auth(relay)], vec![(AppKind::Auth, cx), (AppKind::Auth, rx), (AppKind::Acct, 3)]),
            (vec![relay], vec![], vec![auth(cc), acct(3)], vec![(AppKind::Auth, cc), (AppKind::Acct, 3)]),
            (vec![relay], vec![], vec![], vec![]),
            // A vendor AVP of the same code is not an Application-Id.
            (vec![cx], vec![], vec![Avp::u32(AUTH_APPLICATION_ID, V, cx)], vec![]),
        ];
        for (i, (ours, our_acct, theirs, want)) in cases.into_iter().enumerate() {
            let got: Vec<(AppKind, u32)> = common_apps(&cfg(&ours, &our_acct), &cer(theirs)).into_iter().map(|(k, a)| (k, a.get())).collect();
            assert_eq!(got, want, "case {i}");
        }
    }

    #[test]
    fn no_common_application_is_refused_with_5010() {
        let [port] = free_ports::<1>();
        let srv = Peers::new(Config {
            auth_apps: cx(),
            identity: "hss.nca".into(),
            realm: "t".into(),
            listen: vec![(Proto::Tcp, format!("127.0.0.1:{port}"))],
            ..Default::default()
        });
        srv.start().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let cer = |app: AppId| {
            let mut m = Msg::request(CMD_CE, APP_COMMON);
            m.flags = crate::FLAG_R;
            m.add(Avp::str(ORIGIN_HOST, None, "raw.t")).add(Avp::str(ORIGIN_REALM, None, "t")).add(Avp::u32(AUTH_APPLICATION_ID, None, app.get()));
            m.try_encode().unwrap()
        };
        // A raw peer offering only Rx: CEA 5010 with our capabilities, then
        // the connection is closed.
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        std::io::Write::write_all(&mut s, &cer(APP_RX)).unwrap();
        let cea = read_msg(&mut s).unwrap();
        assert_eq!((cea.cmd, cea.is_request(), cea.result()), (CMD_CE, false, Some(DIAMETER_NO_COMMON_APPLICATION)));
        assert_eq!(cea.str(ORIGIN_HOST).as_deref(), Some("hss.nca"));
        assert!(read_msg(&mut s).is_err(), "closed after the CEA");
        assert!(srv.peers().is_empty(), "never opened");
        // The same offer with Cx is accepted.
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        std::io::Write::write_all(&mut s, &cer(APP_CX)).unwrap();
        assert_eq!(read_msg(&mut s).unwrap().result(), Some(DIAMETER_SUCCESS));
        // A connecting peer whose applications the server lacks never opens.
        let cli = Peers::new(Config {
            auth_apps: vec![(VENDOR_3GPP, APP_RX)],
            identity: "pcrf.nca".into(),
            realm: "t".into(),
            peers: vec![PeerCfg { fqdn: "hss.nca".into(), realm: "t".into(), host: "127.0.0.1".into(), port, ..Default::default() }],
            tc: 1,
            ..Default::default()
        });
        cli.start().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(cli.peers()[0].state, "Closed");
        assert!(matches!(cli.request(Msg::request(CMD_AA, APP_RX), "t", None), Err(DiameterError::NoRoute { .. })));
    }

    #[test]
    fn talk_to_ourselves() {
        let [port] = free_ports::<1>();
        // Two peer managers: one accepts, the other connects and asks.
        let srv = Peers::new(Config {
            auth_apps: cx(),
            identity: "hss.t".into(),
            realm: "t".into(),
            listen: vec![(Proto::Tcp, format!("127.0.0.1:{port}"))],
            ..Default::default()
        });
        srv.add_handler(
            APP_CX,
            CMD_MAR,
            Arc::new(|m: &Msg| {
                let mut a = m.answer();
                a.add(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get()));
                Some(a)
            }),
        );
        srv.start().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let cli = Peers::new(Config {
            auth_apps: cx(),
            identity: "scscf.t".into(),
            realm: "t".into(),
            peers: vec![PeerCfg { fqdn: "hss.t".into(), realm: "t".into(), host: "127.0.0.1".into(), port, ..Default::default() }],
            tc: 1,
            ..Default::default()
        });
        cli.start().unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        while cli.peers()[0].state != "I_Open" && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(cli.peers()[0].origin_host, "hss.t");
        let a = cli.request(Msg::request(CMD_MAR, APP_CX), "t", None).unwrap();
        assert_eq!(a.result(), Some(DIAMETER_SUCCESS));
        assert_eq!(cli.request(Msg::request(CMD_SAR, APP_CX), "t", None).unwrap().result(), Some(DIAMETER_COMMAND_UNSUPPORTED));
    }

    #[test]
    fn callback_requests_are_answered_or_time_out() {
        let [port] = free_ports::<1>();
        let srv = Peers::new(Config {
            auth_apps: cx(),
            identity: "hss.cb".into(),
            realm: "t".into(),
            listen: vec![(Proto::Tcp, format!("127.0.0.1:{port}"))],
            ..Default::default()
        });
        srv.add_handler(
            APP_CX,
            CMD_MAR,
            Arc::new(|m: &Msg| {
                let mut a = m.answer();
                a.add(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get()));
                Some(a)
            }),
        );
        // A UAR is never answered.
        srv.add_handler(APP_CX, CMD_UAR, Arc::new(|_: &Msg| None));
        srv.start().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let cli = Peers::new(Config {
            auth_apps: cx(),
            identity: "icscf.cb".into(),
            realm: "t".into(),
            peers: vec![PeerCfg { fqdn: "hss.cb".into(), realm: "t".into(), host: "127.0.0.1".into(), port, ..Default::default() }],
            tc: 1,
            timeout: Duration::from_secs(1),
            ..Default::default()
        });
        cli.start().unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        while cli.peers()[0].state != "I_Open" && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        let (tx, rx) = mpsc::channel();
        let t = tx.clone();
        cli.request_cb(Msg::request(CMD_MAR, APP_CX), "t", None, Box::new(move |r| drop(t.send(("mar", r.map(|a| a.result()))))));
        let t0 = Instant::now();
        cli.request_cb(Msg::request(CMD_UAR, APP_CX), "t", None, Box::new(move |r| drop(tx.send(("uar", r.map(|a| a.result()))))));
        let (what, r) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!((what, r.ok()), ("mar", Some(Some(DIAMETER_SUCCESS))));
        let (what, r) = rx.recv_timeout(Duration::from_secs(4)).unwrap();
        assert_eq!(what, "uar");
        assert!(r.as_ref().is_err_and(DiameterError::is_timeout), "{r:?}");
        // The cdp timeout (1s), checked by the 1s watchdog.
        assert!(t0.elapsed() >= Duration::from_millis(900) && t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        // Without a peer for the realm: an error at once.
        let (tx, rx) = mpsc::channel();
        let lone = Peers::new(Config { auth_apps: cx(), identity: "x".into(), realm: "t".into(), ..Default::default() });
        lone.request_cb(
            Msg::request(CMD_UAR, APP_CX),
            "t",
            None,
            Box::new(move |r| {
                tx.send(r.is_err()).unwrap();
            }),
        );
        assert!(rx.recv_timeout(Duration::from_millis(100)).unwrap());
    }

    #[test]
    fn a_transaction_timeout_beyond_the_clock_never_expires() {
        let [port] = free_ports::<1>();
        // request_cb must not overflow adding the timeout to Instant::now().
        let srv = Peers::new(Config {
            auth_apps: cx(),
            identity: "hss.big".into(),
            realm: "t".into(),
            listen: vec![(Proto::Tcp, format!("127.0.0.1:{port}"))],
            ..Default::default()
        });
        srv.add_handler(APP_CX, CMD_UAR, Arc::new(|_: &Msg| None));
        srv.start().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let xml = r#"<DiameterPeer FQDN="icscf.big" Realm="t" TransactionTimeout="18446744073709551615"></DiameterPeer>"#;
        let mut cfg = parse_xml_config(xml).unwrap();
        assert_eq!(cfg.timeout, Duration::from_secs(u64::MAX));
        cfg.peers = vec![PeerCfg { fqdn: "hss.big".into(), realm: "t".into(), host: "127.0.0.1".into(), port, ..Default::default() }];
        cfg.tc = 1;
        cfg.auth_apps = cx();
        let cli = Peers::new(cfg);
        cli.start().unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        while cli.peers()[0].state != "I_Open" && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        let (tx, rx) = mpsc::channel();
        cli.request_cb(Msg::request(CMD_UAR, APP_CX), "t", None, Box::new(move |r| tx.send(r.is_ok()).unwrap()));
        assert_eq!(cli.peers()[0].state, "I_Open");
        // Not answered, and not timed out by the 1s watchdog either.
        assert!(rx.recv_timeout(Duration::from_millis(1500)).is_err());
    }

    #[test]
    fn tls_both_ways_with_client_certificates() {
        let [port] = free_ports::<1>();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../etc/tls");
        let srv = Peers::new(Config {
            auth_apps: cx(),
            identity: "localhost".into(),
            realm: "t".into(),
            listen: vec![(Proto::Tls, format!("127.0.0.1:{port}"))],
            tls: TlsCfg {
                certificate: Some(dir.join("server.pem")),
                private_key: Some(dir.join("server.key.pem")),
                ca_list: Some(dir.join("ca.pem")),
                require_certificate: true,
            },
            ..Default::default()
        });
        srv.add_handler(
            APP_CX,
            CMD_MAR,
            Arc::new(|m: &Msg| {
                let mut a = m.answer();
                // Large enough to span several TLS records.
                a.add(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get())).add(Avp::new(USER_NAME, None, vec![b'x'; 70_000]));
                Some(a)
            }),
        );
        srv.start().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let client = |name: &str, cert: Option<&str>| {
            Peers::new(Config {
                auth_apps: cx(),
                identity: name.into(),
                realm: "t".into(),
                peers: vec![PeerCfg { fqdn: "localhost".into(), realm: "t".into(), host: "127.0.0.1".into(), port, proto: Proto::Tls }],
                tls: TlsCfg {
                    certificate: cert.map(|c| dir.join(format!("{c}.pem"))),
                    private_key: cert.map(|c| dir.join(format!("{c}.key.pem"))),
                    ca_list: Some(dir.join("ca.pem")),
                    require_certificate: false,
                },
                tc: 1,
                ..Default::default()
            })
        };
        let cli = client("b.test", Some("b.test"));
        cli.start().unwrap();
        let end = Instant::now() + Duration::from_secs(4);
        while cli.peers()[0].state != "I_Open" && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(cli.peers()[0].origin_host, "localhost");
        for _ in 0..3 {
            let a = cli.request(Msg::request(CMD_MAR, APP_CX), "t", None).unwrap();
            assert_eq!((a.result(), a.get(USER_NAME, None).map(|u| u.data.len())), (Some(DIAMETER_SUCCESS), Some(70_000)));
        }
        assert_eq!(cli.request(Msg::request(CMD_SAR, APP_CX), "t", None).unwrap().result(), Some(DIAMETER_COMMAND_UNSUPPORTED));
        assert!(srv.peers().iter().any(|p| p.fqdn == "b.test" && p.proto == Proto::Tls));
        // Without a client certificate the acceptor refuses the handshake.
        let anon = client("anon.test", None);
        anon.start().unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(anon.peers()[0].state, "Closed");
    }

    #[test]
    fn sctp_when_the_kernel_has_it() {
        let [port] = free_ports::<1>();
        let l = match wire::listen(Proto::Sctp, &format!("127.0.0.1:{port}")) {
            Ok(l) => l,
            // CI's sctp job sets REQUIRE_SCTP: there a missing SCTP is a failure.
            Err(e) if std::env::var_os("REQUIRE_SCTP").is_some() => panic!("REQUIRE_SCTP is set but SCTP is unavailable: {e}"),
            Err(_) => {
                eprintln!("SKIP: SCTP is not supported by this kernel");
                return;
            }
        };
        drop(l);
        let srv = Peers::new(Config {
            auth_apps: cx(),
            identity: "s.t".into(),
            realm: "t".into(),
            listen: vec![(Proto::Sctp, format!("127.0.0.1:{port}"))],
            ..Default::default()
        });
        srv.start().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let cli = Peers::new(Config {
            auth_apps: cx(),
            identity: "c.t".into(),
            realm: "t".into(),
            peers: vec![PeerCfg { fqdn: "s.t".into(), realm: "t".into(), host: "127.0.0.1".into(), port, proto: Proto::Sctp }],
            tc: 1,
            ..Default::default()
        });
        cli.start().unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        while cli.peers()[0].state != "I_Open" && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(cli.request(Msg::request(CMD_SAR, APP_CX), "t", None).unwrap().result(), Some(DIAMETER_COMMAND_UNSUPPORTED));
    }

    #[test]
    fn sctp_connect_fails_cleanly_without_a_listener_or_kernel_support() {
        let [port] = free_ports::<1>();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        // Unsupported kernel: "SCTP is not supported"; otherwise refused.
        assert!(wire::connect(Proto::Sctp, &addr, Duration::from_secs(1)).is_err());
    }

    /// A connected loopback pair: (our end, the raw peer's end).
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let raw = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (ours, _) = l.accept().unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        (ours, raw)
    }

    /// An open connection to `name` (realm "t") over `sock`, registered in
    /// `p`; returns it and its reading half.
    fn open_conn(p: &Peers, name: &str, sock: TcpStream) -> (Arc<Conn>, Reader) {
        let (rd, w) = wire::split(sock, None).unwrap();
        let c = Arc::new(Conn {
            name: name.into(),
            realm: "t".into(),
            origin_host: name.into(),
            proto: Proto::Tcp,
            writer: Arc::new(w),
            watchdog: Mutex::new(Watchdog::new(Duration::from_secs(30), Instant::now())),
            last_selected: Mutex::new(None),
        });
        lock(&p.conns).push(c.clone());
        (c, rd)
    }

    fn manager(identity: &str) -> Arc<Peers> {
        Peers::new(Config { auth_apps: cx(), identity: identity.into(), realm: "t".into(), ..Default::default() })
    }

    fn put(s: &mut TcpStream, b: &[u8]) {
        std::io::Write::write_all(s, b).unwrap();
    }

    fn request_bytes(cmd: CmdCode, app: AppId, hbh: u32) -> Vec<u8> {
        let mut m = Msg::request(cmd, app);
        m.hbh = hbh;
        m.add(Avp::str(SESSION_ID, None, "s;1"));
        m.encode()
    }

    #[test]
    fn an_open_connection_answers_cer_and_dwr_and_closes_on_dpr() {
        let p = manager("hss.rd");
        let (ours, mut raw) = tcp_pair();
        let (c, rd) = open_conn(&p, "peer.rd", ours);
        let me = p.clone();
        let t = std::thread::spawn(move || me.reader(c, rd));
        // An answer nobody waits for is dropped.
        let mut stray = Msg::request(CMD_MAR, APP_CX).answer();
        stray.hbh = 99;
        put(&mut raw, &stray.encode());
        // A CER on an open connection is answered with our capabilities.
        put(&mut raw, &request_bytes(CMD_CE, APP_COMMON, 1));
        let cea = read_msg(&mut raw).unwrap();
        assert_eq!((cea.cmd, cea.hbh, cea.is_request(), cea.result()), (CMD_CE, 1, false, Some(DIAMETER_SUCCESS)));
        assert_eq!(cea.str(ORIGIN_HOST).as_deref(), Some("hss.rd"));
        assert_eq!(cea.get(HOST_IP_ADDRESS, None).unwrap().data, [0, 1, 127, 0, 0, 1], "the local address of the connection");
        assert!(cea.get(VENDOR_SPECIFIC_APPLICATION_ID, None).is_some(), "Cx advertised");
        // DWR: success, the Session-Id copied, our Origin-State-Id.
        put(&mut raw, &request_bytes(CMD_DW, APP_COMMON, 2));
        let dwa = read_msg(&mut raw).unwrap();
        assert_eq!((dwa.cmd, dwa.hbh, dwa.result()), (CMD_DW, 2, Some(DIAMETER_SUCCESS)));
        assert_eq!(dwa.str(SESSION_ID).as_deref(), Some("s;1"));
        assert_eq!(dwa.get(ORIGIN_STATE_ID, None).and_then(Avp::as_u32), Some(p.state_id));
        // DPR: answered, then the connection is closed and forgotten.
        put(&mut raw, &request_bytes(CMD_DP, APP_COMMON, 3));
        let dpa = read_msg(&mut raw).unwrap();
        assert_eq!((dpa.cmd, dpa.hbh, dpa.result()), (CMD_DP, 3, Some(DIAMETER_SUCCESS)));
        t.join().unwrap();
        assert!(read_msg(&mut raw).is_err(), "closed after the DPA");
        assert!(lock(&p.conns).is_empty() && p.peers().is_empty());
    }

    #[test]
    fn panicking_handlers_answer_unable_to_comply() {
        let p = manager("hss.panic");
        p.add_handler(APP_CX, CMD_MAR, Arc::new(|_: &Msg| panic!("handler bug")));
        let (ours, mut raw) = tcp_pair();
        let (c, rd) = open_conn(&p, "peer.panic", ours);
        let me = p.clone();
        let t = std::thread::spawn(move || me.reader(c, rd));
        put(&mut raw, &request_bytes(CMD_MAR, APP_CX, 1));
        let a = read_msg(&mut raw).unwrap();
        assert_eq!((a.cmd, a.hbh, a.result()), (CMD_MAR, 1, Some(DIAMETER_UNABLE_TO_COMPLY)));
        assert_eq!((a.str(ORIGIN_HOST).as_deref(), a.str(SESSION_ID).as_deref()), (Some("hss.panic"), Some("s;1")));
        // The fallback (on a thread of its own) panicking answers the same.
        p.set_fallback_handler(Arc::new(|_: &Msg| panic!("fallback bug")));
        put(&mut raw, &request_bytes(CMD_SAR, APP_CX, 2));
        let a = read_msg(&mut raw).unwrap();
        assert_eq!((a.cmd, a.hbh, a.result()), (CMD_SAR, 2, Some(DIAMETER_UNABLE_TO_COMPLY)));
        // The reader survived both.
        put(&mut raw, &request_bytes(CMD_DP, APP_COMMON, 3));
        assert_eq!(read_msg(&mut raw).unwrap().cmd, CMD_DP);
        t.join().unwrap();
    }

    #[test]
    fn accept_closes_connections_that_do_not_start_with_a_cer() {
        let p = manager("hss.acc");
        let mut cea = Msg::request(CMD_CE, APP_COMMON).answer();
        cea.add(Avp::u32(AUTH_APPLICATION_ID, None, APP_CX.get()));
        // (first message, what it is)
        let cases = [(request_bytes(CMD_DW, APP_COMMON, 1), "a DWR"), (cea.encode(), "a CEA (an answer)"), (vec![2, 0, 0, 20], "not Diameter")];
        for (first, what) in cases {
            let (ours, mut raw) = tcp_pair();
            put(&mut raw, &first);
            p.accept(Proto::Tcp, ours);
            assert!(read_msg(&mut raw).is_err(), "{what}: closed without an answer");
            assert!(lock(&p.conns).is_empty(), "{what}: not opened");
        }
        // A TLS connection without a TLS server configuration.
        let (ours, mut raw) = tcp_pair();
        put(&mut raw, &request_bytes(CMD_CE, APP_COMMON, 1));
        p.accept(Proto::Tls, ours);
        assert!(read_msg(&mut raw).is_err());
        assert!(lock(&p.conns).is_empty());
    }

    #[test]
    fn a_cea_without_a_common_application_is_not_opened() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        // A raw server answering 2001 but offering only Rx.
        let srv = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let cer = read_msg(&mut s).unwrap();
            let mut a = cer.answer();
            a.add(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get())).add(Avp::str(ORIGIN_HOST, None, "pcrf.t")).add(Avp::u32(
                AUTH_APPLICATION_ID,
                None,
                APP_RX.get(),
            ));
            put(&mut s, &a.encode());
            (cer.cmd, read_msg(&mut s).is_err())
        });
        let p = manager("scscf.nca");
        let pc = PeerCfg { fqdn: "pcrf.t".into(), realm: "t".into(), host: "127.0.0.1".into(), port, ..Default::default() };
        let e = p.connect_once(&pc).unwrap_err();
        assert!(e.to_string().contains("pcrf.t supports none of our applications"), "{e}");
        assert_eq!(srv.join().unwrap(), (CMD_CE, true), "a CER, then the connection closed");
        assert!(lock(&p.conns).is_empty());
    }

    #[test]
    fn request_keeps_the_callers_routing_avps_and_times_out() {
        let p = Peers::new(Config { auth_apps: cx(), identity: "icscf.to".into(), realm: "t".into(), timeout: Duration::from_millis(1), ..Default::default() });
        let (ours, mut raw) = tcp_pair();
        let _conn = open_conn(&p, "hss.to", ours);
        let m = Msg::request(CMD_UAR, APP_CX).with(Avp::str(ORIGIN_HOST, None, "other.t")).with(Avp::str(ORIGIN_REALM, None, "o")).with(Avp::str(
            DESTINATION_HOST,
            None,
            "hss.x",
        ));
        let e = p.request(m, "t", Some("hss.to")).unwrap_err();
        assert!(matches!(&e, DiameterError::Timeout { peer: Some(n) } if n == "hss.to"), "{e:?}");
        assert!(lock(&p.pending).is_empty(), "the waiter is gone");
        let sent = read_msg(&mut raw).unwrap();
        let all = |c| sent.get_all(c, None).iter().map(|a| a.as_str()).collect::<Vec<_>>();
        assert_eq!(all(ORIGIN_HOST), ["other.t"]);
        assert_eq!(all(ORIGIN_REALM), ["o"]);
        assert_eq!(all(DESTINATION_REALM), ["t"]);
        assert_eq!(all(DESTINATION_HOST), ["hss.x"]);
        assert!(sent.is_request());
    }

    #[test]
    fn a_failed_write_is_a_send_error_for_every_way_of_sending() {
        let p = manager("icscf.w");
        let (ours, _raw) = tcp_pair();
        ours.shutdown(std::net::Shutdown::Write).unwrap();
        let _conn = open_conn(&p, "hss.w", ours);
        let send_err = |e: &DiameterError| matches!(e, DiameterError::Send { peer, .. } if peer == "hss.w");
        let e = p.request(Msg::request(CMD_UAR, APP_CX), "t", None).unwrap_err();
        assert!(send_err(&e), "{e:?}");
        let (tx, rx) = mpsc::channel();
        p.request_cb(Msg::request(CMD_UAR, APP_CX), "t", None, Box::new(move |r| tx.send(r.map(|_| ())).unwrap()));
        let r = rx.try_recv().expect("called before request_cb returns");
        assert!(r.as_ref().is_err_and(send_err), "{r:?}");
        assert!(lock(&p.pending).is_empty(), "no waiter left behind");
        let e = p.send(Msg::request(CMD_UAR, APP_CX), "t").unwrap_err();
        assert!(send_err(&e), "{e:?}");
    }

    #[test]
    fn send_writes_with_fresh_ids_and_refuses_what_cannot_be_encoded() {
        let p = manager("pcscf.s");
        assert!(matches!(p.send(Msg::request(CMD_AA, APP_RX), "t"), Err(DiameterError::NoRoute { realm }) if realm == "t"));
        let (ours, mut raw) = tcp_pair();
        let (conn, _rd) = open_conn(&p, "pcrf.s", ours);
        // A command code over 24 bits: refused by every sender, nothing written.
        let bad = Msg::request(CmdCode(1 << 24), APP_RX);
        assert!(matches!(p.send(bad.clone(), "t"), Err(DiameterError::Encode(_))));
        assert!(matches!(p.request(bad.clone(), "t", None), Err(DiameterError::Encode(_))));
        let (tx, rx) = mpsc::channel();
        p.request_cb(bad.clone(), "t", None, Box::new(move |r| tx.send(matches!(r, Err(DiameterError::Encode(_)))).unwrap()));
        assert!(rx.try_recv().unwrap());
        assert_eq!(Peers::write(&conn.writer, &bad).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        assert!(lock(&p.pending).is_empty());
        let m = Msg::request(CMD_AA, APP_RX).with(Avp::str(SESSION_ID, None, "s;2"));
        p.send(m.clone(), "t").unwrap();
        p.send(m, "t").unwrap();
        let (a, b) = (read_msg(&mut raw).unwrap(), read_msg(&mut raw).unwrap());
        assert_eq!((a.cmd, a.str(SESSION_ID).as_deref()), (CMD_AA, Some("s;2")), "the first thing written");
        assert_eq!((b.hbh.wrapping_sub(a.hbh), b.e2e.wrapping_sub(a.e2e)), (1, 1), "fresh ids each time");
        assert!(lock(&p.pending).is_empty(), "answers are not waited for");
    }

    #[test]
    fn expire_callbacks_fires_only_the_overdue_ones() {
        let p = Peers::new(Config::default());
        let (tx, rx) = mpsc::channel();
        let cb = |name: &'static str| -> AnswerFn {
            let tx = tx.clone();
            Box::new(move |r| tx.send((name, matches!(r, Err(DiameterError::Timeout { peer: None })))).unwrap())
        };
        let now = Instant::now();
        {
            let mut w = lock(&p.pending);
            w.insert(1, Waiter::Cb(cb("overdue"), Some(now)));
            w.insert(2, Waiter::Cb(cb("later"), now.checked_add(Duration::from_secs(3600))));
            w.insert(3, Waiter::Cb(cb("never"), None));
            w.insert(4, Waiter::Chan(mpsc::channel().0));
        }
        p.expire_callbacks();
        assert_eq!(rx.try_recv().unwrap(), ("overdue", true));
        assert!(rx.try_recv().is_err(), "only one called");
        let mut left: Vec<u32> = lock(&p.pending).keys().copied().collect();
        left.sort_unstable();
        assert_eq!(left, [2, 3, 4]);
    }

    #[test]
    fn tls_setup_needs_its_files() {
        let err = |cfg: Config| match Peers::try_new(cfg) {
            Ok(_) => String::new(),
            Err(e) => e,
        };
        let tls_peer = PeerCfg { fqdn: "hss.t".into(), proto: Proto::Tls, ..Default::default() };
        let e = err(Config { peers: vec![tls_peer.clone()], ..Default::default() });
        assert!(e.contains("need ca_list"), "{e}");
        let e = err(Config { listen: vec![(Proto::Tls, "127.0.0.1:0".into())], ..Default::default() });
        assert!(e.contains("needs a certificate and private_key"), "{e}");
        let missing = TlsCfg { ca_list: Some("/nonexistent/ca.pem".into()), ..Default::default() };
        let e = err(Config { peers: vec![tls_peer], tls: missing, ..Default::default() });
        assert!(e.starts_with("Diameter TLS: "), "{e}");
        // TCP needs no TLS files.
        assert!(Peers::try_new(Config { listen: vec![(Proto::Tcp, "127.0.0.1:0".into())], ..Default::default() }).is_ok());
    }

    #[test]
    fn xml_attribute_values_must_be_quoted() {
        // An unquoted value (or none at all) ends the attribute list.
        for x in [r#"<DiameterPeer FQDN=a.t Realm="t"/>"#, r#"<DiameterPeer Realm="t" FQDN="#] {
            let e = parse_xml_config(x).unwrap_err();
            assert!(e.contains("FQDN missing"), "{x}: {e}");
        }
        let c = parse_xml_config(r#"<DiameterPeer FQDN="a.t" Realm="t"><Peer FQDN="h" port=3869/></DiameterPeer>"#).unwrap();
        assert_eq!(c.peers[0].port, 3868, "the unquoted port is ignored");
    }

    #[test]
    fn peer_realm_prefers_the_connection_then_the_config() {
        let cfg_peer = |f: &str, r: &str| PeerCfg { fqdn: f.into(), realm: r.into(), ..Default::default() };
        let p = Peers::new(Config { peers: vec![cfg_peer("hss.a", "cfg.t"), cfg_peer("norealm", "")], ..Default::default() });
        assert_eq!(p.peer_realm("hss.a").as_deref(), Some("cfg.t"));
        assert_eq!(p.peer_realm("norealm"), None, "an empty realm is none");
        assert_eq!(p.peer_realm("unknown"), None);
        let (ours, _raw) = tcp_pair();
        let _conn = open_conn(&p, "hss.a", ours);
        assert_eq!(p.peer_realm("hss.a").as_deref(), Some("t"), "the realm of the open connection");
    }

    #[test]
    fn start_survives_an_address_it_cannot_listen_on() {
        let p = Peers::new(Config { listen: vec![(Proto::Tcp, "not an address".into())], ..Default::default() });
        assert!(p.start().is_ok());
    }

    #[test]
    fn inbound_connections_beyond_the_limit_are_closed() {
        let [port] = free_ports::<1>();
        let p = Peers::new(Config { auth_apps: cx(), listen: vec![(Proto::Tcp, format!("127.0.0.1:{port}"))], ..Default::default() });
        // The acceptor listens before start() returns.
        p.start().unwrap();
        // MAX_INBOUND connections that never send a CER hold every slot.
        let held: Vec<TcpStream> = (0..MAX_INBOUND).map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap()).collect();
        let mut extra = TcpStream::connect(("127.0.0.1", port)).unwrap();
        extra.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let e = read_msg(&mut extra).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "closed at once: {e}");
        drop(held);
    }
}
