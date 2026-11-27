//! Drivers: one engine on its own thread, fed by one bounded input queue
//! (received messages, commands, DNS results, closed flows), with bounded
//! event delivery and DNS resolution on a helper thread.
//!
//! Two front ends share that loop:
//!
//! - [`spawn_udp`]: a plain std UDP socket (tests, small tools);
//! - [`spawn_transport`] (feature `transport`, on by default): ferrosip's
//!   own transport layer, `sip-transport` — UDP workers, TCP, TLS, WS and
//!   WSS, the connection table and outbound connects — with the engine as
//!   its message handler. In-dialog requests reuse the connection a dialog
//!   was established on (connection id in the leg's flow).
//!
//! The engine thread never waits for the application or for DNS.

use crate::api::{Accepted, CommandError, EventEnvelope, UaCommand, UaEvent};
use crate::engine::{ResolveRequest, Transmit, UaConfig, UaEngine};
use crate::ids::{Generation, IdAllocator, OperationId, SystemEntropy, UaLegId};
use sip_core::{Dest, Proto};
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
#[cfg(feature = "transport")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// RFC 3263 resolution, called on a helper thread (it may block).
pub trait Resolver: Send + 'static {
    fn resolve(&self, req: &ResolveRequest) -> Result<Vec<Dest>, String>;
}

/// ferrosip's resolver (NAPTR → SRV → A/AAAA, with its cache).
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, r: &ResolveRequest) -> Result<Vec<Dest>, String> {
        let v: Vec<Dest> = sip_core::dns::resolver().resolve_uri(&r.host, r.port, r.proto, r.secure).into_iter().collect();
        if v.is_empty() { Err(format!("{}: no address", r.host)) } else { Ok(v) }
    }
}

enum Input {
    Cmd(OperationId, UaCommand),
    Packet(Vec<u8>, Dest),
    #[cfg_attr(not(feature = "transport"), allow(dead_code, reason = "only the transport front end reports closed flows"))]
    FlowClosed(Dest),
    Resolved(u64, Result<Vec<Dest>, String>),
    Drain,
    Shutdown,
}

/// Sizes of the bounded queues.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeConfig {
    /// Commands and received messages waiting for the engine thread.
    pub input_capacity: usize,
    pub event_capacity: usize,
    pub resolve_capacity: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self { input_capacity: 8_192, event_capacity: 4_096, resolve_capacity: 256 }
    }
}

/// Counters of a running driver.
#[derive(Debug, Default)]
pub struct RuntimeStats {
    /// Received messages dropped because the input queue was full.
    pub dropped_input: AtomicU64,
    /// New requests answered 503 by the transport for the same reason.
    pub refused_input: AtomicU64,
}

/// The application's side of a running engine.
pub struct UaHandle {
    input: SyncSender<Input>,
    events: Receiver<EventEnvelope>,
    ids: IdAllocator,
    local: Vec<(Proto, SocketAddr)>,
    stats: Arc<RuntimeStats>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl UaHandle {
    /// Queue a command without waiting. Ids are allocated here, so the
    /// returned leg/operation are valid at once; if the engine then refuses
    /// the command, a `CommandRejected` event (seq 0) carries the error.
    pub fn submit(&self, mut cmd: UaCommand) -> Result<Accepted, CommandError> {
        let op = self.ids.op();
        let leg = match &mut cmd {
            UaCommand::Originate(o) => *o.leg.get_or_insert_with(|| self.ids.leg()),
            other => other.leg().ok_or(CommandError::UnknownLeg)?,
        };
        match self.input.try_send(Input::Cmd(op, cmd)) {
            Ok(()) => Ok(Accepted { op, leg }),
            Err(TrySendError::Full(_)) => Err(CommandError::Overloaded),
            Err(TrySendError::Disconnected(_)) => Err(CommandError::InvalidState("engine stopped")),
        }
    }

    pub fn events(&self) -> &Receiver<EventEnvelope> {
        &self.events
    }

    /// The first advertised address (UDP when there is one).
    pub fn local_addr(&self) -> SocketAddr {
        self.local.iter().find(|(p, _)| *p == Proto::Udp).or_else(|| self.local.first()).map_or(SocketAddr::from(([0, 0, 0, 0], 0)), |(_, a)| *a)
    }

    /// The address advertised for `proto`.
    pub fn local_addr_for(&self, proto: Proto) -> Option<SocketAddr> {
        self.local.iter().find(|(p, _)| *p == proto).map(|(_, a)| *a)
    }

    pub fn stats(&self) -> &RuntimeStats {
        &self.stats
    }

    /// Graceful drain: new calls get 503, established ones continue.
    pub fn drain(&self) {
        let _ = self.input.send(Input::Drain);
    }

    /// Stop the engine thread (and the UDP reader). Transport workers of
    /// [`spawn_transport`] live as long as the process, like ferrosip's.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.input.send(Input::Shutdown);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for UaHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.input.try_send(Input::Shutdown);
    }
}

type SendFn = Box<dyn Fn(&Transmit) -> bool + Send>;

/// Start the engine and resolver threads around `send`.
fn spawn_engine(cfg: UaConfig, resolver: Box<dyn Resolver>, rt: RuntimeConfig, send: SendFn) -> io::Result<(UaHandle, SyncSender<Input>)> {
    let ids = IdAllocator::new();
    let local = cfg.local.clone();
    let engine = UaEngine::with_entropy(cfg, Box::new(SystemEntropy::default()), ids.clone());
    let (in_tx, in_rx) = mpsc::sync_channel(rt.input_capacity.max(1));
    let (ev_tx, ev_rx) = mpsc::sync_channel(rt.event_capacity.max(1));
    let (res_tx, res_rx) = mpsc::sync_channel::<ResolveRequest>(rt.resolve_capacity.max(1));
    let back = in_tx.clone();
    std::thread::Builder::new().name("sip-ua-dns".into()).spawn(move || {
        for r in res_rx {
            let out = resolver.resolve(&r);
            if back.send(Input::Resolved(r.id, out)).is_err() {
                break;
            }
        }
    })?;
    let t = std::thread::Builder::new().name("sip-ua".into()).spawn(move || run(engine, in_rx, ev_tx, res_tx, send))?;
    let handle = UaHandle { input: in_tx.clone(), events: ev_rx, ids, local, stats: Arc::default(), stop: Arc::new(AtomicBool::new(false)), threads: vec![t] };
    Ok((handle, in_tx))
}

/// Bind `bind` (UDP) and run an engine on it. When `cfg.local` has no UDP
/// address, the bound one is advertised (so bind a concrete IP).
pub fn spawn_udp(mut cfg: UaConfig, bind: SocketAddr, resolver: Box<dyn Resolver>, rt: RuntimeConfig) -> io::Result<UaHandle> {
    let sock = UdpSocket::bind(bind)?;
    let local = sock.local_addr()?;
    if !cfg.local.iter().any(|(p, _)| *p == Proto::Udp) {
        if local.ip().is_unspecified() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bind a concrete address or set UaConfig::local"));
        }
        cfg.local.push((Proto::Udp, local));
    }
    let out = sock.try_clone()?;
    let send: SendFn = Box::new(move |t| t.dest.proto == Proto::Udp && out.send_to(&t.data, t.dest.addr).is_ok());
    let (mut handle, input) = spawn_engine(cfg, resolver, rt, send)?;
    let (stop, stats) = (handle.stop.clone(), handle.stats.clone());
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let reader = std::thread::Builder::new().name("sip-ua-udp".into()).spawn(move || {
        let mut buf = vec![0u8; 65_535];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
            let data = buf.get(..n).unwrap_or_default().to_vec();
            match input.try_send(Input::Packet(data, Dest::new(Proto::Udp, from))) {
                Ok(()) => {}
                // UDP: the sender retransmits.
                Err(TrySendError::Full(_)) => {
                    stats.dropped_input.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    })?;
    handle.threads.push(reader);
    Ok(handle)
}

/// Run an engine on ferrosip's transport layer (`sip-transport`): every
/// listener of `tcfg` (UDP, TCP, TLS, WS, WSS) delivers to the engine, and
/// the engine sends through the same connection table, dialling outbound
/// TCP/TLS/WS connections as needed. Addresses the transport advertises are
/// used for Via/Contact unless `cfg.local` names one for that transport.
#[cfg(feature = "transport")]
pub fn spawn_transport(mut cfg: UaConfig, tcfg: &sip_transport::Config, resolver: Box<dyn Resolver>, rt: RuntimeConfig) -> Result<UaHandle, String> {
    use sip_core::Outbound;

    // The transport needs its handler before it starts, and the engine needs
    // the transport's send side: connect them through a late-bound slot.
    let net_slot: Arc<Mutex<Option<Arc<sip_transport::Net>>>> = Arc::default();
    let slot = net_slot.clone();
    let send: SendFn = Box::new(move |t| {
        let net = slot.lock().ok().and_then(|g| g.clone());
        net.is_some_and(|n| n.send(&t.dest, &t.data).is_ok())
    });
    // Advertised addresses are known once the listeners are bound; until
    // `spawn_engine` runs the engine has none, so bind first.
    let handler = Arc::new(Front { input: Mutex::new(None), stats: Arc::default() });
    let (net, _workers) = sip_transport::start(tcfg, handler.clone())?;
    for p in Proto::ALL {
        if !cfg.local.iter().any(|(q, _)| *q == p)
            && let Some(a) = net.advertise(p)
        {
            cfg.local.push((p, a));
        }
    }
    if let Ok(mut g) = net_slot.lock() {
        *g = Some(net);
    }
    let (mut handle, input) = spawn_engine(cfg, resolver, rt, send).map_err(|e| e.to_string())?;
    handle.stats = handler.stats.clone();
    if let Ok(mut g) = handler.input.lock() {
        *g = Some(input);
    }
    Ok(handle)
}

/// The transport's message handler: copies each message into the engine's
/// input queue (the receive buffer is reused by the worker).
#[cfg(feature = "transport")]
struct Front {
    input: Mutex<Option<SyncSender<Input>>>,
    stats: Arc<RuntimeStats>,
}

#[cfg(feature = "transport")]
impl sip_core::Handler for Front {
    fn handle(&self, ctx: &mut sip_core::Ctx<'_, '_>) {
        let Some(tx) = self.input.lock().ok().and_then(|g| g.clone()) else { return };
        match tx.try_send(Input::Packet(ctx.msg.buf.to_vec(), ctx.src)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // Overload: refuse new requests at once rather than letting
                // them retransmit into a full queue; responses and ACKs are
                // dropped (their senders retransmit).
                let new_request = matches!(ctx.msg.method(), Some(m) if m != sip_parser::Method::Ack);
                if new_request {
                    self.stats.refused_input.fetch_add(1, Ordering::Relaxed);
                    let _ = ctx.reply_with(503, "Service Unavailable", b"Retry-After: 2\r\n");
                } else {
                    self.stats.dropped_input.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    fn transport_event(&self, ev: &sip_core::TransportEvent) {
        let sip_core::TransportEvent::Closed { conn, .. } = ev;
        if let Some(tx) = self.input.lock().ok().and_then(|g| g.clone()) {
            // Must not be lost: block briefly rather than drop it.
            let _ = tx.send(Input::FlowClosed(*conn));
        }
    }
}

fn run(mut engine: UaEngine, input: Receiver<Input>, events: SyncSender<EventEnvelope>, resolves: SyncSender<ResolveRequest>, send: SendFn) {
    let start = Instant::now();
    let now = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    // Events the channel had no room for yet (engine events stay in the
    // engine's bounded queue until this is empty).
    let mut outbox: VecDeque<EventEnvelope> = VecDeque::new();
    // Resolutions the helper had no room for.
    let mut unresolved: VecDeque<ResolveRequest> = VecDeque::new();
    loop {
        // Wait for input, at most until the next timer; poll quickly while
        // output is backed up.
        let backed_up = !outbox.is_empty() || !unresolved.is_empty();
        let wait = engine.next_timeout().map_or(1_000, |t| t.saturating_sub(now())).min(if backed_up { 5 } else { 1_000 });
        let first = match input.recv_timeout(Duration::from_millis(wait)) {
            Ok(i) => Some(i),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let mut next = first;
        // Take what is queued now (bounded, so timers and output keep up).
        let mut budget = 256u32;
        while let Some(i) = next.take() {
            match i {
                Input::Cmd(op, cmd) => {
                    let leg = cmd.leg().unwrap_or(UaLegId(0));
                    if let Err(e) = engine.submit_with(op, cmd, now()) {
                        let event = UaEvent::CommandRejected(e);
                        outbox.push_back(EventEnvelope { leg, seq: 0, generation: Generation(0), op: Some(op), dialog: None, event });
                    }
                }
                Input::Packet(data, src) => engine.handle_message(&data, src, now()),
                Input::FlowClosed(conn) => engine.handle_flow_closed(&conn),
                Input::Resolved(id, r) => engine.resolved(id, r, now()),
                Input::Drain => engine.drain(),
                Input::Shutdown => return,
            }
            budget = budget.saturating_sub(1);
            if budget == 0 {
                break;
            }
            next = match input.try_recv() {
                Ok(i) => Some(i),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => return,
            };
        }
        engine.handle_timeout(now());
        while let Some(t) = engine.poll_transmit() {
            if !send(&t)
                && let Some(id) = t.txn
            {
                engine.handle_send_error(id, now());
            }
        }
        while let Some(r) = engine.poll_resolve() {
            unresolved.push_back(r);
        }
        while let Some(r) = unresolved.pop_front() {
            match resolves.try_send(r) {
                Ok(()) => {}
                Err(TrySendError::Full(r)) => {
                    unresolved.push_front(r);
                    break;
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
        loop {
            let next = match outbox.pop_front() {
                Some(e) => e,
                None => match engine.poll_event() {
                    Some(e) => e,
                    None => break,
                },
            };
            match events.try_send(next) {
                Ok(()) => {}
                Err(TrySendError::Full(e)) => {
                    outbox.push_front(e);
                    break;
                }
                // The application is gone: keep running SIP (teardown still works).
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
    }
}
