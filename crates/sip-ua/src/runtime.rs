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
//!
//! Sharding (`RuntimeConfig::shards` > 1): that many engines, each on its
//! own thread, behind the same listeners. Received messages are routed by
//! Call-ID, commands by leg id (see [`crate::shard`]); events of all
//! shards arrive on the one event channel (`seq` is per leg, `log_seq` per
//! shard). One DNS thread serves every shard.

use crate::api::{Accepted, CommandError, EventEnvelope, UaCommand, UaEvent};
use crate::engine::{ResolveRequest, Transmit, UaConfig, UaEngine};
use crate::fence::EgressFence;
use crate::ids::{Generation, IdAllocator, OperationId, SystemEntropy, UaLegId};
use crate::shard::{Shard, shard_for_message, shard_of_leg};
use sip_core::{Dest, Proto};
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
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
    Lease(Instant),
    Drain,
    Shutdown,
}

/// Sizes of the bounded queues.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Commands and received messages waiting for the engine thread.
    pub input_capacity: usize,
    pub event_capacity: usize,
    pub resolve_capacity: usize,
    /// Owner epoch the engine starts with (from the ownership authority).
    pub epoch: u64,
    /// Egress fence: a transmit of an older epoch is dropped, and the
    /// engine halts (its ownership is gone). See [`EgressFence`].
    pub egress_fence: Option<EgressFence>,
    /// Engines (threads) behind the listeners; 1: no sharding.
    pub shards: u32,
    /// Ownership lease the engines start with (see [`UaHandle::renew_lease`]).
    pub lease_until: Option<Instant>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self { input_capacity: 8_192, event_capacity: 4_096, resolve_capacity: 256, epoch: 0, egress_fence: None, shards: 1, lease_until: None }
    }
}

/// Counters of a running driver.
#[derive(Debug, Default)]
pub struct RuntimeStats {
    /// Received messages dropped because the input queue was full.
    pub dropped_input: AtomicU64,
    /// New requests answered 503 by the transport for the same reason.
    pub refused_input: AtomicU64,
    /// Transmits the egress fence refused (each halts the engine).
    pub fenced: AtomicU64,
}

/// The application's side of a running engine.
/// Called by the engine thread whenever events were queued for the
/// application (an async adapter wakes its task with it).
pub type EventWaker = Arc<dyn Fn() + Send + Sync>;

pub struct UaHandle {
    /// One input queue and id allocator per shard.
    inputs: Vec<SyncSender<Input>>,
    ids: Vec<IdAllocator>,
    /// Round robin for new outbound calls.
    next_shard: AtomicUsize,
    events: Receiver<EventEnvelope>,
    waker: Arc<Mutex<Option<EventWaker>>>,
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
        let n = u32::try_from(self.inputs.len()).unwrap_or(1);
        let (shard, leg) = match &mut cmd {
            UaCommand::Originate(o) => {
                let s = match o.leg {
                    Some(l) => shard_of_leg(l, n),
                    None => u32::try_from(self.next_shard.fetch_add(1, Ordering::Relaxed).checked_rem(self.inputs.len()).unwrap_or(0)).unwrap_or(0),
                };
                let ids = self.ids.get(s as usize).ok_or(CommandError::UnknownLeg)?;
                (s, *o.leg.get_or_insert_with(|| ids.leg()))
            }
            other => {
                let l = other.leg().ok_or(CommandError::UnknownLeg)?;
                (shard_of_leg(l, n), l)
            }
        };
        let (Some(ids), Some(input)) = (self.ids.get(shard as usize), self.inputs.get(shard as usize)) else { return Err(CommandError::UnknownLeg) };
        let op = ids.op();
        match input.try_send(Input::Cmd(op, cmd)) {
            Ok(()) => Ok(Accepted { op, leg }),
            Err(TrySendError::Full(_)) => Err(CommandError::Overloaded),
            Err(TrySendError::Disconnected(_)) => Err(CommandError::InvalidState("engine stopped")),
        }
    }

    /// The event channel (blocking receives belong on a thread of the
    /// application's own, not on an async runtime's worker).
    pub fn events(&self) -> &Receiver<EventEnvelope> {
        &self.events
    }

    /// The next event if one is ready; never blocks.
    pub fn try_event(&self) -> Option<EventEnvelope> {
        self.events.try_recv().ok()
    }

    /// Be called (from the engine thread) whenever events are queued: an
    /// async consumer wakes its task (e.g. `tokio::sync::Notify`) and then
    /// drains `try_event`, so no runtime worker ever blocks on a receive.
    /// The waker must not block.
    pub fn set_event_waker(&self, waker: EventWaker) {
        if let Ok(mut g) = self.waker.lock() {
            *g = Some(waker);
        }
        // Events may already be waiting.
        if let Ok(g) = self.waker.lock()
            && let Some(w) = g.as_ref()
        {
            w();
        }
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
        for i in &self.inputs {
            let _ = i.send(Input::Drain);
        }
    }

    /// Self-fencing: every engine halts by itself at `until` unless the
    /// lease is renewed before (see `UaEngine::set_lease` for how to pick
    /// `until` safely). Renewals only move it forward.
    pub fn renew_lease(&self, until: Instant) -> Result<(), CommandError> {
        for i in &self.inputs {
            // Must not be lost; block briefly rather than drop it.
            i.send(Input::Lease(until)).map_err(|_| CommandError::InvalidState("engine stopped"))?;
        }
        Ok(())
    }

    /// Engines (shards) behind this handle.
    pub fn shards(&self) -> usize {
        self.inputs.len()
    }

    /// Stop the engine thread (and the UDP reader). Transport workers of
    /// [`spawn_transport`] live as long as the process, like ferrosip's.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for i in &self.inputs {
            let _ = i.send(Input::Shutdown);
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for UaHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for i in &self.inputs {
            let _ = i.try_send(Input::Shutdown);
        }
    }
}

type SendFn = Box<dyn Fn(&Transmit) -> bool + Send>;

/// What the engine thread shares with the handle.
struct Shared {
    /// The engine clock's origin.
    start: Instant,
    waker: Arc<Mutex<Option<EventWaker>>>,
    fence: Option<EgressFence>,
    stats: Arc<RuntimeStats>,
    shard: usize,
}

/// Start `rt.shards` engine threads (each sending with a `make_send()`)
/// and one resolver thread. Returns the handle and the shards' inputs.
fn spawn_engines(
    cfg: UaConfig,
    resolver: Box<dyn Resolver>,
    rt: RuntimeConfig,
    make_send: &dyn Fn() -> io::Result<SendFn>,
    stats: Arc<RuntimeStats>,
) -> io::Result<(UaHandle, Vec<SyncSender<Input>>)> {
    if cfg.durable {
        // Durable engines hand out transitions to commit, which this driver
        // does not do; it would send nothing.
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "durable mode needs a committing driver (see examples/recoverable_ua)"));
    }
    let count = rt.shards.max(1);
    let local = cfg.local.clone();
    let (ev_tx, ev_rx) = mpsc::sync_channel(rt.event_capacity.max(1));
    let (res_tx, res_rx) = mpsc::sync_channel::<(usize, ResolveRequest)>(rt.resolve_capacity.max(1));
    let waker: Arc<Mutex<Option<EventWaker>>> = Arc::default();
    let directory = (count > 1).then(|| Arc::new(crate::shard::DialogDirectory::default()));
    let (mut inputs, mut ids, mut threads, mut rxs) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for i in 0..count {
        let (in_tx, in_rx) = mpsc::sync_channel(rt.input_capacity.max(1));
        inputs.push(in_tx);
        rxs.push(in_rx);
        ids.push(if count > 1 { IdAllocator::striped(i, count) } else { IdAllocator::new() });
    }
    let back = inputs.clone();
    std::thread::Builder::new().name("sip-ua-dns".into()).spawn(move || {
        for (shard, r) in res_rx {
            let out = resolver.resolve(&r);
            if back.get(shard).is_none_or(|b| b.send(Input::Resolved(r.id, out)).is_err()) {
                break;
            }
        }
    })?;
    for (i, in_rx) in rxs.into_iter().enumerate() {
        let index = u32::try_from(i).unwrap_or(0);
        let shard_cfg = UaConfig { shard: (count > 1).then_some(Shard { index, count }), ..cfg.clone() };
        let mut engine = UaEngine::with_entropy(shard_cfg, Box::new(SystemEntropy::default()), ids.get(i).cloned().unwrap_or_default());
        engine.set_epoch(rt.epoch).map_err(|e| io::Error::other(e.to_string()))?;
        if let Some(d) = &directory {
            engine.set_dialog_directory(d.clone());
        }
        let start = Instant::now();
        if let Some(until) = rt.lease_until {
            engine.set_lease(Some(lease_ms(start, until)));
        }
        let sh = Shared { start, waker: waker.clone(), fence: rt.egress_fence.clone(), stats: stats.clone(), shard: i };
        let (ev, res, send) = (ev_tx.clone(), res_tx.clone(), make_send()?);
        let name = if count > 1 { format!("sip-ua-{i}") } else { "sip-ua".into() };
        threads.push(std::thread::Builder::new().name(name).spawn(move || run(engine, in_rx, ev, res, send, sh))?);
    }
    let handle = UaHandle {
        inputs: inputs.clone(),
        ids,
        next_shard: AtomicUsize::new(0),
        events: ev_rx,
        waker,
        local,
        stats,
        stop: Arc::new(AtomicBool::new(false)),
        threads,
    };
    Ok((handle, inputs))
}

/// Route a received message to its shard's queue.
fn route<'a>(inputs: &'a [SyncSender<Input>], data: &[u8]) -> Option<&'a SyncSender<Input>> {
    let n = u32::try_from(inputs.len()).unwrap_or(1);
    inputs.get(shard_for_message(data, n) as usize)
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
    let make_send = || -> io::Result<SendFn> {
        let out = sock.try_clone()?;
        Ok(Box::new(move |t: &Transmit| t.dest.proto == Proto::Udp && out.send_to(&t.data, t.dest.addr).is_ok()))
    };
    let (mut handle, inputs) = spawn_engines(cfg, resolver, rt, &make_send, Arc::default())?;
    let (stop, stats) = (handle.stop.clone(), handle.stats.clone());
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    // One reader per shard on the shared socket (the kernel hands each
    // datagram to one of them); each routes by Call-ID.
    for r in 0..inputs.len() {
        let (stop, stats, inputs, sock) = (stop.clone(), stats.clone(), inputs.clone(), sock.try_clone()?);
        let reader = std::thread::Builder::new().name(format!("sip-ua-udp-{r}")).spawn(move || {
            let mut buf = vec![0u8; 65_535];
            while !stop.load(Ordering::Relaxed) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
                let data = buf.get(..n).unwrap_or_default().to_vec();
                let Some(input) = route(&inputs, &data) else { continue };
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
    }
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
    let make_send = || -> io::Result<SendFn> {
        let slot = net_slot.clone();
        Ok(Box::new(move |t: &Transmit| {
            let net = slot.lock().ok().and_then(|g| g.clone());
            net.is_some_and(|n| n.send(&t.dest, &t.data).is_ok())
        }))
    };
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
    let (handle, inputs) = spawn_engines(cfg, resolver, rt, &make_send, handler.stats.clone()).map_err(|e| e.to_string())?;
    if let Ok(mut g) = handler.input.lock() {
        *g = Some(inputs);
    }
    Ok(handle)
}

/// The transport's message handler: copies each message into the engine's
/// input queue (the receive buffer is reused by the worker).
#[cfg(feature = "transport")]
struct Front {
    input: Mutex<Option<Vec<SyncSender<Input>>>>,
    stats: Arc<RuntimeStats>,
}

#[cfg(feature = "transport")]
impl sip_core::Handler for Front {
    fn handle(&self, ctx: &mut sip_core::Ctx<'_, '_>) {
        let Some(inputs) = self.input.lock().ok().and_then(|g| g.clone()) else { return };
        let Some(tx) = route(&inputs, ctx.msg.buf) else { return };
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
        if let Some(inputs) = self.input.lock().ok().and_then(|g| g.clone()) {
            // Must not be lost: block briefly rather than drop it. Every
            // shard may have dialogs on the flow.
            for tx in &inputs {
                let _ = tx.send(Input::FlowClosed(*conn));
            }
        }
    }
}

/// An `Instant` on the engine clock (ms since `start`); one already past is `0`.
fn lease_ms(start: Instant, until: Instant) -> u64 {
    u64::try_from(until.saturating_duration_since(start).as_millis()).unwrap_or(u64::MAX)
}

fn run(
    mut engine: UaEngine,
    input: Receiver<Input>,
    events: SyncSender<EventEnvelope>,
    resolves: SyncSender<(usize, ResolveRequest)>,
    send: SendFn,
    sh: Shared,
) {
    let start = sh.start;
    let now = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    // Events the channel had no room for yet (engine events stay in the
    // engine's bounded queue until this is empty).
    let mut outbox: VecDeque<EventEnvelope> = VecDeque::new();
    // Resolutions the helper had no room for.
    let mut unresolved: VecDeque<(usize, ResolveRequest)> = VecDeque::new();
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
                        outbox.push_back(EventEnvelope { leg, seq: 0, log_seq: 0, generation: Generation(0), op: Some(op), dialog: None, event });
                    }
                }
                Input::Packet(data, src) => engine.handle_message(&data, src, now()),
                Input::FlowClosed(conn) => engine.handle_flow_closed(&conn),
                Input::Resolved(id, r) => engine.resolved(id, r, now()),
                Input::Lease(until) => engine.set_lease(Some(lease_ms(start, until))),
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
            if let Some(f) = &sh.fence
                && !f.admits(t.epoch)
            {
                // A newer owner exists: nothing more leaves this engine.
                sh.stats.fenced.fetch_add(1, Ordering::Relaxed);
                engine.halt();
                break;
            }
            if !send(&t)
                && let Some(id) = t.txn
            {
                engine.handle_send_error(id, now());
            }
        }
        while let Some(r) = engine.poll_resolve() {
            unresolved.push_back((sh.shard, r));
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
        let mut delivered = false;
        loop {
            let next = match outbox.pop_front() {
                Some(e) => e,
                None => match engine.poll_event() {
                    Some(e) => e,
                    None => break,
                },
            };
            match events.try_send(next) {
                Ok(()) => delivered = true,
                Err(TrySendError::Full(e)) => {
                    outbox.push_front(e);
                    break;
                }
                // The application is gone: keep running SIP (teardown still works).
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
        if delivered
            && let Ok(g) = sh.waker.lock()
            && let Some(w) = g.as_ref()
        {
            w();
        }
    }
}
