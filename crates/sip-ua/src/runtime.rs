//! A ready-made driver: one engine on its own thread with a UDP socket,
//! bounded command/event channels and DNS resolution on a helper thread.
//!
//! It is deliberately small and std-only. Production deployments inside
//! ferrosip feed the engine from the existing transport workers instead
//! (see `docs/sip-ua.md`), but the contract is the same: the engine thread
//! never waits for the application or for DNS.

use crate::api::{Accepted, CommandError, EventEnvelope, UaCommand, UaEvent};
use crate::engine::{ResolveRequest, UaConfig, UaEngine};
use crate::ids::{Generation, IdAllocator, OperationId, SystemEntropy, UaLegId};
use sip_core::{Dest, Proto};
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
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
    Resolved(u64, Result<Vec<Dest>, String>),
    Drain,
    Shutdown,
}

/// Sizes of the bounded queues.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeConfig {
    pub command_capacity: usize,
    pub event_capacity: usize,
    pub resolve_capacity: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self { command_capacity: 1_024, event_capacity: 4_096, resolve_capacity: 256 }
    }
}

/// The application's side of a running engine.
pub struct UaHandle {
    input: SyncSender<Input>,
    events: Receiver<EventEnvelope>,
    ids: IdAllocator,
    local: SocketAddr,
    thread: Option<JoinHandle<()>>,
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

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Graceful drain: new calls get 503, established ones continue.
    pub fn drain(&self) {
        let _ = self.input.send(Input::Drain);
    }

    pub fn shutdown(mut self) {
        let _ = self.input.send(Input::Shutdown);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for UaHandle {
    fn drop(&mut self) {
        let _ = self.input.try_send(Input::Shutdown);
    }
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
    let ids = IdAllocator::new();
    let engine = UaEngine::with_entropy(cfg, Box::new(SystemEntropy::default()), ids.clone());
    let (in_tx, in_rx) = mpsc::sync_channel(rt.command_capacity.max(1));
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
    let thread = std::thread::Builder::new().name("sip-ua".into()).spawn(move || run(engine, sock, in_rx, ev_tx, res_tx))?;
    Ok(UaHandle { input: in_tx, events: ev_rx, ids, local, thread: Some(thread) })
}

fn run(mut engine: UaEngine, sock: UdpSocket, input: Receiver<Input>, events: SyncSender<EventEnvelope>, resolves: SyncSender<ResolveRequest>) {
    let start = Instant::now();
    let now = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut buf = vec![0u8; 65_535];
    // Events the channel had no room for yet (engine events stay in the
    // engine's bounded queue until this is empty).
    let mut outbox: VecDeque<EventEnvelope> = VecDeque::new();
    // Resolutions the helper had no room for.
    let mut unresolved: VecDeque<ResolveRequest> = VecDeque::new();
    loop {
        // Inputs from the application and the resolver.
        loop {
            match input.try_recv() {
                Ok(Input::Cmd(op, cmd)) => {
                    let leg = cmd.leg().unwrap_or(UaLegId(0));
                    if let Err(e) = engine.submit_with(op, cmd, now()) {
                        let event = UaEvent::CommandRejected(e);
                        outbox.push_back(EventEnvelope { leg, seq: 0, generation: Generation(0), op: Some(op), dialog: None, event });
                    }
                }
                Ok(Input::Resolved(id, r)) => engine.resolved(id, r, now()),
                Ok(Input::Drain) => engine.drain(),
                Ok(Input::Shutdown) | Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => break,
            }
        }
        engine.handle_timeout(now());
        // Outputs.
        while let Some(t) = engine.poll_transmit() {
            let ok = t.dest.proto == Proto::Udp && sock.send_to(&t.data, t.dest.addr).is_ok();
            if !ok && let Some(id) = t.txn {
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
        // Wait for a datagram, at most until the next timer (or 5 ms, to
        // pick up commands promptly).
        let wait = engine.next_timeout().map_or(5, |t| t.saturating_sub(now())).clamp(1, 5);
        if sock.set_read_timeout(Some(Duration::from_millis(wait))).is_err() {
            return;
        }
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let data = buf.get(..n).unwrap_or_default();
            engine.handle_message(data, Dest::new(Proto::Udp, from), now());
        }
    }
}
