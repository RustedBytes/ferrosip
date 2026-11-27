//! The UA engine: legs, dialogs, transactions and timers, sans-IO.
//!
//! Inputs: [`UaEngine::handle_message`], [`UaEngine::submit`],
//! [`UaEngine::handle_timeout`], [`UaEngine::resolved`],
//! [`UaEngine::handle_send_error`]. Outputs are pulled:
//! [`UaEngine::poll_transmit`], [`UaEngine::poll_event`],
//! [`UaEngine::poll_resolve`], [`UaEngine::next_timeout`].
//!
//! One engine is one logical owner: every leg's transitions are serialized
//! by `&mut self`. Run one engine per worker and shard legs between them
//! (e.g. by Call-ID) to scale out; the engine never blocks, never sleeps
//! and never does I/O, so a driver can be built on any runtime.

use crate::api::*;
use crate::auth::{self, Credentials};
use crate::cause::{Cause, CauseKind, SipStatus};
use crate::ids::*;
use crate::msg::{Header, Limits, Method, SipMessage, is_safe_value, is_token, split_values, strip_tag, uri_of};
use crate::sdp;
use crate::txn::{State as TxState, TimerConfig, TimerKind, Txn, TxnOut};
use sip_core::{Dest, Proto};
use sip_parser::parse_uri;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Engine configuration.
#[derive(Clone, Debug)]
pub struct UaConfig {
    pub timers: TimerConfig,
    pub limits: Limits,
    /// Address advertised in Via/Contact for each transport we can use.
    pub local: Vec<(Proto, SocketAddr)>,
    pub user_agent: Option<String>,
    /// User part of generated Contact URIs.
    pub contact_user: String,
    /// New legs (either direction) beyond this are refused (503 / error).
    pub max_legs: usize,
    /// Undelivered non-critical events beyond this fail the affected leg.
    pub max_pending_events: usize,
    pub max_auth_attempts: u8,
    /// How long the application has to answer a remote offer.
    pub answer_timeout_ms: u64,
    /// Outbound INVITEs are cancelled after this without a 2xx.
    pub no_answer_timeout_ms: u64,
    /// Inbound INVITEs get 480 after this without a final from the application.
    pub uas_answer_timeout_ms: u64,
}

impl Default for UaConfig {
    fn default() -> Self {
        Self {
            timers: TimerConfig::default(),
            limits: Limits::default(),
            local: Vec::new(),
            user_agent: Some("ferrosip-ua".into()),
            contact_user: "ua".into(),
            max_legs: 10_000,
            max_pending_events: 4_096,
            max_auth_attempts: 2,
            answer_timeout_ms: 5_000,
            no_answer_timeout_ms: 120_000,
            uas_answer_timeout_ms: 180_000,
        }
    }
}

const ALLOW: &str = "INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, UPDATE";

/// Headers the application cannot set through `headers` (the engine owns them).
const RESERVED: &[&str] =
    &["via", "from", "to", "call-id", "cseq", "contact", "content-length", "content-type", "max-forwards", "route", "record-route", "require", "rseq", "rack"];

/// One message for the driver to send.
#[derive(Clone, Debug)]
pub struct Transmit {
    pub dest: Dest,
    pub data: Arc<[u8]>,
    /// Report a send failure with [`UaEngine::handle_send_error`].
    pub txn: Option<TxnId>,
}

/// A host the driver must resolve (RFC 3263) off the hot path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveRequest {
    pub id: u64,
    pub host: String,
    pub port: Option<u16>,
    /// The URI's `;transport=` (None: not given).
    pub proto: Option<Proto>,
    /// `sips:` URI.
    pub secure: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Uac,
    Uas,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// UAC: INVITE sent, nothing but 100 received. UAS: no 1xx sent yet.
    Calling,
    /// A provisional with a to-tag was received / sent.
    Early,
    Confirmed,
    /// BYE / CANCEL sent; waiting for the transaction to finish.
    Terminating,
    Terminated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferState {
    Stable,
    LocalOffer,
    RemoteOffer,
}

/// What `snapshot` reports about a leg (for reconciliation after missed events).
#[derive(Clone, Debug)]
pub struct LegSnapshot {
    pub leg: UaLegId,
    pub role: Role,
    pub phase: Phase,
    pub call_id: String,
    pub dialog: Option<SipDialogId>,
    /// Latest generation issued.
    pub generation: Generation,
    /// Latest generation whose offer/answer completed.
    pub stable_generation: Generation,
    pub offer: OfferState,
    /// Sequence number of the last event emitted for this leg.
    pub last_seq: u64,
    pub remote_target: String,
}

#[derive(Clone, Debug, Default)]
pub struct UaStats {
    pub legs: usize,
    pub transactions: usize,
    pub timers: usize,
    pub queued_events: usize,
    pub queued_transmits: usize,
    pub pending_resolves: usize,
    pub malformed: u64,
    pub rejected_overload: u64,
    pub events_shed: u64,
}

// ------------------------------------------------------------- internals --

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ClientKey {
    branch: String,
    method: Method,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ServerKey {
    branch: String,
    sent_by: String,
    method: Method,
}

#[derive(Clone, Debug)]
enum TxnKey {
    Client(ClientKey),
    Server(ServerKey),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    /// The leg's initial INVITE (client or server).
    Invite(UaLegId),
    /// Client: our re-INVITE (with its operation). Server: theirs.
    ReInvite(UaLegId, Option<OperationId>),
    Update(UaLegId, Option<OperationId>),
    Bye(UaLegId),
    Cancel(UaLegId),
    Info(UaLegId, OperationId),
    /// Responses are not needed (fork-loser BYE, stateless replies).
    Detached,
}

struct TxnEntry {
    txn: Txn,
    purpose: Purpose,
    key: TxnKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LegTimer {
    /// UAS: retransmit the 2xx until ACK (RFC 3261 §13.3.1.4).
    Retransmit2xx,
    /// UAS: 64·T1 without ACK.
    AckTimeout,
    /// The application did not answer a remote offer.
    AnswerDeadline,
    /// UAC: no 2xx in time: CANCEL.
    NoAnswer,
    /// UAC: CANCEL sent, the INVITE never completed.
    CancelGuard,
    /// UAS: the application never sent a final.
    UasAnswer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TimerRef {
    Txn(TxnId, TimerKind),
    Leg(UaLegId, LegTimer),
}

/// Where an offer/answer exchange is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OfferVia {
    /// Our offer in the initial INVITE.
    Invite,
    /// Our offer in a 2xx (delayed offer); the answer comes in the ACK.
    OurTwoXx,
    /// Their offer in the 2xx to our body-less INVITE; the answer goes in the ACK.
    TheirTwoXx,
    ReInvite,
    Update,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Oa {
    Stable,
    LocalOffer(OfferVia, Option<OperationId>),
    RemoteOffer(OfferVia),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CancelState {
    None,
    /// Asked to cancel before any provisional arrived (RFC 3261 §9.1).
    Requested,
    Sent,
}

struct Pending2xx {
    cseq: u32,
    bytes: Arc<[u8]>,
    dest: Dest,
    interval: u64,
}

struct Leg {
    id: UaLegId,
    role: Role,
    phase: Phase,
    call_id: String,
    local_tag: String,
    remote_tag: Option<String>,
    /// Our From (UAC) / To (UAS) value, with our tag.
    local_hdr: String,
    /// Their header value; carries their tag once known.
    remote_hdr: String,
    local_contact: String,
    remote_target: String,
    route_set: Vec<String>,
    local_cseq: u32,
    remote_cseq: Option<u32>,
    /// Connection affinity (reliable transports): in-dialog requests reuse it.
    flow: Option<Dest>,
    secure: bool,
    invite_txn: Option<TxnId>,
    /// UAC: the INVITE without Via/CSeq/auth, to rebuild for auth retries.
    invite_template: Option<SipMessage>,
    invite_dest: Option<Dest>,
    /// Remote tags of early dialogs (forks) seen so far.
    early: Vec<String>,
    /// 2xx from forks we did not keep: (tag, ACK bytes, dest) to re-ACK retransmissions.
    killed: Vec<(String, Arc<[u8]>, Dest)>,
    oa: Oa,
    negotiated: bool,
    early_answer: Option<Vec<u8>>,
    remote_offer: Option<Vec<u8>>,
    generation: u64,
    stable_generation: u64,
    seq: u64,
    /// UAC: the ACK of the last 2xx (cseq, bytes, dest).
    ack: Option<(u32, Arc<[u8]>, Dest)>,
    /// UAC: 2xx (cseq) whose ACK waits for the application's answer.
    ack_wait: Option<u32>,
    pending_2xx: Option<Pending2xx>,
    server_reinvite: Option<TxnId>,
    server_update: Option<TxnId>,
    client_reinvite: Option<TxnId>,
    client_update: Option<TxnId>,
    cancel: CancelState,
    cancel_reason: Option<String>,
    cancel_cause: Option<Cause>,
    /// UAS: the 2xx to the initial INVITE is not ACKed yet.
    initial_ack_pending: bool,
    /// UAS: BYE as soon as the 2xx is ACKed.
    bye_after_ack: Option<Option<String>>,
    bye_cause: Option<Cause>,
    creds: Option<Credentials>,
    auth_attempts: u8,
    timers: Vec<(LegTimer, u64)>,
    origin_op: Option<OperationId>,
    /// Non-critical events could not be queued: shed this leg.
    overloaded: bool,
    /// Merged-request key (UAS).
    merged_key: Option<(String, String, u32)>,
    /// Remote tags registered in the dialog index.
    dialog_tags: Vec<String>,
}

impl Leg {
    fn dialog_id(&self) -> Option<SipDialogId> {
        Some(SipDialogId { call_id: self.call_id.clone(), local_tag: self.local_tag.clone(), remote_tag: self.remote_tag.clone()? })
    }

    fn arm(&mut self, t: LegTimer, at: u64) {
        self.timers.retain(|(k, _)| *k != t);
        self.timers.push((t, at));
    }

    fn disarm(&mut self, t: LegTimer) {
        self.timers.retain(|(k, _)| *k != t);
    }

    fn is_armed(&self, t: LegTimer, at: u64) -> bool {
        self.timers.iter().any(|&(k, a)| k == t && a == at)
    }

    fn offer_state(&self) -> OfferState {
        match self.oa {
            Oa::Stable => OfferState::Stable,
            Oa::LocalOffer(..) => OfferState::LocalOffer,
            Oa::RemoteOffer(_) => OfferState::RemoteOffer,
        }
    }
}

struct PendingResolve {
    leg: UaLegId,
    req: SipMessage,
    purpose: Purpose,
    /// An ACK for a 2xx (no transaction).
    stateless: bool,
}

enum Target {
    Ready(Dest),
    Resolve(String, Option<u16>, Option<Proto>, bool),
}

fn is_ip(host: &str) -> Option<IpAddr> {
    host.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

fn default_port(p: Proto) -> u16 {
    match p {
        Proto::Tls => 5061,
        Proto::Ws => 80,
        Proto::Wss => 443,
        Proto::Udp | Proto::Tcp => 5060,
    }
}

fn proto_param(v: &[u8]) -> Option<Proto> {
    let s = std::str::from_utf8(v).ok()?.to_ascii_lowercase();
    Some(match s.as_str() {
        "udp" => Proto::Udp,
        "tcp" => Proto::Tcp,
        "tls" => Proto::Tls,
        "ws" => Proto::Ws,
        "wss" => Proto::Wss,
        _ => return None,
    })
}

/// RFC 3263 inputs of a URI, or the destination when the host is an IP.
fn uri_target(uri: &str) -> Option<Target> {
    let u = parse_uri(uri.as_bytes())?;
    let secure = u.is_sips();
    let proto = u.param(b"transport").and_then(proto_param);
    let host = String::from_utf8_lossy(u.host).into_owned();
    if let Some(ip) = is_ip(&host) {
        let p = proto.unwrap_or(if secure { Proto::Tls } else { Proto::Udp });
        return Some(Target::Ready(Dest::new(p, SocketAddr::new(ip, u.port.unwrap_or(default_port(p))))));
    }
    Some(Target::Resolve(host, u.port, proto, secure))
}

fn is_loose(route: &str) -> bool {
    parse_uri(uri_of(route).as_bytes()).is_some_and(|u| u.param(b"lr").is_some())
}

fn angle(v: &str) -> String {
    let t = v.trim();
    if t.contains('<') { t.to_string() } else { format!("<{t}>") }
}

fn reason_text(code: u16) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        181 => "Call Is Being Forwarded",
        182 => "Queued",
        183 => "Session Progress",
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        415 => "Unsupported Media Type",
        420 => "Bad Extension",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        482 => "Loop Detected",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        491 => "Request Pending",
        500 => "Server Internal Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        603 => "Decline",
        _ => "Unknown",
    }
}

fn check_headers(h: &[Header]) -> Result<(), CommandError> {
    for x in h {
        if !is_token(&x.name) || !is_safe_value(&x.value) {
            return Err(CommandError::InvalidArgument(format!("bad header {:?}", x.name)));
        }
        if RESERVED.iter().any(|r| crate::msg::same_name(r, &x.name)) {
            return Err(CommandError::InvalidArgument(format!("header {} is managed by the engine", x.name)));
        }
    }
    Ok(())
}

fn check_sdp(b: &[u8]) -> Result<(), CommandError> {
    if sdp::is_valid(b) { Ok(()) } else { Err(CommandError::InvalidArgument("body is not SDP".into())) }
}

/// Where responses to `req` (received from `src`) go: RFC 3261 §18.2.2
/// with RFC 3581 rport; reliable transports reuse the connection.
fn response_dest(req: &SipMessage, src: Dest) -> Dest {
    if src.proto.is_stream() {
        return src;
    }
    let port = match req.top_via() {
        Some(v) if !v.rport => v.port.unwrap_or(5060),
        _ => src.addr.port(),
    };
    Dest::new(Proto::Udp, SocketAddr::new(src.addr.ip(), port))
}

fn server_key(req: &SipMessage) -> Option<ServerKey> {
    let via = req.top_via()?;
    let method = match req.method()? {
        Method::Ack => Method::Invite,
        m => m.clone(),
    };
    let sent_by = via.sent_by();
    let branch = match via.branch {
        Some(b) if b.starts_with("z9hG4bK") => b,
        // RFC 2543 peers: match on the request's identity instead.
        _ => format!("2543|{}|{}|{}|{sent_by}", req.call_id()?, req.from_tag().unwrap_or_default(), req.cseq()?.0),
    };
    Some(ServerKey { branch, sent_by, method })
}

/// The sans-IO UA engine.
pub struct UaEngine {
    cfg: UaConfig,
    entropy: Box<dyn Entropy>,
    ids: IdAllocator,
    next_txn: u64,
    next_resolve: u64,
    timer_seq: u64,
    legs: HashMap<UaLegId, Leg>,
    dialogs: HashMap<(String, String, String), UaLegId>,
    merged: HashMap<(String, String, u32), UaLegId>,
    txns: HashMap<TxnId, TxnEntry>,
    client_keys: HashMap<ClientKey, TxnId>,
    server_keys: HashMap<ServerKey, TxnId>,
    timers: BinaryHeap<Reverse<(u64, u64, TimerRef)>>,
    transmits: VecDeque<Transmit>,
    events: VecDeque<EventEnvelope>,
    resolves: VecDeque<ResolveRequest>,
    pending_resolve: HashMap<u64, PendingResolve>,
    draining: bool,
    stats: UaStats,
}

impl UaEngine {
    pub fn new(cfg: UaConfig) -> Self {
        Self::with_entropy(cfg, Box::new(crate::ids::SystemEntropy::default()), IdAllocator::new())
    }

    /// With a given randomness source and a shared id allocator.
    pub fn with_entropy(cfg: UaConfig, entropy: Box<dyn Entropy>, ids: IdAllocator) -> Self {
        Self {
            cfg,
            entropy,
            ids,
            next_txn: 0,
            next_resolve: 0,
            timer_seq: 0,
            legs: HashMap::new(),
            dialogs: HashMap::new(),
            merged: HashMap::new(),
            txns: HashMap::new(),
            client_keys: HashMap::new(),
            server_keys: HashMap::new(),
            timers: BinaryHeap::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            resolves: VecDeque::new(),
            pending_resolve: HashMap::new(),
            draining: false,
            stats: UaStats::default(),
        }
    }

    pub fn config(&self) -> &UaConfig {
        &self.cfg
    }

    pub fn ids(&self) -> &IdAllocator {
        &self.ids
    }

    // ------------------------------------------------------------ output --

    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<EventEnvelope> {
        self.events.pop_front()
    }

    pub fn poll_resolve(&mut self) -> Option<ResolveRequest> {
        self.resolves.pop_front()
    }

    /// The earliest armed timer (may be a cancelled one; firing it is harmless).
    pub fn next_timeout(&self) -> Option<u64> {
        self.timers.peek().map(|Reverse((at, _, _))| *at)
    }

    // ------------------------------------------------------------- query --

    pub fn snapshot(&self, leg: UaLegId) -> Option<LegSnapshot> {
        let l = self.legs.get(&leg)?;
        Some(LegSnapshot {
            leg,
            role: l.role,
            phase: l.phase,
            call_id: l.call_id.clone(),
            dialog: l.dialog_id(),
            generation: Generation(l.generation),
            stable_generation: Generation(l.stable_generation),
            offer: l.offer_state(),
            last_seq: l.seq,
            remote_target: l.remote_target.clone(),
        })
    }

    pub fn legs(&self) -> Vec<UaLegId> {
        let mut v: Vec<_> = self.legs.keys().copied().collect();
        v.sort();
        v
    }

    pub fn stats(&self) -> UaStats {
        UaStats {
            legs: self.legs.len(),
            transactions: self.txns.len(),
            timers: self.timers.len(),
            queued_events: self.events.len(),
            queued_transmits: self.transmits.len(),
            pending_resolves: self.pending_resolve.len(),
            ..self.stats.clone()
        }
    }

    /// Stop accepting new legs; established ones continue.
    pub fn drain(&mut self) {
        self.draining = true;
    }

    pub fn is_draining(&self) -> bool {
        self.draining
    }

    /// No legs and no transactions left (every timer has run out).
    pub fn is_idle(&self) -> bool {
        self.legs.is_empty() && self.txns.is_empty() && self.pending_resolve.is_empty()
    }

    // ------------------------------------------------------------ helpers --

    fn token(&mut self) -> String {
        format!("{:016x}", self.entropy.next_u64())
    }

    fn branch(&mut self) -> String {
        format!("z9hG4bK{:016x}{:08x}", self.entropy.next_u64(), self.entropy.next_u64() >> 32)
    }

    fn rand_below(&mut self, n: u64) -> u64 {
        self.entropy.next_u64().checked_rem(n).unwrap_or(0)
    }

    fn local_addr(&self, p: Proto) -> Option<SocketAddr> {
        self.cfg.local.iter().find(|(q, _)| *q == p).map(|(_, a)| *a)
    }

    fn contact_for(&self, p: Proto, secure: bool) -> Option<String> {
        let a = self.local_addr(p)?;
        let scheme = if secure && p.is_tls() { "sips" } else { "sip" };
        let tp = match p {
            Proto::Udp => "",
            Proto::Tcp => ";transport=tcp",
            Proto::Tls if secure => "",
            Proto::Tls => ";transport=tls",
            Proto::Ws => ";transport=ws",
            Proto::Wss => ";transport=wss",
        };
        Some(format!("{scheme}:{}@{a}{tp}", self.cfg.contact_user))
    }

    fn schedule(&mut self, at: u64, r: TimerRef) {
        self.timer_seq = self.timer_seq.wrapping_add(1);
        self.timers.push(Reverse((at, self.timer_seq, r)));
    }

    fn arm_leg(&mut self, leg: &mut Leg, t: LegTimer, at: u64) {
        leg.arm(t, at);
        self.schedule(at, TimerRef::Leg(leg.id, t));
    }

    fn emit(&mut self, leg: &mut Leg, op: Option<OperationId>, event: UaEvent) {
        if !event.is_critical() && self.events.len() >= self.cfg.max_pending_events {
            // No room: the leg is failed explicitly instead of dropping
            // this event silently (the Failed/Terminated that follow are
            // critical and always queued; there is at most one per leg).
            self.stats.events_shed = self.stats.events_shed.saturating_add(1);
            leg.overloaded = true;
            return;
        }
        leg.seq = leg.seq.saturating_add(1);
        self.events.push_back(EventEnvelope { leg: leg.id, seq: leg.seq, generation: Generation(leg.generation), op, dialog: leg.dialog_id(), event });
    }

    fn send_raw(&mut self, dest: Dest, data: Arc<[u8]>, txn: Option<TxnId>) {
        self.transmits.push_back(Transmit { dest, data, txn });
    }

    fn new_txn_id(&mut self) -> TxnId {
        self.next_txn = self.next_txn.wrapping_add(1);
        TxnId(self.next_txn)
    }

    /// Run a closure on a leg taken out of the map; put it back unless it
    /// terminated (then clean up everything that indexes it).
    fn with_leg<R>(&mut self, id: UaLegId, now: u64, f: impl FnOnce(&mut Self, &mut Leg) -> R) -> Option<R> {
        let mut leg = self.legs.remove(&id)?;
        let r = f(self, &mut leg);
        if leg.overloaded && leg.phase != Phase::Terminated {
            leg.overloaded = false;
            let cause = Cause::new(CauseKind::Overload).with_detail("event queue full");
            self.emit(&mut leg, None, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
            self.hangup_leg(&mut leg, Some("Q.850;cause=42".into()), Some(503), cause, now);
        }
        if leg.phase == Phase::Terminated {
            self.cleanup(&mut leg);
        } else {
            self.legs.insert(id, leg);
        }
        Some(r)
    }

    fn cleanup(&mut self, leg: &mut Leg) {
        for t in leg.dialog_tags.drain(..) {
            self.dialogs.remove(&(leg.call_id.clone(), leg.local_tag.clone(), t));
        }
        if let Some(k) = leg.merged_key.take() {
            self.merged.remove(&k);
        }
        leg.timers.clear();
        // A client INVITE still waiting for a final has no timer of its
        // own (timer B stops at the first provisional): drop it with the leg.
        for t in [leg.invite_txn, leg.client_reinvite].into_iter().flatten() {
            let drop_it = self.txns.get(&t).is_some_and(|e| matches!(e.txn.kind, crate::txn::Kind::InviteClient) && e.txn.state == TxState::Proceeding);
            if drop_it {
                self.remove_txn(t);
            }
        }
        self.pending_resolve.retain(|_, p| p.leg != leg.id);
    }

    fn remove_txn(&mut self, t: TxnId) {
        if let Some(e) = self.txns.remove(&t) {
            match e.key {
                TxnKey::Client(k) => {
                    self.client_keys.remove(&k);
                }
                TxnKey::Server(k) => {
                    self.server_keys.remove(&k);
                }
            }
        }
    }

    fn terminate(&mut self, leg: &mut Leg, cause: Cause) {
        if leg.phase == Phase::Terminated {
            return;
        }
        leg.phase = Phase::Terminated;
        let op = leg.origin_op;
        self.emit(leg, op, UaEvent::Terminated(TerminationEvent { cause }));
    }

    fn fail(&mut self, leg: &mut Leg, op: Option<OperationId>, cause: Cause) {
        self.emit(leg, op, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
        self.terminate(leg, cause);
    }

    fn register_dialog(&mut self, leg: &mut Leg, tag: &str) {
        if !leg.dialog_tags.iter().any(|t| t == tag) {
            leg.dialog_tags.push(tag.to_string());
        }
        self.dialogs.insert((leg.call_id.clone(), leg.local_tag.clone(), tag.to_string()), leg.id);
    }

    fn unregister_dialog(&mut self, leg: &mut Leg, tag: &str) {
        leg.dialog_tags.retain(|t| t != tag);
        self.dialogs.remove(&(leg.call_id.clone(), leg.local_tag.clone(), tag.to_string()));
    }

    // ------------------------------------------------------ transactions --

    /// Execute a transaction's effects.
    fn run(&mut self, id: TxnId, outs: Vec<TxnOut>, now: u64) {
        let Some((dest, purpose)) = self.txns.get(&id).map(|e| (e.txn.dest, e.purpose)) else { return };
        for o in outs {
            match o {
                TxnOut::Send(b) => self.send_raw(dest, b, Some(id)),
                TxnOut::Arm(k, at) => self.schedule(at, TimerRef::Txn(id, k)),
                TxnOut::Response(r) => self.on_txn_response(id, purpose, r, now),
                TxnOut::Ack(a) => self.on_dialog_ack(a, now),
                TxnOut::Timeout => self.on_txn_failure(id, purpose, CauseKind::Timeout, now),
                TxnOut::TransportError => self.on_txn_failure(id, purpose, CauseKind::Transport, now),
                TxnOut::Terminated => self.remove_txn(id),
            }
        }
    }

    fn txn_do(&mut self, id: TxnId, now: u64, f: impl FnOnce(&mut Txn) -> Vec<TxnOut>) {
        let Some(e) = self.txns.get_mut(&id) else { return };
        let outs = f(&mut e.txn);
        self.run(id, outs, now);
    }

    /// Start a client transaction for `req`, adding our Via (and Contact
    /// where the method needs one).
    fn start_client(&mut self, mut req: SipMessage, dest: Dest, purpose: Purpose, now: u64) -> Result<TxnId, CommandError> {
        let adv = self.local_addr(dest.proto).ok_or(CommandError::NoLocalAddress)?;
        let branch = self.branch();
        req.prepend_header("Via", format!("SIP/2.0/{} {adv};branch={branch};rport", dest.proto.via_name()));
        let method = req.method().cloned().unwrap_or(Method::Options);
        self.finish_contact(&mut req, dest.proto, purpose);
        self.start_client_prepared(req, dest, purpose, ClientKey { branch, method }, now)
    }

    fn finish_contact(&mut self, req: &mut SipMessage, proto: Proto, purpose: Purpose) {
        let needs = matches!(req.method(), Some(Method::Invite | Method::Update));
        if !needs || req.header("Contact").is_some() {
            return;
        }
        let leg_id = match purpose {
            Purpose::Invite(l) | Purpose::ReInvite(l, _) | Purpose::Update(l, _) => Some(l),
            _ => None,
        };
        let secure = leg_id.and_then(|l| self.legs.get(&l)).is_some_and(|l| l.secure);
        let existing = leg_id.and_then(|l| self.legs.get(&l)).map(|l| l.local_contact.clone()).filter(|c| !c.is_empty());
        let contact = existing.or_else(|| self.contact_for(proto, secure));
        if let Some(c) = contact {
            req.push_header("Contact", format!("<{c}>"));
            if let Some(l) = leg_id.and_then(|l| self.legs.get_mut(&l)) {
                l.local_contact = c;
            }
        }
    }

    fn start_client_prepared(&mut self, req: SipMessage, dest: Dest, purpose: Purpose, key: ClientKey, now: u64) -> Result<TxnId, CommandError> {
        let id = self.new_txn_id();
        let (txn, outs) = Txn::client(id, req, dest, self.cfg.timers, now);
        self.client_keys.insert(key.clone(), id);
        self.txns.insert(id, TxnEntry { txn, purpose, key: TxnKey::Client(key) });
        match purpose {
            Purpose::Invite(l) => {
                if let Some(leg) = self.legs.get_mut(&l) {
                    leg.invite_txn = Some(id);
                    leg.invite_dest = Some(dest);
                }
            }
            Purpose::ReInvite(l, Some(_)) => {
                if let Some(leg) = self.legs.get_mut(&l) {
                    leg.client_reinvite = Some(id);
                }
            }
            Purpose::Update(l, Some(_)) => {
                if let Some(leg) = self.legs.get_mut(&l) {
                    leg.client_update = Some(id);
                }
            }
            _ => {}
        }
        self.run(id, outs, now);
        Ok(id)
    }

    /// Next hop of a request: the leg's flow, else the first Route (loose
    /// routing) or the Request-URI.
    fn target_for(&self, req: &SipMessage, flow: Option<Dest>) -> Option<Target> {
        if let Some(f) = flow {
            return Some(Target::Ready(f));
        }
        let hop = req.values("Route").into_iter().next().map(|r| uri_of(&r)).or_else(|| req.uri().map(str::to_string))?;
        uri_target(&hop)
    }

    /// Send a request of a leg: now, or after resolution.
    fn dispatch(&mut self, leg: &Leg, req: SipMessage, purpose: Purpose, stateless: bool, next_hop: Option<Dest>, now: u64) -> Result<(), CommandError> {
        let target = match next_hop {
            Some(d) => Target::Ready(d),
            None => self.target_for(&req, leg.flow).ok_or_else(|| CommandError::InvalidArgument("unroutable request URI".into()))?,
        };
        match target {
            Target::Ready(d) => {
                if stateless {
                    self.send_ack_now(leg.id, req, d)
                } else {
                    self.start_client(req, d, purpose, now).map(|_| ())
                }
            }
            Target::Resolve(host, port, proto, secure) => {
                self.next_resolve = self.next_resolve.wrapping_add(1);
                let id = self.next_resolve;
                self.pending_resolve.insert(id, PendingResolve { leg: leg.id, req, purpose, stateless });
                self.resolves.push_back(ResolveRequest { id, host, port, proto, secure });
                Ok(())
            }
        }
    }

    fn send_ack_now(&mut self, leg: UaLegId, mut req: SipMessage, d: Dest) -> Result<(), CommandError> {
        let adv = self.local_addr(d.proto).ok_or(CommandError::NoLocalAddress)?;
        let branch = self.branch();
        req.prepend_header("Via", format!("SIP/2.0/{} {adv};branch={branch};rport", d.proto.via_name()));
        let cseq = req.cseq().map_or(0, |c| c.0);
        let bytes: Arc<[u8]> = req.to_bytes().into();
        if let Some(l) = self.legs.get_mut(&leg) {
            l.ack = Some((cseq, bytes.clone(), d));
        }
        self.send_raw(d, bytes, None);
        Ok(())
    }

    /// The driver resolved a [`ResolveRequest`] (first entry is used).
    pub fn resolved(&mut self, id: u64, result: Result<Vec<Dest>, String>, now: u64) {
        let Some(p) = self.pending_resolve.remove(&id) else { return };
        let dest = match result {
            Ok(v) => v.into_iter().next().ok_or_else(|| "no address".to_string()),
            Err(e) => Err(e),
        };
        let leg_id = p.leg;
        let had_leg = self.legs.contains_key(&leg_id);
        let res = match (&dest, had_leg) {
            (Ok(d), true) => {
                if p.stateless {
                    // The leg is in the map, so send_ack_now can record the ACK.
                    self.send_ack_now(leg_id, p.req, *d).map_err(|e| e.to_string())
                } else {
                    self.start_client(p.req, *d, p.purpose, now).map(|_| ()).map_err(|e| e.to_string())
                }
            }
            (Ok(_), false) => Ok(()),
            (Err(e), _) => Err(e.clone()),
        };
        if let Err(e) = res {
            let kind = if dest.is_err() { CauseKind::Dns } else { CauseKind::Transport };
            let cause = Cause::new(kind).with_detail(e);
            self.request_failed(leg_id, p.purpose, cause, now);
        }
    }

    /// A transmit with `txn` could not be sent.
    pub fn handle_send_error(&mut self, txn: TxnId, now: u64) {
        self.txn_do(txn, now, Txn::on_transport_error);
    }

    /// A reliable flow closed: drop the affinity so later requests use the
    /// route set / remote target again.
    pub fn handle_flow_closed(&mut self, conn: &Dest) {
        for l in self.legs.values_mut() {
            if l.flow.as_ref() == Some(conn) {
                l.flow = None;
            }
        }
    }

    /// A request could not even be started (DNS, no local address).
    fn request_failed(&mut self, leg: UaLegId, purpose: Purpose, cause: Cause, now: u64) {
        self.with_leg(leg, now, |s, l| match purpose {
            Purpose::Invite(_) => {
                let op = l.origin_op;
                s.fail(l, op, cause);
            }
            Purpose::Bye(_) => s.terminate(l, l.bye_cause.clone().unwrap_or(cause)),
            Purpose::ReInvite(_, op) | Purpose::Update(_, op) => {
                l.client_reinvite = None;
                l.client_update = None;
                s.rollback(l);
                s.emit(l, op, UaEvent::Failed(FailureEvent { cause, leg_failed: false, retry_after_ms: None }));
            }
            Purpose::Info(_, op) => s.emit(l, Some(op), UaEvent::Failed(FailureEvent { cause, leg_failed: false, retry_after_ms: None })),
            Purpose::Cancel(_) | Purpose::Detached => {}
        });
    }

    // ------------------------------------------------------------ timers --

    /// Run every timer due at `now`.
    pub fn handle_timeout(&mut self, now: u64) {
        while let Some(Reverse((at, _, r))) = self.timers.peek().copied() {
            if at > now {
                break;
            }
            self.timers.pop();
            match r {
                TimerRef::Txn(id, kind) => self.txn_do(id, now, |t| t.on_timer(kind, at, now)),
                TimerRef::Leg(id, t) => {
                    self.with_leg(id, now, |s, l| {
                        if l.is_armed(t, at) {
                            l.disarm(t);
                            s.on_leg_timer(l, t, now);
                        }
                    });
                }
            }
        }
    }

    fn on_leg_timer(&mut self, leg: &mut Leg, t: LegTimer, now: u64) {
        match t {
            LegTimer::Retransmit2xx => {
                if let Some(p) = &mut leg.pending_2xx {
                    p.interval = p.interval.saturating_mul(2).min(self.cfg.timers.t2);
                    let (d, b, i) = (p.dest, p.bytes.clone(), p.interval);
                    self.send_raw(d, b, None);
                    self.arm_leg(leg, LegTimer::Retransmit2xx, now.saturating_add(i));
                }
            }
            LegTimer::AckTimeout => {
                if leg.pending_2xx.take().is_some() {
                    leg.initial_ack_pending = false;
                    leg.disarm(LegTimer::Retransmit2xx);
                    let cause = Cause::new(CauseKind::NoAck);
                    self.emit(leg, None, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
                    leg.bye_after_ack = None;
                    self.send_bye(leg, None, cause, now);
                }
            }
            LegTimer::AnswerDeadline => {
                if let Oa::RemoteOffer(via) = leg.oa {
                    let cause = Cause::new(CauseKind::AnswerTimeout);
                    let fatal = via == OfferVia::TheirTwoXx;
                    self.emit(leg, None, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: fatal, retry_after_ms: None }));
                    self.answer_remote_offer(leg, None, now);
                    if fatal {
                        self.send_bye(leg, Some("Q.850;cause=102".into()), cause, now);
                    }
                }
            }
            LegTimer::NoAnswer => {
                if matches!(leg.phase, Phase::Calling | Phase::Early) {
                    self.cancel_leg(leg, Some("Q.850;cause=19".into()), Cause::sip(CauseKind::Timeout, 408, "No Answer"), now);
                }
            }
            LegTimer::CancelGuard => {
                if leg.phase != Phase::Confirmed {
                    let cause = leg.cancel_cause.clone().unwrap_or_else(|| Cause::new(CauseKind::Cancelled));
                    self.terminate(leg, cause.with_detail("no final response after CANCEL"));
                }
            }
            LegTimer::UasAnswer => {
                if leg.role == Role::Uas && matches!(leg.phase, Phase::Calling | Phase::Early) {
                    let cause = Cause::sip(CauseKind::Timeout, 480, "Temporarily Unavailable").with_detail("application did not answer");
                    self.emit(leg, None, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
                    self.uas_final(leg, 480, None, Vec::new(), None, now);
                    self.terminate(leg, cause);
                }
            }
        }
    }

    // ----------------------------------------------------------- inbound --

    /// One received SIP message (datagram or framed stream message).
    pub fn handle_message(&mut self, data: &[u8], src: Dest, now: u64) {
        let msg = match SipMessage::parse(data, &self.cfg.limits) {
            Ok(m) => m,
            Err(_) => {
                self.stats.malformed = self.stats.malformed.saturating_add(1);
                return;
            }
        };
        if msg.is_request() { self.on_request(msg, src, now) } else { self.on_response(msg, now) }
    }

    fn on_response(&mut self, resp: SipMessage, now: u64) {
        let (Some(via), Some((_, method))) = (resp.top_via(), resp.cseq()) else { return };
        let Some(branch) = via.branch else { return };
        let Some(&id) = self.client_keys.get(&ClientKey { branch, method }) else { return };
        self.txn_do(id, now, |t| t.on_response(resp, now));
    }

    /// Build a response to `req` (RFC 3261 §8.2.6.2).
    fn build_response(&self, req: &SipMessage, code: u16, reason: Option<&str>, to_tag: Option<&str>) -> SipMessage {
        let mut r = SipMessage::response(code, reason.unwrap_or_else(|| reason_text(code)));
        for v in req.header_lines("Via") {
            r.push_header("Via", v);
        }
        if let Some(f) = req.header("From") {
            r.push_header("From", f);
        }
        if let Some(t) = req.header("To") {
            match to_tag {
                Some(tag) if code > 100 && req.to_tag().is_none() => r.push_header("To", format!("{t};tag={tag}")),
                _ => r.push_header("To", t),
            }
        }
        if let Some(c) = req.call_id() {
            r.push_header("Call-ID", c);
        }
        if let Some(c) = req.header("CSeq") {
            r.push_header("CSeq", c);
        }
        if let Some(ua) = &self.cfg.user_agent {
            r.push_header("Server", ua.as_str());
        }
        r
    }

    /// Reply through server transaction `tid`.
    fn reply(&mut self, tid: TxnId, mut resp: SipMessage, now: u64) {
        if resp.status() == Some(405) || (resp.status() == Some(200) && resp.header("Allow").is_none()) {
            resp.push_header("Allow", ALLOW);
        }
        self.txn_do(tid, now, |t| t.respond(&resp, now));
    }

    fn reply_simple(&mut self, tid: TxnId, code: u16, to_tag: Option<&str>, extra: &[(&str, String)], now: u64) {
        let Some(req) = self.txns.get(&tid).map(|e| e.txn.request.clone()) else { return };
        let mut r = self.build_response(&req, code, None, to_tag);
        for (n, v) in extra {
            r.push_header(*n, v.as_str());
        }
        self.reply(tid, r, now);
    }

    fn on_request(&mut self, req: SipMessage, src: Dest, now: u64) {
        let Some(key) = server_key(&req) else { return };
        let Some(method) = req.method().cloned() else { return };
        if let Some(&tid) = self.server_keys.get(&key) {
            self.txn_do(tid, now, |t| t.on_request(req, now));
            return;
        }
        if method == Method::Ack {
            self.on_dialog_ack(req, now);
            return;
        }
        let dest = response_dest(&req, src);
        let tid = self.new_txn_id();
        let txn = Txn::server(tid, req.clone(), dest, self.cfg.timers, now);
        self.server_keys.insert(key.clone(), tid);
        self.txns.insert(tid, TxnEntry { txn, purpose: Purpose::Detached, key: TxnKey::Server(key.clone()) });
        if method == Method::Cancel {
            self.on_cancel(tid, &req, key, now);
            return;
        }
        if let Some(to_tag) = req.to_tag() {
            let k = (req.call_id().unwrap_or_default().to_string(), to_tag, req.from_tag().unwrap_or_default());
            match self.dialogs.get(&k).copied() {
                Some(leg) => {
                    self.with_leg(leg, now, |s, l| s.on_in_dialog(l, tid, req, now));
                }
                None => self.reply_simple(tid, 481, None, &[], now),
            }
            return;
        }
        match method {
            Method::Invite => self.on_new_invite(tid, req, src, now),
            Method::Options => {
                let tag = self.token();
                self.reply_simple(tid, 200, Some(&tag), &[("Accept", "application/sdp".into())], now);
            }
            Method::Bye | Method::Info | Method::Update | Method::Prack | Method::Notify => self.reply_simple(tid, 481, None, &[], now),
            _ => self.reply_simple(tid, 405, None, &[], now),
        }
    }

    fn on_cancel(&mut self, tid: TxnId, req: &SipMessage, key: ServerKey, now: u64) {
        let inv = ServerKey { method: Method::Invite, ..key };
        let Some(&itid) = self.server_keys.get(&inv) else {
            self.reply_simple(tid, 481, None, &[], now);
            return;
        };
        self.reply_simple(tid, 200, None, &[], now);
        let Some(Purpose::Invite(leg)) = self.txns.get(&itid).map(|e| e.purpose) else { return };
        let final_sent = self.txns.get(&itid).is_some_and(|e| e.txn.final_sent());
        if final_sent {
            return;
        }
        let reason = req.header("Reason").map(str::to_string);
        self.with_leg(leg, now, |s, l| {
            let tag = l.local_tag.clone();
            s.reply_simple(itid, 487, Some(&tag), &[], now);
            s.emit(l, None, UaEvent::Cancelled);
            let cause = Cause::sip(CauseKind::Cancelled, 487, "Request Terminated").with_reason_header(reason.as_deref());
            s.terminate(l, cause);
        });
    }

    fn on_new_invite(&mut self, tid: TxnId, req: SipMessage, src: Dest, now: u64) {
        if self.draining || self.legs.len() >= self.cfg.max_legs {
            self.stats.rejected_overload = self.stats.rejected_overload.saturating_add(1);
            let tag = self.token();
            self.reply_simple(tid, 503, Some(&tag), &[("Retry-After", "5".into())], now);
            return;
        }
        let Some(from_tag) = req.from_tag() else {
            self.reply_simple(tid, 400, None, &[], now);
            return;
        };
        let Some(contact) = req.contact_uri() else {
            self.reply_simple(tid, 400, None, &[("Warning", "399 - \"missing Contact\"".into())], now);
            return;
        };
        let call_id = req.call_id().unwrap_or_default().to_string();
        let cseq = req.cseq().map_or(0, |c| c.0);
        let mkey = (call_id.clone(), from_tag.clone(), cseq);
        if self.merged.contains_key(&mkey) {
            // RFC 3261 §8.2.2.2: the same request arrived over another path.
            let tag = self.token();
            self.reply_simple(tid, 482, Some(&tag), &[], now);
            return;
        }
        let required = req.values("Require");
        if !required.is_empty() {
            self.reply_simple(tid, 420, None, &[("Unsupported", required.join(", "))], now);
            return;
        }
        let ruri = req.uri().unwrap_or_default().to_string();
        let secure = parse_uri(ruri.as_bytes()).is_some_and(|u| u.is_sips());
        if secure && !src.proto.is_tls() {
            self.reply_simple(tid, 400, None, &[("Warning", "399 - \"SIPS requires TLS\"".into())], now);
            return;
        }
        let offer = if req.body.is_empty() {
            None
        } else if req.sdp().is_none() {
            self.reply_simple(tid, 415, None, &[("Accept", "application/sdp".into())], now);
            return;
        } else if !sdp::is_valid(&req.body) {
            self.reply_simple(tid, 400, None, &[("Warning", "399 - \"malformed SDP\"".into())], now);
            return;
        } else {
            Some(req.body.clone())
        };
        let id = self.ids.leg();
        let local_tag = self.token();
        let to = req.header("To").unwrap_or_default().to_string();
        let local_contact = self.contact_for(src.proto, secure).unwrap_or_default();
        let mut leg = Leg {
            id,
            role: Role::Uas,
            phase: Phase::Calling,
            call_id: call_id.clone(),
            local_tag: local_tag.clone(),
            remote_tag: Some(from_tag.clone()),
            local_hdr: format!("{to};tag={local_tag}"),
            remote_hdr: req.header("From").unwrap_or_default().to_string(),
            local_contact,
            remote_target: contact,
            route_set: req.values("Record-Route"),
            local_cseq: 0,
            remote_cseq: Some(cseq),
            flow: src.proto.is_stream().then_some(src),
            secure,
            invite_txn: Some(tid),
            invite_template: None,
            invite_dest: None,
            early: Vec::new(),
            killed: Vec::new(),
            oa: if offer.is_some() { Oa::RemoteOffer(OfferVia::Invite) } else { Oa::Stable },
            negotiated: false,
            early_answer: None,
            remote_offer: offer.clone(),
            generation: u64::from(offer.is_some()),
            stable_generation: 0,
            seq: 0,
            ack: None,
            ack_wait: None,
            pending_2xx: None,
            server_reinvite: None,
            server_update: None,
            client_reinvite: None,
            client_update: None,
            cancel: CancelState::None,
            cancel_reason: None,
            cancel_cause: None,
            initial_ack_pending: false,
            bye_after_ack: None,
            bye_cause: None,
            creds: None,
            auth_attempts: 0,
            timers: Vec::new(),
            origin_op: None,
            overloaded: false,
            merged_key: Some(mkey.clone()),
            dialog_tags: Vec::new(),
        };
        if let Some(e) = self.txns.get_mut(&tid) {
            e.purpose = Purpose::Invite(id);
        }
        self.merged.insert(mkey, id);
        self.register_dialog(&mut leg, &from_tag);
        self.reply_simple(tid, 100, None, &[], now);
        let at = now.saturating_add(self.cfg.uas_answer_timeout_ms);
        self.arm_leg(&mut leg, LegTimer::UasAnswer, at);
        let ev = InboundInvite {
            request_uri: ruri,
            from: req.header("From").unwrap_or_default().to_string(),
            to,
            call_id,
            source: src,
            headers: req.headers.clone(),
            sdp: offer,
        };
        self.emit(&mut leg, None, UaEvent::IncomingInvite(ev));
        self.legs.insert(id, leg);
        // Apply the overload policy if the event could not be queued.
        self.with_leg(id, now, |_, _| ());
    }

    /// A dialog-creating response of the UAS (1xx/2xx to the initial INVITE).
    fn uas_dialog_response(&self, leg: &Leg, req: &SipMessage, code: u16, reason: Option<&str>, headers: &[Header], body: Option<&[u8]>) -> SipMessage {
        let mut r = self.build_response(req, code, reason, Some(&leg.local_tag));
        for rr in req.header_lines("Record-Route") {
            r.push_header("Record-Route", rr);
        }
        if !leg.local_contact.is_empty() {
            r.push_header("Contact", format!("<{}>", leg.local_contact));
        }
        if code >= 200 {
            r.push_header("Allow", ALLOW);
        }
        for h in headers {
            r.push_header(h.name.as_str(), h.value.as_str());
        }
        if let Some(b) = body {
            r.push_header("Content-Type", "application/sdp");
            r.body = b.to_vec();
        }
        r
    }

    fn uas_final(&mut self, leg: &mut Leg, code: u16, reason: Option<&str>, headers: Vec<Header>, reason_hdr: Option<String>, now: u64) {
        let Some(tid) = leg.invite_txn else { return };
        let Some(req) = self.txns.get(&tid).map(|e| e.txn.request.clone()) else { return };
        let mut r = self.build_response(&req, code, reason, Some(&leg.local_tag));
        for h in headers {
            r.push_header(h.name, h.value);
        }
        if let Some(rh) = reason_hdr {
            r.push_header("Reason", rh);
        }
        self.reply(tid, r, now);
        leg.disarm(LegTimer::UasAnswer);
    }

    fn on_dialog_ack(&mut self, ack: SipMessage, now: u64) {
        let (Some(call_id), Some(to), Some(from)) = (ack.call_id(), ack.to_tag(), ack.from_tag()) else { return };
        let Some(&leg) = self.dialogs.get(&(call_id.to_string(), to, from)) else { return };
        let cseq = ack.cseq().map_or(0, |c| c.0);
        self.with_leg(leg, now, |s, l| {
            if l.pending_2xx.as_ref().is_none_or(|p| p.cseq != cseq) {
                return;
            }
            l.pending_2xx = None;
            l.initial_ack_pending = false;
            l.disarm(LegTimer::Retransmit2xx);
            l.disarm(LegTimer::AckTimeout);
            let answer = ack.sdp().map(<[u8]>::to_vec);
            if let Oa::LocalOffer(OfferVia::OurTwoXx, op) = l.oa {
                match answer.filter(|a| sdp::is_valid(a)) {
                    Some(a) => {
                        l.oa = Oa::Stable;
                        l.negotiated = true;
                        l.stable_generation = l.generation;
                        s.emit(l, op, UaEvent::Ack(AckEvent { sdp: Some(a) }));
                    }
                    None => {
                        let cause = Cause::new(CauseKind::ProtocolViolation).with_detail("ACK without the answer to our offer");
                        s.emit(l, op, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
                        s.send_bye(l, Some("Q.850;cause=111".into()), cause, now);
                        return;
                    }
                }
            } else {
                s.emit(l, None, UaEvent::Ack(AckEvent { sdp: None }));
            }
            if let Some(reason) = l.bye_after_ack.take() {
                let cause = l.bye_cause.clone().unwrap_or_else(|| Cause::new(CauseKind::Local));
                s.send_bye(l, reason, cause, now);
            }
        });
    }

    fn glare_retry_after(&mut self) -> String {
        self.rand_below(10).to_string()
    }

    fn on_in_dialog(&mut self, leg: &mut Leg, tid: TxnId, req: SipMessage, now: u64) {
        let Some(method) = req.method().cloned() else { return };
        let Some((cseq, _)) = req.cseq() else { return };
        // RFC 3261 §12.2.2: lower or equal CSeq is out of order.
        if leg.remote_cseq.is_some_and(|r| cseq <= r) {
            self.reply_simple(tid, 500, None, &[("Warning", "399 - \"CSeq out of order\"".into())], now);
            return;
        }
        leg.remote_cseq = Some(cseq);
        match method {
            Method::Bye => {
                self.reply_simple(tid, 200, None, &[], now);
                self.close_pending_server(leg, now);
                let reason = req.header("Reason").map(str::to_string);
                if leg.phase == Phase::Terminating {
                    let cause = leg.bye_cause.clone().unwrap_or_else(|| Cause::new(CauseKind::NormalClearing));
                    self.terminate(leg, cause);
                } else {
                    self.emit(leg, None, UaEvent::RemoteBye(ByeEvent { reason: reason.clone() }));
                    self.terminate(leg, Cause::new(CauseKind::NormalClearing).with_reason_header(reason.as_deref()));
                }
            }
            Method::Invite => self.on_reinvite(leg, tid, req, now),
            Method::Update => self.on_update(leg, tid, req, now),
            Method::Info => {
                self.reply_simple(tid, 200, None, &[], now);
                let ev = InfoEvent { content_type: req.content_type().map(str::to_string), body: req.body.clone(), headers: req.headers.clone() };
                self.emit(leg, None, UaEvent::Info(ev));
            }
            Method::Options => self.reply_simple(tid, 200, None, &[("Accept", "application/sdp".into())], now),
            // We never send reliable provisionals.
            Method::Prack => self.reply_simple(tid, 481, None, &[], now),
            _ => self.reply_simple(tid, 501, None, &[], now),
        }
    }

    /// RFC 3261 §15.1.2: answer requests still pending when the dialog ends.
    fn close_pending_server(&mut self, leg: &mut Leg, now: u64) {
        if leg.role == Role::Uas && matches!(leg.phase, Phase::Calling | Phase::Early) {
            let tag = leg.local_tag.clone();
            if let Some(t) = leg.invite_txn {
                self.reply_simple(t, 487, Some(&tag), &[], now);
            }
        }
        for t in [leg.server_reinvite.take(), leg.server_update.take()].into_iter().flatten() {
            self.reply_simple(t, 487, None, &[], now);
        }
        leg.pending_2xx = None;
    }

    /// Is an offer from the peer acceptable now? Replies and returns false if not.
    fn offer_allowed(&mut self, leg: &Leg, tid: TxnId, now: u64) -> bool {
        // RFC 3261 §14.2 / RFC 3311 §5.2: glare is an offer *we* sent in a
        // request still in progress. Our offer in a 2xx awaiting its ACK is a
        // pending server INVITE instead: 500 + Retry-After below.
        let our_request = matches!(leg.oa, Oa::LocalOffer(v, _) if v != OfferVia::OurTwoXx);
        if our_request || leg.client_reinvite.is_some() || leg.client_update.is_some() {
            self.reply_simple(tid, 491, None, &[], now);
            return false;
        }
        let busy = !matches!(leg.oa, Oa::Stable)
            || leg.server_reinvite.is_some()
            || leg.server_update.is_some()
            || leg.pending_2xx.is_some()
            || leg.ack_wait.is_some();
        if busy || leg.phase != Phase::Confirmed {
            let ra = self.glare_retry_after();
            self.reply_simple(tid, 500, None, &[("Retry-After", ra)], now);
            return false;
        }
        true
    }

    fn on_reinvite(&mut self, leg: &mut Leg, tid: TxnId, req: SipMessage, now: u64) {
        if let Some(e) = self.txns.get_mut(&tid) {
            e.purpose = Purpose::ReInvite(leg.id, None);
        }
        if !self.offer_allowed(leg, tid, now) {
            return;
        }
        let offer = if req.body.is_empty() {
            None
        } else if req.sdp().is_some_and(sdp::is_valid) {
            Some(req.body.clone())
        } else {
            self.reply_simple(tid, 488, None, &[], now);
            return;
        };
        self.reply_simple(tid, 100, None, &[], now);
        leg.server_reinvite = Some(tid);
        leg.generation = leg.generation.saturating_add(1);
        leg.oa = Oa::RemoteOffer(OfferVia::ReInvite);
        leg.remote_offer = offer.clone();
        let deadline = now.saturating_add(self.cfg.answer_timeout_ms);
        self.arm_leg(leg, LegTimer::AnswerDeadline, deadline);
        self.emit(leg, None, UaEvent::RemoteOffer(RemoteOfferEvent { kind: OfferKind::ReInvite, sdp: offer, deadline }));
    }

    fn on_update(&mut self, leg: &mut Leg, tid: TxnId, req: SipMessage, now: u64) {
        if let Some(e) = self.txns.get_mut(&tid) {
            e.purpose = Purpose::Update(leg.id, None);
        }
        if req.body.is_empty() {
            // Target refresh only (RFC 3311 §5.2).
            if let Some(c) = req.contact_uri() {
                leg.remote_target = c;
            }
            let contact = format!("<{}>", leg.local_contact);
            self.reply_simple(tid, 200, None, &[("Contact", contact)], now);
            return;
        }
        if !self.offer_allowed(leg, tid, now) {
            return;
        }
        if !req.sdp().is_some_and(sdp::is_valid) {
            self.reply_simple(tid, 488, None, &[], now);
            return;
        }
        if let Some(c) = req.contact_uri() {
            leg.remote_target = c;
        }
        leg.server_update = Some(tid);
        leg.generation = leg.generation.saturating_add(1);
        leg.oa = Oa::RemoteOffer(OfferVia::Update);
        leg.remote_offer = Some(req.body.clone());
        let deadline = now.saturating_add(self.cfg.answer_timeout_ms);
        self.arm_leg(leg, LegTimer::AnswerDeadline, deadline);
        self.emit(leg, None, UaEvent::RemoteOffer(RemoteOfferEvent { kind: OfferKind::Update, sdp: Some(req.body), deadline }));
    }

    /// Answer (Some) or reject (None) the outstanding remote offer.
    fn answer_remote_offer(&mut self, leg: &mut Leg, sdp_body: Option<Vec<u8>>, now: u64) {
        let Oa::RemoteOffer(via) = leg.oa else { return };
        leg.disarm(LegTimer::AnswerDeadline);
        let offer = leg.remote_offer.take();
        match via {
            OfferVia::TheirTwoXx => {
                let cseq = leg.ack_wait.take().unwrap_or(leg.local_cseq);
                let body = match sdp_body {
                    Some(b) => {
                        leg.negotiated = true;
                        leg.stable_generation = leg.generation;
                        b
                    }
                    None => sdp::reject_all(offer.as_deref().unwrap_or_default()),
                };
                leg.oa = Oa::Stable;
                self.send_ack(leg, cseq, Some(body), now);
            }
            OfferVia::ReInvite => {
                let Some(tid) = leg.server_reinvite.take() else { return };
                let Some(req) = self.txns.get(&tid).map(|e| e.txn.request.clone()) else {
                    leg.oa = Oa::Stable;
                    return;
                };
                match sdp_body {
                    Some(b) => {
                        let had_offer = offer.is_some();
                        if let Some(c) = req.contact_uri() {
                            leg.remote_target = c;
                        }
                        let r = self.uas_dialog_response(leg, &req, 200, None, &[], Some(&b));
                        let cseq = req.cseq().map_or(0, |c| c.0);
                        let dest = self.txns.get(&tid).map(|e| e.txn.dest);
                        let bytes: Arc<[u8]> = r.to_bytes().into();
                        self.reply(tid, r, now);
                        if had_offer {
                            leg.oa = Oa::Stable;
                            leg.stable_generation = leg.generation;
                        } else {
                            leg.oa = Oa::LocalOffer(OfferVia::OurTwoXx, None);
                        }
                        if let Some(d) = dest {
                            self.start_2xx_retransmit(leg, cseq, bytes, d, now);
                        }
                    }
                    None => {
                        leg.oa = Oa::Stable;
                        self.reply_simple(tid, 488, None, &[], now);
                    }
                }
            }
            OfferVia::Update => {
                let Some(tid) = leg.server_update.take() else { return };
                leg.oa = Oa::Stable;
                match sdp_body {
                    Some(b) => {
                        let Some(req) = self.txns.get(&tid).map(|e| e.txn.request.clone()) else { return };
                        let mut r = self.build_response(&req, 200, None, None);
                        r.push_header("Contact", format!("<{}>", leg.local_contact));
                        r.push_header("Content-Type", "application/sdp");
                        r.body = b;
                        self.reply(tid, r, now);
                        leg.stable_generation = leg.generation;
                    }
                    None => self.reply_simple(tid, 488, None, &[], now),
                }
            }
            OfferVia::Invite | OfferVia::OurTwoXx => {}
        }
    }

    fn start_2xx_retransmit(&mut self, leg: &mut Leg, cseq: u32, bytes: Arc<[u8]>, dest: Dest, now: u64) {
        let t1 = self.cfg.timers.t1;
        leg.pending_2xx = Some(Pending2xx { cseq, bytes, dest, interval: t1 });
        self.arm_leg(leg, LegTimer::Retransmit2xx, now.saturating_add(t1));
        let t64 = self.cfg.timers.t64();
        self.arm_leg(leg, LegTimer::AckTimeout, now.saturating_add(t64));
    }

    // ------------------------------------------------------- UAC replies --

    fn on_txn_response(&mut self, tid: TxnId, purpose: Purpose, resp: SipMessage, now: u64) {
        match purpose {
            Purpose::Invite(leg) => {
                let found = self.with_leg(leg, now, |s, l| s.uac_invite_response(l, tid, &resp, now));
                if found.is_none() {
                    self.ack_orphan_2xx(tid, &resp);
                }
            }
            Purpose::ReInvite(leg, Some(op)) => {
                let found = self.with_leg(leg, now, |s, l| s.reinvite_response(l, tid, op, &resp, now));
                if found.is_none() {
                    self.ack_orphan_2xx(tid, &resp);
                }
            }
            Purpose::Update(leg, Some(op)) => {
                self.with_leg(leg, now, |s, l| s.update_response(l, tid, op, &resp, now));
            }
            Purpose::Bye(leg) => {
                if resp.status().is_some_and(|c| c >= 200) {
                    self.with_leg(leg, now, |s, l| {
                        let cause = l.bye_cause.clone().unwrap_or_else(|| Cause::new(CauseKind::NormalClearing));
                        s.terminate(l, cause);
                    });
                }
            }
            Purpose::Info(leg, op) => {
                let Some(code) = resp.status().filter(|c| *c >= 200) else { return };
                self.with_leg(leg, now, |s, l| {
                    let status = SipStatus { code, reason: resp.reason().unwrap_or_default().to_string() };
                    if code < 300 {
                        s.emit(l, Some(op), UaEvent::Completed(CompletedEvent { status, sdp: None }));
                    } else {
                        s.op_failed(l, Some(op), &resp, now);
                    }
                });
            }
            Purpose::ReInvite(_, None) | Purpose::Update(_, None) | Purpose::Cancel(_) | Purpose::Detached => {}
        }
    }

    /// A 2xx for an INVITE whose leg is gone: ACK it so the peer stops
    /// retransmitting (the BYE was sent when the leg ended).
    fn ack_orphan_2xx(&mut self, tid: TxnId, resp: &SipMessage) {
        if !resp.status().is_some_and(|c| (200..300).contains(&c)) {
            return;
        }
        let Some(e) = self.txns.get(&tid) else { return };
        let (req, dest) = (e.txn.request.clone(), e.txn.dest);
        let ack = self.ack_for(&req, resp, None);
        self.send_with_via(ack, resp, dest);
    }

    /// ACK (or BYE) for a 2xx outside our leg's own dialog state: the dialog
    /// is built from the response itself.
    fn ack_for(&self, invite: &SipMessage, resp: &SipMessage, body: Option<Vec<u8>>) -> SipMessage {
        self.dialog_request_from_2xx(invite, resp, Method::Ack, invite.cseq().map_or(1, |c| c.0), body)
    }

    fn dialog_request_from_2xx(&self, invite: &SipMessage, resp: &SipMessage, method: Method, cseq: u32, body: Option<Vec<u8>>) -> SipMessage {
        let target = resp.contact_uri().or_else(|| invite.uri().map(str::to_string)).unwrap_or_default();
        let mut routes = resp.values("Record-Route");
        routes.reverse();
        let (ruri, routes) = route_request(&target, &routes);
        let mut m = SipMessage::request(method.clone(), ruri);
        m.push_header("Max-Forwards", "70");
        if let Some(f) = invite.header("From") {
            m.push_header("From", f);
        }
        if let Some(t) = resp.header("To") {
            m.push_header("To", t);
        }
        if let Some(c) = invite.call_id() {
            m.push_header("Call-ID", c);
        }
        m.push_header("CSeq", format!("{cseq} {method}"));
        for r in routes {
            m.push_header("Route", r);
        }
        if let Some(b) = body {
            m.push_header("Content-Type", "application/sdp");
            m.body = b;
        }
        m
    }

    /// Send a transaction-less request (ACK) built from a response; next hop
    /// from its first Route / Request-URI when it is an IP, else `fallback`.
    fn send_with_via(&mut self, mut m: SipMessage, _resp: &SipMessage, fallback: Dest) -> Option<Arc<[u8]>> {
        let d = match self.target_for(&m, None) {
            Some(Target::Ready(d)) => d,
            _ => fallback,
        };
        let adv = self.local_addr(d.proto)?;
        let branch = self.branch();
        m.prepend_header("Via", format!("SIP/2.0/{} {adv};branch={branch};rport", d.proto.via_name()));
        let b: Arc<[u8]> = m.to_bytes().into();
        self.send_raw(d, b.clone(), None);
        Some(b)
    }

    /// End a dialog we will not keep (a forked 2xx, or a 2xx after CANCEL):
    /// ACK it, then BYE it (RFC 3261 §13.2.2.4).
    fn kill_2xx(&mut self, leg: &mut Leg, tid: TxnId, resp: &SipMessage, now: u64) {
        let tag = resp.to_tag().unwrap_or_default();
        if let Some((_, b, d)) = leg.killed.iter().find(|(t, _, _)| *t == tag) {
            let (b, d) = (b.clone(), *d);
            self.send_raw(d, b, None);
            return;
        }
        let Some(e) = self.txns.get(&tid) else { return };
        let (invite, dest) = (e.txn.request.clone(), e.txn.dest);
        // A delayed-offer 2xx carries an offer: the ACK must answer it.
        let body = if invite.sdp().is_none() { resp.sdp().map(sdp::reject_all) } else { None };
        let ack = self.ack_for(&invite, resp, body);
        if let Some(b) = self.send_with_via(ack, resp, dest) {
            leg.killed.push((tag, b, dest));
        }
        let cseq = invite.cseq().map_or(1, |c| c.0).saturating_add(1);
        let mut bye = self.dialog_request_from_2xx(&invite, resp, Method::Bye, cseq, None);
        bye.push_header("Reason", "SIP;cause=200;text=\"Call completed elsewhere\"");
        let d = match self.target_for(&bye, None) {
            Some(Target::Ready(d)) => d,
            _ => dest,
        };
        // The BYE's outcome does not matter to the leg.
        let _ = self.start_client(bye, d, Purpose::Detached, now);
    }

    fn uac_invite_response(&mut self, leg: &mut Leg, tid: TxnId, resp: &SipMessage, now: u64) {
        if leg.invite_txn != Some(tid) {
            // An earlier INVITE (replaced by an authenticated retry).
            if resp.status().is_some_and(|c| (200..300).contains(&c)) {
                self.kill_2xx(leg, tid, resp, now);
            }
            return;
        }
        let Some(code) = resp.status() else { return };
        let tag = resp.to_tag();
        let status = SipStatus { code, reason: resp.reason().unwrap_or_default().to_string() };
        if code < 200 {
            if code > 100 {
                if let Some(t) = tag.clone() {
                    if !leg.early.contains(&t) {
                        leg.early.push(t.clone());
                    }
                    self.register_dialog(leg, &t);
                }
                if let (Oa::LocalOffer(OfferVia::Invite, _), Some(a)) = (leg.oa, resp.sdp()) {
                    leg.early_answer = Some(a.to_vec());
                    leg.oa = Oa::Stable;
                    leg.negotiated = true;
                    leg.stable_generation = leg.generation;
                }
                if leg.phase == Phase::Calling {
                    leg.phase = Phase::Early;
                }
            }
            if leg.cancel == CancelState::Requested {
                self.send_cancel(leg, now);
            } else if code > 100 && leg.cancel == CancelState::None {
                let op = leg.origin_op;
                self.emit(leg, op, UaEvent::Provisional(ProvisionalEvent { status, remote_tag: tag, sdp: resp.sdp().map(<[u8]>::to_vec) }));
            }
            return;
        }
        if code < 300 {
            let Some(tag) = tag else { return };
            if leg.remote_tag.as_deref() == Some(tag.as_str()) {
                // Retransmitted 2xx: our ACK was lost.
                if let Some((c, b, d)) = &leg.ack
                    && resp.cseq().is_some_and(|x| x.0 == *c)
                {
                    let (b, d) = (b.clone(), *d);
                    self.send_raw(d, b, None);
                }
                return;
            }
            if leg.remote_tag.is_some() || leg.cancel == CancelState::Sent || leg.phase == Phase::Terminating {
                self.kill_2xx(leg, tid, resp, now);
                if leg.cancel == CancelState::Sent && leg.remote_tag.is_none() {
                    // CANCEL lost the race with this 2xx.
                    let cause = leg.cancel_cause.clone().unwrap_or_else(|| Cause::new(CauseKind::Cancelled));
                    self.terminate(leg, cause.with_detail("2xx crossed CANCEL; ACK+BYE sent"));
                }
                return;
            }
            self.confirm_uac(leg, tid, resp, status, now);
            return;
        }
        // 3xx-6xx (the transaction ACKed it).
        if matches!(code, 401 | 407) && self.retry_with_auth(leg, tid, resp, now) {
            return;
        }
        for t in std::mem::take(&mut leg.early) {
            self.unregister_dialog(leg, &t);
        }
        let reason = resp.header("Reason");
        let cause = if leg.cancel == CancelState::Sent && code == 487 {
            leg.cancel_cause.clone().unwrap_or_else(|| Cause::sip(CauseKind::Cancelled, code, status.reason.clone()))
        } else if matches!(code, 401 | 407) {
            Cause::sip(CauseKind::AuthFailed, code, status.reason.clone())
        } else {
            Cause::sip(CauseKind::SipResponse, code, status.reason.clone()).with_reason_header(reason)
        };
        let op = leg.origin_op;
        // A 487 to our own CANCEL ends the leg as asked: not a failure.
        if leg.cancel == CancelState::Sent && code == 487 {
            self.terminate(leg, cause);
        } else {
            self.fail(leg, op, cause);
        }
    }

    fn confirm_uac(&mut self, leg: &mut Leg, tid: TxnId, resp: &SipMessage, status: SipStatus, now: u64) {
        let tag = resp.to_tag().unwrap_or_default();
        leg.remote_tag = Some(tag.clone());
        leg.remote_hdr = resp.header("To").unwrap_or_default().to_string();
        if let Some(c) = resp.contact_uri() {
            leg.remote_target = c;
        }
        let mut rr = resp.values("Record-Route");
        rr.reverse();
        leg.route_set = rr;
        for t in std::mem::take(&mut leg.early) {
            if t != tag {
                self.unregister_dialog(leg, &t);
            }
        }
        self.register_dialog(leg, &tag);
        leg.phase = Phase::Confirmed;
        leg.disarm(LegTimer::NoAnswer);
        // Only needed to resend the INVITE with credentials.
        leg.invite_template = None;
        let cseq = self.txns.get(&tid).and_then(|e| e.txn.request.cseq()).map_or(leg.local_cseq, |c| c.0);
        let op = leg.origin_op;
        let answer = resp.sdp().map(<[u8]>::to_vec);
        if leg.negotiated || matches!(leg.oa, Oa::LocalOffer(OfferVia::Invite, _)) {
            if !leg.negotiated && answer.as_deref().is_none_or(|a| !sdp::is_valid(a)) {
                self.send_ack(leg, cseq, None, now);
                let cause = Cause::new(CauseKind::ProtocolViolation).with_detail("2xx without an answer to our offer");
                self.emit(leg, op, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
                self.send_bye(leg, Some("Q.850;cause=111".into()), cause, now);
                return;
            }
            leg.oa = Oa::Stable;
            leg.negotiated = true;
            leg.stable_generation = leg.generation;
            self.send_ack(leg, cseq, None, now);
            self.emit(leg, op, UaEvent::Accepted(AcceptedEvent { status, sdp: answer }));
            return;
        }
        // Delayed offer: the 2xx carries the offer, our ACK the answer.
        let Some(offer) = answer.filter(|a| sdp::is_valid(a)) else {
            self.send_ack(leg, cseq, None, now);
            let cause = Cause::new(CauseKind::ProtocolViolation).with_detail("2xx to an offer-less INVITE without an offer");
            self.emit(leg, op, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
            self.send_bye(leg, Some("Q.850;cause=111".into()), cause, now);
            return;
        };
        leg.generation = leg.generation.saturating_add(1);
        leg.oa = Oa::RemoteOffer(OfferVia::TheirTwoXx);
        leg.remote_offer = Some(offer.clone());
        leg.ack_wait = Some(cseq);
        let deadline = now.saturating_add(self.cfg.answer_timeout_ms.min(self.cfg.timers.t64()));
        self.arm_leg(leg, LegTimer::AnswerDeadline, deadline);
        self.emit(leg, op, UaEvent::Accepted(AcceptedEvent { status, sdp: Some(offer.clone()) }));
        self.emit(leg, op, UaEvent::RemoteOffer(RemoteOfferEvent { kind: OfferKind::InviteResponse, sdp: Some(offer), deadline }));
    }

    fn retry_with_auth(&mut self, leg: &mut Leg, tid: TxnId, resp: &SipMessage, now: u64) -> bool {
        let Some(creds) = leg.creds.clone() else { return false };
        if leg.auth_attempts >= self.cfg.max_auth_attempts || leg.cancel != CancelState::None || leg.phase == Phase::Terminating {
            return false;
        }
        let Some(mut req) = leg.invite_template.clone() else { return false };
        let uri = req.uri().unwrap_or_default().to_string();
        let cnonce = self.token();
        let Some((hname, hval)) = auth::authorize(resp, &creds, "INVITE", &uri, &cnonce) else { return false };
        let Some(cseq) = leg.local_cseq.checked_add(1).filter(|c| *c < 1 << 31) else { return false };
        leg.auth_attempts = leg.auth_attempts.saturating_add(1);
        leg.local_cseq = cseq;
        req.set_header("CSeq", format!("{cseq} INVITE"));
        req.set_header(hname, hval);
        leg.invite_template = Some(req.clone());
        for t in std::mem::take(&mut leg.early) {
            self.unregister_dialog(leg, &t);
        }
        leg.phase = Phase::Calling;
        let dest = leg.invite_dest.or_else(|| self.txns.get(&tid).map(|e| e.txn.dest));
        let Some(dest) = dest else { return false };
        // The leg is out of the map: register the txn on it directly.
        match self.start_client(req, dest, Purpose::Detached, now) {
            Ok(id) => {
                if let Some(e) = self.txns.get_mut(&id) {
                    e.purpose = Purpose::Invite(leg.id);
                }
                leg.invite_txn = Some(id);
                true
            }
            Err(_) => false,
        }
    }

    /// An in-dialog request with our dialog state (RFC 3261 §12.2.1.1).
    fn dialog_request(&self, leg: &Leg, method: Method, cseq: u32) -> SipMessage {
        let (ruri, routes) = route_request(&leg.remote_target, &leg.route_set);
        let mut m = SipMessage::request(method.clone(), ruri);
        m.push_header("Max-Forwards", "70");
        m.push_header("From", leg.local_hdr.as_str());
        m.push_header("To", leg.remote_hdr.as_str());
        m.push_header("Call-ID", leg.call_id.as_str());
        m.push_header("CSeq", format!("{cseq} {method}"));
        for r in routes {
            m.push_header("Route", r);
        }
        if let Some(ua) = &self.cfg.user_agent {
            m.push_header("User-Agent", ua.as_str());
        }
        m
    }

    fn next_cseq(leg: &mut Leg) -> Option<u32> {
        let c = leg.local_cseq.checked_add(1).filter(|c| *c < 1 << 31)?;
        leg.local_cseq = c;
        Some(c)
    }

    fn send_ack(&mut self, leg: &mut Leg, cseq: u32, body: Option<Vec<u8>>, now: u64) {
        let mut ack = self.dialog_request(leg, Method::Ack, cseq);
        if let Some(b) = body {
            ack.push_header("Content-Type", "application/sdp");
            ack.body = b;
        }
        // The leg is out of the map here: record the ACK on it directly.
        match self.target_for(&ack, leg.flow) {
            Some(Target::Ready(d)) => {
                let Some(adv) = self.local_addr(d.proto) else { return };
                let branch = self.branch();
                ack.prepend_header("Via", format!("SIP/2.0/{} {adv};branch={branch};rport", d.proto.via_name()));
                let bytes: Arc<[u8]> = ack.to_bytes().into();
                leg.ack = Some((cseq, bytes.clone(), d));
                self.send_raw(d, bytes, None);
            }
            Some(Target::Resolve(..)) => {
                let _ = self.dispatch(leg, ack, Purpose::Detached, true, None, now);
            }
            None => {}
        }
    }

    fn send_bye(&mut self, leg: &mut Leg, reason: Option<String>, cause: Cause, now: u64) {
        if leg.phase == Phase::Terminating || leg.phase == Phase::Terminated {
            return;
        }
        leg.bye_cause = Some(cause.clone());
        let Some(cseq) = Self::next_cseq(leg) else {
            self.terminate(leg, cause);
            return;
        };
        let mut bye = self.dialog_request(leg, Method::Bye, cseq);
        if let Some(r) = reason {
            bye.push_header("Reason", r);
        }
        leg.phase = Phase::Terminating;
        leg.disarm(LegTimer::Retransmit2xx);
        leg.disarm(LegTimer::AckTimeout);
        leg.disarm(LegTimer::AnswerDeadline);
        let id = leg.id;
        if self.dispatch_leg_request(leg, bye, Purpose::Bye(id), None, now).is_err() {
            self.terminate(leg, cause);
        }
    }

    /// `dispatch` for a leg that is out of the map (inside `with_leg`).
    fn dispatch_leg_request(&mut self, leg: &mut Leg, req: SipMessage, purpose: Purpose, next_hop: Option<Dest>, now: u64) -> Result<(), CommandError> {
        let target = match next_hop {
            Some(d) => Some(Target::Ready(d)),
            None => self.target_for(&req, leg.flow),
        };
        match target {
            Some(Target::Ready(d)) => {
                let mut req = req;
                if matches!(req.method(), Some(Method::Invite | Method::Update)) && req.header("Contact").is_none() {
                    if leg.local_contact.is_empty() {
                        leg.local_contact = self.contact_for(d.proto, leg.secure).ok_or(CommandError::NoLocalAddress)?;
                    }
                    req.push_header("Contact", format!("<{}>", leg.local_contact));
                }
                let id = self.start_client(req, d, purpose, now)?;
                match purpose {
                    Purpose::Invite(_) => {
                        leg.invite_txn = Some(id);
                        leg.invite_dest = Some(d);
                    }
                    Purpose::ReInvite(_, Some(_)) => leg.client_reinvite = Some(id),
                    Purpose::Update(_, Some(_)) => leg.client_update = Some(id),
                    _ => {}
                }
                Ok(())
            }
            Some(Target::Resolve(host, port, proto, secure)) => {
                self.next_resolve = self.next_resolve.wrapping_add(1);
                let id = self.next_resolve;
                self.pending_resolve.insert(id, PendingResolve { leg: leg.id, req, purpose, stateless: false });
                self.resolves.push_back(ResolveRequest { id, host, port, proto, secure });
                Ok(())
            }
            None => Err(CommandError::InvalidArgument("unroutable remote target".into())),
        }
    }

    fn send_cancel(&mut self, leg: &mut Leg, now: u64) {
        let Some(tid) = leg.invite_txn else { return };
        let Some(e) = self.txns.get(&tid) else { return };
        if e.txn.state == TxState::Calling {
            // RFC 3261 §9.1: wait for a provisional.
            leg.cancel = CancelState::Requested;
            return;
        }
        if e.txn.state != TxState::Proceeding {
            return;
        }
        let (inv, dest) = (e.txn.request.clone(), e.txn.dest);
        let mut c = SipMessage::request(Method::Cancel, inv.uri().unwrap_or_default());
        let top = inv.header("Via").map(|v| split_values(v).into_iter().next().unwrap_or_else(|| v.to_string())).unwrap_or_default();
        c.push_header("Via", top.as_str());
        for r in inv.header_lines("Route") {
            c.push_header("Route", r);
        }
        c.push_header("Max-Forwards", "70");
        for h in ["From", "To", "Call-ID"] {
            if let Some(v) = inv.header(h) {
                c.push_header(h, v);
            }
        }
        let n = inv.cseq().map_or(1, |x| x.0);
        c.push_header("CSeq", format!("{n} CANCEL"));
        if let Some(r) = &leg.cancel_reason {
            c.push_header("Reason", r.as_str());
        }
        let branch = inv.top_via().and_then(|v| v.branch).unwrap_or_default();
        leg.cancel = CancelState::Sent;
        let id = leg.id;
        let _ = self.start_client_prepared(c, dest, Purpose::Cancel(id), ClientKey { branch, method: Method::Cancel }, now);
    }

    fn cancel_leg(&mut self, leg: &mut Leg, reason: Option<String>, cause: Cause, now: u64) {
        if leg.cancel != CancelState::None {
            return;
        }
        leg.cancel_reason = reason;
        leg.cancel_cause = Some(cause);
        leg.disarm(LegTimer::NoAnswer);
        let guard = now.saturating_add(self.cfg.timers.t64());
        self.arm_leg(leg, LegTimer::CancelGuard, guard);
        if leg.invite_txn.is_none() {
            // Still resolving: nothing went out.
            let c = leg.cancel_cause.clone().unwrap_or_else(|| Cause::new(CauseKind::Cancelled));
            self.terminate(leg, c);
            return;
        }
        leg.cancel = CancelState::Requested;
        self.send_cancel(leg, now);
    }

    fn rollback(&mut self, leg: &mut Leg) {
        leg.oa = Oa::Stable;
    }

    /// An operation's request got a final non-2xx.
    fn op_failed(&mut self, leg: &mut Leg, op: Option<OperationId>, resp: &SipMessage, now: u64) {
        let code = resp.status().unwrap_or(500);
        let cause = Cause::sip(CauseKind::SipResponse, code, resp.reason().unwrap_or_default()).with_reason_header(resp.header("Reason"));
        match code {
            // RFC 3261 §12.2.1.2: the dialog is gone.
            481 => self.fail(leg, op, cause),
            408 => {
                self.emit(leg, op, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
                self.send_bye(leg, None, cause, now);
            }
            491 => {
                // RFC 3261 §14.1: the Call-ID owner waits 2.1–4 s, the other 0–2 s.
                let wait = if leg.role == Role::Uac {
                    2_100u64.saturating_add(self.rand_below(191).saturating_mul(10))
                } else {
                    self.rand_below(201).saturating_mul(10)
                };
                self.emit(leg, op, UaEvent::Failed(FailureEvent { cause, leg_failed: false, retry_after_ms: Some(wait) }));
            }
            _ => self.emit(leg, op, UaEvent::Failed(FailureEvent { cause, leg_failed: false, retry_after_ms: None })),
        }
    }

    fn reinvite_response(&mut self, leg: &mut Leg, tid: TxnId, op: OperationId, resp: &SipMessage, now: u64) {
        let Some(code) = resp.status() else { return };
        if code < 200 {
            return;
        }
        let cseq = resp.cseq().map_or(0, |c| c.0);
        if code < 300 {
            if let Some((c, b, d)) = &leg.ack
                && *c == cseq
            {
                let (b, d) = (b.clone(), *d);
                self.send_raw(d, b, None);
                return;
            }
            if leg.client_reinvite != Some(tid) {
                return;
            }
            leg.client_reinvite = None;
            if let Some(c) = resp.contact_uri() {
                leg.remote_target = c;
            }
            self.send_ack(leg, cseq, None, now);
            let status = SipStatus { code, reason: resp.reason().unwrap_or_default().to_string() };
            match resp.sdp().filter(|a| sdp::is_valid(a)) {
                Some(a) => {
                    leg.oa = Oa::Stable;
                    leg.stable_generation = leg.generation;
                    self.emit(leg, Some(op), UaEvent::Completed(CompletedEvent { status, sdp: Some(a.to_vec()) }));
                }
                None => {
                    self.rollback(leg);
                    let cause = Cause::new(CauseKind::ProtocolViolation).with_detail("re-INVITE 2xx without an answer");
                    self.emit(leg, Some(op), UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
                    self.send_bye(leg, Some("Q.850;cause=111".into()), cause, now);
                }
            }
            return;
        }
        if leg.client_reinvite != Some(tid) {
            return;
        }
        leg.client_reinvite = None;
        self.rollback(leg);
        self.op_failed(leg, Some(op), resp, now);
    }

    fn update_response(&mut self, leg: &mut Leg, tid: TxnId, op: OperationId, resp: &SipMessage, now: u64) {
        let Some(code) = resp.status().filter(|c| *c >= 200) else { return };
        if leg.client_update != Some(tid) {
            return;
        }
        leg.client_update = None;
        if code >= 300 {
            self.rollback(leg);
            self.op_failed(leg, Some(op), resp, now);
            return;
        }
        if let Some(c) = resp.contact_uri() {
            leg.remote_target = c;
        }
        let status = SipStatus { code, reason: resp.reason().unwrap_or_default().to_string() };
        match resp.sdp().filter(|a| sdp::is_valid(a)) {
            Some(a) => {
                leg.oa = Oa::Stable;
                leg.stable_generation = leg.generation;
                self.emit(leg, Some(op), UaEvent::Completed(CompletedEvent { status, sdp: Some(a.to_vec()) }));
            }
            None => {
                self.rollback(leg);
                let cause = Cause::new(CauseKind::ProtocolViolation).with_detail("UPDATE 2xx without an answer");
                self.emit(leg, Some(op), UaEvent::Failed(FailureEvent { cause, leg_failed: false, retry_after_ms: None }));
            }
        }
    }

    fn on_txn_failure(&mut self, _tid: TxnId, purpose: Purpose, kind: CauseKind, now: u64) {
        let cause = if kind == CauseKind::Timeout { Cause::sip(kind, 408, "Request Timeout") } else { Cause::new(kind) };
        match purpose {
            Purpose::Invite(leg) => {
                self.with_leg(leg, now, |s, l| {
                    if l.role == Role::Uac && matches!(l.phase, Phase::Calling | Phase::Early) {
                        let op = l.origin_op;
                        if l.cancel != CancelState::None {
                            let c = l.cancel_cause.clone().unwrap_or(cause);
                            s.terminate(l, c);
                        } else {
                            s.fail(l, op, cause);
                        }
                    } else if l.role == Role::Uas && l.phase != Phase::Confirmed {
                        // Timer H: our non-2xx was never ACKed; the leg already ended.
                    }
                });
            }
            Purpose::ReInvite(leg, Some(op)) | Purpose::Update(leg, Some(op)) => {
                self.with_leg(leg, now, |s, l| {
                    l.client_reinvite = None;
                    l.client_update = None;
                    s.rollback(l);
                    s.emit(l, Some(op), UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
                    s.send_bye(l, None, cause, now);
                });
            }
            Purpose::Bye(leg) => {
                self.with_leg(leg, now, |s, l| {
                    let c = l.bye_cause.clone().unwrap_or(cause);
                    s.terminate(l, c);
                });
            }
            Purpose::Info(leg, op) => {
                self.with_leg(leg, now, |s, l| {
                    s.emit(l, Some(op), UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: kind == CauseKind::Timeout, retry_after_ms: None }));
                    if kind == CauseKind::Timeout {
                        s.send_bye(l, None, cause, now);
                    }
                });
            }
            Purpose::ReInvite(_, None) | Purpose::Update(_, None) | Purpose::Cancel(_) | Purpose::Detached => {}
        }
    }

    // ---------------------------------------------------------- commands --

    /// Validate and start a command. `Ok` means accepted: the protocol
    /// outcome arrives later as events carrying the returned operation id.
    pub fn submit(&mut self, cmd: UaCommand, now: u64) -> Result<Accepted, CommandError> {
        let op = self.ids.op();
        self.submit_with(op, cmd, now)
    }

    /// `submit` with a caller-allocated operation id.
    pub fn submit_with(&mut self, op: OperationId, cmd: UaCommand, now: u64) -> Result<Accepted, CommandError> {
        if let UaCommand::Originate(o) = cmd {
            return self.originate(op, *o, now);
        }
        let leg = cmd.leg().ok_or(CommandError::UnknownLeg)?;
        if !self.legs.contains_key(&leg) {
            return Err(CommandError::UnknownLeg);
        }
        self.with_leg(leg, now, |s, l| s.leg_command(l, op, cmd, now)).unwrap_or(Err(CommandError::UnknownLeg)).map(|()| Accepted { op, leg })
    }

    fn leg_command(&mut self, leg: &mut Leg, op: OperationId, cmd: UaCommand, now: u64) -> Result<(), CommandError> {
        match cmd {
            UaCommand::Originate(_) => Err(CommandError::InvalidState("originate addresses no leg")),
            UaCommand::Provisional(r) => self.cmd_provisional(leg, r, now),
            UaCommand::Accept(r) => self.cmd_accept(leg, op, r, now),
            UaCommand::Reject(r) => {
                if leg.role != Role::Uas || !matches!(leg.phase, Phase::Calling | Phase::Early) {
                    return Err(CommandError::InvalidState("reject needs an unanswered inbound leg"));
                }
                if !(300..=699).contains(&r.code) {
                    return Err(CommandError::InvalidArgument("reject code must be 300..=699".into()));
                }
                check_headers(&r.headers)?;
                let reason = r.reason.filter(|x| is_safe_value(x));
                self.uas_final(leg, r.code, reason.as_deref(), r.headers, None, now);
                let cause = Cause::sip(CauseKind::Local, r.code, reason.unwrap_or_else(|| reason_text(r.code).to_string()));
                self.terminate(leg, cause);
                Ok(())
            }
            UaCommand::Cancel(r) => {
                if leg.role != Role::Uac || !matches!(leg.phase, Phase::Calling | Phase::Early) {
                    return Err(CommandError::InvalidState("cancel needs an unanswered outbound leg"));
                }
                let reason = r.reason.filter(|x| is_safe_value(x));
                self.cancel_leg(leg, reason, Cause::new(CauseKind::Cancelled), now);
                Ok(())
            }
            UaCommand::Hangup(r) => {
                let reason = r.reason.filter(|x| is_safe_value(x));
                self.hangup_leg(leg, reason, r.code, Cause::new(CauseKind::Local), now);
                Ok(())
            }
            UaCommand::Negotiate(r) => self.cmd_negotiate(leg, op, r, now),
            UaCommand::SendInfo(r) => {
                if leg.phase != Phase::Confirmed {
                    return Err(CommandError::InvalidState("INFO needs a confirmed dialog"));
                }
                if !is_safe_value(&r.content_type) {
                    return Err(CommandError::InvalidArgument("content type".into()));
                }
                check_headers(&r.headers)?;
                let cseq = Self::next_cseq(leg).ok_or(CommandError::InvalidState("CSeq space exhausted"))?;
                let mut m = self.dialog_request(leg, Method::Info, cseq);
                for h in r.headers {
                    m.push_header(h.name, h.value);
                }
                m.push_header("Content-Type", r.content_type);
                m.body = r.body;
                let id = leg.id;
                self.dispatch_leg_request(leg, m, Purpose::Info(id, op), None, now)
            }
            UaCommand::RespondToOffer(r) => {
                if !matches!(leg.oa, Oa::RemoteOffer(_)) {
                    return Err(CommandError::InvalidState("no remote offer outstanding"));
                }
                if r.generation.0 != leg.generation {
                    return Err(CommandError::StaleGeneration);
                }
                if let Some(b) = &r.sdp {
                    check_sdp(b)?;
                }
                let via = leg.oa;
                self.answer_remote_offer(leg, r.sdp.clone(), now);
                if via == Oa::RemoteOffer(OfferVia::TheirTwoXx) && r.sdp.is_none() {
                    let cause = Cause::new(CauseKind::Local).with_detail("offer in 2xx rejected by the application");
                    self.send_bye(leg, None, cause, now);
                }
                Ok(())
            }
        }
    }

    fn hangup_leg(&mut self, leg: &mut Leg, reason: Option<String>, code: Option<u16>, cause: Cause, now: u64) {
        match (leg.role, leg.phase) {
            (_, Phase::Terminating | Phase::Terminated) => {}
            (Role::Uas, Phase::Calling | Phase::Early) => {
                let code = code.filter(|c| (300..=699).contains(c)).unwrap_or(480);
                self.uas_final(leg, code, None, Vec::new(), reason, now);
                let c = if cause.kind == CauseKind::Local { Cause::sip(CauseKind::Local, code, reason_text(code)) } else { cause };
                self.terminate(leg, c);
            }
            (Role::Uac, Phase::Calling | Phase::Early) => self.cancel_leg(leg, reason, cause, now),
            (_, Phase::Confirmed) => {
                if leg.role == Role::Uas && leg.initial_ack_pending && leg.pending_2xx.is_some() {
                    // RFC 3261 §15: wait for the ACK of our initial 2xx (or its timeout).
                    leg.bye_cause = Some(cause);
                    leg.bye_after_ack = Some(reason);
                    return;
                }
                if leg.oa == Oa::RemoteOffer(OfferVia::TheirTwoXx) {
                    self.answer_remote_offer(leg, None, now);
                }
                self.close_pending_server(leg, now);
                self.send_bye(leg, reason, cause, now);
            }
        }
    }

    fn cmd_provisional(&mut self, leg: &mut Leg, r: ProvisionalRequest, now: u64) -> Result<(), CommandError> {
        if leg.role != Role::Uas || !matches!(leg.phase, Phase::Calling | Phase::Early) {
            return Err(CommandError::InvalidState("provisional needs an unanswered inbound leg"));
        }
        if !(101..=199).contains(&r.code) {
            return Err(CommandError::InvalidArgument("provisional code must be 101..=199".into()));
        }
        check_headers(&r.headers)?;
        if let Some(b) = &r.sdp {
            check_sdp(b)?;
            match leg.oa {
                Oa::RemoteOffer(OfferVia::Invite) => {}
                Oa::Stable if leg.negotiated => {}
                // An offer is only allowed in a reliable provisional (RFC 3262), which we don't send.
                _ => return Err(CommandError::InvalidState("early SDP needs an offer in the INVITE")),
            }
        }
        let tid = leg.invite_txn.ok_or(CommandError::InvalidState("no INVITE"))?;
        let req = self.txns.get(&tid).map(|e| e.txn.request.clone()).ok_or(CommandError::InvalidState("INVITE transaction gone"))?;
        let reason = r.reason.filter(|x| is_safe_value(x));
        let resp = self.uas_dialog_response(leg, &req, r.code, reason.as_deref(), &r.headers, r.sdp.as_deref());
        self.reply(tid, resp, now);
        if let Some(b) = r.sdp {
            leg.early_answer = Some(b);
            leg.remote_offer = None;
            leg.oa = Oa::Stable;
            leg.negotiated = true;
            leg.stable_generation = leg.generation;
        }
        leg.phase = Phase::Early;
        Ok(())
    }

    fn cmd_accept(&mut self, leg: &mut Leg, op: OperationId, r: AcceptRequest, now: u64) -> Result<(), CommandError> {
        if leg.role != Role::Uas || !matches!(leg.phase, Phase::Calling | Phase::Early) {
            return Err(CommandError::InvalidState("accept needs an unanswered inbound leg"));
        }
        check_headers(&r.headers)?;
        if let Some(b) = &r.sdp {
            check_sdp(b)?;
        }
        let (body, next_oa) = match leg.oa {
            Oa::RemoteOffer(OfferVia::Invite) => {
                (r.sdp.ok_or(CommandError::InvalidArgument("the INVITE has an offer: accept needs the answer".into()))?, Oa::Stable)
            }
            Oa::Stable if leg.negotiated => {
                (r.sdp.or_else(|| leg.early_answer.clone()).ok_or(CommandError::InvalidArgument("answer missing".into()))?, Oa::Stable)
            }
            Oa::Stable => {
                (r.sdp.ok_or(CommandError::InvalidArgument("delayed offer: accept needs our offer".into()))?, Oa::LocalOffer(OfferVia::OurTwoXx, Some(op)))
            }
            _ => return Err(CommandError::OfferPending),
        };
        let tid = leg.invite_txn.ok_or(CommandError::InvalidState("no INVITE"))?;
        let (req, dest) = self.txns.get(&tid).map(|e| (e.txn.request.clone(), e.txn.dest)).ok_or(CommandError::InvalidState("INVITE transaction gone"))?;
        let resp = self.uas_dialog_response(leg, &req, 200, None, &r.headers, Some(&body));
        let bytes: Arc<[u8]> = resp.to_bytes().into();
        self.reply(tid, resp, now);
        leg.remote_offer = None;
        leg.early_answer = None;
        if next_oa == Oa::Stable {
            leg.negotiated = true;
            leg.stable_generation = leg.generation;
        } else {
            leg.generation = leg.generation.saturating_add(1);
        }
        leg.oa = next_oa;
        leg.phase = Phase::Confirmed;
        leg.initial_ack_pending = true;
        leg.disarm(LegTimer::UasAnswer);
        let cseq = req.cseq().map_or(0, |c| c.0);
        self.start_2xx_retransmit(leg, cseq, bytes, dest, now);
        Ok(())
    }

    fn cmd_negotiate(&mut self, leg: &mut Leg, op: OperationId, r: NegotiateRequest, now: u64) -> Result<(), CommandError> {
        if leg.phase != Phase::Confirmed {
            return Err(CommandError::InvalidState("negotiate needs a confirmed dialog"));
        }
        check_sdp(&r.sdp)?;
        let busy = leg.oa != Oa::Stable
            || leg.client_reinvite.is_some()
            || leg.client_update.is_some()
            || leg.server_reinvite.is_some()
            || leg.server_update.is_some()
            || leg.pending_2xx.is_some()
            || leg.ack_wait.is_some();
        if busy {
            return Err(CommandError::OfferPending);
        }
        let (method, via) = match r.method {
            NegotiateMethod::ReInvite => (Method::Invite, OfferVia::ReInvite),
            NegotiateMethod::Update => (Method::Update, OfferVia::Update),
        };
        let cseq = Self::next_cseq(leg).ok_or(CommandError::InvalidState("CSeq space exhausted"))?;
        let mut m = self.dialog_request(leg, method, cseq);
        m.push_header("Allow", ALLOW);
        m.push_header("Content-Type", "application/sdp");
        m.body = r.sdp;
        let id = leg.id;
        let purpose = if via == OfferVia::ReInvite { Purpose::ReInvite(id, Some(op)) } else { Purpose::Update(id, Some(op)) };
        leg.generation = leg.generation.saturating_add(1);
        leg.oa = Oa::LocalOffer(via, Some(op));
        if let Err(e) = self.dispatch_leg_request(leg, m, purpose, None, now) {
            leg.oa = Oa::Stable;
            return Err(e);
        }
        Ok(())
    }

    fn originate(&mut self, op: OperationId, o: OriginateRequest, now: u64) -> Result<Accepted, CommandError> {
        if self.draining {
            return Err(CommandError::Draining);
        }
        if self.legs.len() >= self.cfg.max_legs {
            self.stats.rejected_overload = self.stats.rejected_overload.saturating_add(1);
            return Err(CommandError::Overloaded);
        }
        let ruri_ok = parse_uri(o.request_uri.as_bytes()).is_some_and(|u| u.scheme.eq_ignore_ascii_case(b"sip") || u.is_sips());
        if !ruri_ok || !is_safe_value(&o.request_uri) || o.request_uri.contains(['<', '>', ' ']) {
            return Err(CommandError::InvalidArgument("request URI".into()));
        }
        if !is_safe_value(&o.from) || parse_uri(uri_of(&o.from).as_bytes()).is_none() || o.from.contains(";tag=") {
            return Err(CommandError::InvalidArgument("From".into()));
        }
        let to = o.to.clone().unwrap_or_else(|| format!("<{}>", o.request_uri));
        if !is_safe_value(&to) || parse_uri(uri_of(&to).as_bytes()).is_none() {
            return Err(CommandError::InvalidArgument("To".into()));
        }
        if o.route_set.iter().any(|r| !is_safe_value(r) || parse_uri(uri_of(r).as_bytes()).is_none()) {
            return Err(CommandError::InvalidArgument("route".into()));
        }
        if o.contact.as_ref().is_some_and(|c| !is_safe_value(c) || parse_uri(c.as_bytes()).is_none()) {
            return Err(CommandError::InvalidArgument("contact".into()));
        }
        check_headers(&o.headers)?;
        if let Some(b) = &o.sdp {
            check_sdp(b)?;
        }
        let id = o.leg.unwrap_or_else(|| self.ids.leg());
        if self.legs.contains_key(&id) {
            return Err(CommandError::InvalidArgument("leg id in use".into()));
        }
        let call_id = self.token();
        let local_tag = self.token();
        let secure = parse_uri(o.request_uri.as_bytes()).is_some_and(|u| u.is_sips());
        let route_set: Vec<String> = o.route_set.iter().map(|r| angle(r)).collect();
        let mut leg = Leg {
            id,
            role: Role::Uac,
            phase: Phase::Calling,
            call_id: call_id.clone(),
            local_tag: local_tag.clone(),
            remote_tag: None,
            local_hdr: format!("{};tag={local_tag}", o.from.trim()),
            remote_hdr: strip_tag(&to),
            local_contact: o.contact.clone().unwrap_or_default(),
            remote_target: o.request_uri.clone(),
            route_set,
            local_cseq: 1,
            remote_cseq: None,
            flow: None,
            secure,
            invite_txn: None,
            invite_template: None,
            invite_dest: None,
            early: Vec::new(),
            killed: Vec::new(),
            oa: if o.sdp.is_some() { Oa::LocalOffer(OfferVia::Invite, Some(op)) } else { Oa::Stable },
            negotiated: false,
            early_answer: None,
            remote_offer: None,
            generation: u64::from(o.sdp.is_some()),
            stable_generation: 0,
            seq: 0,
            ack: None,
            ack_wait: None,
            pending_2xx: None,
            server_reinvite: None,
            server_update: None,
            client_reinvite: None,
            client_update: None,
            cancel: CancelState::None,
            cancel_reason: None,
            cancel_cause: None,
            initial_ack_pending: false,
            bye_after_ack: None,
            bye_cause: None,
            creds: o.credentials,
            auth_attempts: 0,
            timers: Vec::new(),
            origin_op: Some(op),
            overloaded: false,
            merged_key: None,
            dialog_tags: Vec::new(),
        };
        let mut inv = self.dialog_request(&leg, Method::Invite, 1);
        inv.push_header("Allow", ALLOW);
        if let Some(c) = &o.contact {
            inv.push_header("Contact", format!("<{c}>"));
        }
        for h in o.headers {
            inv.push_header(h.name, h.value);
        }
        if let Some(b) = o.sdp {
            inv.push_header("Content-Type", "application/sdp");
            inv.body = b;
        }
        leg.invite_template = Some(inv.clone());
        let timeout = o.no_answer_timeout_ms.unwrap_or(self.cfg.no_answer_timeout_ms);
        self.arm_leg(&mut leg, LegTimer::NoAnswer, now.saturating_add(timeout));
        self.legs.insert(id, leg);
        let leg_ref = self.legs.remove(&id);
        let Some(mut leg) = leg_ref else { return Err(CommandError::UnknownLeg) };
        let res = self.dispatch_leg_request(&mut leg, inv, Purpose::Invite(id), o.next_hop, now);
        match res {
            Ok(()) => {
                self.legs.insert(id, leg);
                Ok(Accepted { op, leg: id })
            }
            Err(e) => {
                self.cleanup(&mut leg);
                Err(e)
            }
        }
    }
}

/// Request-URI and Route headers for a request with this target and route
/// set (RFC 3261 §12.2.1.1, strict-router compatibility included).
fn route_request(target: &str, routes: &[String]) -> (String, Vec<String>) {
    match routes.first() {
        None => (target.to_string(), Vec::new()),
        Some(first) if is_loose(first) => (target.to_string(), routes.to_vec()),
        Some(first) => {
            let mut rest: Vec<String> = routes.iter().skip(1).cloned().collect();
            rest.push(format!("<{target}>"));
            (uri_of(first), rest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_rules() {
        let (r, rs) = route_request("sip:b@10.0.0.2", &["<sip:p1;lr>".into(), "<sip:p2;lr>".into()]);
        assert_eq!(r, "sip:b@10.0.0.2");
        assert_eq!(rs.len(), 2);
        let (r, rs) = route_request("sip:b@10.0.0.2", &["<sip:strict@p1>".into(), "<sip:p2;lr>".into()]);
        assert_eq!(r, "sip:strict@p1");
        assert_eq!(rs, vec!["<sip:p2;lr>".to_string(), "<sip:b@10.0.0.2>".to_string()]);
    }

    #[test]
    fn uri_targets() {
        let Some(Target::Ready(d)) = uri_target("sip:a@10.1.2.3:5070;transport=tcp") else { panic!() };
        assert_eq!((d.proto, d.addr.to_string()), (Proto::Tcp, "10.1.2.3:5070".to_string()));
        let Some(Target::Ready(d)) = uri_target("sips:a@[::1]") else { panic!() };
        assert_eq!((d.proto, d.addr.port()), (Proto::Tls, 5061));
        let Some(Target::Resolve(h, p, pr, s)) = uri_target("sip:example.com") else { panic!() };
        assert_eq!((h.as_str(), p, pr, s), ("example.com", None, None, false));
    }

    #[test]
    fn response_destination() {
        let mut r = SipMessage::request(Method::Bye, "sip:x");
        r.push_header("Via", "SIP/2.0/UDP 10.0.0.1:5080;branch=z9hG4bK1");
        let src = Dest::new(Proto::Udp, "192.0.2.1:40000".parse().unwrap());
        assert_eq!(response_dest(&r, src).addr.to_string(), "192.0.2.1:5080");
        r.set_header("Via", "SIP/2.0/UDP 10.0.0.1:5080;branch=z9hG4bK1;rport");
        assert_eq!(response_dest(&r, src).addr.to_string(), "192.0.2.1:40000");
    }
}
