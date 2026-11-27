//! RFC 3261 §17 transaction state machines with the RFC 6026 corrections
//! (the INVITE client and server "Accepted" state), sans-IO.
//!
//! A transaction never sends or sleeps itself: every input returns the
//! [`TxnOut`] effects (send these bytes, arm this timer, hand this to the
//! transaction user) and the engine executes them. Time is a monotonic
//! millisecond counter supplied by the caller, so tests drive it with a
//! fake clock.
//!
//! Proxy transactions (`mod-txn`) aggregate responses across branches
//! (§16.7) and are a different machine; a UA transaction passes every
//! response to its user, which is what fork handling needs.

use crate::ids::TxnId;
use crate::msg::{Method, SipMessage};
use sip_core::Dest;
use std::sync::Arc;

/// RFC 3261 timer values, milliseconds.
#[derive(Clone, Copy, Debug)]
pub struct TimerConfig {
    pub t1: u64,
    pub t2: u64,
    pub t4: u64,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self { t1: 500, t2: 4_000, t4: 5_000 }
    }
}

impl TimerConfig {
    /// 64·T1: timers B, F, H, J, L, M.
    pub fn t64(&self) -> u64 {
        self.t1.saturating_mul(64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TimerKind {
    /// INVITE client retransmit.
    A,
    /// INVITE client timeout.
    B,
    /// INVITE client: absorb non-2xx retransmissions.
    D,
    /// Non-INVITE client retransmit.
    E,
    /// Non-INVITE client timeout.
    F,
    /// Non-INVITE client: absorb retransmissions.
    K,
    /// INVITE server: retransmit the non-2xx final.
    G,
    /// INVITE server: give up waiting for the ACK.
    H,
    /// INVITE server: absorb ACK retransmissions.
    I,
    /// Non-INVITE server: absorb request retransmissions.
    J,
    /// INVITE server Accepted state (RFC 6026).
    L,
    /// INVITE client Accepted state (RFC 6026).
    M,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    InviteClient,
    NonInviteClient,
    InviteServer,
    NonInviteServer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Calling,
    Trying,
    Proceeding,
    Completed,
    /// RFC 6026: a 2xx was received (client) or sent (server).
    Accepted,
    Confirmed,
    Terminated,
}

/// Effects of one input, executed by the engine in order.
#[derive(Debug)]
pub enum TxnOut {
    Send(Arc<[u8]>),
    /// Arm `kind` at absolute time `at` (replacing an armed one).
    Arm(TimerKind, u64),
    /// Pass a response to the transaction user (client transactions).
    Response(SipMessage),
    /// An ACK matched an INVITE server transaction in the Accepted state.
    Ack(SipMessage),
    /// The request was never answered in time (B, F) / the ACK never came (H).
    Timeout,
    /// A send failed.
    TransportError,
    Terminated,
}

pub struct Txn {
    pub id: TxnId,
    pub kind: Kind,
    pub state: State,
    /// Requests go here (client); responses go here (server).
    pub dest: Dest,
    pub request: SipMessage,
    request_bytes: Arc<[u8]>,
    last_response: Option<Arc<[u8]>>,
    ack: Option<Arc<[u8]>>,
    interval: u64,
    /// Armed timers and their deadlines (stale heap entries are ignored).
    armed: Vec<(TimerKind, u64)>,
    cfg: TimerConfig,
    pub created: u64,
}

impl Txn {
    fn reliable(&self) -> bool {
        self.dest.proto.is_stream()
    }

    fn arm(&mut self, out: &mut Vec<TxnOut>, kind: TimerKind, at: u64) {
        self.armed.retain(|(k, _)| *k != kind);
        self.armed.push((kind, at));
        out.push(TxnOut::Arm(kind, at));
    }

    fn disarm(&mut self, kind: TimerKind) {
        self.armed.retain(|(k, _)| *k != kind);
    }

    fn terminate(&mut self, out: &mut Vec<TxnOut>) {
        self.state = State::Terminated;
        self.armed.clear();
        out.push(TxnOut::Terminated);
    }

    /// Arm `kind` after `delay`, or terminate at once when the delay is 0
    /// (timers D, I, J, K are zero on reliable transports).
    fn linger(&mut self, out: &mut Vec<TxnOut>, kind: TimerKind, now: u64, delay: u64) {
        if delay == 0 {
            self.terminate(out);
        } else {
            self.arm(out, kind, now.saturating_add(delay));
        }
    }

    /// The timer `kind` is armed for exactly `at`.
    pub fn is_armed(&self, kind: TimerKind, at: u64) -> bool {
        self.armed.iter().any(|&(k, a)| k == kind && a == at)
    }

    /// Start a client transaction: sends the request and arms its timers.
    pub fn client(id: TxnId, request: SipMessage, dest: Dest, cfg: TimerConfig, now: u64) -> (Self, Vec<TxnOut>) {
        let invite = request.method() == Some(&Method::Invite);
        let bytes: Arc<[u8]> = request.to_bytes().into();
        let mut t = Self {
            id,
            kind: if invite { Kind::InviteClient } else { Kind::NonInviteClient },
            state: if invite { State::Calling } else { State::Trying },
            dest,
            request,
            request_bytes: bytes.clone(),
            last_response: None,
            ack: None,
            interval: cfg.t1,
            armed: Vec::new(),
            cfg,
            created: now,
        };
        let mut out = vec![TxnOut::Send(bytes)];
        let (retr, timeout) = if invite { (TimerKind::A, TimerKind::B) } else { (TimerKind::E, TimerKind::F) };
        if !t.reliable() {
            t.arm(&mut out, retr, now.saturating_add(cfg.t1));
        }
        t.arm(&mut out, timeout, now.saturating_add(cfg.t64()));
        (t, out)
    }

    /// Start a server transaction for a received request.
    pub fn server(id: TxnId, request: SipMessage, dest: Dest, cfg: TimerConfig, now: u64) -> Self {
        let invite = request.method() == Some(&Method::Invite);
        Self {
            id,
            kind: if invite { Kind::InviteServer } else { Kind::NonInviteServer },
            state: if invite { State::Proceeding } else { State::Trying },
            dest,
            request,
            request_bytes: Arc::from(&[][..]),
            last_response: None,
            ack: None,
            interval: cfg.t1,
            armed: Vec::new(),
            cfg,
            created: now,
        }
    }

    /// The final response this server transaction sent, if any.
    pub fn final_sent(&self) -> bool {
        matches!(self.state, State::Completed | State::Accepted | State::Confirmed | State::Terminated)
    }

    /// RFC 3261 §17.1.1.3: the ACK for a non-2xx final.
    fn build_ack(&self, resp: &SipMessage) -> SipMessage {
        let uri = self.request.uri().unwrap_or_default().to_string();
        let mut ack = SipMessage::request(Method::Ack, uri);
        if let Some(v) = self.request.header("Via") {
            // Only the top Via (ours).
            let top = crate::msg::split_values(v).into_iter().next().unwrap_or_else(|| v.to_string());
            ack.push_header("Via", top);
        }
        for r in self.request.header_lines("Route") {
            ack.push_header("Route", r);
        }
        ack.push_header("Max-Forwards", "70");
        if let Some(f) = self.request.header("From") {
            ack.push_header("From", f);
        }
        if let Some(t) = resp.header("To").or_else(|| self.request.header("To")) {
            ack.push_header("To", t);
        }
        if let Some(c) = self.request.call_id() {
            ack.push_header("Call-ID", c);
        }
        let n = self.request.cseq().map_or(1, |(n, _)| n);
        ack.push_header("CSeq", format!("{n} ACK"));
        ack
    }

    /// A response for this client transaction.
    pub fn on_response(&mut self, resp: SipMessage, now: u64) -> Vec<TxnOut> {
        let mut out = Vec::new();
        let Some(code) = resp.status() else { return out };
        match (self.kind, self.state) {
            (Kind::InviteClient, State::Calling | State::Proceeding) => {
                self.disarm(TimerKind::A);
                if code < 200 {
                    self.state = State::Proceeding;
                    // Timer B governs Calling only.
                    self.disarm(TimerKind::B);
                    out.push(TxnOut::Response(resp));
                } else if code < 300 {
                    self.disarm(TimerKind::B);
                    self.state = State::Accepted;
                    self.arm(&mut out, TimerKind::M, now.saturating_add(self.cfg.t64()));
                    out.push(TxnOut::Response(resp));
                } else {
                    self.disarm(TimerKind::B);
                    let ack: Arc<[u8]> = self.build_ack(&resp).to_bytes().into();
                    out.push(TxnOut::Send(ack.clone()));
                    self.ack = Some(ack);
                    self.state = State::Completed;
                    out.push(TxnOut::Response(resp));
                    let d = if self.reliable() { 0 } else { 32_000 };
                    self.linger(&mut out, TimerKind::D, now, d);
                }
            }
            (Kind::InviteClient, State::Completed) if code >= 300 => {
                if let Some(a) = &self.ack {
                    out.push(TxnOut::Send(a.clone()));
                }
            }
            // RFC 6026 §8.4: further 2xx go to the TU, which ACKs them.
            (Kind::InviteClient, State::Accepted) if (200..300).contains(&code) => out.push(TxnOut::Response(resp)),
            (Kind::NonInviteClient, State::Trying | State::Proceeding) => {
                if code < 200 {
                    self.state = State::Proceeding;
                    out.push(TxnOut::Response(resp));
                } else {
                    self.disarm(TimerKind::E);
                    self.disarm(TimerKind::F);
                    self.state = State::Completed;
                    out.push(TxnOut::Response(resp));
                    let k = if self.reliable() { 0 } else { self.cfg.t4 };
                    self.linger(&mut out, TimerKind::K, now, k);
                }
            }
            _ => {}
        }
        out
    }

    /// Send a response through this server transaction.
    pub fn respond(&mut self, resp: &SipMessage, now: u64) -> Vec<TxnOut> {
        let mut out = Vec::new();
        let Some(code) = resp.status() else { return out };
        let bytes: Arc<[u8]> = resp.to_bytes().into();
        match (self.kind, self.state) {
            (Kind::InviteServer, State::Proceeding) => {
                out.push(TxnOut::Send(bytes.clone()));
                self.last_response = Some(bytes);
                if (200..300).contains(&code) {
                    // RFC 6026 §7.1: the TU retransmits the 2xx; we absorb
                    // INVITE retransmissions until timer L.
                    self.state = State::Accepted;
                    self.arm(&mut out, TimerKind::L, now.saturating_add(self.cfg.t64()));
                } else if code >= 300 {
                    self.state = State::Completed;
                    if !self.reliable() {
                        self.interval = self.cfg.t1;
                        self.arm(&mut out, TimerKind::G, now.saturating_add(self.cfg.t1));
                    }
                    self.arm(&mut out, TimerKind::H, now.saturating_add(self.cfg.t64()));
                }
            }
            (Kind::NonInviteServer, State::Trying | State::Proceeding) => {
                out.push(TxnOut::Send(bytes.clone()));
                self.last_response = Some(bytes);
                if code < 200 {
                    self.state = State::Proceeding;
                } else {
                    self.state = State::Completed;
                    let j = if self.reliable() { 0 } else { self.cfg.t64() };
                    self.linger(&mut out, TimerKind::J, now, j);
                }
            }
            _ => {}
        }
        out
    }

    /// A retransmission of this server transaction's request (or the ACK of
    /// an INVITE server transaction).
    pub fn on_request(&mut self, req: SipMessage, now: u64) -> Vec<TxnOut> {
        let mut out = Vec::new();
        let is_ack = req.method() == Some(&Method::Ack);
        match (self.kind, self.state, is_ack) {
            (Kind::InviteServer, State::Completed, true) => {
                self.disarm(TimerKind::G);
                self.disarm(TimerKind::H);
                self.state = State::Confirmed;
                let i = if self.reliable() { 0 } else { self.cfg.t4 };
                self.linger(&mut out, TimerKind::I, now, i);
            }
            (Kind::InviteServer, State::Accepted, true) => out.push(TxnOut::Ack(req)),
            (Kind::InviteServer, State::Proceeding | State::Completed, false) | (Kind::NonInviteServer, State::Proceeding | State::Completed, false) => {
                if let Some(r) = &self.last_response {
                    out.push(TxnOut::Send(r.clone()));
                }
            }
            // Accepted (RFC 6026 §7.1), Confirmed, Trying: absorb.
            _ => {}
        }
        out
    }

    pub fn on_timer(&mut self, kind: TimerKind, at: u64, now: u64) -> Vec<TxnOut> {
        let mut out = Vec::new();
        if !self.is_armed(kind, at) {
            return out;
        }
        self.disarm(kind);
        match (kind, self.state) {
            (TimerKind::A, State::Calling) => {
                out.push(TxnOut::Send(self.request_bytes.clone()));
                self.interval = self.interval.saturating_mul(2);
                self.arm(&mut out, TimerKind::A, now.saturating_add(self.interval));
            }
            (TimerKind::E, State::Trying | State::Proceeding) => {
                out.push(TxnOut::Send(self.request_bytes.clone()));
                self.interval = if self.state == State::Proceeding { self.cfg.t2 } else { self.interval.saturating_mul(2).min(self.cfg.t2) };
                self.arm(&mut out, TimerKind::E, now.saturating_add(self.interval));
            }
            (TimerKind::G, State::Completed) => {
                if let Some(r) = &self.last_response {
                    out.push(TxnOut::Send(r.clone()));
                }
                self.interval = self.interval.saturating_mul(2).min(self.cfg.t2);
                self.arm(&mut out, TimerKind::G, now.saturating_add(self.interval));
            }
            (TimerKind::B, State::Calling) | (TimerKind::F, State::Trying | State::Proceeding) | (TimerKind::H, State::Completed) => {
                out.push(TxnOut::Timeout);
                self.terminate(&mut out);
            }
            (TimerKind::D | TimerKind::K | TimerKind::I | TimerKind::J | TimerKind::L | TimerKind::M, _) => self.terminate(&mut out),
            _ => {}
        }
        out
    }

    /// The transport could not send a message of this transaction.
    pub fn on_transport_error(&mut self) -> Vec<TxnOut> {
        let mut out = Vec::new();
        if self.state == State::Terminated {
            return out;
        }
        if matches!(self.kind, Kind::InviteClient | Kind::NonInviteClient) && matches!(self.state, State::Calling | State::Trying | State::Proceeding) {
            out.push(TxnOut::TransportError);
        }
        self.terminate(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::Proto;

    fn dest(p: Proto) -> Dest {
        Dest::new(p, "127.0.0.1:5060".parse().unwrap())
    }

    fn req(m: Method) -> SipMessage {
        let mut r = SipMessage::request(m.clone(), "sip:b@h");
        r.push_header("Via", "SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK1");
        r.push_header("From", "<sip:a@h>;tag=1");
        r.push_header("To", "<sip:b@h>");
        r.push_header("Call-ID", "c");
        r.push_header("CSeq", format!("1 {m}"));
        r
    }

    fn resp(code: u16, m: Method) -> SipMessage {
        let mut r = SipMessage::response(code, "X");
        r.push_header("Via", "SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK1");
        r.push_header("To", "<sip:b@h>;tag=2");
        r.push_header("CSeq", format!("1 {m}"));
        r
    }

    fn arms(out: &[TxnOut]) -> Vec<(TimerKind, u64)> {
        out.iter().filter_map(|o| if let TxnOut::Arm(k, a) = o { Some((*k, *a)) } else { None }).collect()
    }

    #[test]
    fn invite_client_retransmits_doubling_then_times_out() {
        let cfg = TimerConfig::default();
        let (mut t, out) = Txn::client(TxnId(1), req(Method::Invite), dest(Proto::Udp), cfg, 0);
        assert_eq!(arms(&out), vec![(TimerKind::A, 500), (TimerKind::B, 32_000)]);
        let o = t.on_timer(TimerKind::A, 500, 500);
        assert!(matches!(o.first(), Some(TxnOut::Send(_))));
        assert_eq!(arms(&o), vec![(TimerKind::A, 1_500)]);
        let o = t.on_timer(TimerKind::A, 1_500, 1_500);
        assert_eq!(arms(&o), vec![(TimerKind::A, 3_500)]);
        // A stale timer is ignored.
        assert!(t.on_timer(TimerKind::A, 500, 3_000).is_empty());
        let o = t.on_timer(TimerKind::B, 32_000, 32_000);
        assert!(matches!(o.as_slice(), [TxnOut::Timeout, TxnOut::Terminated]));
    }

    #[test]
    fn invite_client_reliable_has_no_retransmissions_and_no_timer_d() {
        let (mut t, out) = Txn::client(TxnId(1), req(Method::Invite), dest(Proto::Tcp), TimerConfig::default(), 0);
        assert_eq!(arms(&out), vec![(TimerKind::B, 32_000)]);
        let o = t.on_response(resp(486, Method::Invite), 10);
        assert!(matches!(o.as_slice(), [TxnOut::Send(_), TxnOut::Response(_), TxnOut::Terminated]));
    }

    #[test]
    fn invite_client_acks_non_2xx_and_reacks_retransmissions() {
        let (mut t, _) = Txn::client(TxnId(1), req(Method::Invite), dest(Proto::Udp), TimerConfig::default(), 0);
        assert!(matches!(t.on_response(resp(180, Method::Invite), 10).as_slice(), [TxnOut::Response(_)]));
        let o = t.on_response(resp(486, Method::Invite), 20);
        let TxnOut::Send(ack) = &o[0] else { panic!() };
        let ack = SipMessage::parse(ack, &Default::default()).unwrap();
        assert_eq!(ack.method(), Some(&Method::Ack));
        assert_eq!(ack.to_tag().as_deref(), Some("2"));
        assert_eq!(ack.cseq(), Some((1, Method::Ack)));
        assert_eq!(arms(&o), vec![(TimerKind::D, 32_020)]);
        // Retransmitted final: ACK again, not passed up.
        assert!(matches!(t.on_response(resp(486, Method::Invite), 30).as_slice(), [TxnOut::Send(_)]));
    }

    #[test]
    fn invite_client_accepted_state_passes_every_2xx() {
        let (mut t, _) = Txn::client(TxnId(1), req(Method::Invite), dest(Proto::Udp), TimerConfig::default(), 0);
        let o = t.on_response(resp(200, Method::Invite), 5);
        assert!(matches!(o.as_slice(), [TxnOut::Arm(TimerKind::M, 32_005), TxnOut::Response(_)]));
        assert!(matches!(t.on_response(resp(200, Method::Invite), 6).as_slice(), [TxnOut::Response(_)]));
        assert!(t.on_response(resp(500, Method::Invite), 7).is_empty());
        assert!(matches!(t.on_timer(TimerKind::M, 32_005, 32_005).as_slice(), [TxnOut::Terminated]));
    }

    #[test]
    fn non_invite_client_caps_at_t2() {
        let cfg = TimerConfig::default();
        let (mut t, _) = Txn::client(TxnId(1), req(Method::Bye), dest(Proto::Udp), cfg, 0);
        let mut at = 500;
        let mut seen = Vec::new();
        for _ in 0..6 {
            let o = t.on_timer(TimerKind::E, at, at);
            at = arms(&o)[0].1;
            seen.push(at);
        }
        assert_eq!(seen, vec![1_500, 3_500, 7_500, 11_500, 15_500, 19_500]);
        // A provisional moves the interval to T2 at once.
        let (mut t, _) = Txn::client(TxnId(2), req(Method::Bye), dest(Proto::Udp), cfg, 0);
        t.on_response(resp(100, Method::Bye), 1);
        assert_eq!(arms(&t.on_timer(TimerKind::E, 500, 500)), vec![(TimerKind::E, 4_500)]);
        let o = t.on_response(resp(200, Method::Bye), 600);
        assert_eq!(arms(&o), vec![(TimerKind::K, 5_600)]);
        assert!(t.on_response(resp(200, Method::Bye), 700).is_empty());
    }

    #[test]
    fn invite_server_non_2xx_waits_for_ack() {
        let cfg = TimerConfig::default();
        let mut t = Txn::server(TxnId(1), req(Method::Invite), dest(Proto::Udp), cfg, 0);
        assert!(matches!(t.respond(&resp(180, Method::Invite), 0).as_slice(), [TxnOut::Send(_)]));
        // Retransmitted INVITE gets the last provisional.
        assert!(matches!(t.on_request(req(Method::Invite), 1).as_slice(), [TxnOut::Send(_)]));
        let o = t.respond(&resp(486, Method::Invite), 2);
        assert_eq!(arms(&o), vec![(TimerKind::G, 502), (TimerKind::H, 32_002)]);
        assert_eq!(arms(&t.on_timer(TimerKind::G, 502, 502)), vec![(TimerKind::G, 1_502)]);
        let o = t.on_request(req(Method::Ack), 600);
        assert_eq!(arms(&o), vec![(TimerKind::I, 5_600)]);
        assert_eq!(t.state, State::Confirmed);
        assert!(t.on_timer(TimerKind::G, 1_502, 1_502).is_empty());
        assert!(t.on_request(req(Method::Ack), 700).is_empty());
    }

    #[test]
    fn invite_server_missing_ack_times_out() {
        let mut t = Txn::server(TxnId(1), req(Method::Invite), dest(Proto::Tcp), TimerConfig::default(), 0);
        let o = t.respond(&resp(500, Method::Invite), 0);
        assert_eq!(arms(&o), vec![(TimerKind::H, 32_000)]);
        assert!(matches!(t.on_timer(TimerKind::H, 32_000, 32_000).as_slice(), [TxnOut::Timeout, TxnOut::Terminated]));
    }

    #[test]
    fn invite_server_accepted_absorbs_retransmissions() {
        let mut t = Txn::server(TxnId(1), req(Method::Invite), dest(Proto::Udp), TimerConfig::default(), 0);
        let o = t.respond(&resp(200, Method::Invite), 0);
        assert_eq!(arms(&o), vec![(TimerKind::L, 32_000)]);
        assert!(t.on_request(req(Method::Invite), 1).is_empty());
        assert!(matches!(t.on_request(req(Method::Ack), 2).as_slice(), [TxnOut::Ack(_)]));
    }

    #[test]
    fn non_invite_server_replays_final() {
        let mut t = Txn::server(TxnId(1), req(Method::Bye), dest(Proto::Udp), TimerConfig::default(), 0);
        assert!(t.on_request(req(Method::Bye), 0).is_empty());
        let o = t.respond(&resp(200, Method::Bye), 0);
        assert_eq!(arms(&o), vec![(TimerKind::J, 32_000)]);
        assert!(matches!(t.on_request(req(Method::Bye), 5).as_slice(), [TxnOut::Send(_)]));
        // A second final is not sent.
        assert!(t.respond(&resp(500, Method::Bye), 6).is_empty());
        let mut t = Txn::server(TxnId(2), req(Method::Bye), dest(Proto::Tls), TimerConfig::default(), 0);
        assert!(matches!(t.respond(&resp(200, Method::Bye), 0).as_slice(), [TxnOut::Send(_), TxnOut::Terminated]));
    }

    #[test]
    fn transport_error_reports_once() {
        let (mut t, _) = Txn::client(TxnId(1), req(Method::Options), dest(Proto::Udp), TimerConfig::default(), 0);
        assert!(matches!(t.on_transport_error().as_slice(), [TxnOut::TransportError, TxnOut::Terminated]));
        assert!(t.on_transport_error().is_empty());
    }
}
