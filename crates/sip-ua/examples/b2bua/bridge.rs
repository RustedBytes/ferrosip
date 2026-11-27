//! Two-leg bridging logic of the example B2BUA (not the production
//! softswitch): every inbound call is originated towards one target, and
//! signalling is relayed between the two independent legs. SDP goes through
//! a [`MediaAdapter`], the seam where an rtpflux client plugs in.

use sip_ua::msg::strip_tag;
use sip_ua::*;
use std::collections::{HashMap, HashSet};

/// The external media engine. Each method returns the SDP to send on the
/// *other* leg (a relay rewrites addresses here; passthrough keeps them).
pub trait MediaAdapter {
    fn offer(&mut self, call: u64, from: UaLegId, sdp: &[u8]) -> Result<Vec<u8>, String>;
    fn answer(&mut self, call: u64, from: UaLegId, sdp: &[u8]) -> Result<Vec<u8>, String>;
    /// Both legs are gone: free the media session (idempotent).
    fn release(&mut self, call: u64);
}

impl<T: MediaAdapter + ?Sized> MediaAdapter for Box<T> {
    fn offer(&mut self, call: u64, from: UaLegId, sdp: &[u8]) -> Result<Vec<u8>, String> {
        (**self).offer(call, from, sdp)
    }
    fn answer(&mut self, call: u64, from: UaLegId, sdp: &[u8]) -> Result<Vec<u8>, String> {
        (**self).answer(call, from, sdp)
    }
    fn release(&mut self, call: u64) {
        (**self).release(call)
    }
}

/// Media flows end to end; only signalling goes through the B2BUA.
#[derive(Default)]
pub struct Passthrough {
    pub released: Vec<u64>,
}

impl MediaAdapter for Passthrough {
    fn offer(&mut self, _: u64, _: UaLegId, sdp: &[u8]) -> Result<Vec<u8>, String> {
        Ok(sdp.to_vec())
    }
    fn answer(&mut self, _: u64, _: UaLegId, sdp: &[u8]) -> Result<Vec<u8>, String> {
        Ok(sdp.to_vec())
    }
    fn release(&mut self, call: u64) {
        if !self.released.contains(&call) {
            self.released.push(call);
        }
    }
}

pub type Submit<'a> = &'a mut dyn FnMut(UaCommand) -> Result<Accepted, CommandError>;

pub struct Bridge<M: MediaAdapter> {
    pub media: M,
    /// `host:port` every call is sent to.
    target: String,
    peer: HashMap<UaLegId, (UaLegId, u64)>,
    inbound: HashSet<UaLegId>,
    /// Inbound legs whose INVITE had no offer.
    delayed: HashSet<UaLegId>,
    /// Inbound leg → (outbound leg, generation) waiting for the ACK's answer.
    ack_answer: HashMap<UaLegId, (UaLegId, Generation)>,
    /// Our relayed offer (op) → the leg and generation that asked for it.
    relayed: HashMap<OperationId, (UaLegId, Generation)>,
    /// Every live leg → its call (independent of `peer`, which is unlinked
    /// as soon as one side ends).
    calls: HashMap<UaLegId, u64>,
    alive: HashMap<u64, u8>,
    next_call: u64,
}

impl<M: MediaAdapter> Bridge<M> {
    pub fn new(media: M, target: impl Into<String>) -> Self {
        Self {
            media,
            target: target.into(),
            peer: HashMap::new(),
            inbound: HashSet::new(),
            delayed: HashSet::new(),
            ack_answer: HashMap::new(),
            relayed: HashMap::new(),
            calls: HashMap::new(),
            alive: HashMap::new(),
            next_call: 0,
        }
    }

    /// Calls with at least one live leg.
    pub fn active_calls(&self) -> usize {
        self.alive.len()
    }

    pub fn on_event(&mut self, ev: &EventEnvelope, submit: Submit<'_>) {
        let leg = ev.leg;
        let other = self.peer.get(&leg).copied();
        match &ev.event {
            UaEvent::IncomingInvite(ii) => self.incoming(leg, ii, submit),
            UaEvent::Provisional(p) => {
                let Some((inb, call)) = other else { return };
                let code = if p.status.code == 183 { 183 } else { 180 };
                let sdp = p.sdp.as_deref().and_then(|s| self.media.answer(call, leg, s).ok()).filter(|_| !self.delayed.contains(&inb));
                let r = submit(UaCommand::Provisional(ProvisionalRequest { leg: inb, code, reason: None, sdp, headers: vec![] }));
                if r.is_err() {
                    let _ = submit(UaCommand::Provisional(ProvisionalRequest { leg: inb, code, reason: None, sdp: None, headers: vec![] }));
                }
            }
            UaEvent::Accepted(a) => {
                let Some((inb, call)) = other else { return };
                let sdp = match a.sdp.as_deref() {
                    Some(s) if self.delayed.contains(&inb) => self.media.offer(call, leg, s).ok(),
                    Some(s) => self.media.answer(call, leg, s).ok(),
                    None => None,
                };
                if submit(UaCommand::Accept(AcceptRequest { leg: inb, sdp, headers: vec![] })).is_err() {
                    let _ = submit(UaCommand::Hangup(HangupRequest { leg, reason: Some("Q.850;cause=47".into()), code: None }));
                }
            }
            UaEvent::RemoteOffer(o) => {
                let Some((dst, call)) = other else { return };
                match (o.kind, o.sdp.as_deref()) {
                    (OfferKind::InviteResponse, _) => {
                        self.ack_answer.insert(dst, (leg, ev.generation));
                    }
                    (kind, Some(s)) => {
                        let method = if kind == OfferKind::Update { NegotiateMethod::Update } else { NegotiateMethod::ReInvite };
                        let relayed = self
                            .media
                            .offer(call, leg, s)
                            .map_err(|_| ())
                            .and_then(|sdp| submit(UaCommand::Negotiate(NegotiateRequest { leg: dst, method, sdp })).map_err(|_| ()));
                        match relayed {
                            Ok(acc) => {
                                self.relayed.insert(acc.op, (leg, ev.generation));
                            }
                            Err(()) => {
                                let _ = submit(UaCommand::RespondToOffer(OfferResponse { leg, generation: ev.generation, sdp: None }));
                            }
                        }
                    }
                    // Body-less re-INVITE: not relayed by this example.
                    (_, None) => {
                        let _ = submit(UaCommand::RespondToOffer(OfferResponse { leg, generation: ev.generation, sdp: None }));
                    }
                }
            }
            UaEvent::Ack(a) => {
                let (Some(s), Some((out, generation))) = (a.sdp.as_deref(), self.ack_answer.remove(&leg)) else { return };
                let call = other.map_or(0, |o| o.1);
                let sdp = self.media.answer(call, leg, s).ok();
                let _ = submit(UaCommand::RespondToOffer(OfferResponse { leg: out, generation, sdp }));
            }
            UaEvent::Completed(c) => {
                let Some((asker, generation)) = ev.op.and_then(|op| self.relayed.remove(&op)) else { return };
                let call = other.map_or(0, |o| o.1);
                let sdp = c.sdp.as_deref().and_then(|s| self.media.answer(call, leg, s).ok());
                let _ = submit(UaCommand::RespondToOffer(OfferResponse { leg: asker, generation, sdp }));
            }
            UaEvent::Failed(_) => {
                if let Some((asker, generation)) = ev.op.and_then(|op| self.relayed.remove(&op)) {
                    let _ = submit(UaCommand::RespondToOffer(OfferResponse { leg: asker, generation, sdp: None }));
                }
            }
            UaEvent::Terminated(t) => self.terminated(leg, &t.cause, submit),
            // Executing a transfer (calling the target, re-inviting the
            // other leg) is softswitch policy; this example declines.
            UaEvent::ReferRequested(_) => {
                let _ = submit(UaCommand::RespondToRefer(ReferResponse { leg, accept: false }));
            }
            UaEvent::ReferProgress(_) | UaEvent::Cancelled | UaEvent::RemoteBye(_) | UaEvent::Info(_) | UaEvent::CommandRejected(_) => {}
        }
    }

    fn incoming(&mut self, inb: UaLegId, ii: &InboundInvite, submit: Submit<'_>) {
        self.next_call = self.next_call.wrapping_add(1);
        let call = self.next_call;
        let sdp = match ii.sdp.as_deref().map(|s| self.media.offer(call, inb, s)) {
            Some(Ok(s)) => Some(s),
            Some(Err(_)) => {
                let _ = submit(UaCommand::Reject(RejectRequest { leg: inb, code: 488, reason: None, headers: vec![] }));
                return;
            }
            None => None,
        };
        let user = sip_parser::parse_uri(ii.request_uri.as_bytes()).and_then(|u| u.user).map(|u| String::from_utf8_lossy(u).into_owned()).unwrap_or_default();
        let ruri = if user.is_empty() { format!("sip:{}", self.target) } else { format!("sip:{user}@{}", self.target) };
        let o = OriginateRequest { request_uri: ruri, from: strip_tag(&ii.from), sdp, ..Default::default() };
        match submit(UaCommand::Originate(Box::new(o))) {
            Ok(acc) => {
                self.peer.insert(inb, (acc.leg, call));
                self.peer.insert(acc.leg, (inb, call));
                self.inbound.insert(inb);
                self.calls.insert(inb, call);
                self.calls.insert(acc.leg, call);
                if ii.sdp.is_none() {
                    self.delayed.insert(inb);
                }
                self.alive.insert(call, 2);
            }
            Err(_) => {
                self.media.release(call);
                let _ = submit(UaCommand::Reject(RejectRequest { leg: inb, code: 503, reason: None, headers: vec![] }));
            }
        }
    }

    fn terminated(&mut self, leg: UaLegId, cause: &Cause, submit: Submit<'_>) {
        self.delayed.remove(&leg);
        self.ack_answer.remove(&leg);
        self.inbound.remove(&leg);
        // Tell the other leg, carrying the original cause.
        if let Some((other, _)) = self.peer.remove(&leg)
            && self.peer.remove(&other).is_some()
        {
            let code = cause.sip.as_ref().map(|s| s.code).filter(|c| (400..=699).contains(c));
            let reason = format!("Q.850;cause={}", cause.q850);
            let _ = submit(UaCommand::Hangup(HangupRequest { leg: other, reason: Some(reason), code }));
        }
        let Some(call) = self.calls.remove(&leg) else { return };
        let left = self.alive.get(&call).copied().unwrap_or(1).saturating_sub(1);
        if left == 0 {
            self.alive.remove(&call);
            self.media.release(call);
        } else {
            self.alive.insert(call, left);
        }
    }
}
