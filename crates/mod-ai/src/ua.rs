//! The SIP side of AI calls, on the shared UA engine (`sip-ua`).
//!
//! The engine owns the INVITE server transaction, 100 Trying, the 2xx
//! retransmissions until the ACK, CANCEL/487, BYE (either way), re-INVITE
//! and in-dialog OPTIONS/INFO/UPDATE. This module feeds it the messages
//! `ai_answer()` / `ai_dialog()` see, runs its timers, sends what it emits
//! through the proxy's transport, and turns its events into the call
//! threads' `Ev`s. The call threads answer, reject and hang up with
//! engine commands.

use crate::call::{Call, Ev};
use sip_core::sync::lock;
use sip_core::{Dest, Outbound, Proto};
use sip_ua::{CauseKind, CommandError, OfferResponse, UaCommand, UaConfig, UaEngine, UaEvent, UaLegId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct Ua {
    engine: Mutex<UaEngine>,
    start: Instant,
    legs: Mutex<HashMap<UaLegId, Arc<Call>>>,
    net: Arc<dyn Outbound>,
}

impl Ua {
    pub fn new(net: Arc<dyn Outbound>) -> Self {
        let local = Proto::ALL.into_iter().filter_map(|p| net.advertise(p).map(|a| (p, a))).collect();
        let cfg = UaConfig {
            local,
            contact_user: "ai".into(),
            user_agent: None,
            // As before the engine: no session timer of our own (a caller's
            // request is still honoured).
            session_expires: None,
            max_legs: 1_000_000,
            // Callers that resend an INVITE or send a CANCEL with a new
            // branch were matched by Call-ID before; keep accepting them.
            lenient_matching: true,
            ..UaConfig::default()
        };
        Self { engine: Mutex::new(UaEngine::new(cfg)), start: Instant::now(), legs: Mutex::new(HashMap::new()), net }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// A message of an AI call. For a new INVITE, `new_call` is the call it
    /// creates; the result is its leg when the engine took the INVITE (it
    /// answered it itself otherwise, e.g. 420 or 400).
    pub fn input(&self, data: &[u8], src: Dest, new_call: Option<&Arc<Call>>) -> Option<UaLegId> {
        let now = self.now();
        let mut e = lock(&self.engine);
        e.handle_message(data, src, now);
        self.flush(&mut e, new_call, now)
    }

    pub fn command(&self, cmd: UaCommand) -> Result<(), CommandError> {
        let now = self.now();
        let mut e = lock(&self.engine);
        let r = e.submit(cmd, now).map(|_| ());
        self.flush(&mut e, None, now);
        r
    }

    /// Run the engine's timers (called every few ms).
    pub fn tick(&self) {
        let now = self.now();
        let mut e = lock(&self.engine);
        if e.next_timeout().is_some_and(|t| t <= now) {
            e.handle_timeout(now);
            self.flush(&mut e, None, now);
        }
    }

    /// Send what the engine emitted and dispatch its events (which may
    /// emit more: answering a re-INVITE).
    fn flush(&self, e: &mut UaEngine, new_call: Option<&Arc<Call>>, now: u64) -> Option<UaLegId> {
        let mut new_leg = None;
        loop {
            let mut busy = false;
            while let Some(t) = e.poll_transmit() {
                busy = true;
                if let Err(err) = self.net.send(&t.dest, &t.data) {
                    sip_core::elog!("ai: send to {} failed: {err}", t.dest);
                    if let Some(id) = t.txn {
                        e.handle_send_error(id, now);
                    }
                }
            }
            // AI calls are answered to the caller's Contact, normally an IP;
            // a name is resolved here (cached by the resolver).
            while let Some(r) = e.poll_resolve() {
                busy = true;
                let v: Vec<Dest> = sip_core::dns::resolver().resolve_uri(&r.host, r.port, r.proto, r.secure).into_iter().collect();
                let res = if v.is_empty() { Err(format!("{}: no address", r.host)) } else { Ok(v) };
                e.resolved(r.id, res, now);
            }
            while let Some(ev) = e.poll_event() {
                busy = true;
                let leg = ev.leg;
                if let UaEvent::IncomingInvite(_) = &ev.event {
                    if let Some(c) = new_call {
                        let _ = c.leg.set(leg);
                        lock(&self.legs).insert(leg, c.clone());
                        new_leg = Some(leg);
                    }
                    continue;
                }
                let Some(call) = lock(&self.legs).get(&leg).cloned() else { continue };
                match ev.event {
                    UaEvent::Ack(_) => call.send(Ev::Ack),
                    UaEvent::RemoteBye(_) => call.send(Ev::Bye),
                    UaEvent::Cancelled => call.lock().cancelled = true,
                    UaEvent::RemoteOffer(o) => {
                        // re-INVITE (hold, new address): same stream, new version.
                        let version = {
                            let mut st = call.lock();
                            st.sdp_version = st.sdp_version.saturating_add(1);
                            st.sdp_version
                        };
                        let body = o.sdp.as_deref().map(String::from_utf8_lossy).unwrap_or_default();
                        if let Ok(offer) = crate::sdp::parse_offer(&body) {
                            call.send(Ev::Remote(offer.addr));
                        }
                        let answer = Some(call.sdp(version).into_bytes());
                        let _ = e.submit(UaCommand::RespondToOffer(OfferResponse { leg, generation: ev.generation, sdp: answer }), now);
                    }
                    UaEvent::Failed(f) if f.leg_failed => {
                        let why = match f.cause.kind {
                            CauseKind::NoAck => "no ACK for 200 OK".to_string(),
                            _ => f.cause.to_string(),
                        };
                        call.send(Ev::Ended(why));
                    }
                    UaEvent::Terminated(t) => {
                        call.send(Ev::Ended(t.cause.to_string()));
                        lock(&self.legs).remove(&leg);
                    }
                    _ => {}
                }
            }
            if !busy {
                return new_leg;
            }
        }
    }
}
