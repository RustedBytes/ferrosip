//! RFC 3262 reliable provisional responses (100rel / PRACK).
//!
//! UAC: every reliable 1xx (Require: 100rel + RSeq) of an early dialog is
//! PRACKed in RSeq order; duplicates and out-of-order ones are dropped. An
//! offer in a reliable 1xx is answered in the PRACK, which waits for the
//! application's answer.
//!
//! UAS: a provisional is sent reliably when the caller requires 100rel, or
//! supports it and the provisional carries SDP. It is retransmitted (T1
//! doubling) until its PRACK; after 64·T1 the INVITE is rejected with 5xx.
//! Only one is outstanding at a time: later body-less ones are queued.

use super::*;
use std::collections::VecDeque;

/// UAC: one early dialog (one per remote tag of the INVITE's 1xx).
#[derive(Debug)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub(super) struct EarlyDialog {
    pub(super) tag: String,
    pub(super) remote_hdr: String,
    pub(super) remote_target: String,
    pub(super) route_set: Vec<String>,
    /// RSeq of the last reliable 1xx accepted on this early dialog.
    pub(super) last_rseq: Option<u32>,
}

/// UAS: our reliable provisional awaiting its PRACK.
#[derive(Debug)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub(super) struct Reliable {
    rseq: u32,
    #[cfg_attr(feature = "recovery", serde(with = "crate::recovery::bytes_serde::arc"))]
    bytes: Arc<[u8]>,
    #[cfg_attr(feature = "recovery", serde(with = "crate::recovery::dest_serde"))]
    dest: Dest,
    interval: u64,
    /// It carried our offer: the PRACK must answer it.
    offer: bool,
    op: OperationId,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub(super) enum PeerRel {
    #[default]
    No,
    Supported,
    Required,
}

#[derive(Debug, Default)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub(super) struct Prack {
    /// UAS: the caller's 100rel support.
    pub(super) peer: PeerRel,
    next_rseq: u32,
    pending: Option<Reliable>,
    queue: VecDeque<(ProvisionalRequest, OperationId)>,
    /// UAC: PRACK held for the answer to an offer in a reliable 1xx:
    /// (remote tag, RSeq, INVITE CSeq).
    pub(super) hold: Option<(String, u32, u32)>,
    /// The session was negotiated through a reliable 1xx / PRACK.
    pub(super) negotiated_early: bool,
}

impl Prack {
    pub(super) fn pending_offer(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| p.offer)
    }
}

/// `RSeq` of a reliable provisional, None if it isn't one.
pub(super) fn rseq_of(resp: &SipMessage) -> Option<u32> {
    if !resp.has_option("Require", "100rel") {
        return None;
    }
    resp.header("RSeq")?.trim().parse().ok()
}

/// `RAck: 776656 1 INVITE` → (776656, 1, INVITE).
fn parse_rack(v: &str) -> Option<(u32, u32, Method)> {
    let mut it = v.split_ascii_whitespace();
    let rseq = it.next()?.parse().ok()?;
    let cseq = it.next()?.parse().ok()?;
    Some((rseq, cseq, Method::parse(it.next()?)))
}

impl UaEngine {
    // ------------------------------------------------------------- UAC --

    /// Record a 1xx's early dialog (RFC 3261 §12.1.2); false when it is a
    /// new one beyond `max_early_dialogs` (the 1xx is then ignored).
    pub(super) fn note_early_dialog(&mut self, leg: &mut Leg, tag: &str, resp: &SipMessage) -> bool {
        if !leg.early.iter().any(|e| e.tag == tag) && leg.early.len() >= self.cfg.max_early_dialogs {
            self.stats.early_dialogs_dropped = self.stats.early_dialogs_dropped.saturating_add(1);
            return false;
        }
        let mut rr = resp.values("Record-Route");
        rr.reverse();
        let target = resp.contact_uri().unwrap_or_else(|| leg.remote_target.clone());
        let hdr = resp.header("To").unwrap_or_default().to_string();
        match leg.early.iter_mut().find(|e| e.tag == tag) {
            Some(e) => {
                e.remote_target = target;
                e.remote_hdr = hdr;
            }
            None => leg.early.push(EarlyDialog { tag: tag.to_string(), remote_hdr: hdr, remote_target: target, route_set: rr, last_rseq: None }),
        }
        self.register_dialog(leg, tag);
        true
    }

    /// A reliable 1xx with RSeq `rseq`: false when it must be ignored
    /// (a retransmission, or out of order).
    pub(super) fn accept_rseq(leg: &mut Leg, tag: &str, rseq: u32) -> bool {
        let Some(e) = leg.early.iter_mut().find(|e| e.tag == tag) else { return false };
        match e.last_rseq {
            Some(last) if rseq <= last || Some(rseq) != last.checked_add(1) => false,
            _ => {
                e.last_rseq = Some(rseq);
                true
            }
        }
    }

    /// PRACK a reliable 1xx of early dialog `tag` (with the answer, if the 1xx had an offer).
    pub(super) fn send_prack(&mut self, leg: &mut Leg, tag: &str, rseq: u32, invite_cseq: u32, body: Option<Vec<u8>>, now: u64) {
        let Some(e) = leg.early.iter().find(|e| e.tag == tag) else { return };
        let (ruri, routes) = route_request(&e.remote_target, &e.route_set);
        let remote_hdr = e.remote_hdr.clone();
        let Some(cseq) = Self::next_cseq(leg) else { return };
        let mut m = SipMessage::request(Method::Prack, ruri);
        m.push_header("Max-Forwards", "70");
        m.push_header("From", leg.local_hdr.as_str());
        m.push_header("To", remote_hdr);
        m.push_header("Call-ID", leg.call_id.as_str());
        m.push_header("CSeq", format!("{cseq} PRACK"));
        for r in routes {
            m.push_header("Route", r);
        }
        m.push_header("RAck", format!("{rseq} {invite_cseq} INVITE"));
        if let Some(b) = body {
            m.push_header("Content-Type", "application/sdp");
            m.body = b;
        }
        // The PRACK's own outcome doesn't change the leg (RFC 3262 §4).
        let _ = self.dispatch_leg_request(leg, m, Purpose::Detached, None, now);
    }

    /// The application answered (or rejected) an offer in a reliable 1xx.
    pub(super) fn answer_reliable_offer(&mut self, leg: &mut Leg, offer: Option<Vec<u8>>, answer: Option<Vec<u8>>, now: u64) {
        leg.oa = Oa::Stable;
        let Some((tag, rseq, cseq)) = leg.ext.rel.hold.take() else { return };
        let body = match answer {
            Some(b) => {
                leg.negotiated = true;
                leg.ext.rel.negotiated_early = true;
                leg.stable_generation = leg.generation;
                leg.ext.local_sdp = Some(b.clone());
                b
            }
            None => sdp::reject_all(offer.as_deref().unwrap_or_default()),
        };
        self.send_prack(leg, &tag, rseq, cseq, Some(body), now);
    }

    // ------------------------------------------------------------- UAS --

    /// Send (or queue) a provisional; reliable when the caller requires
    /// 100rel, or supports it and the provisional carries SDP.
    pub(super) fn uas_provisional(&mut self, leg: &mut Leg, op: OperationId, r: ProvisionalRequest, now: u64) -> Result<(), CommandError> {
        let reliable = match leg.ext.rel.peer {
            PeerRel::Required => true,
            PeerRel::Supported => r.sdp.is_some(),
            PeerRel::No => false,
        };
        let mut offer = false;
        if let Some(b) = &r.sdp {
            check_sdp(b)?;
            match leg.oa {
                Oa::RemoteOffer(OfferVia::Invite) => {}
                Oa::Stable if leg.negotiated => {}
                // Our offer: only in a reliable provisional (RFC 3262 §5).
                Oa::Stable if reliable => offer = true,
                _ => return Err(CommandError::InvalidState("early SDP needs an offer in the INVITE or a reliable provisional")),
            }
        }
        if reliable && leg.ext.rel.pending.is_some() {
            if r.sdp.is_some() {
                return Err(CommandError::OfferPending);
            }
            leg.ext.rel.queue.push_back((r, op));
            return Ok(());
        }
        let tid = leg.invite_txn.ok_or(CommandError::InvalidState("no INVITE"))?;
        let (req, dest) = self.txns.get(&tid).map(|e| (e.txn.request.clone(), e.txn.dest)).ok_or(CommandError::InvalidState("INVITE transaction gone"))?;
        let reason = r.reason.filter(|x| is_safe_value(x));
        let mut resp = self.uas_dialog_response(leg, &req, r.code, reason.as_deref(), &r.headers, r.sdp.as_deref());
        if reliable {
            if leg.ext.rel.next_rseq == 0 {
                // RFC 3262 §3: start anywhere in 1..2^31-1, leaving room to count up.
                leg.ext.rel.next_rseq = u32::try_from(self.rand_below(1 << 30)).unwrap_or(0).saturating_add(1);
            }
            let rseq = leg.ext.rel.next_rseq;
            leg.ext.rel.next_rseq = rseq.saturating_add(1);
            resp.push_header("Require", "100rel");
            resp.push_header("RSeq", rseq.to_string());
            let bytes: Arc<[u8]> = resp.to_bytes().into();
            let t1 = self.cfg.timers.t1;
            leg.ext.rel.pending = Some(Reliable { rseq, bytes, dest, interval: t1, offer, op });
            self.arm_leg(leg, LegTimer::Rel1xxRetransmit, now.saturating_add(t1));
            let give_up = now.saturating_add(self.cfg.timers.t64());
            self.arm_leg(leg, LegTimer::Rel1xxGiveUp, give_up);
        }
        self.reply(tid, resp, now);
        if let Some(b) = r.sdp {
            leg.ext.local_sdp = Some(b.clone());
            if offer {
                leg.generation = leg.generation.saturating_add(1);
                leg.oa = Oa::LocalOffer(OfferVia::OurReliable1xx, Some(op));
            } else {
                if !reliable {
                    leg.early_answer = Some(b);
                } else {
                    leg.ext.rel.negotiated_early = true;
                }
                leg.remote_offer = None;
                leg.oa = Oa::Stable;
                leg.negotiated = true;
                leg.stable_generation = leg.generation;
            }
        }
        leg.set_phase(Phase::Early);
        Ok(())
    }

    /// The INVITE got (or is about to get) a final: stop reliable 1xx work.
    pub(super) fn rel_finish(leg: &mut Leg) {
        leg.ext.rel.pending = None;
        leg.ext.rel.queue.clear();
        leg.disarm(LegTimer::Rel1xxRetransmit);
        leg.disarm(LegTimer::Rel1xxGiveUp);
    }

    /// A PRACK from the caller.
    pub(super) fn on_prack(&mut self, leg: &mut Leg, tid: TxnId, req: &SipMessage, now: u64) {
        let invite_cseq = leg.invite_txn.and_then(|t| self.txns.get(&t)).and_then(|e| e.txn.request.cseq()).map(|c| c.0);
        let rack = req.header("RAck").and_then(parse_rack);
        let matches = match (&leg.ext.rel.pending, rack, invite_cseq) {
            (Some(p), Some((rseq, cseq, Method::Invite)), Some(ic)) => p.rseq == rseq && cseq == ic,
            _ => false,
        };
        if !matches {
            self.reply_simple(tid, 481, None, &[], now);
            return;
        }
        self.reply_simple(tid, 200, None, &[], now);
        let Some(p) = leg.ext.rel.pending.take() else { return };
        leg.disarm(LegTimer::Rel1xxRetransmit);
        leg.disarm(LegTimer::Rel1xxGiveUp);
        if p.offer {
            match req.sdp().filter(|a| sdp::is_valid(a)) {
                Some(a) => {
                    leg.oa = Oa::Stable;
                    leg.negotiated = true;
                    leg.ext.rel.negotiated_early = true;
                    leg.stable_generation = leg.generation;
                    let status = SipStatus { code: 200, reason: "PRACK".into() };
                    self.emit(leg, Some(p.op), UaEvent::Completed(CompletedEvent { status, sdp: Some(a.to_vec()) }));
                }
                None => {
                    let cause = Cause::new(CauseKind::ProtocolViolation).with_detail("PRACK without the answer to our offer");
                    self.emit(leg, Some(p.op), UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
                    self.uas_final(leg, 488, None, Vec::new(), None, now);
                    Self::rel_finish(leg);
                    self.terminate(leg, cause);
                    return;
                }
            }
        }
        if let Some((r, op)) = leg.ext.rel.queue.pop_front() {
            let _ = self.uas_provisional(leg, op, r, now);
        }
    }

    pub(super) fn rel_retransmit(&mut self, leg: &mut Leg, now: u64) {
        let Some(p) = &mut leg.ext.rel.pending else { return };
        p.interval = p.interval.saturating_mul(2);
        let (d, b, i) = (p.dest, p.bytes.clone(), p.interval);
        self.send_raw(d, b, None);
        self.arm_leg(leg, LegTimer::Rel1xxRetransmit, now.saturating_add(i));
    }

    /// RFC 3262 §3: no PRACK after 64·T1: reject the INVITE with a 5xx.
    pub(super) fn rel_give_up(&mut self, leg: &mut Leg, now: u64) {
        if leg.ext.rel.pending.is_none() || !matches!(leg.phase, Phase::Calling | Phase::Early) {
            return;
        }
        Self::rel_finish(leg);
        let cause = Cause::sip(CauseKind::NoAck, 504, "Server Time-out").with_detail("no PRACK for a reliable provisional");
        self.emit(leg, None, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
        self.uas_final(leg, 504, Some("No PRACK"), Vec::new(), None, now);
        self.terminate(leg, cause);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rack_and_rseq() {
        assert_eq!(parse_rack("776656 1 INVITE"), Some((776_656, 1, Method::Invite)));
        assert_eq!(parse_rack("x 1 INVITE"), None);
        let mut r = SipMessage::response(183, "Session Progress");
        r.push_header("RSeq", "5");
        assert_eq!(rseq_of(&r), None, "RSeq without Require: 100rel");
        r.push_header("Require", "100rel");
        assert_eq!(rseq_of(&r), Some(5));
    }
}
