//! RFC 3515 REFER with its implicit subscription, and RFC 3891 Replaces.
//!
//! Sending: `Refer` → REFER; its 2xx completes the operation; the peer's
//! NOTIFYs (`message/sipfrag`) become `ReferProgress` until the
//! subscription terminates (or `refer_timeout_ms` passes).
//!
//! Receiving: REFER → `ReferRequested`; the application accepts (202 and
//! an initial NOTIFY "100 Trying") or declines (603; also after the
//! deadline), then reports progress with `NotifyRefer`.
//! One REFER at a time per direction and dialog.

use super::*;
use crate::refer::{Replaces, split_refer_to};

#[derive(Debug, Default)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub(super) struct ReferState {
    /// Our REFER before its final response: (transaction, operation).
    client_pending: Option<(TxnId, OperationId)>,
    /// Our accepted REFER: its subscription is running.
    client: Option<OperationId>,
    /// Their REFER waiting for the application's decision.
    server_pending: Option<TxnId>,
    /// We accepted their REFER and owe NOTIFYs.
    server_active: bool,
    /// The final NOTIFY of our REFER overtook its 2xx.
    done_early: bool,
}

fn sipfrag_status(body: &[u8]) -> Option<SipStatus> {
    let s = std::str::from_utf8(body).ok()?;
    let line = s.lines().next()?.trim();
    let rest = line.strip_prefix("SIP/2.0 ")?;
    let (code, reason) = rest.split_once(' ').unwrap_or((rest, ""));
    let code: u16 = code.parse().ok().filter(|c| (100..700).contains(c))?;
    Some(SipStatus { code, reason: reason.to_string() })
}

impl ReferState {
    /// Their REFER still waiting for a decision (the leg is ending).
    pub(super) fn take_server_pending(&mut self) -> Option<TxnId> {
        self.server_pending.take()
    }
}

impl UaEngine {
    // ---------------------------------------------------------- sending --

    pub(super) fn cmd_refer(&mut self, leg: &mut Leg, op: OperationId, r: ReferRequest, now: u64) -> Result<(), CommandError> {
        if leg.phase != Phase::Confirmed {
            return Err(CommandError::InvalidState("REFER needs a confirmed dialog"));
        }
        if leg.ext.refer.client.is_some() || leg.ext.refer.client_pending.is_some() {
            return Err(CommandError::InvalidState("a REFER of ours is in progress"));
        }
        if !is_safe_value(&r.refer_to) || split_refer_to(&r.refer_to).is_none() {
            return Err(CommandError::InvalidArgument("Refer-To".into()));
        }
        if r.referred_by.as_ref().is_some_and(|v| !is_safe_value(v)) {
            return Err(CommandError::InvalidArgument("Referred-By".into()));
        }
        check_headers(&r.headers)?;
        let cseq = Self::next_cseq(leg).ok_or(CommandError::InvalidState("CSeq space exhausted"))?;
        let mut m = self.dialog_request(leg, Method::Refer, cseq);
        m.push_header("Contact", format!("<{}>", leg.local_contact));
        m.push_header("Refer-To", angle(&r.refer_to));
        if let Some(rb) = r.referred_by {
            m.push_header("Referred-By", angle(&rb));
        }
        for h in r.headers {
            m.push_header(h.name, h.value);
        }
        let id = leg.id;
        self.dispatch_leg_request(leg, m, Purpose::Refer(id, op), None, now)
    }

    /// The transaction of our REFER started (`dispatch_leg_request`).
    pub(super) fn refer_started(leg: &mut Leg, tid: TxnId, op: OperationId) {
        leg.ext.refer.client_pending = Some((tid, op));
    }

    pub(super) fn refer_response(&mut self, leg: &mut Leg, tid: TxnId, op: OperationId, resp: &SipMessage, now: u64) {
        let Some(code) = resp.status().filter(|c| *c >= 200) else { return };
        if leg.ext.refer.client_pending.is_some_and(|(t, _)| t == tid) {
            leg.ext.refer.client_pending = None;
        }
        if code < 300 {
            // A final NOTIFY may already have arrived before the 2xx.
            if leg.ext.refer.client.is_none() && !leg.ext.refer.done_early {
                leg.ext.refer.client = Some(op);
                let at = now.saturating_add(self.cfg.refer_timeout_ms);
                self.arm_leg(leg, LegTimer::ReferGuard, at);
            }
            leg.ext.refer.done_early = false;
            let status = SipStatus { code, reason: resp.reason().unwrap_or_default().to_string() };
            self.emit(leg, Some(op), UaEvent::Completed(CompletedEvent { status, sdp: None }));
        } else {
            leg.ext.refer.done_early = false;
            self.op_failed(leg, Some(op), resp, now);
        }
    }

    /// A NOTIFY in the dialog (the subscription of our REFER).
    pub(super) fn on_notify(&mut self, leg: &mut Leg, tid: TxnId, req: &SipMessage, now: u64) {
        let event = req.header("Event").unwrap_or_default();
        if !event.split(';').next().unwrap_or_default().trim().eq_ignore_ascii_case("refer") {
            self.reply_simple(tid, 489, None, &[("Allow-Events", "refer".into())], now);
            return;
        }
        // RFC 3515 §2.4.4: the NOTIFY may overtake the REFER's 2xx.
        let op = leg.ext.refer.client.or(leg.ext.refer.client_pending.map(|(_, o)| o));
        let Some(op) = op else {
            self.reply_simple(tid, 481, None, &[], now);
            return;
        };
        self.reply_simple(tid, 200, None, &[], now);
        let last = req.header("Subscription-State").is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("terminated"));
        let Some(status) = sipfrag_status(&req.body) else {
            // A NOTIFY without a status (e.g. only ending the subscription).
            if last {
                self.refer_finished(leg);
            }
            return;
        };
        self.emit(leg, Some(op), UaEvent::ReferProgress(ReferProgressEvent { status, last }));
        if last {
            if leg.ext.refer.client.is_none() {
                leg.ext.refer.done_early = true;
            }
            self.refer_finished(leg);
        }
    }

    fn refer_finished(&mut self, leg: &mut Leg) {
        leg.ext.refer.client = None;
        leg.disarm(LegTimer::ReferGuard);
    }

    /// The subscription of our REFER never terminated.
    pub(super) fn refer_guard(&mut self, leg: &mut Leg) {
        if let Some(op) = leg.ext.refer.client.take() {
            let cause = Cause::new(CauseKind::Timeout).with_detail("REFER subscription did not terminate");
            self.emit(leg, Some(op), UaEvent::Failed(FailureEvent { cause, leg_failed: false, retry_after_ms: None }));
        }
    }

    // -------------------------------------------------------- receiving --

    pub(super) fn on_refer(&mut self, leg: &mut Leg, tid: TxnId, req: &SipMessage, now: u64) {
        if leg.phase != Phase::Confirmed {
            self.reply_simple(tid, 403, None, &[("Warning", "399 - \"REFER outside a confirmed dialog\"".into())], now);
            return;
        }
        let refer_to: Vec<&str> = req.header_lines("Refer-To").collect();
        let parsed = match refer_to.as_slice() {
            [one] => split_refer_to(one).map(|p| (one.to_string(), p)),
            _ => None,
        };
        let Some((raw, (target, replaces))) = parsed else {
            self.reply_simple(tid, 400, None, &[("Warning", "399 - \"one valid Refer-To required\"".into())], now);
            return;
        };
        if leg.ext.refer.server_pending.is_some() || leg.ext.refer.server_active {
            let ra = self.glare_retry_after();
            self.reply_simple(tid, 500, None, &[("Retry-After", ra)], now);
            return;
        }
        leg.ext.refer.server_pending = Some(tid);
        let deadline = now.saturating_add(self.cfg.answer_timeout_ms);
        self.arm_leg(leg, LegTimer::ReferAnswer, deadline);
        let ev =
            ReferEvent { refer_to: raw, target, replaces, referred_by: req.header("Referred-By").map(str::to_string), headers: req.headers.clone(), deadline };
        self.emit(leg, None, UaEvent::ReferRequested(ev));
    }

    pub(super) fn cmd_respond_refer(&mut self, leg: &mut Leg, r: ReferResponse, now: u64) -> Result<(), CommandError> {
        let tid = leg.ext.refer.server_pending.take().ok_or(CommandError::InvalidState("no REFER to answer"))?;
        leg.disarm(LegTimer::ReferAnswer);
        if !r.accept {
            self.reply_simple(tid, 603, None, &[], now);
            return Ok(());
        }
        let contact = format!("<{}>", leg.local_contact);
        self.reply_simple(tid, 202, None, &[("Contact", contact)], now);
        leg.ext.refer.server_active = true;
        self.send_refer_notify(leg, 100, "Trying", false, now);
        Ok(())
    }

    pub(super) fn refer_answer_timeout(&mut self, leg: &mut Leg, now: u64) {
        if let Some(tid) = leg.ext.refer.server_pending.take() {
            self.reply_simple(tid, 603, None, &[], now);
            let cause = Cause::new(CauseKind::AnswerTimeout).with_detail("REFER not answered by the application");
            self.emit(leg, None, UaEvent::Failed(FailureEvent { cause, leg_failed: false, retry_after_ms: None }));
        }
    }

    pub(super) fn cmd_notify_refer(&mut self, leg: &mut Leg, r: ReferNotify, now: u64) -> Result<(), CommandError> {
        if !leg.ext.refer.server_active {
            return Err(CommandError::InvalidState("no accepted REFER"));
        }
        if !(100..700).contains(&r.code) {
            return Err(CommandError::InvalidArgument("status code".into()));
        }
        let reason = r.reason.filter(|x| is_safe_value(x)).unwrap_or_else(|| reason_text(r.code).to_string());
        self.send_refer_notify(leg, r.code, &reason, r.last, now);
        if r.last {
            leg.ext.refer.server_active = false;
        }
        Ok(())
    }

    fn send_refer_notify(&mut self, leg: &mut Leg, code: u16, reason: &str, last: bool, now: u64) {
        let Some(cseq) = Self::next_cseq(leg) else { return };
        let mut m = self.dialog_request(leg, Method::Notify, cseq);
        m.push_header("Contact", format!("<{}>", leg.local_contact));
        m.push_header("Event", "refer");
        m.push_header("Subscription-State", if last { "terminated;reason=noresource" } else { "active;expires=60" });
        m.push_header("Content-Type", "message/sipfrag;version=2.0");
        m.body = format!("SIP/2.0 {code} {reason}\r\n").into_bytes();
        // A failed NOTIFY doesn't end the call (RFC 5057: only the subscription).
        let _ = self.dispatch_leg_request(leg, m, Purpose::Detached, None, now);
    }

    // --------------------------------------------------------- Replaces --

    /// RFC 3891 §3: the leg an INVITE's Replaces names, or the error to
    /// answer: 481 (no such dialog, or an early dialog we initiated), 486
    /// (`early-only` but confirmed), 400 (malformed).
    pub(super) fn match_replaces(&self, req: &SipMessage) -> Result<Option<UaLegId>, u16> {
        let Some(v) = req.header("Replaces") else { return Ok(None) };
        let r = Replaces::parse(v).ok_or(400u16)?;
        let key = (r.call_id.clone(), r.to_tag.clone(), r.from_tag.clone());
        let (id, role, phase) = match self.dialogs.get(&key) {
            Some(id) => {
                let leg = self.legs.get(id).ok_or(481u16)?;
                (*id, leg.role, leg.phase)
            }
            // Sharded: the replaced dialog may be another shard's.
            None => {
                let (_, id, status) = self.directory.as_ref().and_then(|d| d.get(&key)).ok_or(481u16)?;
                let (role, phase) = status.get();
                (id, role, phase)
            }
        };
        match (role, phase) {
            (_, Phase::Terminating | Phase::Terminated) => Err(481),
            (Role::Uac, Phase::Calling | Phase::Early) => Err(481),
            (_, Phase::Confirmed) if r.early_only => Err(486),
            _ => Ok(Some(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sipfrag() {
        assert_eq!(sipfrag_status(b"SIP/2.0 180 Ringing\r\n"), Some(SipStatus { code: 180, reason: "Ringing".into() }));
        assert_eq!(sipfrag_status(b"SIP/2.0 200\r\n").map(|s| s.code), Some(200));
        assert_eq!(sipfrag_status(b"junk"), None);
    }
}
