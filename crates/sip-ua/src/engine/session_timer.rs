//! RFC 4028 session timers.
//!
//! Negotiated on the INVITE / 2xx and again on every re-INVITE or UPDATE.
//! The refresher sends a body-less UPDATE at half the interval (a
//! re-INVITE with our last SDP when the peer does not allow UPDATE); both
//! sides end the session with BYE when no refresh arrived by
//! `interval − min(32 s, interval / 3)` (§10).

use super::*;

/// Per-leg session timer state.
#[derive(Debug, Default)]
pub(super) struct SessionTimer {
    /// Negotiated interval in seconds; None: no session timer.
    pub(super) interval: Option<u32>,
    /// We send the refreshes.
    pub(super) we_refresh: bool,
    /// The peer lists UPDATE in Allow: refresh with UPDATE.
    pub(super) peer_update: bool,
    /// The peer supports the `timer` extension.
    pub(super) peer_supports: bool,
    /// Our refresh in progress.
    pub(super) refreshing: Option<TxnId>,
    /// 422 retries of the current request.
    pub(super) retries_422: u8,
    /// Interval to ask for (raised by a 422's Min-SE).
    pub(super) requested: Option<u32>,
    /// (interval, we refresh) for our 2xx to the peer's pending request.
    pub(super) pending: Option<(u32, bool)>,
}

/// `Session-Expires: 1800;refresher=uac` → (1800, Some("uac")).
pub(super) fn parse_se(v: &str) -> Option<(u32, Option<String>)> {
    let mut parts = v.split(';');
    let secs = parts.next()?.trim().parse::<u32>().ok()?;
    let refresher = parts.find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim().eq_ignore_ascii_case("refresher").then(|| v.trim().to_ascii_lowercase())
    });
    Some((secs, refresher))
}

fn min_se_of(m: &SipMessage) -> Option<u32> {
    m.header("Min-SE")?.split(';').next()?.trim().parse().ok()
}

fn allows_update(m: &SipMessage) -> Option<bool> {
    m.header("Allow").map(|_| m.values("Allow").iter().any(|v| v.eq_ignore_ascii_case("UPDATE")))
}

impl UaEngine {
    /// The interval we would ask for on a new request of this leg.
    fn st_wanted(&self, leg: &Leg) -> Option<u32> {
        let st = &leg.ext.st;
        st.interval.or(st.requested).or(self.cfg.session_expires).map(|v| v.max(self.cfg.min_se))
    }

    /// Session-Expires / Min-SE / Supported on a request we send.
    pub(super) fn st_request_headers(&self, leg: &Leg, m: &mut SipMessage) {
        let Some(se) = self.st_wanted(leg) else { return };
        let v = match leg.ext.st.interval {
            // Keep the current refresher: from this transaction's view we are the UAC.
            Some(_) => format!("{se};refresher={}", if leg.ext.st.we_refresh { "uac" } else { "uas" }),
            // Initial request: let the UAS choose (RFC 4028 §7.1).
            None => se.to_string(),
        };
        m.set_header("Session-Expires", v);
        m.set_header("Min-SE", self.cfg.min_se.to_string());
    }

    /// A 2xx to a request we sent (INVITE, re-INVITE, UPDATE).
    pub(super) fn st_on_2xx(&mut self, leg: &mut Leg, resp: &SipMessage, now: u64) {
        leg.ext.st.retries_422 = 0;
        if let Some(u) = allows_update(resp) {
            leg.ext.st.peer_update = u;
        }
        if resp.has_option("Require", "timer") || resp.has_option("Supported", "timer") {
            leg.ext.st.peer_supports = true;
        }
        match resp.header("Session-Expires").and_then(parse_se) {
            Some((secs, refresher)) => {
                leg.ext.st.interval = Some(secs.max(1));
                // We are the UAC of this transaction; a missing refresher means us.
                leg.ext.st.we_refresh = refresher.as_deref() != Some("uas");
            }
            // §7.2: no Session-Expires in the 2xx, no session expiration.
            None => leg.ext.st.interval = None,
        }
        self.st_arm(leg, now);
    }

    /// The peer's INVITE / re-INVITE / UPDATE: Err(min) when it must get
    /// 422 with that Min-SE; otherwise remembers what our 2xx will carry.
    pub(super) fn st_on_request(&self, leg: &mut Leg, req: &SipMessage) -> Result<(), u32> {
        let st = &mut leg.ext.st;
        st.peer_supports = req.has_option("Supported", "timer") || req.has_option("Require", "timer");
        if let Some(u) = allows_update(req) {
            st.peer_update = u;
        }
        st.pending = match req.header("Session-Expires").and_then(parse_se) {
            Some((secs, _)) if secs < self.cfg.min_se => return Err(self.cfg.min_se),
            Some((secs, refresher)) => {
                // §9: no refresher in the request: the UAC if it can, else us.
                let we = match refresher.as_deref() {
                    Some("uas") => true,
                    Some("uac") => false,
                    _ => !st.peer_supports,
                };
                Some((secs, we))
            }
            None => st.interval.or(self.cfg.session_expires).map(|v| (v.max(self.cfg.min_se), true)),
        };
        Ok(())
    }

    /// Our 2xx to the peer's request: Session-Expires (and Require: timer)
    /// with the values `st_on_request` settled; the timer starts now.
    pub(super) fn st_response_headers(&mut self, leg: &mut Leg, r: &mut SipMessage, now: u64) {
        let Some((secs, we)) = leg.ext.st.pending.take() else { return };
        r.set_header("Session-Expires", format!("{secs};refresher={}", if we { "uas" } else { "uac" }));
        if leg.ext.st.peer_supports {
            r.push_header("Require", "timer");
        }
        leg.ext.st.interval = Some(secs.max(1));
        leg.ext.st.we_refresh = we;
        self.st_arm(leg, now);
    }

    /// (Re)arm the refresh and expiry timers from the negotiated interval.
    pub(super) fn st_arm(&mut self, leg: &mut Leg, now: u64) {
        let Some(secs) = leg.ext.st.interval else {
            leg.disarm(LegTimer::SessionRefresh);
            leg.disarm(LegTimer::SessionExpire);
            return;
        };
        let ms = u64::from(secs).saturating_mul(1_000);
        if leg.ext.st.we_refresh {
            self.arm_leg(leg, LegTimer::SessionRefresh, now.saturating_add(ms / 2));
        } else {
            leg.disarm(LegTimer::SessionRefresh);
        }
        let margin = (ms / 3).min(32_000);
        self.arm_leg(leg, LegTimer::SessionExpire, now.saturating_add(ms.saturating_sub(margin)));
    }

    /// Time to refresh (we are the refresher).
    pub(super) fn st_refresh(&mut self, leg: &mut Leg, now: u64) {
        if leg.phase != Phase::Confirmed || leg.ext.st.refreshing.is_some() || leg.ext.st.interval.is_none() {
            return;
        }
        let update = leg.ext.st.peer_update;
        let busy_invite = leg.oa != Oa::Stable
            || leg.client_reinvite.is_some()
            || leg.server_reinvite.is_some()
            || leg.pending_2xx.is_some()
            || leg.ack_wait.is_some()
            || leg.ext.local_sdp.is_none();
        if !update && busy_invite {
            // Try again shortly; the expiry timer still bounds the session.
            self.arm_leg(leg, LegTimer::SessionRefresh, now.saturating_add(2_000));
            return;
        }
        let Some(cseq) = Self::next_cseq(leg) else { return };
        let method = if update { Method::Update } else { Method::Invite };
        let mut m = self.dialog_request(leg, method, cseq);
        m.push_header("Supported", "timer");
        self.st_request_headers(leg, &mut m);
        if !update {
            m.push_header("Allow", ALLOW);
            m.push_header("Content-Type", "application/sdp");
            m.body = leg.ext.local_sdp.clone().unwrap_or_default();
            leg.oa = Oa::LocalOffer(OfferVia::ReInvite, None);
        }
        let id = leg.id;
        if self.dispatch_leg_request(leg, m, Purpose::Refresh(id), None, now).is_err() {
            if !update {
                leg.oa = Oa::Stable;
            }
            self.arm_leg(leg, LegTimer::SessionRefresh, now.saturating_add(2_000));
        }
    }

    /// The response to our refresh.
    pub(super) fn refresh_response(&mut self, leg: &mut Leg, tid: TxnId, resp: &SipMessage, now: u64) {
        let Some(code) = resp.status().filter(|c| *c >= 200) else { return };
        let Some((cseq, method)) = resp.cseq() else { return };
        let invite = method == Method::Invite;
        if leg.ext.st.refreshing != Some(tid) {
            // A retransmitted 2xx to our refresh re-INVITE: ACK again.
            if invite
                && code < 300
                && let Some((c, b, d)) = &leg.ack
                && *c == cseq
            {
                let (b, d) = (b.clone(), *d);
                self.send_raw(d, b, None);
            }
            return;
        }
        leg.ext.st.refreshing = None;
        if invite {
            leg.client_reinvite = None;
            if leg.oa == Oa::LocalOffer(OfferVia::ReInvite, None) {
                leg.oa = Oa::Stable;
            }
        }
        if code < 300 {
            if invite {
                self.send_ack(leg, cseq, None, now);
            }
            if let Some(c) = resp.contact_uri() {
                leg.remote_target = c;
            }
            self.st_on_2xx(leg, resp, now);
            return;
        }
        match code {
            422 if leg.ext.st.retries_422 < 2 => {
                leg.ext.st.retries_422 = leg.ext.st.retries_422.saturating_add(1);
                let min = min_se_of(resp).unwrap_or(self.cfg.min_se);
                leg.ext.st.interval = leg.ext.st.interval.map(|v| v.max(min));
                self.st_refresh(leg, now);
            }
            405 | 501 if !invite => {
                leg.ext.st.peer_update = false;
                self.st_refresh(leg, now);
            }
            481 => {
                let cause = Cause::sip(CauseKind::SipResponse, code, resp.reason().unwrap_or_default());
                self.fail(leg, None, cause);
            }
            408 => self.refresh_failed(leg, Cause::sip(CauseKind::Timeout, 408, "Request Timeout"), now),
            // 491, 500 and the rest: try again; expiry ends the session if it keeps failing.
            _ => self.arm_leg(leg, LegTimer::SessionRefresh, now.saturating_add(2_000)),
        }
    }

    /// The refresh timed out or could not be sent: RFC 3261 §12.2.1.2 (408).
    pub(super) fn refresh_failed(&mut self, leg: &mut Leg, cause: Cause, now: u64) {
        leg.ext.st.refreshing = None;
        if leg.oa == Oa::LocalOffer(OfferVia::ReInvite, None) {
            leg.oa = Oa::Stable;
            leg.client_reinvite = None;
        }
        self.emit(leg, None, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
        self.send_bye(leg, Some("Q.850;cause=102".into()), cause, now);
    }

    /// No refresh in time.
    pub(super) fn st_expired(&mut self, leg: &mut Leg, now: u64) {
        if leg.phase != Phase::Confirmed {
            return;
        }
        let cause = Cause::new(CauseKind::SessionExpired);
        self.emit(leg, None, UaEvent::Failed(FailureEvent { cause: cause.clone(), leg_failed: true, retry_after_ms: None }));
        self.send_bye(leg, Some("Q.850;cause=102;text=\"session timer expired\"".into()), cause, now);
    }

    /// 422 to our initial INVITE: ask again with the peer's Min-SE.
    pub(super) fn retry_after_422(&mut self, leg: &mut Leg, tid: TxnId, resp: &SipMessage, now: u64) -> bool {
        if leg.ext.st.retries_422 >= 2 {
            return false;
        }
        let Some(min) = min_se_of(resp) else { return false };
        leg.ext.st.retries_422 = leg.ext.st.retries_422.saturating_add(1);
        let secs = self.st_wanted(leg).unwrap_or(min).max(min);
        leg.ext.st.requested = Some(secs);
        let min_se = self.cfg.min_se.max(min);
        self.resend_invite(leg, tid, now, |m| {
            m.set_header("Session-Expires", secs.to_string());
            m.set_header("Min-SE", min_se.to_string());
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_session_expires() {
        assert_eq!(parse_se("1800;refresher=UAS"), Some((1800, Some("uas".into()))));
        assert_eq!(parse_se(" 90 "), Some((90, None)));
        assert_eq!(parse_se("x"), None);
    }
}
