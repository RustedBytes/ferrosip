//! Why a leg or an operation failed, without losing the original SIP detail.

use std::fmt;

/// A final SIP status as received (or sent).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub struct SipStatus {
    pub code: u16,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub enum CauseKind {
    /// The peer answered with a final non-2xx (or sent BYE with a Reason).
    SipResponse,
    /// No final response in time (timer B/F, no-answer timeout).
    Timeout,
    /// The transport reported a send failure / closed flow.
    Transport,
    /// Next-hop resolution failed.
    Dns,
    /// Cancelled locally or remotely.
    Cancelled,
    /// Digest authentication failed or retries were exhausted.
    AuthFailed,
    /// The UAS never received an ACK for its 2xx.
    NoAck,
    /// The application did not answer an offer that needed one in time.
    AnswerTimeout,
    /// The peer violated the protocol (e.g. 2xx without the required answer).
    ProtocolViolation,
    /// The engine shed the leg (event queue overflow, drain).
    Overload,
    /// RFC 4028: the session was not refreshed in time.
    SessionExpired,
    /// Normal clearing by BYE (either side).
    NormalClearing,
    /// Rejected or hung up by the application.
    Local,
}

/// Terminal or failure cause: kind, Q.850 mapping and the original status.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub struct Cause {
    pub kind: CauseKind,
    /// The SIP status that caused it (received or locally generated).
    pub sip: Option<SipStatus>,
    /// Q.850 cause value: from the peer's `Reason: Q.850;cause=N` when
    /// present, else mapped from the SIP status (RFC 3398 §8.2.6.1).
    pub q850: u16,
    /// Human-readable detail (never contains credentials).
    pub detail: Option<String>,
    /// A 3xx's Contact URIs, best q first, for the application to follow
    /// (when the engine doesn't, see `UaConfig::max_redirects`).
    pub contacts: Vec<String>,
}

impl Cause {
    pub fn new(kind: CauseKind) -> Self {
        let q850 = match kind {
            CauseKind::Timeout | CauseKind::NoAck | CauseKind::AnswerTimeout | CauseKind::SessionExpired => 102,
            CauseKind::Transport | CauseKind::Dns => 38,
            CauseKind::Cancelled => 16,
            CauseKind::AuthFailed => 21,
            CauseKind::ProtocolViolation => 111,
            CauseKind::Overload => 42,
            CauseKind::NormalClearing | CauseKind::Local | CauseKind::SipResponse => 16,
        };
        Self { kind, sip: None, q850, detail: None, contacts: Vec::new() }
    }

    pub fn sip(kind: CauseKind, code: u16, reason: impl Into<String>) -> Self {
        Self { kind, q850: q850_for_sip(code), sip: Some(SipStatus { code, reason: reason.into() }), detail: None, contacts: Vec::new() }
    }

    pub fn with_detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }

    /// Prefer the Q.850 cause the peer put in a `Reason` header.
    pub fn with_reason_header(mut self, reason: Option<&str>) -> Self {
        if let Some(c) = reason.and_then(q850_from_reason) {
            self.q850 = c;
        }
        self
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (Q.850 {})", self.kind, self.q850)?;
        if let Some(s) = &self.sip {
            write!(f, " SIP {} {}", s.code, s.reason)?;
        }
        if let Some(d) = &self.detail {
            write!(f, ": {d}")?;
        }
        Ok(())
    }
}

/// RFC 3398 §8.2.6.1 SIP → ISUP cause mapping; codes it doesn't list map to
/// their class default (4xx: 127 interworking, 5xx: 41, 6xx: 31).
pub fn q850_for_sip(code: u16) -> u16 {
    let listed = match code {
        200..=299 => 16,
        400 | 500 | 503 => 41,
        401..=403 | 407 | 603 => 21,
        404 | 485 | 604 => 1,
        405 => 63,
        406 | 415 | 501 => 79,
        408 | 504 => 102,
        410 => 22,
        480 => 18,
        481 => 41,
        482 | 483 => 25,
        484 => 28,
        486 | 600 => 17,
        488 => 88,
        502 => 38,
        606 => 58,
        _ => 0,
    };
    match (listed, code) {
        (0, 400..=499) => 127,
        (0, 500..=599) => 41,
        (0, _) => 31,
        (c, _) => c,
    }
}

/// `Reason: Q.850;cause=16;text="..."` (RFC 3326), possibly among others.
pub fn q850_from_reason(v: &str) -> Option<u16> {
    crate::msg::split_values(v).into_iter().find_map(|r| {
        let mut parts = r.split(';');
        let proto = parts.next()?.trim();
        if !proto.eq_ignore_ascii_case("Q.850") {
            return None;
        }
        parts.find_map(|p| {
            let (k, val) = p.split_once('=')?;
            k.trim().eq_ignore_ascii_case("cause").then(|| val.trim().parse::<u16>().ok()).flatten()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_and_reason_override() {
        assert_eq!(q850_for_sip(486), 17);
        assert_eq!(q850_for_sip(404), 1);
        assert_eq!(q850_for_sip(499), 127);
        assert_eq!(q850_for_sip(599), 41);
        let c = Cause::sip(CauseKind::SipResponse, 503, "Service Unavailable").with_reason_header(Some("SIP;cause=503, Q.850;cause=34;text=\"x\""));
        assert_eq!(c.q850, 34);
        assert_eq!(c.sip.as_ref().map(|s| s.code), Some(503));
        assert_eq!(q850_from_reason("SIP;cause=200"), None);
    }
}
