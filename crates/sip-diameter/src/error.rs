//! Why a Diameter request got no answer.

use std::fmt;

/// The failure of [`crate::Peers::request`], [`crate::Peers::request_cb`]
/// (passed to the callback) and [`crate::Peers::send`]. Callers branch on
/// it: Kamailio's IMS modules answer a timeout differently from a request
/// that could not be sent at all.
#[derive(Debug)]
pub enum DiameterError {
    /// No open connection to a peer for the destination realm (or host).
    NoRoute { realm: String },
    /// Writing the request to the peer failed.
    Send { peer: String, err: std::io::Error },
    /// No answer within the transaction timeout; the peer when known.
    Timeout { peer: Option<String> },
    /// The request can't be encoded (a field over its 24-bit limit).
    Encode(String),
    /// There is no peer manager (the `cdp` module isn't loaded).
    NoCdp,
}

impl DiameterError {
    /// The answer did not come in time (the request did go out).
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }
}

impl fmt::Display for DiameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute { realm } => write!(f, "no open Diameter peer for realm {realm}"),
            Self::Send { peer, err } => write!(f, "Diameter send to {peer}: {err}"),
            Self::Timeout { peer: Some(p) } => write!(f, "Diameter request to {p} timed out"),
            Self::Timeout { peer: None } => f.write_str("Diameter request timed out"),
            Self::Encode(e) => write!(f, "Diameter request not sent: {e}"),
            Self::NoCdp => f.write_str("no cdp"),
        }
    }
}

impl std::error::Error for DiameterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Send { err, .. } => Some(err),
            _ => None,
        }
    }
}

impl From<DiameterError> for String {
    fn from(e: DiameterError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::DiameterError;

    #[test]
    fn display() {
        assert_eq!(DiameterError::NoRoute { realm: "r".into() }.to_string(), "no open Diameter peer for realm r");
        assert_eq!(DiameterError::Timeout { peer: Some("hss".into()) }.to_string(), "Diameter request to hss timed out");
        assert!(DiameterError::Timeout { peer: None }.is_timeout());
        let s: String = DiameterError::Send { peer: "hss".into(), err: std::io::Error::other("reset") }.into();
        assert_eq!(s, "Diameter send to hss: reset");
        assert_eq!(DiameterError::Encode("too big".into()).to_string(), "Diameter request not sent: too big");
        assert_eq!(DiameterError::NoCdp.to_string(), "no cdp");
    }

    #[test]
    fn only_a_send_failure_has_a_source() {
        use std::error::Error;
        let send = DiameterError::Send { peer: "hss".into(), err: std::io::Error::other("reset") };
        assert_eq!(send.source().map(ToString::to_string).as_deref(), Some("reset"));
        assert!(!send.is_timeout());
        for e in [DiameterError::NoRoute { realm: "r".into() }, DiameterError::Timeout { peer: None }, DiameterError::Encode("x".into()), DiameterError::NoCdp]
        {
            assert!(e.source().is_none(), "{e}");
        }
    }
}
