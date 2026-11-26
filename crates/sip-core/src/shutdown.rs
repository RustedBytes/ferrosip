//! Graceful shutdown state, set by `main` on SIGTERM/SIGINT.
//!
//! While draining:
//! - the TCP/TLS/WS listeners refuse new connections;
//! - new initial requests (no To-tag, except ACK/CANCEL) get
//!   `503 Service Unavailable` with `Retry-After`;
//! - everything that belongs to work in progress still flows (replies,
//!   in-dialog requests, ACK, CANCEL), so in-flight transactions can finish.
//!
//! `main` waits until no module reports busy work ([`crate::Module::busy`]) or
//! the timeout expires, runs [`crate::Module::shutdown`], then exits.

use sip_parser::uri::{name_addr, param};
use sip_parser::{HdrFlags, HdrKind, Method, Msg};
use std::sync::atomic::{AtomicBool, Ordering};

static DRAINING: AtomicBool = AtomicBool::new(false);

/// Start draining (idempotent).
pub fn begin() {
    DRAINING.store(true, Ordering::Release);
}

/// A graceful shutdown is in progress.
#[inline]
pub fn draining() -> bool {
    DRAINING.load(Ordering::Relaxed)
}

/// `Retry-After` for requests refused while draining: a restarted server
/// (or another instance) is usually back within this time.
pub const RETRY_AFTER_SECS: u32 = 5;

/// Would this request start new work (and so be refused while draining)?
/// Requests with a To-tag belong to an existing dialog; ACK and CANCEL
/// belong to an existing transaction.
pub fn starts_new_work(msg: &mut Msg<'_>) -> bool {
    if !msg.is_request() || matches!(msg.method(), Some(Method::Ack | Method::Cancel)) {
        return false;
    }
    if msg.parse_headers(HdrFlags::of(HdrKind::To)).is_err() {
        return true;
    }
    !msg.get(HdrKind::To).is_some_and(|h| param(name_addr(h.body).1, b"tag").is_some_and(|t| !t.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn starts(raw: &str) -> bool {
        let arena = bumpalo::Bump::new();
        let mut m = Msg::parse(raw.as_bytes(), &arena).unwrap();
        starts_new_work(&mut m)
    }

    #[test]
    fn only_initial_requests_count_as_new_work() {
        let req = |method: &str, to: &str| {
            format!(
                "{method} sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@x>;tag=1\r\nTo: {to}\r\nCall-ID: c\r\nCSeq: 1 {method}\r\nContent-Length: 0\r\n\r\n"
            )
        };
        assert!(starts(&req("INVITE", "<sip:b@x>")));
        assert!(starts(&req("REGISTER", "<sip:b@x>")));
        assert!(!starts(&req("BYE", "<sip:b@x>;tag=9")));
        assert!(!starts(&req("ACK", "<sip:b@x>")));
        assert!(!starts(&req("CANCEL", "<sip:b@x>")));
        assert!(!starts(
            "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ));
    }
}
