//! Stateless reply generation (Kamailio's `sl` / `sl_send_reply`).

use crate::shm::fx_hash;
use sip_parser::{HdrFlags, HdrKind, Msg, ParseError};
use std::io::Write;

/// Builds a reply to request `req` into `out` (appends).
pub fn build_reply(req: &mut Msg<'_>, code: u16, reason: &str, out: &mut Vec<u8>) -> Result<(), ParseError> {
    build_reply_with(req, code, reason, b"", out)
}

/// Like `build_reply`, with extra header lines (each ending in CRLF).
pub fn build_reply_with(req: &mut Msg<'_>, code: u16, reason: &str, extra: &[u8], out: &mut Vec<u8>) -> Result<(), ParseError> {
    build_reply_body(req, code, reason, extra, None, out)
}

/// Full form: extra headers and an optional (content-type, body).
pub fn build_reply_body(req: &mut Msg<'_>, code: u16, reason: &str, extra: &[u8], body: Option<(&str, &[u8])>, out: &mut Vec<u8>) -> Result<(), ParseError> {
    req.parse_headers(HdrFlags::EOH)?;
    let buf = req.buf;
    #[allow(clippy::let_underscore_must_use, reason = "writing into memory can't fail")]
    let _ = write!(out, "SIP/2.0 {code} {reason}\r\n");
    for h in req.headers.iter() {
        match h.kind {
            HdrKind::Via | HdrKind::From | HdrKind::CallId | HdrKind::CSeq => {
                out.extend_from_slice(buf.get(h.start..h.end).unwrap_or_default());
            }
            HdrKind::To => {
                out.extend_from_slice(buf.get(h.start..h.end).unwrap_or_default());
                let has_tag = h.body.windows(5).any(|w| w.eq_ignore_ascii_case(b";tag="));
                // Kamailio's sl (sl_funcs.c): a To-tag from 180 on.
                if code >= 180 && !has_tag {
                    // Deterministic To-tag so a retransmitted request gets an
                    // identical reply without keeping any state.
                    let id = req.get(HdrKind::CallId).map_or(&b""[..], |c| c.body);
                    trim_crlf(out);
                    #[allow(clippy::let_underscore_must_use, reason = "writing into memory can't fail")]
                    let _ = write!(out, ";tag={:016x}\r\n", fx_hash(id));
                }
            }
            _ => {}
        }
    }
    out.extend_from_slice(extra);
    out.extend_from_slice(b"Server: ferrosip\r\n");
    match body {
        Some((ctype, b)) => {
            if !ctype.is_empty() {
                #[allow(clippy::let_underscore_must_use, reason = "writing into memory can't fail")]
                let _ = write!(out, "Content-Type: {ctype}\r\n");
            }
            #[allow(clippy::let_underscore_must_use, reason = "writing into memory can't fail")]
            let _ = write!(out, "Content-Length: {}\r\n\r\n", b.len());
            out.extend_from_slice(b);
        }
        None => out.extend_from_slice(b"Content-Length: 0\r\n\r\n"),
    }
    Ok(())
}

fn trim_crlf(v: &mut Vec<u8>) {
    while matches!(v.last(), Some(b'\r' | b'\n')) {
        v.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &str = "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1;rport=5060;received=10.0.0.1\r\n\
Via: SIP/2.0/TCP 10.0.0.2;branch=z9hG4bK2, SIP/2.0/UDP 10.0.0.3;branch=z9hG4bK3\r\n\
Record-Route: <sip:proxy;lr>\r\n\
From: Alice <sip:alice@example.com>;tag=ft\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-1\r\n\
CSeq: 5 INVITE\r\n\
Contact: <sip:alice@10.0.0.1>\r\n\
Max-Forwards: 70\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 3\r\n\r\nv=0";

    fn reply(req: &str, code: u16, extra: &str, body: Option<(&str, &[u8])>) -> String {
        let arena = bumpalo::Bump::new();
        let mut m = Msg::parse(req.as_bytes(), &arena).unwrap();
        let mut out = b"junk-before|".to_vec();
        build_reply_body(&mut m, code, "Reason Here", extra.as_bytes(), body, &mut out).unwrap();
        String::from_utf8(out).unwrap().strip_prefix("junk-before|").unwrap().to_string()
    }

    fn tag(call_id: &str) -> String {
        format!("{:016x}", fx_hash(call_id.as_bytes()))
    }

    #[test]
    fn copies_via_from_callid_cseq_and_adds_a_to_tag() {
        let want = format!(
            "SIP/2.0 404 Reason Here\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1;rport=5060;received=10.0.0.1\r\n\
Via: SIP/2.0/TCP 10.0.0.2;branch=z9hG4bK2, SIP/2.0/UDP 10.0.0.3;branch=z9hG4bK3\r\n\
From: Alice <sip:alice@example.com>;tag=ft\r\n\
To: <sip:bob@example.com>;tag={}\r\n\
Call-ID: call-1\r\n\
CSeq: 5 INVITE\r\n\
Server: ferrosip\r\n\
Content-Length: 0\r\n\r\n",
            tag("call-1")
        );
        assert_eq!(reply(REQ, 404, "", None), want);
    }

    #[test]
    fn to_tag_rules() {
        let to_line = |r: &str| r.lines().find(|l| l.starts_with("To:") || l.starts_with("t:")).unwrap().to_string();
        assert_eq!(to_line(&reply(REQ, 100, "", None)), "To: <sip:bob@example.com>", "no tag on 100 Trying");
        assert_eq!(to_line(&reply(REQ, 101, "", None)), "To: <sip:bob@example.com>", "nor below 180, as Kamailio's sl");
        assert_eq!(to_line(&reply(REQ, 179, "", None)), "To: <sip:bob@example.com>");
        assert_eq!(to_line(&reply(REQ, 180, "", None)), format!("To: <sip:bob@example.com>;tag={}", tag("call-1")));
        assert_eq!(reply(REQ, 486, "", None), reply(REQ, 486, "", None), "a retransmission gets the same reply");
        let other = REQ.replace("call-1", "call-2");
        assert_ne!(to_line(&reply(&other, 486, "", None)), to_line(&reply(REQ, 486, "", None)), "the tag follows the Call-ID");
        for existing in ["To: <sip:bob@example.com>;tag=abc", "To: <sip:bob@example.com>;TAG=abc"] {
            let req = REQ.replace("To: <sip:bob@example.com>", existing);
            assert_eq!(to_line(&reply(&req, 200, "", None)), existing, "an existing tag is kept");
        }
        let compact = REQ.replace("To: <sip:bob@example.com>", "t: <sip:bob@example.com>");
        assert_eq!(to_line(&reply(&compact, 200, "", None)), format!("t: <sip:bob@example.com>;tag={}", tag("call-1")), "compact form");
    }

    #[test]
    fn extra_headers_and_body() {
        let r = reply(REQ, 200, "X-A: 1\r\nX-B: 2\r\n", Some(("text/plain", b"hello")));
        assert!(r.ends_with("CSeq: 5 INVITE\r\nX-A: 1\r\nX-B: 2\r\nServer: ferrosip\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"), "{r}");
        let r = reply(REQ, 200, "", Some(("", b"xy")));
        assert!(r.ends_with("Server: ferrosip\r\nContent-Length: 2\r\n\r\nxy"), "no Content-Type when it is empty: {r}");
        let r = reply(REQ, 200, "", Some(("text/plain", b"")));
        assert!(r.ends_with("Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n"), "{r}");
        for gone in ["Record-Route", "Contact", "Max-Forwards", "application/sdp", "v=0"] {
            assert!(!reply(REQ, 200, "", None).contains(gone), "{gone} is not copied");
        }
    }

    #[test]
    fn build_reply_wrappers() {
        let arena = bumpalo::Bump::new();
        let mut m = Msg::parse(REQ.as_bytes(), &arena).unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        build_reply(&mut m, 403, "Forbidden", &mut a).unwrap();
        build_reply_with(&mut m, 403, "Forbidden", b"", &mut b).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with(b"SIP/2.0 403 Forbidden\r\n"));
    }

    #[test]
    fn trim_crlf_strips_only_line_ends() {
        let cases: &[(&[u8], &[u8])] = &[(b"a\r\n", b"a"), (b"a\n\r\n", b"a"), (b"a ", b"a "), (b"", b""), (b"\r\n", b"")];
        for (input, want) in cases {
            let mut v = input.to_vec();
            trim_crlf(&mut v);
            assert_eq!(&v[..], *want);
        }
    }
}
