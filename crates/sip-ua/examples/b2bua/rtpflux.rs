//! A [`MediaAdapter`] that anchors media in rtpflux over its ng control
//! protocol (`offer` / `answer` / `delete`, the rtpengine protocol).
//!
//! The two SIP legs of a call have independent Call-IDs, so the media
//! session gets ids of its own: `call-id = b2b-<call>` and one tag per
//! leg (`leg-<id>`). A re-offer from either leg names the other leg's tag
//! (`to-tag`), and rtpflux swaps the roles when the answerer re-offers.
//! Calls are blocking UDP round trips: this runs on the application's
//! thread, never on the SIP engine's.

use crate::bridge::MediaAdapter;
use mod_media::bencode::B;
use sip_ua::UaLegId;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

struct Session {
    /// The leg whose offer is waiting for an answer.
    offerer: Option<UaLegId>,
    /// Tags known to the relay: the first offerer and the first answerer.
    legs: Vec<UaLegId>,
}

pub struct Rtpflux {
    sock: UdpSocket,
    ng: SocketAddr,
    seq: u64,
    sessions: HashMap<u64, Session>,
}

fn tag(l: UaLegId) -> String {
    format!("leg-{}", l.0)
}

impl Rtpflux {
    pub fn new(ng: SocketAddr) -> std::io::Result<Self> {
        let sock = UdpSocket::bind(if ng.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
        sock.set_read_timeout(Some(Duration::from_millis(1_000)))?;
        Ok(Self { sock, ng, seq: 0, sessions: HashMap::new() })
    }

    /// One ng request; retried (same cookie) on a lost datagram.
    fn cmd(&mut self, items: Vec<(&str, B)>) -> Result<B, String> {
        self.seq = self.seq.wrapping_add(1);
        let cookie = format!("{}_{}", std::process::id(), self.seq);
        let dict = B::Dict(items.into_iter().map(|(k, v)| (k.as_bytes().to_vec(), v)).collect());
        let mut msg = format!("{cookie} ").into_bytes();
        dict.encode(&mut msg);
        let mut buf = vec![0u8; 65_535];
        for _ in 0..3 {
            self.sock.send_to(&msg, self.ng).map_err(|e| format!("ng send: {e}"))?;
            while let Ok(n) = self.sock.recv(&mut buf) {
                let reply = buf.get(..n).unwrap_or_default();
                let Some(rest) = reply.strip_prefix(cookie.as_bytes()).and_then(|r| r.strip_prefix(b" ")) else { continue };
                let (b, _) = B::decode(rest).ok_or("ng: undecodable reply")?;
                return match b.get("result").and_then(B::str) {
                    Some(b"ok" | b"pong") => Ok(b),
                    _ => Err(format!("ng: {}", b.get("error-reason").and_then(B::str).map(String::from_utf8_lossy).unwrap_or_default())),
                };
            }
        }
        Err("ng: no reply from rtpflux".into())
    }

    fn sdp_of(b: &B) -> Result<Vec<u8>, String> {
        b.get("sdp").and_then(B::str).map(<[u8]>::to_vec).ok_or_else(|| "ng: reply without sdp".into())
    }

    pub fn ping(&mut self) -> Result<(), String> {
        self.cmd(vec![("command", B::s("ping"))]).map(|_| ())
    }

    /// Call-IDs the relay has (for checks).
    #[allow(dead_code, reason = "used by tests/b2bua_rtpflux.rs")]
    pub fn list(&mut self) -> Result<Vec<String>, String> {
        let b = self.cmd(vec![("command", B::s("list"))])?;
        Ok(match b.get("calls") {
            Some(B::List(v)) => v.iter().filter_map(B::str).map(|s| String::from_utf8_lossy(s).into_owned()).collect(),
            _ => Vec::new(),
        })
    }
}

impl MediaAdapter for Rtpflux {
    fn offer(&mut self, call: u64, from: UaLegId, sdp: &[u8]) -> Result<Vec<u8>, String> {
        let s = self.sessions.entry(call).or_insert(Session { offerer: None, legs: Vec::new() });
        if !s.legs.contains(&from) {
            s.legs.push(from);
        }
        s.offerer = Some(from);
        let other = s.legs.iter().copied().find(|l| *l != from);
        let mut items = vec![("command", B::s("offer")), ("call-id", B::s(format!("b2b-{call}"))), ("from-tag", B::s(tag(from))), ("sdp", B::s(sdp))];
        if let Some(o) = other {
            items.push(("to-tag", B::s(tag(o))));
        }
        let r = self.cmd(items)?;
        Self::sdp_of(&r)
    }

    fn answer(&mut self, call: u64, from: UaLegId, sdp: &[u8]) -> Result<Vec<u8>, String> {
        let s = self.sessions.get_mut(&call).ok_or("answer without an offer")?;
        let offerer = s.offerer.take().ok_or("answer without an offer")?;
        if !s.legs.contains(&from) {
            s.legs.push(from);
        }
        let items = vec![
            ("command", B::s("answer")),
            ("call-id", B::s(format!("b2b-{call}"))),
            ("from-tag", B::s(tag(offerer))),
            ("to-tag", B::s(tag(from))),
            ("sdp", B::s(sdp)),
        ];
        let r = self.cmd(items)?;
        Self::sdp_of(&r)
    }

    fn release(&mut self, call: u64) {
        if self.sessions.remove(&call).is_some() {
            // Idempotent on the relay side too: an unknown call is only a warning.
            let _ = self.cmd(vec![("command", B::s("delete")), ("call-id", B::s(format!("b2b-{call}")))]);
        }
    }
}
