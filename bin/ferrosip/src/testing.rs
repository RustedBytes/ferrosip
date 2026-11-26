//! `ferrosip test`: routing tests (`test "name" { … }` in .fsr) run
//! in-process with the real modules and a network that only records what
//! is sent. No sockets, no database.
//!
//! Each test runs in a child process (`--run-test N`): modules keep
//! process-wide state, so tests can't see each other's. The child compiles
//! the routing with the test's mocks in place, then runs `route[test__N]`:
//! - `send(text)` passes a SIP message to the routing, as received from
//!   `from` (missing Via/From/To/Call-ID/CSeq/Max-Forwards are filled in);
//! - `answer(code)` replies to the last request the routing relayed, as its
//!   destination would (tm sees a real reply: `await` resumes);
//! - `$fsrtest(code|reason|relays|uri.N|dest.N|calls.F)` describe what the
//!   routing sent since the last `send`;
//! - `assert` failures are collected and printed; the exit code says
//!   whether the test passed.

use sip_core::module::DynStr;
use sip_core::pv::{PvSpec, Val};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Dest, Handler, Lumps, Outbound, Proto, Registry};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Records every message instead of sending it.
#[derive(Default)]
pub struct TestNet {
    sent: Mutex<Vec<(Dest, Vec<u8>)>>,
}

impl Outbound for TestNet {
    fn send(&self, dst: &Dest, data: &[u8]) -> std::io::Result<()> {
        lock(&self.sent).push((*dst, data.to_vec()));
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        Some(SocketAddr::from(([127, 0, 0, 1], 5060)))
    }
}

pub struct Harness {
    pub net: Arc<TestNet>,
    handler: OnceLock<Arc<dyn Handler>>,
    /// Where the current `send`'s messages start in `net.sent`.
    mark: AtomicUsize,
    seq: AtomicUsize,
    failures: Mutex<Vec<String>>,
    calls: Mutex<HashMap<String, usize>>,
    asserts: AtomicUsize,
}

/// First line, method (or "" for a reply) and status code of a message.
fn first_line(m: &[u8]) -> &str {
    let line = m.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or_default();
    std::str::from_utf8(line).unwrap_or("")
}

fn is_reply(m: &[u8]) -> bool {
    m.starts_with(b"SIP/2.0 ")
}

fn code(m: &[u8]) -> i64 {
    first_line(m).split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

fn header<'a>(m: &'a str, name: &str) -> Vec<&'a str> {
    m.split("\r\n").take_while(|l| !l.is_empty()).filter(|l| l.split_once(':').is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name))).collect()
}

impl Harness {
    pub fn new() -> Arc<Self> {
        Arc::new(Harness {
            net: Arc::default(),
            handler: OnceLock::new(),
            mark: AtomicUsize::new(0),
            seq: AtomicUsize::new(0),
            failures: Mutex::default(),
            calls: Mutex::default(),
            asserts: AtomicUsize::new(0),
        })
    }

    pub fn set_handler(&self, h: Arc<dyn Handler>) {
        let _ = self.handler.set(h);
    }

    /// Run one message through the routing (a request as from `src`, or a
    /// reply from a relay destination).
    fn deliver(&self, raw: &[u8], src: Dest) -> Result<(), String> {
        let Some(h) = self.handler.get() else { return Err("the routing isn't ready".into()) };
        let arena = bumpalo::Bump::new();
        let mut msg = sip_parser::Msg::parse(raw, &arena).map_err(|e| format!("not a SIP message ({e:?}):\n{}", String::from_utf8_lossy(raw)))?;
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut msg, &mut lumps, &mut out, &*self.net, None, src, 0);
        h.handle(&mut ctx);
        Ok(())
    }

    /// A test's message text as SIP: CRLF lines without the indentation,
    /// and the headers a test needn't spell out.
    fn complete(&self, text: &str, from: SocketAddr) -> Result<Vec<u8>, String> {
        let n = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let text = text.trim_matches(|c| c == '\n' || c == '\r');
        let (head, body) = match text.find("\n\n").or_else(|| text.find("\r\n\r\n")) {
            Some(i) => {
                let (head, body) = text.split_at(i);
                (head, body.trim_start_matches(['\r', '\n']))
            }
            None => (text, ""),
        };
        let mut lines: Vec<String> = head.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        let Some(first) = lines.first().cloned() else { return Err("send(): an empty message".into()) };
        let mut w = first.split_whitespace();
        let (method, ruri) = (w.next().unwrap_or(""), w.next().unwrap_or(""));
        if method.is_empty() || ruri.is_empty() {
            return Err(format!("send(): {first:?} is not a request line (METHOD uri)"));
        }
        if w.next().is_none()
            && let Some(l) = lines.first_mut()
        {
            *l = format!("{first} SIP/2.0");
        }
        // By full or compact name (`v:`, `f:`, `t:`, `i:`, `l:`).
        let has = |lines: &[String], h: &str| {
            let compact = match h {
                "Via" => "v",
                "From" => "f",
                "To" => "t",
                "Call-ID" => "i",
                "Content-Length" => "l",
                _ => h,
            };
            lines.iter().skip(1).any(|l| l.split_once(':').is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(h) || n.trim().eq_ignore_ascii_case(compact)))
        };
        let body = body.replace("\r\n", "\n").replace('\n', "\r\n");
        let fill = [
            ("Via", format!("Via: SIP/2.0/UDP {from};branch=z9hG4bKtest{n}")),
            ("Max-Forwards", "Max-Forwards: 70".to_string()),
            ("From", format!("From: <sip:test@{}>;tag=t{n}", from.ip())),
            ("To", format!("To: <{ruri}>")),
            ("Call-ID", format!("Call-ID: test-{n}")),
            ("CSeq", format!("CSeq: 1 {method}")),
        ];
        let mut extra: Vec<String> = fill.into_iter().filter(|(h, _)| !has(&lines, h)).map(|(_, l)| l).collect();
        if !has(&lines, "Content-Length") {
            extra.push(format!("Content-Length: {}", body.len()));
        }
        lines.splice(1..1, extra);
        let mut m = lines.join("\r\n");
        m.push_str("\r\n\r\n");
        m.push_str(&body);
        Ok(m.into_bytes())
    }

    /// What was sent since the last `send` (requests other than ACK/CANCEL,
    /// and replies).
    fn since(&self) -> Vec<(Dest, Vec<u8>)> {
        let sent = lock(&self.net.sent);
        sent.get(self.mark.load(Ordering::Relaxed)..).unwrap_or_default().to_vec()
    }

    /// Requests relayed since the last `send`, one per branch: UDP
    /// retransmissions (same top Via) aren't counted again.
    fn relays(&self) -> Vec<(Dest, Vec<u8>)> {
        let mut seen = std::collections::HashSet::new();
        self.since()
            .into_iter()
            .filter(|(_, m)| !is_reply(m) && !m.starts_with(b"ACK ") && !m.starts_with(b"CANCEL "))
            .filter(|(_, m)| seen.insert(top_via(m).to_vec()))
            .collect()
    }

    /// The final reply sent upstream (None: none yet).
    fn reply(&self) -> Option<Vec<u8>> {
        self.since().into_iter().map(|(_, m)| m).rev().find(|m| is_reply(m) && code(m) >= 200)
    }

    fn fail(&self, what: String) {
        lock(&self.failures).push(what);
    }

    /// `(asserts run, failures)`.
    pub fn result(&self) -> (usize, Vec<String>) {
        (self.asserts.load(Ordering::Relaxed), lock(&self.failures).clone())
    }
}

/// The test functions and `$fsrtest`, and the mocks of this test.
pub fn register(reg: &mut Registry, h: &Arc<Harness>, mocks: &[(String, i64)]) -> Result<(), String> {
    let hs = h.clone();
    reg.export(
        "fsr_test",
        "fsr_test_send",
        |a: &[Arg]| match a {
            [text, from, ..] => Ok((text.dyn_str()?, from.dyn_str()?)),
            _ => Err("fsr_test_send(text, from)".into()),
        },
        move |ctx: &mut Ctx, (text, from): &(DynStr, DynStr)| {
            let (text, from) = (text.eval(ctx).into_owned(), from.eval(ctx).into_owned());
            let addr: SocketAddr = match from.parse() {
                Ok(a) => a,
                Err(_) => {
                    hs.fail(format!("send(): from {from:?} is not ip:port"));
                    return -1;
                }
            };
            let raw = match hs.complete(&text, addr) {
                Ok(r) => r,
                Err(e) => {
                    hs.fail(e);
                    return -1;
                }
            };
            hs.mark.store(lock(&hs.net.sent).len(), Ordering::Relaxed);
            if let Err(e) = hs.deliver(&raw, Dest::new(Proto::Udp, addr)) {
                hs.fail(e);
            }
            1
        },
    );
    let hs = h.clone();
    reg.export(
        "fsr_test",
        "fsr_test_answer",
        |a: &[Arg]| match a {
            [code, reason, ..] => Ok((code.dyn_int()?, reason.dyn_str()?)),
            _ => Err("fsr_test_answer(code, reason)".into()),
        },
        move |ctx: &mut Ctx, (code, reason): &(sip_core::module::DynInt, DynStr)| {
            let (code, reason) = (code.eval(ctx).unwrap_or(500), reason.eval(ctx).into_owned());
            // The latest request the routing relayed, from anywhere in the test.
            let last = lock(&hs.net.sent).iter().rev().find(|(_, m)| !is_reply(m) && !m.starts_with(b"ACK ")).cloned();
            let Some((dst, req)) = last else {
                hs.fail(format!("answer({code}): nothing was relayed to answer"));
                return -1;
            };
            let req = String::from_utf8_lossy(&req).into_owned();
            let n = hs.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            let mut out = format!("SIP/2.0 {code} {reason}\r\n");
            for h in ["Via", "From", "To", "Call-ID", "CSeq"] {
                for l in header(&req, h) {
                    let l = if h == "To" && !l.contains(";tag=") && code > 100 { format!("{l};tag=a{n}") } else { l.to_string() };
                    out.push_str(&l);
                    out.push_str("\r\n");
                }
            }
            out.push_str("Content-Length: 0\r\n\r\n");
            if let Err(e) = hs.deliver(out.as_bytes(), dst) {
                hs.fail(e);
            }
            1
        },
    );
    reg.export(
        "fsr_test",
        "fsr_test_wait",
        |a: &[Arg]| a.first().ok_or("fsr_test_wait(ms)")?.dyn_int(),
        |ctx: &mut Ctx, ms: &sip_core::module::DynInt| {
            std::thread::sleep(std::time::Duration::from_millis(u64::try_from(ms.eval(ctx).unwrap_or(0)).unwrap_or(0)));
            1
        },
    );
    let hs = h.clone();
    reg.export(
        "fsr_test",
        "fsr_test_assert",
        |a: &[Arg]| match a {
            [v, what, ..] => Ok((v.dyn_int()?, what.dyn_str()?)),
            _ => Err("fsr_test_assert(value, what)".into()),
        },
        move |ctx: &mut Ctx, (v, what): &(sip_core::module::DynInt, DynStr)| {
            hs.asserts.fetch_add(1, Ordering::Relaxed);
            if v.eval(ctx).unwrap_or(0) <= 0 {
                let what = what.eval(ctx).into_owned();
                hs.fail(match what.split_once("): ") {
                    Some((a, b)) => format!("{a}) failed: {b}"),
                    None => format!("{what} failed"),
                });
            }
            1
        },
    );
    let hs = h.clone();
    reg.pv(
        "fsrtest",
        PvSpec::ro(move |_, p| {
            let (what, n) = p.name.split_once('.').map_or((p.name.as_str(), ""), |(a, b)| (a, b));
            match what {
                "code" => hs.reply().map_or(Val::Int(0), |m| Val::Int(code(&m))),
                "reason" => hs.reply().map_or(Val::str(""), |m| Val::str(first_line(&m).splitn(3, ' ').nth(2).unwrap_or(""))),
                "relays" => Val::Int(i64::try_from(hs.relays().len()).unwrap_or(i64::MAX)),
                "uri" | "dest" => {
                    let r = hs.relays();
                    let i: usize = n.parse().unwrap_or(0);
                    // 1-based; 0: the latest.
                    let m = match i.checked_sub(1) {
                        None => r.last(),
                        Some(k) => r.get(k),
                    };
                    match (m, what) {
                        (Some((_, m)), "uri") => Val::str(first_line(m).split(' ').nth(1).unwrap_or("")),
                        (Some((d, _)), _) => Val::str(d.addr.to_string()),
                        (None, _) => Val::str(""),
                    }
                }
                "calls" => Val::Int(lock(&hs.calls).get(n).map_or(0, |&c| i64::try_from(c).unwrap_or(i64::MAX))),
                _ => Val::Null,
            }
        })
        .with_param(),
    );
    for (f, rc) in mocks {
        // A route return code is a C int: out of range saturates, keeping the sign.
        let rc = i32::try_from(*rc).unwrap_or(if *rc < 0 { i32::MIN } else { i32::MAX });
        let (hs, name) = (h.clone(), f.clone());
        let func: sip_core::ExportFn = Arc::new(move |_: &mut Ctx<'_, '_>, _: &(dyn std::any::Any + Send + Sync)| {
            let mut calls = lock(&hs.calls);
            let n = calls.entry(name.clone()).or_default();
            *n = n.saturating_add(1);
            rc
        });
        if !reg.override_func(f, func) {
            return Err(format!("can't mock {f}(): its module isn't loaded (the routing doesn't use it)"));
        }
    }
    Ok(())
}

/// The first Via header line of a message (its branch tells a branch apart
/// from a retransmission of it).
fn top_via(m: &[u8]) -> &[u8] {
    m.split(|&c| c == b'\n').find(|l| l.len() > 4 && (l.get(..4).is_some_and(|p| p.eq_ignore_ascii_case(b"via:")) || l.starts_with(b"v:"))).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(text: &str) -> String {
        let h = Harness::new();
        String::from_utf8(h.complete(text, "192.0.2.1:5070".parse().unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn a_request_line_alone_gets_every_header() {
        assert_eq!(
            complete("INVITE sip:bob@example.com"),
            "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5070;branch=z9hG4bKtest1\r\nMax-Forwards: 70\r\n\
             From: <sip:test@192.0.2.1>;tag=t1\r\nTo: <sip:bob@example.com>\r\nCall-ID: test-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn given_headers_are_kept_and_not_repeated() {
        let m = complete("\n  OPTIONS sip:x SIP/2.0\n  Max-Forwards: 0\n  f: <sip:a@b>;tag=1\n  i: abc\n  CSEQ: 7 OPTIONS\n");
        assert_eq!(
            m,
            "OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5070;branch=z9hG4bKtest1\r\nTo: <sip:x>\r\nContent-Length: 0\r\n\
             Max-Forwards: 0\r\nf: <sip:a@b>;tag=1\r\ni: abc\r\nCSEQ: 7 OPTIONS\r\n\r\n"
        );
    }

    #[test]
    fn the_body_is_crlf_and_counted() {
        for text in ["MESSAGE sip:x\nContent-Type: text/plain\n\nhello\nworld", "MESSAGE sip:x\r\nContent-Type: text/plain\r\n\r\nhello\r\nworld"] {
            let m = complete(text);
            assert!(m.contains("\r\nContent-Length: 12\r\n") && m.ends_with("\r\n\r\nhello\r\nworld"), "{text:?}: {m:?}");
        }
    }

    #[test]
    fn bad_requests_are_refused() {
        let h = Harness::new();
        let from: SocketAddr = "192.0.2.1:5070".parse().unwrap();
        assert_eq!(h.complete("\n\n", from).unwrap_err(), "send(): an empty message");
        assert!(h.complete("INVITE", from).unwrap_err().contains("is not a request line"));
    }

    #[test]
    fn message_helpers() {
        let m = b"SIP/2.0 486 Busy Here\r\nVia: SIP/2.0/UDP a;branch=1\r\nvia: SIP/2.0/UDP b\r\nTo: <sip:x>\r\n\r\nVia: in the body";
        assert_eq!(first_line(m), "SIP/2.0 486 Busy Here");
        assert!(is_reply(m) && !is_reply(b"INVITE sip:x SIP/2.0"));
        assert_eq!(code(m), 486);
        assert_eq!(code(b"INVITE sip:x SIP/2.0"), 0);
        let text = String::from_utf8_lossy(m);
        assert_eq!(header(&text, "VIA"), ["Via: SIP/2.0/UDP a;branch=1", "via: SIP/2.0/UDP b"], "headers only, any case");
        assert_eq!(top_via(m), b"Via: SIP/2.0/UDP a;branch=1\r");
        assert_eq!(top_via(b"INVITE x SIP/2.0\r\nv: SIP/2.0/UDP c\r\n"), b"v: SIP/2.0/UDP c\r");
    }

    #[test]
    fn relays_and_the_final_reply_since_the_last_send() {
        let h = Harness::new();
        let d = Dest::new(Proto::Udp, "10.0.0.1:5060".parse().unwrap());
        let push = |m: &str| lock(&h.net.sent).push((d, m.as_bytes().to_vec()));
        push("INVITE sip:old SIP/2.0\r\nVia: SIP/2.0/UDP p;branch=0\r\n\r\n");
        h.mark.store(1, Ordering::Relaxed);
        push("SIP/2.0 100 Trying\r\n\r\n");
        push("INVITE sip:a SIP/2.0\r\nVia: SIP/2.0/UDP p;branch=1\r\n\r\n");
        push("INVITE sip:a SIP/2.0\r\nVia: SIP/2.0/UDP p;branch=1\r\n\r\n");
        push("CANCEL sip:a SIP/2.0\r\nVia: SIP/2.0/UDP p;branch=1\r\n\r\n");
        push("INVITE sip:b SIP/2.0\r\nVia: SIP/2.0/UDP p;branch=2\r\n\r\n");
        push("ACK sip:b SIP/2.0\r\nVia: SIP/2.0/UDP p;branch=2\r\n\r\n");
        assert_eq!(h.reply(), None, "a 100 is not a final reply");
        push("SIP/2.0 486 Busy Here\r\n\r\n");
        let uris: Vec<String> = h.relays().iter().map(|(_, m)| first_line(m).to_string()).collect();
        assert_eq!(uris, ["INVITE sip:a SIP/2.0", "INVITE sip:b SIP/2.0"], "retransmissions, ACK and CANCEL don't count");
        assert_eq!(h.reply().map(|m| code(&m)), Some(486));
    }
}
