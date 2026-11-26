//! One AI call: the SIP dialog we answer (UAS), its RTP stream, and the
//! provider WebSocket, run by one thread per call.

use crate::audio::Codec;
use crate::provider::{self, Action, Kind, Session, Setup};
use crate::wsc::{self, Event};
use crate::{Config, Inner};
use bumpalo::Bump;
use mod_txn::UacRequest;
use sip_core::net::Dest;
use sip_core::sync::lock;
use sip_parser::Msg;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

/// 20 ms of 8 kHz audio.
const FRAME: usize = 160;
const TICK: Duration = Duration::from_millis(20);
/// Most audio we queue for the caller (the provider sends faster than real time).
const MAX_QUEUE: usize = 8000 * 600;
const T1: Duration = Duration::from_millis(500);
const T2: Duration = Duration::from_secs(4);
/// Give up on the ACK for our 200 OK after 64·T1 (RFC 3261 §13.3.1.4).
const ACK_WAIT: Duration = T1.saturating_mul(64);

/// `t + d`; `t` itself in the (theoretical) case the clock can't represent it.
fn later(t: Instant, d: Duration) -> Instant {
    t.checked_add(d).unwrap_or(t)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Opening the provider session (100 Trying sent).
    Connecting,
    /// 200 OK sent, waiting for the ACK.
    Answered,
    Up,
    /// Over; kept a little while to absorb retransmissions.
    Done,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Phase::Connecting => "connecting",
            Phase::Answered => "answered",
            Phase::Up => "up",
            Phase::Done => "done",
        }
    }
}

pub enum Ev {
    Ack,
    Bye,
    /// A re-INVITE moved the caller's media.
    Remote(SocketAddr),
    Stop,
}

pub struct St {
    pub phase: Phase,
    /// Our last response to the INVITE, for retransmitted INVITEs.
    pub last_reply: Option<Vec<u8>>,
    pub remote: SocketAddr,
    pub ended: Option<Instant>,
    pub cancelled: bool,
    pub sdp_version: u64,
    pub reason: String,
}

pub struct Call {
    pub callid: String,
    pub tag: String,
    pub kind: Kind,
    /// The caller's From (with its tag) and our To (without ours).
    pub from_hdr: String,
    pub to_hdr: String,
    pub contact: String,
    /// Record-Route values, in order: our route set back to the caller.
    pub routes: Vec<String>,
    pub rr_lines: String,
    pub src: Dest,
    pub invite: Vec<u8>,
    pub codec: Codec,
    /// Our RTP address as advertised in SDP.
    pub local: SocketAddr,
    pub contact_uri: String,
    /// The system prompt and voice override this call was answered with.
    pub prompt: String,
    pub voice: String,
    pub session_id: u64,
    pub started: Instant,
    pub created: SystemTime,
    pub st: Mutex<St>,
    pub tx: Mutex<Sender<Ev>>,
    pub rtp_in: AtomicU64,
    pub rtp_out: AtomicU64,
    pub stopping: AtomicBool,
}

impl Call {
    pub fn lock(&self) -> MutexGuard<'_, St> {
        lock(&self.st)
    }

    pub fn send(&self, ev: Ev) {
        let _ = lock(&self.tx).send(ev);
    }

    pub fn sdp(&self, version: u64) -> String {
        crate::sdp::answer(self.local.ip(), self.local.port(), self.codec, self.session_id, version)
    }

    /// A response to the INVITE (To-tag added by the builder: the same one
    /// as `self.tag`).
    pub fn reply(&self, code: u16, reason: &str, extra: &str, body: Option<&str>) -> Option<Vec<u8>> {
        let arena = Bump::new();
        let mut msg = Msg::parse(&self.invite, &arena).ok()?;
        let mut out = Vec::new();
        sip_core::reply::build_reply_body(&mut msg, code, reason, extra.as_bytes(), body.map(|b| ("application/sdp", b.as_bytes())), &mut out).ok()?;
        Some(out)
    }

    pub fn answer_200(&self, version: u64) -> Option<Vec<u8>> {
        let extra = format!("{}Contact: <{}>\r\nAllow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n", self.rr_lines, self.contact_uri);
        self.reply(200, "OK", &extra, Some(&self.sdp(version)))
    }

    pub fn json(&self) -> serde_json::Value {
        let st = self.lock();
        let mut v = serde_json::json!({
            "call_id": self.callid,
            "provider": self.kind.name(),
            "state": st.phase.name(),
            "from": self.from_hdr,
            "to": self.to_hdr,
            "codec": self.codec.name(),
            "remote_rtp": st.remote.to_string(),
            "local_rtp": self.local.to_string(),
            "duration": self.started.elapsed().as_secs(),
            "started": self.created.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
            "rtp_in": self.rtp_in.load(Ordering::Relaxed),
            "rtp_out": self.rtp_out.load(Ordering::Relaxed),
            "prompt": self.prompt,
        });
        if !self.voice.is_empty()
            && let Some(o) = v.as_object_mut()
        {
            o.insert("voice".into(), serde_json::json!(self.voice));
        }
        v
    }
}

/// How a call ended, for `ai.recent` and the call-length histogram.
pub const OUTCOMES: [&str; 3] = ["answered", "failed", "cancelled"];

pub fn connect_hist(kind: Kind) -> &'static sip_core::stats::Histogram {
    static CONNECT: &[u64] = &[50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000];
    sip_core::stats::histogram("ai_connect_seconds", "Time to open the provider session (TCP, TLS, WebSocket)", &[("provider", kind.name())], CONNECT)
}

pub fn call_hist(kind: Kind, outcome: &str) -> &'static sip_core::stats::Histogram {
    sip_core::stats::histogram(
        "ai_call_seconds",
        "AI call length, from the INVITE to the end, by provider and outcome",
        &[("provider", kind.name()), ("outcome", outcome)],
        sip_core::stats::buckets::CALL,
    )
}

/// Why a call ended, and whether we still owe the caller a BYE.
enum End {
    CallerBye,
    Bye(String),
    /// Never answered (final non-2xx sent): nothing to hang up.
    Failed(&'static str, String),
}

/// Audio queued for the caller, with the provider item it belongs to.
struct Playback {
    samples: VecDeque<i16>,
    segments: VecDeque<(Option<String>, usize)>,
    item: Option<String>,
    item_played: usize,
}

impl Playback {
    fn push(&mut self, pcm: Vec<i16>, item: Option<String>) {
        let n = pcm.len().min(MAX_QUEUE.saturating_sub(self.samples.len()));
        if n == 0 {
            return;
        }
        self.samples.extend(pcm.into_iter().take(n));
        match self.segments.back_mut() {
            // Bounded by MAX_QUEUE.
            Some((i, len)) if *i == item => *len = len.saturating_add(n),
            _ => self.segments.push_back((item, n)),
        }
    }

    /// The next 20 ms (silence-padded) to send.
    fn frame(&mut self, out: &mut [i16; FRAME]) {
        let n = self.samples.len().min(FRAME);
        for (o, s) in out.iter_mut().zip(self.samples.drain(..n).chain(std::iter::repeat(0))) {
            *o = s;
        }
        let mut left = n;
        while left > 0 {
            let Some((item, len)) = self.segments.front_mut() else { break };
            if self.item != *item {
                self.item = item.clone();
                self.item_played = 0;
            }
            // take <= both, so the subtractions are exact.
            let take = left.min(*len);
            *len = len.saturating_sub(take);
            left = left.saturating_sub(take);
            self.item_played = self.item_played.saturating_add(take);
            if *len == 0 {
                self.segments.pop_front();
            }
        }
    }

    fn clear(&mut self) -> Option<(String, u64)> {
        let playing = !self.samples.is_empty();
        self.samples.clear();
        self.segments.clear();
        let heard = self.item.take().filter(|_| playing).map(|i| (i, self.item_played as u64 / 8));
        self.item_played = 0;
        heard
    }
}

pub fn run(inner: Arc<Inner>, call: Arc<Call>, rx: Receiver<Ev>, sock: UdpSocket) {
    let end = session(&inner, &call, &rx, &sock, &call.prompt, &call.voice);
    let (outcome, reason) = match &end {
        End::CallerBye => ("answered", "caller hung up".to_string()),
        End::Bye(r) => ("answered", r.clone()),
        End::Failed(o, r) => (*o, r.clone()),
    };
    {
        let mut st = call.lock();
        st.phase = Phase::Done;
        st.ended = Some(Instant::now());
        st.reason = reason.clone();
    }
    inner.active.fetch_sub(1, Ordering::Relaxed);
    if let End::Bye(_) = end {
        bye(&inner, &call);
    }
    let mut summary = call.json();
    if let Some(o) = summary.as_object_mut() {
        o.insert("state".into(), serde_json::json!("ended"));
        o.insert("outcome".into(), serde_json::json!(outcome));
        o.insert("reason".into(), serde_json::json!(reason));
        o.insert("ended".into(), serde_json::json!(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())));
    }
    inner.remember(summary);
    call_hist(call.kind, outcome).observe(call.started.elapsed());
    sip_core::elog!("ai: call {} ({}) ended after {}s: {reason}", call.callid, call.kind.name(), call.started.elapsed().as_secs());
}

/// Hang up: the caller sent nothing back yet, or we're done.
fn bye(inner: &Inner, call: &Call) {
    let dst = match call.routes.first() {
        Some(r) => sip_core::pvcore::dest_from_uri(crate::uri_of(r).as_bytes()),
        None => Some(call.src),
    };
    let mut headers = format!("From: {};tag={}\r\nTo: {}\r\n", call.to_hdr, call.tag, call.from_hdr);
    if !call.routes.is_empty() {
        headers.push_str(&format!("Route: {}\r\n", call.routes.join(",")));
    }
    let r = UacRequest { method: "BYE".into(), ruri: call.contact.clone(), dst, call_id: Some(call.callid.clone()), cseq: 1, headers, ..Default::default() };
    if let Err(e) = inner.tm.t_uac(r, None) {
        sip_core::elog!("ai: call {}: cannot send BYE: {e}", call.callid);
    }
}

fn send_sip(inner: &Inner, call: &Call, data: &[u8]) {
    if let Some(net) = inner.net.get()
        && let Err(e) = net.send(&call.src, data)
    {
        sip_core::elog!("ai: call {}: send to {:?} failed: {e}", call.callid, call.src.addr);
    }
}

/// Final non-2xx for the INVITE (the caller ACKs it; ai_dialog absorbs that).
fn fail(inner: &Inner, call: &Call, code: u16, reason: &str, why: &str) -> End {
    let warn = format!("Warning: 399 ferrosip \"{}\"\r\n", why.replace(['"', '\r', '\n'], " "));
    if let Some(r) = call.reply(code, reason, &warn, None) {
        send_sip(inner, call, &r);
        call.lock().last_reply = Some(r);
    }
    End::Failed("failed", why.to_string())
}

fn session(inner: &Inner, call: &Call, rx: &Receiver<Ev>, sock: &UdpSocket, prompt: &str, voice: &str) -> End {
    let cfg: &Config = &inner.cfg;
    let pcfg = match call.kind {
        Kind::OpenAi => &cfg.openai,
        Kind::Gemini => &cfg.gemini,
    };
    let (url, headers) = provider::target(call.kind, pcfg);
    let cancelled = || call.lock().cancelled || call.stopping.load(Ordering::Relaxed);
    let connecting = Instant::now();
    let mut ws = match wsc::Client::connect(&url, &headers, &cfg.tls, cfg.connect_timeout, &cancelled) {
        Ok(ws) => {
            connect_hist(call.kind).observe(connecting.elapsed());
            ws
        }
        Err(e) if call.lock().cancelled => {
            let _ = e;
            return fail_487(inner, call);
        }
        Err(e) => {
            // The URL carries Gemini's key: log the host only.
            let host = wsc::parse_url(&url).map(|u| u.host).unwrap_or_default();
            sip_core::elog!("ai: call {}: cannot reach {} ({host}): {e}", call.callid, call.kind.name());
            inner.failed.fetch_add(1, Ordering::Relaxed);
            return fail(inner, call, 503, "Service Unavailable", &format!("provider unavailable: {}", e.chars().take(120).collect::<String>()));
        }
    };
    let mut sess = Session::new(call.kind, call.codec);
    for m in sess.setup(pcfg, &Setup { prompt, voice, first_message: &cfg.first_message, end_call_tool: cfg.end_call_tool }) {
        if let Err(e) = ws.send_text(&m) {
            return fail(inner, call, 503, "Service Unavailable", &format!("provider session: {e}"));
        }
    }
    // Answer, unless a CANCEL won the race.
    {
        let mut st = call.lock();
        if st.cancelled {
            drop(st);
            return fail_487(inner, call);
        }
        let Some(ok) = call.answer_200(st.sdp_version) else { return End::Failed("failed", "cannot build the 200 OK".into()) };
        st.phase = Phase::Answered;
        st.last_reply = Some(ok.clone());
        drop(st);
        send_sip(inner, call, &ok);
    }
    let answered = Instant::now();
    let udp = matches!(call.src.proto, sip_core::net::Proto::Udp);
    let (mut rt_at, mut rt_every) = (later(answered, T1), T1);
    let mut acked = false;

    let mut seed = [0u8; 10];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed);
    let mut rtp = crate::rtp::Sender::new(seed);
    let mut remote = call.lock().remote;
    let mut latched = false;
    let mut play = Playback { samples: VecDeque::new(), segments: VecDeque::new(), item: None, item_played: 0 };
    let mut hangup_at: Option<Instant> = None;
    let mut last_rtp = Instant::now();
    let mut next_tick = Instant::now();
    let (mut buf, mut pkt, mut events, mut actions) = (vec![0u8; 2048], Vec::with_capacity(200), Vec::new(), Vec::new());
    let mut frame = [0i16; FRAME];

    loop {
        let now = Instant::now();
        while let Ok(ev) = rx.try_recv() {
            match ev {
                Ev::Ack => {
                    if !acked {
                        acked = true;
                        call.lock().phase = Phase::Up;
                    }
                }
                Ev::Bye => return End::CallerBye,
                Ev::Remote(a) => {
                    remote = a;
                    latched = false;
                }
                Ev::Stop => return End::Bye("shutting down".into()),
            }
        }
        if !acked {
            if now.duration_since(answered) > ACK_WAIT {
                return End::Bye("no ACK for 200 OK".into());
            }
            if udp && now >= rt_at {
                if let Some(r) = call.lock().last_reply.clone() {
                    send_sip(inner, call, &r);
                }
                rt_every = rt_every.saturating_mul(2).min(T2);
                rt_at = later(now, rt_every);
            }
        }
        if now.duration_since(answered) > cfg.max_duration {
            return End::Bye("max_duration reached".into());
        }
        if now.duration_since(last_rtp) > cfg.rtp_timeout {
            return End::Bye("no RTP from the caller".into());
        }

        // Provider → caller (blocks a few ms when idle: the loop's pace).
        events.clear();
        ws.poll(&mut events);
        for e in events.drain(..) {
            match e {
                Event::Closed(why) => return End::Bye(format!("AI session closed: {why}")),
                Event::Message(m) => {
                    actions.clear();
                    sess.on_message(&m, &mut actions);
                    for a in actions.drain(..) {
                        match a {
                            Action::Play(pcm, item) => play.push(pcm, item),
                            Action::Interrupt => {
                                if let Some((item, ms)) = play.clear()
                                    && let Some(t) = sess.truncate(&item, ms)
                                {
                                    let _ = ws.send_text(&t);
                                }
                            }
                            Action::Hangup => {
                                hangup_at.get_or_insert(now);
                            }
                            Action::Send(m) => {
                                if let Err(e) = ws.send_text(&m) {
                                    return End::Bye(format!("AI session: {e}"));
                                }
                            }
                            Action::Ready => {}
                            Action::Log(l) => sip_core::elog!("ai: call {}: {l}", call.callid),
                        }
                    }
                }
            }
        }

        // Caller → provider.
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let Some((pt, _, payload)) = buf.get(..n).and_then(crate::rtp::parse) else { continue };
                    if pt != call.codec.pt() {
                        continue; // telephone-event, comfort noise
                    }
                    // Symmetric RTP: answer where the caller really sends
                    // from (NAT), once per offer.
                    if !latched && cfg.rtp_latch {
                        remote = from;
                        latched = true;
                        call.lock().remote = from;
                    } else if from != remote {
                        continue;
                    }
                    last_rtp = Instant::now();
                    call.rtp_in.fetch_add(1, Ordering::Relaxed);
                    if let Some(m) = sess.audio(payload)
                        && let Err(e) = ws.send_text(&m)
                    {
                        return End::Bye(format!("AI session: {e}"));
                    }
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                Err(_) => break, // ICMP port unreachable and the like
            }
        }

        // Our RTP, every 20 ms (silence when the AI is quiet: keeps NATs open).
        let now = Instant::now();
        if now.duration_since(next_tick) > TICK.saturating_mul(10) {
            next_tick = now; // stalled: don't burst to catch up
        }
        while now >= next_tick {
            play.frame(&mut frame);
            let payload: Vec<u8> = frame.iter().map(|&s| call.codec.encode(s)).collect();
            rtp.packet(call.codec.pt(), &payload, &mut pkt);
            if sock.send_to(&pkt, remote).is_ok() {
                call.rtp_out.fetch_add(1, Ordering::Relaxed);
            }
            let Some(t) = next_tick.checked_add(TICK) else { break };
            next_tick = t;
        }
        if let Some(at) = hangup_at
            && (play.samples.is_empty() && now.duration_since(at) > Duration::from_millis(600) || now.duration_since(at) > Duration::from_secs(20))
        {
            return End::Bye("the AI ended the call".into());
        }
    }
}

fn fail_487(inner: &Inner, call: &Call) -> End {
    if let Some(r) = call.reply(487, "Request Terminated", "", None) {
        send_sip(inner, call, &r);
        call.lock().last_reply = Some(r);
    }
    End::Failed("cancelled", "cancelled by the caller".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn playback_tracks_items() {
        let mut p = Playback { samples: VecDeque::new(), segments: VecDeque::new(), item: None, item_played: 0 };
        p.push(vec![1; 200], Some("a".into()));
        p.push(vec![2; 200], Some("b".into()));
        let mut f = [0; FRAME];
        p.frame(&mut f);
        p.frame(&mut f);
        assert_eq!(&f[..40], &[1; 40]);
        assert_eq!(&f[40..], &[2; 120]);
        assert_eq!((p.item.as_deref(), p.item_played), (Some("b"), 120));
        p.frame(&mut f);
        assert_eq!(&f[80..], &[0; 80], "padded with silence");
        assert_eq!(p.clear(), None, "nothing left playing");
        p.push(vec![3; 800], Some("c".into()));
        p.frame(&mut f);
        assert_eq!(p.clear(), Some(("c".into(), 20)));
        assert!(p.samples.is_empty());
    }

    fn playback() -> Playback {
        Playback { samples: VecDeque::new(), segments: VecDeque::new(), item: None, item_played: 0 }
    }

    #[test]
    fn playback_queue_is_bounded() {
        let mut p = playback();
        p.push(vec![1; MAX_QUEUE - 10], Some("a".into()));
        p.push(vec![2; 100], Some("b".into()));
        assert_eq!(p.samples.len(), MAX_QUEUE);
        assert_eq!(p.segments, [(Some("a".to_string()), MAX_QUEUE - 10), (Some("b".to_string()), 10)]);
        p.push(vec![3; 5], Some("c".into()));
        assert_eq!(p.segments.len(), 2, "a full queue takes nothing");
        p.push(Vec::new(), Some("d".into()));
        assert_eq!(p.segments.len(), 2, "an empty chunk adds no segment");
    }

    #[test]
    fn playback_merges_chunks_of_one_item_and_counts_heard_ms() {
        let mut p = playback();
        p.push(vec![1; 100], Some("a".into()));
        p.push(vec![1; 100], Some("a".into()));
        p.push(vec![1; 100], None);
        assert_eq!(p.segments, [(Some("a".to_string()), 200), (None, 100)]);
        let mut f = [0; FRAME];
        p.frame(&mut f);
        assert_eq!((p.item.as_deref(), p.item_played), (Some("a"), 160));
        p.frame(&mut f);
        assert_eq!((p.item.as_deref(), p.item_played), (None, 100), "40 of a, then the 100 of the unnamed item");
        assert_eq!(p.clear(), None, "an unnamed item can't be truncated");
        // 8 samples are 1 ms; partial ms round down.
        let mut p = playback();
        p.push(vec![1; 400], Some("x".into()));
        p.frame(&mut f);
        p.frame(&mut f);
        assert_eq!(p.clear(), Some(("x".into(), 40)));
        assert_eq!((p.item.clone(), p.item_played, p.samples.len(), p.segments.len()), (None, 0, 0, 0));
        assert_eq!(p.clear(), None, "a second clear reports nothing");
        // Nothing played yet: the item hasn't started.
        let mut p = playback();
        p.push(vec![1; 10], Some("y".into()));
        assert_eq!(p.clear(), None);
    }

    #[test]
    fn empty_playback_sends_silence() {
        let mut p = playback();
        let mut f = [7; FRAME];
        p.frame(&mut f);
        assert_eq!(f, [0; FRAME]);
        assert_eq!((p.item.clone(), p.item_played), (None, 0));
    }

    #[test]
    fn phases_and_timers() {
        let names: Vec<&str> = [Phase::Connecting, Phase::Answered, Phase::Up, Phase::Done].iter().map(|p| p.name()).collect();
        assert_eq!(names, ["connecting", "answered", "up", "done"]);
        assert_eq!(ACK_WAIT, Duration::from_secs(32), "64·T1 (RFC 3261 §13.3.1.4)");
        assert_eq!(FRAME, 160, "20 ms at 8 kHz");
        // 200 OK retransmissions: T1, doubling, capped at T2.
        let mut every = T1;
        let mut gaps = Vec::new();
        for _ in 0..6 {
            gaps.push(every.as_millis());
            every = every.saturating_mul(2).min(T2);
        }
        assert_eq!(gaps, [500, 1000, 2000, 4000, 4000, 4000]);
        let t = Instant::now();
        assert_eq!(later(t, Duration::from_secs(1)).duration_since(t), Duration::from_secs(1));
        assert_eq!(later(t, Duration::MAX), t, "an unrepresentable time stays at t");
        assert_eq!(OUTCOMES, ["answered", "failed", "cancelled"]);
    }

    fn test_call() -> Call {
        let invite = "INVITE sip:ai@x SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.5:5060;branch=z9hG4bK1\r\nFrom: <sip:a@x>;tag=f1\r\nTo: <sip:ai@x>\r\n\
                      Call-ID: abc@h\r\nCSeq: 1 INVITE\r\nContact: <sip:a@192.0.2.5>\r\nContent-Length: 0\r\n\r\n";
        let (tx, _rx) = std::sync::mpsc::channel();
        Call {
            callid: "abc@h".into(),
            tag: format!("{:016x}", sip_core::shm::fx_hash(b"abc@h")),
            kind: Kind::OpenAi,
            from_hdr: "<sip:a@x>;tag=f1".into(),
            to_hdr: "<sip:ai@x>".into(),
            contact: "sip:a@192.0.2.5".into(),
            routes: Vec::new(),
            rr_lines: "Record-Route: <sip:p1;lr>\r\n".into(),
            src: Dest::new(sip_core::net::Proto::Udp, "192.0.2.5:5060".parse().unwrap()),
            invite: invite.as_bytes().to_vec(),
            codec: Codec::Pcma,
            local: "192.0.2.1:30000".parse().unwrap(),
            contact_uri: "sip:ai@192.0.2.1:5060".into(),
            prompt: "P".into(),
            voice: String::new(),
            session_id: 42,
            started: Instant::now(),
            created: SystemTime::UNIX_EPOCH,
            st: Mutex::new(St {
                phase: Phase::Connecting,
                last_reply: None,
                remote: "192.0.2.5:4000".parse().unwrap(),
                ended: None,
                cancelled: false,
                sdp_version: 1,
                reason: String::new(),
            }),
            tx: Mutex::new(tx),
            rtp_in: AtomicU64::new(0),
            rtp_out: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
        }
    }

    #[test]
    fn the_200_ok_carries_our_tag_contact_and_sdp() {
        let c = test_call();
        let ok = String::from_utf8(c.answer_200(3).unwrap()).unwrap();
        assert!(ok.starts_with("SIP/2.0 200 OK\r\n"), "{ok}");
        assert!(ok.contains(&format!("To: <sip:ai@x>;tag={}\r\n", c.tag)), "the reply builder's To-tag is the call's tag: {ok}");
        assert!(ok.contains("Record-Route: <sip:p1;lr>\r\nContact: <sip:ai@192.0.2.1:5060>\r\nAllow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n"), "{ok}");
        assert!(ok.contains("Content-Type: application/sdp\r\n"), "{ok}");
        assert!(ok.ends_with(&c.sdp(3)), "{ok}");
        assert!(c.sdp(3).contains("o=ferrosip 42 3 IN IP4 192.0.2.1\r\n"));
        let busy = String::from_utf8(c.reply(487, "Request Terminated", "", None).unwrap()).unwrap();
        assert!(busy.starts_with("SIP/2.0 487 Request Terminated\r\n") && busy.ends_with("Content-Length: 0\r\n\r\n"), "{busy}");
    }

    #[test]
    fn call_json_shape() {
        let c = test_call();
        let v = c.json();
        assert_eq!(v["state"], "connecting");
        assert_eq!((v["provider"].as_str(), v["codec"].as_str(), v["started"].as_u64()), (Some("openai"), Some("PCMA"), Some(0)));
        assert_eq!((v["remote_rtp"].as_str(), v["local_rtp"].as_str()), (Some("192.0.2.5:4000"), Some("192.0.2.1:30000")));
        assert!(v.get("voice").is_none(), "no voice override: no field");
        c.lock().phase = Phase::Up;
        assert_eq!(c.json()["state"], "up");
    }
}
