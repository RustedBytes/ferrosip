//! A crash-recoverable media B2BUA: sip-ua in durable mode (FileJournal)
//! for signalling, rtpflux's native API (`rtpflux-client-async`) for media.
//!
//! ```text
//! sip-ua-rtpflux --listen 127.0.0.1:5495 --dir /tmp/b2b --forward sip:bob@127.0.0.1:5497 \
//!                --media 127.0.0.1:2224 --token <tenant token>
//! ```
//!
//! An inbound call (leg A) gets an rtpflux endpoint answering its offer
//! and a second endpoint offering PCMU/PCMA for the outbound leg B, which
//! is originated under the operation key `b2b:<Call-ID>`. When B answers,
//! its answer is applied, the two endpoints are bridged and A is answered.
//! A BYE (or failure) on either side ends the other and destroys both
//! endpoints.
//!
//! Recovery. The SIP state is restored from the journal. The application's
//! own state (per call: A's leg, A's offer, B's answer, endpoint ids) is a
//! small file written (fsync, atomic rename) before each media or SIP
//! action that depends on it. Every media action is idempotent (relay
//! idempotency keys `<Call-ID>/a`, `/b`, `/bridge`; destroy of a destroyed
//! endpoint succeeds) and B's INVITE is a keyed command, so after a crash
//! the process repeats the steps of each call's current state: nothing is
//! created twice, no second INVITE is sent. A crash does not touch media:
//! the relay keeps bridging RTP while the process is down (a client that
//! disconnects destroys nothing).
//!
//! Output (stdout, one line each): `READY`, `RESTORED <leg>`, `EVENT <leg>
//! <seq> <kind>`, `BLEG <cid> <leg> replayed=<b>`, `BRIDGED <cid>`,
//! `ANSWERED <cid>`, `DESTROYED <cid>`, `MEDIA <error>`, `ENDPOINTS-CHANGED <cid>`
//! (a repeated create returned other endpoints: must not happen).

#![allow(clippy::print_stdout, reason = "a test tool")]

use rtpflux_client_async::{AttachBridgeRequest, Config, CreateEndpointRequest, DestroyEndpointRequest, MediaClient};
use serde_json::{Value, json};
use sip_ua::recovery::{FileJournal, RestoreOptions};
use sip_ua::*;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned()
}

fn need(name: &str) -> String {
    arg(name).unwrap_or_else(|| {
        eprintln!("missing {name}");
        std::process::exit(2)
    })
}

fn wall() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn say(line: &str) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{line}");
    let _ = o.flush();
}

/// One call's application state.
#[derive(Clone, Debug, Default)]
struct Rec {
    a_leg: u64,
    offer: String,
    b_answer: Option<String>,
    ep_a: Option<String>,
    ep_b: Option<String>,
}

struct App {
    file: PathBuf,
    recs: BTreeMap<String, Rec>,
    media: MediaClient,
    forward: String,
    from: String,
    start: Instant,
}

fn key(cid: &str) -> String {
    format!("b2b:{cid}")
}

impl App {
    fn now(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn load(file: &Path) -> BTreeMap<String, Rec> {
        let Ok(text) = std::fs::read_to_string(file) else { return BTreeMap::new() };
        let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&text) else { return BTreeMap::new() };
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        m.iter()
            .map(|(cid, v)| {
                let rec = Rec {
                    a_leg: v.get("a_leg").and_then(Value::as_u64).unwrap_or(0),
                    offer: s(v, "offer").unwrap_or_default(),
                    b_answer: s(v, "b_answer"),
                    ep_a: s(v, "ep_a"),
                    ep_b: s(v, "ep_b"),
                };
                (cid.clone(), rec)
            })
            .collect()
    }

    /// Durably (fsync + atomic rename): a crash leaves the old or the new file.
    fn save(&self) {
        let m: serde_json::Map<String, Value> = self
            .recs
            .iter()
            .map(|(cid, r)| (cid.clone(), json!({"a_leg": r.a_leg, "offer": r.offer, "b_answer": r.b_answer, "ep_a": r.ep_a, "ep_b": r.ep_b})))
            .collect();
        let tmp = self.file.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(Value::Object(m).to_string().as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.file)?;
            if let Some(d) = self.file.parent() {
                std::fs::File::open(d)?.sync_all()?;
            }
            Ok(())
        };
        if let Err(e) = write() {
            // The application's store failed: stop (fail closed), like the journal.
            say(&format!("HALT app state: {e}"));
            std::process::exit(3);
        }
    }

    /// Which call and side a leg is.
    fn call_of(&self, ua: &UaEngine, leg: UaLegId) -> Option<(String, bool)> {
        self.recs.iter().find_map(|(cid, r)| {
            if r.a_leg == leg.0 {
                Some((cid.clone(), true))
            } else if ua.op_outcome(&key(cid)).is_some_and(|o| o.leg == leg) {
                Some((cid.clone(), false))
            } else {
                None
            }
        })
    }

    /// Bring a call forward from whatever state it is in. Every step is
    /// idempotent, so this is both the normal path and the recovery path.
    async fn ensure(&mut self, ua: &mut UaEngine, cid: &str) {
        let Some(rec) = self.recs.get(cid).cloned() else { return };
        let mut a_req = CreateEndpointRequest::answering(rec.offer.clone());
        a_req.label = Some(format!("{cid}/a"));
        a_req.idempotency_key = Some(format!("{cid}/a"));
        let a = match self.media.create_endpoint(a_req).await {
            Ok(a) => a,
            Err(e) => return self.media_failed(ua, cid, &e.to_string()).await,
        };
        let mut b_req = CreateEndpointRequest::offering(["PCMU", "PCMA"]);
        b_req.label = Some(format!("{cid}/b"));
        b_req.idempotency_key = Some(format!("{cid}/b"));
        let b = match self.media.create_endpoint(b_req).await {
            Ok(b) => b,
            Err(e) => return self.media_failed(ua, cid, &e.to_string()).await,
        };
        if rec.ep_a.as_deref() != Some(&a.endpoint_id) || rec.ep_b.as_deref() != Some(&b.endpoint_id) {
            if rec.ep_a.is_some() || rec.ep_b.is_some() {
                // A repeated create must return the same endpoints (relay idempotency).
                say(&format!("ENDPOINTS-CHANGED {cid}"));
            }
            if let Some(r) = self.recs.get_mut(cid) {
                r.ep_a = Some(a.endpoint_id.clone());
                r.ep_b = Some(b.endpoint_id.clone());
            }
            self.save();
        }
        // Leg B: one INVITE for the call, whatever happens to this process.
        let o = OriginateRequest { request_uri: self.forward.clone(), from: self.from.clone(), sdp: Some(b.sdp.clone().into_bytes()), ..Default::default() };
        let now = self.now();
        if ua.op_outcome(&key(cid)).is_none() {
            match ua.submit_keyed(&key(cid), UaCommand::Originate(Box::new(o)), now) {
                Ok(k) => say(&format!("BLEG {cid} {} replayed={}", k.leg.0, k.replayed)),
                Err(e) => say(&format!("BLEG {cid} error {e}")),
            }
        }
        let Some(answer) = rec.b_answer else { return };
        // B answered: media first, then answer A.
        if let Err(e) = self
            .media
            .apply_answer(rtpflux_client_async::ApplyAnswerRequest {
                endpoint_id: b.endpoint_id.clone(),
                sdp: answer,
                expected_generation: None,
                options: None,
                deadline: None,
            })
            .await
        {
            // Already applied (a repeat after a restart) is fine.
            say(&format!("MEDIA apply_answer {e}"));
        }
        let mut br = AttachBridgeRequest::new(&a.endpoint_id, &b.endpoint_id);
        br.idempotency_key = Some(format!("{cid}/bridge"));
        if let Err(e) = self.media.attach_bridge(br).await {
            return self.media_failed(ua, cid, &e.to_string()).await;
        }
        say(&format!("BRIDGED {cid}"));
        let a_leg = UaLegId(rec.a_leg);
        if ua.snapshot(a_leg).is_some_and(|s| matches!(s.phase, Phase::Calling | Phase::Early)) {
            let now = self.now();
            match ua.submit(UaCommand::Accept(AcceptRequest { leg: a_leg, sdp: Some(a.sdp.into_bytes()), headers: vec![] }), now) {
                Ok(_) => say(&format!("ANSWERED {cid}")),
                Err(e) => say(&format!("ANSWER {cid} error {e}")),
            }
        }
    }

    async fn media_failed(&mut self, ua: &mut UaEngine, cid: &str, e: &str) {
        say(&format!("MEDIA {cid} {e}"));
        self.teardown(ua, cid).await;
    }

    /// End both legs and free the media (idempotent).
    async fn teardown(&mut self, ua: &mut UaEngine, cid: &str) {
        let Some(rec) = self.recs.get(cid).cloned() else { return };
        let now = self.now();
        let mut legs = vec![UaLegId(rec.a_leg)];
        legs.extend(ua.op_outcome(&key(cid)).map(|o| o.leg));
        for leg in legs {
            if ua.snapshot(leg).is_some() {
                let _ = ua.submit(UaCommand::Hangup(HangupRequest { leg, reason: None, code: Some(480) }), now);
            }
        }
        for ep in [rec.ep_a, rec.ep_b].into_iter().flatten() {
            if let Err(e) = self.media.destroy_endpoint(DestroyEndpointRequest::new(ep)).await {
                // Not destroyed: keep the record so a restart tries again.
                say(&format!("MEDIA destroy {e}"));
                return;
            }
        }
        self.recs.remove(cid);
        self.save();
        say(&format!("DESTROYED {cid}"));
    }

    async fn on_event(&mut self, ua: &mut UaEngine, e: &EventEnvelope) {
        match &e.event {
            UaEvent::IncomingInvite(i) => {
                let Some(offer) = i.sdp.as_ref().map(|s| String::from_utf8_lossy(s).into_owned()) else {
                    let now = self.now();
                    let _ = ua.submit(UaCommand::Reject(RejectRequest { leg: e.leg, code: 488, reason: None, headers: vec![] }), now);
                    return;
                };
                self.recs.insert(i.call_id.clone(), Rec { a_leg: e.leg.0, offer, ..Rec::default() });
                self.save();
                self.ensure(ua, &i.call_id).await;
            }
            UaEvent::Accepted(acc) => {
                if let Some((cid, false)) = self.call_of(ua, e.leg) {
                    if let Some(r) = self.recs.get_mut(&cid) {
                        r.b_answer = acc.sdp.as_ref().map(|s| String::from_utf8_lossy(s).into_owned());
                    }
                    self.save();
                    self.ensure(ua, &cid).await;
                }
            }
            UaEvent::RemoteBye(_) | UaEvent::Cancelled | UaEvent::Terminated(_) | UaEvent::Failed(FailureEvent { leg_failed: true, .. }) => {
                if let Some((cid, _)) = self.call_of(ua, e.leg) {
                    self.teardown(ua, &cid).await;
                }
            }
            _ => {}
        }
    }
}

fn kind(e: &UaEvent) -> String {
    format!("{e:?}").split(['(', ' ', '{']).next().unwrap_or("?").to_owned()
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let listen: std::net::SocketAddr = need("--listen").parse().expect("--listen address");
    let dir = PathBuf::from(need("--dir"));
    let media = match MediaClient::connect(Config::tcp(need("--media"), need("--token"))).await {
        Ok(m) => m,
        Err(e) => {
            say(&format!("MEDIA connect {e}"));
            std::process::exit(2);
        }
    };
    let sock = UdpSocket::bind(listen).await.expect("bind");
    std::fs::create_dir_all(&dir).expect("dir");
    let mut journal = FileJournal::open(&dir).expect("journal");
    let file = dir.join("app.json");
    let mut app = App { recs: App::load(&file), file, media, forward: need("--forward"), from: format!("<sip:b2b@{listen}>"), start: Instant::now() };
    let cfg = UaConfig { local: vec![(Proto::Udp, listen)], durable: true, ..UaConfig::default() };
    let epoch = journal.state().epoch;
    let (mut ua, report) = UaEngine::restore(
        cfg,
        Box::new(SystemEntropy::default()),
        IdAllocator::new(),
        journal.state(),
        &RestoreOptions { epoch, ..RestoreOptions::default() },
        app.now(),
        wall(),
    )
    .expect("restore");
    for l in &report.legs {
        say(&format!("RESTORED {l:?}"));
    }
    for t in &report.replay_transmits {
        let _ = sock.send_to(&t.data, t.dest.addr).await;
    }
    journal.dispatched(report.replay_up_to).expect("journal");
    for e in &report.replay_events {
        say(&format!("EVENT {} {} {} replay", e.leg.0, e.seq, kind(&e.event)));
        app.on_event(&mut ua, e).await;
    }
    // Recovery: repeat each known call's steps; end the calls whose A leg is gone.
    let cids: Vec<String> = app.recs.keys().cloned().collect();
    for cid in cids {
        let a = app.recs.get(&cid).map(|r| UaLegId(r.a_leg));
        if a.is_some_and(|a| ua.snapshot(a).is_some()) {
            app.ensure(&mut ua, &cid).await;
        } else {
            app.teardown(&mut ua, &cid).await;
        }
    }
    // An inbound leg this application never recorded (it crashed between
    // the event and its own write): it cannot be continued; refuse it.
    for leg in report.restored() {
        if ua.snapshot(leg).is_some_and(|s| s.role == Role::Uas && matches!(s.phase, Phase::Calling | Phase::Early)) && app.call_of(&ua, leg).is_none() {
            let now = app.now();
            let _ = ua.submit(UaCommand::Reject(RejectRequest { leg, code: 480, reason: None, headers: vec![] }), now);
        }
    }
    say("READY");

    let mut buf = vec![0u8; 65_535];
    loop {
        if let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_millis(5), sock.recv_from(&mut buf)).await {
            let now = app.now();
            ua.handle_message(buf.get(..n).unwrap_or_default(), Dest::new(Proto::Udp, from), now);
        }
        let now = app.now();
        ua.handle_timeout(now);
        loop {
            let now = app.now();
            let Some(t) = ua.take_transition(now, wall()) else { break };
            if t.needs_commit
                && let Err(e) = journal.append(&t.record)
            {
                say(&format!("HALT {e}"));
                ua.halt();
                break;
            }
            for x in &t.record.transmits {
                let _ = sock.send_to(&x.data, x.dest.addr).await;
            }
            if t.needs_commit {
                journal.dispatched(t.record.seq).expect("journal");
            }
            for e in &t.record.events {
                say(&format!("EVENT {} {} {}", e.leg.0, e.seq, kind(&e.event)));
                app.on_event(&mut ua, e).await;
            }
        }
    }
}
