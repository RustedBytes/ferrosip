//! Unit tests of tm's pure parts: §16.7 response aggregation, forking by
//! q-value, DNS failover under `max_branches`, the retransmission and
//! final-response timers, parameters, tm's error replies and the script
//! functions that work on the context alone.

use super::*;
use sip_core::pv::PvParam;

const UP: &str = "udp:192.0.2.1:5060";

const INVITE: &str = "INVITE sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKup1\r\n\
Max-Forwards: 70\r\n\
From: <sip:a@example.com>;tag=f1\r\n\
To: <sip:b@example.com>\r\n\
Call-ID: call-1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";

const OPTIONS: &str = "OPTIONS sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKup2\r\n\
Max-Forwards: 70\r\n\
From: <sip:a@example.com>;tag=f1\r\n\
To: <sip:b@example.com>\r\n\
Call-ID: call-2\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";

/// An Outbound that sends nothing and advertises 198.51.100.1:5060.
struct NoNet;

impl Outbound for NoNet {
    fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        Some(SocketAddr::from(([198, 51, 100, 1], 5060)))
    }
}

fn dest(s: &str) -> Dest {
    Dest::parse(s).unwrap()
}

/// A reply as a branch would receive it (upstream Via only).
fn reply(code: u16, reason: &str, extra: &str) -> Arc<[u8]> {
    format!(
        "SIP/2.0 {code} {reason}\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKup1\r\nFrom: <sip:a@example.com>;tag=f1\r\n\
To: <sip:b@example.com>;tag=t{code}\r\nCall-ID: call-1\r\nCSeq: 1 INVITE\r\n{extra}Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
    .into()
}

/// A branch to `dst` in `state`, without a final.
fn live(id: &str, dst: &str, state: BState, group: usize) -> Branch {
    Branch {
        id: id.as_bytes().into(),
        dst: dest(dst),
        ruri: b"sip:b@10.0.0.1".to_vec(),
        req_out: Arc::from(&b"INVITE sip:b@10.0.0.1 SIP/2.0\r\n\r\n"[..]),
        group,
        state,
        rt_ms: T1,
        fr_inv_armed: false,
        cancel_sent: false,
        code: 0,
        reply: None,
        local: false,
        alts: Vec::new(),
        cancel_req: None,
        cancel_rt: 0,
        ack: None,
    }
}

/// A completed branch with this final (received, or `local`: ours).
fn done(code: u16, local: bool) -> Branch {
    let mut b = live("b", "udp:10.0.0.1:5060", BState::Completed, 0);
    b.code = code;
    b.local = local;
    b.reply = Some(reply(code, "Reason", ""));
    b
}

fn txn(method: Method, req: &str, branches: Vec<Branch>) -> Txn {
    Txn {
        method,
        created: Instant::now(),
        timed: 0,
        upstream: dest(UP),
        orig_req: req.as_bytes().to_vec(),
        fail_req: None,
        rr: None,
        cancel_hdrs: b"From: <sip:a@example.com>;tag=f1\r\nTo: <sip:b@example.com>\r\nCall-ID: call-1\r\nCSeq: 1 CANCEL\r\n".to_vec(),
        branches,
        group: 0,
        canceled: false,
        final_sent: false,
        last_reply: None,
        fr: 30_000,
        fr_inv: 120_000,
        skey: (Arc::from(&b"z9hG4bKup1|192.0.2.1:5060"[..]), method),
        on_failure: None,
        on_reply: None,
        awaiting: None,
        await_ready: false,
        in_failure: false,
        upstream_canceled: false,
        vars: TxnVars::default(),
        local: false,
        local_cb: None,
        susp: None,
        timer_id: None,
        handle: 0,
        t1: T1,
        t2: T2,
        blind: 0,
        step: 0,
        max_br: 12,
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Messages sent to `to`, as text.
fn sent_to(io: &[Io], to: &str) -> Vec<String> {
    let to = dest(to);
    io.iter()
        .filter_map(|i| match i {
            Io::Send(d, m) if *d == to => Some(text(m)),
            _ => None,
        })
        .collect()
}

/// Status lines sent upstream.
fn upstream(io: &[Io]) -> Vec<String> {
    sent_to(io, UP).iter().map(|m| m.lines().next().unwrap_or_default().to_string()).collect()
}

/// Timers started: (delay, kind, branch id).
fn timers(io: &[Io]) -> Vec<(u64, String, String)> {
    io.iter()
        .filter_map(|i| match i {
            Io::Timer(ms, k, id) => Some((*ms, format!("{k:?}"), text(id))),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------- §16.7

#[test]
fn rank_orders_final_classes_as_rfc3261_16_7() {
    // Lower is better.
    let cases: &[(u16, (u8, u8))] = &[
        (600, (0, 0)),
        (603, (0, 0)),
        (699, (0, 0)),
        (300, (1, 0)),
        (302, (1, 0)),
        (401, (2, 0)),
        (407, (2, 0)),
        (415, (2, 0)),
        (420, (2, 0)),
        (484, (2, 0)),
        (400, (2, 1)),
        (404, (2, 1)),
        (408, (2, 1)),
        (486, (2, 1)),
        (500, (3, 0)),
        (503, (3, 0)),
        (599, (3, 0)),
        (100, (9, 0)),
        (180, (9, 0)),
        (200, (9, 0)),
        (700, (9, 0)),
        (0, (9, 0)),
    ];
    for &(code, want) in cases {
        assert_eq!(rank(code), want, "rank({code})");
    }
}

#[test]
fn best_index_picks_6xx_then_lowest_class_and_received_over_local() {
    // (finals as (code, local), expected winner)
    type Finals = &'static [(u16, bool)];
    let cases: &[(Finals, Option<usize>)] = &[
        (&[(486, false), (603, false), (302, false)], Some(1)),
        (&[(503, false), (486, false)], Some(1)),
        (&[(404, false), (407, false)], Some(1)),
        (&[(486, false), (415, false), (401, false)], Some(1)),
        // Same rank: the received reply beats our own 408.
        (&[(408, true), (486, false)], Some(1)),
        (&[(408, true), (408, false)], Some(1)),
        // A lower class wins even when it is ours.
        (&[(500, false), (408, true)], Some(1)),
        (&[(503, false), (477, true)], Some(1)),
        // Equal rank and origin: the first branch.
        (&[(302, false), (301, false)], Some(0)),
        (&[(486, false), (480, false)], Some(0)),
        // Branches without a final (0: skipped or failed over) don't count.
        (&[(0, false), (486, false)], Some(1)),
        (&[(0, false)], None),
        (&[], None),
    ];
    for (finals, want) in cases {
        let t = txn(Method::Invite, INVITE, finals.iter().map(|&(c, l)| done(c, l)).collect());
        assert_eq!(t.best_index(), *want, "finals {finals:?}");
    }
}

#[test]
fn best_index_ignores_replies_dropped_by_failure_reply_mode() {
    let mut b = vec![done(603, false), done(486, false)];
    b[0].reply = None;
    let t = txn(Method::Invite, INVITE, b);
    assert_eq!(t.best_index(), Some(1));
}

#[test]
fn chosen_503_is_answered_with_tms_own_500() {
    let mut b = live("b", "udp:10.0.0.1:5060", BState::Completed, 0);
    b.code = 503;
    b.reply = Some(reply(503, "Overloaded", "Retry-After: 120\r\nX-Peer: yes\r\n"));
    let t = txn(Method::Invite, INVITE, vec![b]);
    let (r, remapped) = t.best_reply();
    let r = text(&r);
    assert!(remapped);
    assert!(r.starts_with("SIP/2.0 500 Service Unavailable\r\n"), "{r}");
    // Built from the request: none of the 503's headers or To-tag.
    assert!(!r.contains("Retry-After") && !r.contains("X-Peer") && !r.contains("tag=t503"), "{r}");
    assert!(r.contains("Call-ID: call-1") && r.contains("CSeq: 1 INVITE"), "{r}");
}

#[test]
fn local_transaction_gets_the_503_itself() {
    let mut b = done(503, false);
    b.reply = Some(reply(503, "Overloaded", "Retry-After: 120\r\n"));
    let mut t = txn(Method::Invite, INVITE, vec![b]);
    t.local = true;
    let (r, remapped) = t.best_reply();
    assert!(!remapped);
    assert!(text(&r).starts_with("SIP/2.0 503 Overloaded\r\n"));
    assert!(text(&r).contains("Retry-After: 120\r\n"));
}

#[test]
fn challenges_of_all_401_407_branches_are_merged_into_the_winner() {
    let mut a = done(401, false);
    a.reply = Some(reply(401, "Unauthorized", "WWW-Authenticate: Digest realm=\"a\"\r\n"));
    let mut b = done(407, false);
    b.reply = Some(reply(407, "Proxy Authentication Required", "Proxy-Authenticate: Digest realm=\"b\"\r\n"));
    let mut c = done(401, false);
    c.reply = Some(reply(401, "Unauthorized", "WWW-Authenticate: Digest realm=\"c\"\r\nWWW-Authenticate: Digest realm=\"c2\"\r\n"));
    let t = txn(Method::Invite, INVITE, vec![done(486, false), a, b, c]);
    let (r, remapped) = t.best_reply();
    let r = text(&r);
    assert!(!remapped);
    assert!(r.starts_with("SIP/2.0 401 Unauthorized\r\n"), "{r}");
    let (head, body) = r.split_once("\r\n\r\n").unwrap();
    assert_eq!(body, "");
    let challenges: Vec<&str> = head.lines().filter(|l| l.contains("-Authenticate:")).collect();
    assert_eq!(
        challenges,
        [
            "WWW-Authenticate: Digest realm=\"a\"",
            "Proxy-Authenticate: Digest realm=\"b\"",
            "WWW-Authenticate: Digest realm=\"c\"",
            "WWW-Authenticate: Digest realm=\"c2\""
        ]
    );
}

#[test]
fn without_a_final_the_caller_gets_408_or_487_after_cancel() {
    let t = txn(Method::Invite, INVITE, vec![]);
    assert!(text(&t.best_reply().0).starts_with("SIP/2.0 408 Request Timeout\r\n"));
    // Canceled INVITE, only our own 408: 487.
    let mut t = txn(Method::Invite, INVITE, vec![done(408, true)]);
    t.upstream_canceled = true;
    assert!(text(&t.best_reply().0).starts_with("SIP/2.0 487 Request Terminated\r\n"));
    // Canceled INVITE with a received final: that final.
    let mut t = txn(Method::Invite, INVITE, vec![done(486, false)]);
    t.upstream_canceled = true;
    assert!(text(&t.best_reply().0).starts_with("SIP/2.0 486 Reason\r\n"));
    // Not an INVITE: no 487.
    let mut t = txn(Method::Options, OPTIONS, vec![]);
    t.upstream_canceled = true;
    assert!(text(&t.best_reply().0).starts_with("SIP/2.0 408 Request Timeout\r\n"));
}

#[test]
fn best_reply_goes_upstream_only_when_every_branch_is_final() {
    let b = vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0), live("b1", "udp:10.0.0.2:5060", BState::Proceeding, 0)];
    let mut t = txn(Method::Invite, INVITE, b);
    let mut io = Vec::new();
    t.on_final(0, 486, reply(486, "Busy Here", ""), 5_000, &NoNet, &mut io);
    assert!(upstream(&io).is_empty() && !t.final_sent);
    t.on_final(1, 302, reply(302, "Moved", ""), 5_000, &NoNet, &mut io);
    assert_eq!(upstream(&io), ["SIP/2.0 302 Moved"]);
    assert!(t.final_sent);
    assert!(timers(&io).contains(&(5_000, "Wait".into(), "b0".into())));
    // A late final for a completed branch changes nothing.
    let mut io = Vec::new();
    t.on_final(1, 200, reply(200, "OK", ""), 5_000, &NoNet, &mut io);
    assert!(io.is_empty());
}

#[test]
fn every_2xx_to_an_invite_goes_upstream_but_only_the_first_otherwise() {
    for (method, req, want) in [(Method::Invite, INVITE, 2), (Method::Options, OPTIONS, 1)] {
        let b = vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0), live("b1", "udp:10.0.0.2:5060", BState::Calling, 0)];
        let mut t = txn(method, req, b);
        let mut io = Vec::new();
        t.on_final(0, 200, reply(200, "OK", ""), 5_000, &NoNet, &mut io);
        t.on_final(1, 200, reply(200, "OK", ""), 5_000, &NoNet, &mut io);
        assert_eq!(upstream(&io).len(), want, "{method:?}");
        assert!(t.canceled && t.final_sent);
    }
}

#[test]
fn a_6xx_cancels_ringing_branches_and_wins() {
    let b = vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0), live("b1", "udp:10.0.0.2:5060", BState::Proceeding, 0)];
    let mut t = txn(Method::Invite, INVITE, b);
    let mut io = Vec::new();
    t.on_final(0, 603, reply(603, "Decline", ""), 5_000, &NoNet, &mut io);
    assert!(t.canceled && !t.final_sent);
    let cancels = sent_to(&io, "udp:10.0.0.2:5060");
    assert_eq!(cancels.len(), 1);
    let c = &cancels[0];
    assert!(c.starts_with("CANCEL sip:b@10.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.1:5060;branch=b1\r\n"), "{c}");
    assert!(c.contains("CSeq: 1 CANCEL\r\n") && c.ends_with("Content-Length: 0\r\n\r\n"), "{c}");
    // UDP: retransmitted from T1; given up after 64·T1.
    let tm = timers(&io);
    assert!(tm.contains(&(500, "CancelRetransmit".into(), "b1".into())), "{tm:?}");
    assert!(tm.contains(&(32_000, "CancelTimeout".into(), "b1".into())), "{tm:?}");
    let mut io = Vec::new();
    t.on_final(1, 487, reply(487, "Request Terminated", ""), 5_000, &NoNet, &mut io);
    assert_eq!(upstream(&io), ["SIP/2.0 603 Decline"]);
}

#[test]
fn cancel_over_tcp_is_not_retransmitted() {
    let b = vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0), live("b1", "tcp:10.0.0.2:5060", BState::Proceeding, 0)];
    let mut t = txn(Method::Invite, INVITE, b);
    let mut io = Vec::new();
    t.on_final(0, 600, reply(600, "Busy Everywhere", ""), 5_000, &NoNet, &mut io);
    let tm = timers(&io);
    assert_eq!(tm, [(32_000, "CancelTimeout".into(), "b1".into())]);
    assert_eq!(t.branches[1].cancel_rt, 0);
}

#[test]
fn serial_forking_starts_the_next_q_group_when_the_current_one_failed() {
    let b = vec![
        live("g0", "udp:10.0.0.1:5060", BState::Calling, 0),
        live("g1a", "udp:10.0.0.2:5060", BState::Pending, 1),
        live("g1b", "tcp:10.0.0.3:5060", BState::Pending, 1),
        live("g2", "udp:10.0.0.4:5060", BState::Pending, 2),
    ];
    let mut t = txn(Method::Invite, INVITE, b);
    let mut io = Vec::new();
    t.on_final(0, 486, reply(486, "Busy Here", ""), 5_000, &NoNet, &mut io);
    assert!(upstream(&io).is_empty());
    assert_eq!(t.group, 1);
    let states: Vec<BState> = t.branches.iter().map(|b| b.state).collect();
    assert_eq!(states, [BState::Completed, BState::Calling, BState::Calling, BState::Pending]);
    assert_eq!(sent_to(&io, "udp:10.0.0.2:5060").len(), 1);
    assert_eq!(sent_to(&io, "tcp:10.0.0.3:5060").len(), 1);
    // UDP gets a retransmission timer at T1; both get fr_timer.
    assert_eq!(
        timers(&io),
        [(500, "Retransmit".into(), "g1a".into()), (30_000, "FinalResponse".into(), "g1a".into()), (30_000, "FinalResponse".into(), "g1b".into())]
    );
    let mut io = Vec::new();
    t.on_final(1, 480, reply(480, "Unavailable", ""), 5_000, &NoNet, &mut io);
    assert!(io.is_empty(), "group 1 still has a branch running");
    t.on_final(2, 404, reply(404, "Not Found", ""), 5_000, &NoNet, &mut io);
    assert_eq!(t.group, 2);
    t.on_final(3, 408, reply(408, "Timeout", ""), 5_000, &NoNet, &mut io);
    // All failed: the best of all groups (first of equal rank).
    assert_eq!(upstream(&io), ["SIP/2.0 486 Busy Here"]);
}

#[test]
fn a_2xx_or_6xx_stops_serial_forking() {
    for (code, reason) in [(200, "OK"), (603, "Decline")] {
        let b = vec![live("g0", "udp:10.0.0.1:5060", BState::Calling, 0), live("g1", "udp:10.0.0.2:5060", BState::Pending, 1)];
        let mut t = txn(Method::Invite, INVITE, b);
        let mut io = Vec::new();
        t.on_final(0, code, reply(code, reason, ""), 5_000, &NoNet, &mut io);
        assert!(sent_to(&io, "udp:10.0.0.2:5060").is_empty(), "{code}");
        assert_eq!(t.branches[1].state, BState::Completed, "{code}");
        assert_eq!(upstream(&io), [format!("SIP/2.0 {code} {reason}")]);
    }
}

#[test]
fn an_armed_failure_route_runs_instead_of_sending_the_best_reply() {
    let mut t = txn(Method::Invite, INVITE, vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0)]);
    t.on_failure = Some(0);
    let mut io = Vec::new();
    t.on_final(0, 486, reply(486, "Busy Here", ""), 5_000, &NoNet, &mut io);
    assert!(upstream(&io).is_empty());
    assert!(t.in_failure && !t.final_sent);
    assert!(io.iter().any(|i| matches!(i, Io::Failure(k) if *k == t.skey)));
    // While the route runs, nothing is aggregated.
    let mut io = Vec::new();
    t.check_done(5_000, &NoNet, &mut io);
    assert!(io.is_empty());
}

#[test]
fn local_final_answers_once() {
    let mut t = txn(Method::Invite, INVITE, vec![]);
    t.timer_id = Some(b"susp".to_vec().into());
    let mut io = Vec::new();
    t.local_final(500, "Server Internal Error - Suspended Too Long", 5_000, &mut io);
    t.local_final(408, "Request Timeout", 5_000, &mut io);
    assert_eq!(upstream(&io), ["SIP/2.0 500 Server Internal Error - Suspended Too Long"]);
    assert_eq!(timers(&io), [(5_000, "Wait".into(), "susp".into())]);
}

// ------------------------------------------------- DNS failover, max_branches

/// A branch to 10.0.1.1 with a fallback address, its request carrying our
/// Via for that branch.
fn failover_txn(max_br: usize, blind: usize) -> Txn {
    let adv = NoNet.advertise(Proto::Udp).unwrap();
    let mut b = live("z9hG4bKfs.1", "udp:10.0.1.1:5060", BState::Calling, 0);
    let mut req = b"INVITE sip:b@example.com SIP/2.0\r\n".to_vec();
    req.extend_from_slice(&via_line(Proto::Udp, adv, b"z9hG4bKfs.1"));
    req.extend_from_slice(b"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKup1\r\nContent-Length: 0\r\n\r\n");
    b.req_out = req.into();
    b.alts = vec![dest("tcp:10.0.1.2:5070")];
    let mut t = txn(Method::Invite, INVITE, vec![b]);
    t.max_br = max_br;
    t.blind = blind;
    t
}

#[test]
fn dns_failover_on_503_sends_a_new_branch_to_the_next_address() {
    let mut t = failover_txn(12, 0);
    let mut io = Vec::new();
    t.on_final(0, 503, reply(503, "Service Unavailable", ""), 5_000, &NoNet, &mut io);
    assert!(upstream(&io).is_empty());
    assert_eq!(t.branches.len(), 2);
    // The failed attempt is left out of aggregation.
    assert_eq!((t.branches[0].state, t.branches[0].code), (BState::Completed, 0));
    let nb = &t.branches[1];
    assert_eq!((&*nb.id, nb.dst, nb.state), (&b"z9hG4bKfs.1.1"[..], dest("tcp:10.0.1.2:5070"), BState::Calling));
    let sent = sent_to(&io, "tcp:10.0.1.2:5070");
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].starts_with("INVITE sip:b@example.com SIP/2.0\r\nVia: SIP/2.0/TCP 198.51.100.1:5060;branch=z9hG4bKfs.1.1\r\nVia: SIP/2.0/UDP 192.0.2.1"),
        "{}",
        sent[0]
    );
    assert!(io.iter().any(|i| matches!(i, Io::Map(id, _) if &**id == b"z9hG4bKfs.1.1")));
}

#[test]
fn dns_failover_on_local_408_and_477_but_not_on_other_finals() {
    for (code, local, fails_over) in [(408, true, true), (477, true, true), (408, false, false), (486, false, false), (500, false, false)] {
        let mut t = failover_txn(12, 0);
        let mut io = Vec::new();
        if local {
            t.on_local_final(0, code, "x", 5_000, &NoNet, &mut io);
        } else {
            t.on_final(0, code, reply(code, "x", ""), 5_000, &NoNet, &mut io);
        }
        assert_eq!(t.branches.len() == 2, fails_over, "{code} local={local}");
    }
}

#[test]
fn dns_failover_stops_at_max_branches_counting_suspends() {
    for (max_br, blind) in [(1, 0), (2, 1)] {
        let mut t = failover_txn(max_br, blind);
        let mut io = Vec::new();
        t.on_final(0, 503, reply(503, "Service Unavailable", ""), 5_000, &NoNet, &mut io);
        assert_eq!(t.branches.len(), 1, "max_br={max_br} blind={blind}");
        // The 503 is final: upstream gets tm's 500.
        assert_eq!(upstream(&io), ["SIP/2.0 500 Service Unavailable"]);
    }
    let mut t = failover_txn(2, 0);
    assert_eq!(t.used_slots(), 1);
    t.blind = 1;
    assert_eq!(t.used_slots(), 2);
}

#[test]
fn no_dns_failover_after_cancel() {
    let mut t = failover_txn(12, 0);
    t.canceled = true;
    let mut io = Vec::new();
    t.on_final(0, 503, reply(503, "Service Unavailable", ""), 5_000, &NoNet, &mut io);
    assert_eq!(t.branches.len(), 1);
}

// ---------------------------------------------------------------- timers

/// A Tm holding `t`, its branches indexed.
fn tm_with(t: Txn) -> Tm {
    let tm = Tm::default();
    for b in &t.branches {
        tm.by_branch.insert(b.id.clone(), t.skey.clone());
    }
    if let Some(id) = &t.timer_id {
        tm.by_branch.insert(id.clone(), t.skey.clone());
    }
    tm.txns.insert(t.skey.clone(), t);
    tm
}

fn fire(tm: &Tm, kind: TimerKind, id: &str) -> Vec<Io> {
    let mut io = Vec::new();
    tm.on_timer(&TimerCmd { delay_ms: 0, kind, branch: id.as_bytes().into() }, &NoNet, &mut io);
    io
}

/// Fire the retransmission timer `n` times; the intervals it re-armed with.
fn retransmit_intervals(tm: &Tm, id: &str, n: usize) -> Vec<u64> {
    (0..n).flat_map(|_| timers(&fire(tm, TimerKind::Retransmit, id))).map(|(ms, _, _)| ms).collect()
}

fn skey_of(tm: &Tm) -> ServerKey {
    let mut k = None;
    tm.txns.for_each_mut(|key, _| k = Some(key.clone()));
    k.unwrap()
}

fn set_state(tm: &Tm, i: usize, s: BState) {
    tm.txns.with(&skey_of(tm), |t| t.branches[i].state = s);
}

#[test]
fn invite_retransmissions_double_without_cap_until_a_provisional() {
    let tm = tm_with(txn(Method::Invite, INVITE, vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0)]));
    assert_eq!(retransmit_intervals(&tm, "b0", 6), [1_000, 2_000, 4_000, 8_000, 16_000, 32_000]);
    let io = fire(&tm, TimerKind::Retransmit, "b0");
    assert_eq!(sent_to(&io, "udp:10.0.0.1:5060").len(), 1, "each firing resends the request");
    set_state(&tm, 0, BState::Proceeding);
    assert!(fire(&tm, TimerKind::Retransmit, "b0").is_empty());
}

#[test]
fn non_invite_retransmissions_cap_at_t2_until_a_final() {
    let tm = tm_with(txn(Method::Options, OPTIONS, vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0)]));
    assert_eq!(retransmit_intervals(&tm, "b0", 5), [1_000, 2_000, 4_000, 4_000, 4_000]);
    set_state(&tm, 0, BState::Proceeding);
    assert_eq!(retransmit_intervals(&tm, "b0", 1), [4_000], "a provisional doesn't stop non-INVITE retransmissions");
    set_state(&tm, 0, BState::Completed);
    assert!(fire(&tm, TimerKind::Retransmit, "b0").is_empty());
}

#[test]
fn retransmission_follows_configured_t1_t2_and_saturates() {
    let mut t = txn(Method::Options, OPTIONS, vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0)]);
    t.t1 = 100;
    t.t2 = 300;
    t.branches[0].rt_ms = 100;
    let tm = tm_with(t);
    assert_eq!(retransmit_intervals(&tm, "b0", 3), [200, 300, 300]);
    let mut t = txn(Method::Invite, INVITE, vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0)]);
    t.branches[0].rt_ms = u64::MAX;
    let tm = tm_with(t);
    assert_eq!(retransmit_intervals(&tm, "b0", 1), [u64::MAX]);
}

#[test]
fn cancel_retransmissions_double_up_to_t2_until_answered() {
    let mut b = live("b0", "udp:10.0.0.1:5060", BState::Proceeding, 0);
    b.cancel_req = Some(Arc::from(&b"CANCEL sip:b@10.0.0.1 SIP/2.0\r\n\r\n"[..]));
    b.cancel_rt = T1;
    b.cancel_sent = true;
    let tm = tm_with(txn(Method::Invite, INVITE, vec![b]));
    let iv: Vec<u64> = (0..5).flat_map(|_| timers(&fire(&tm, TimerKind::CancelRetransmit, "b0"))).map(|(ms, _, _)| ms).collect();
    assert_eq!(iv, [1_000, 2_000, 4_000, 4_000, 4_000]);
    // A real final for the INVITE ends them.
    tm.txns.with(&skey_of(&tm), |t| {
        let b = &mut t.branches[0];
        (b.state, b.code, b.local) = (BState::Completed, 487, false);
    });
    assert!(fire(&tm, TimerKind::CancelRetransmit, "b0").is_empty());
}

#[test]
fn fr_timer_gives_a_silent_branch_a_local_408() {
    let tm = tm_with(txn(Method::Options, OPTIONS, vec![live("b0", "udp:10.0.0.1:5060", BState::Calling, 0)]));
    let io = fire(&tm, TimerKind::FinalResponse, "b0");
    assert_eq!(upstream(&io), ["SIP/2.0 408 Request Timeout"]);
    tm.txns.with(&skey_of(&tm), |t| assert!(t.branches[0].local && t.final_sent));
}

#[test]
fn fr_timer_on_a_ringing_invite_defers_to_fr_inv_timer() {
    // Ringing without its own timer: fr_inv_timer counted from the send.
    let tm = tm_with(txn(Method::Invite, INVITE, vec![live("b0", "udp:10.0.0.1:5060", BState::Proceeding, 0)]));
    let io = fire(&tm, TimerKind::FinalResponse, "b0");
    assert_eq!(timers(&io), [(90_000, "InviteFinal".into(), "b0".into())]);
    assert!(upstream(&io).is_empty());
    // Armed: fr_timer is ignored.
    assert!(fire(&tm, TimerKind::FinalResponse, "b0").is_empty());
    // fr_inv_timer: CANCEL the branch, 408.
    let io = fire(&tm, TimerKind::InviteFinal, "b0");
    assert_eq!(sent_to(&io, "udp:10.0.0.1:5060").iter().filter(|m| m.starts_with("CANCEL ")).count(), 1);
    assert_eq!(upstream(&io), ["SIP/2.0 408 Request Timeout"]);
}

#[test]
fn fr_inv_timer_not_above_fr_timer_times_out_a_ringing_invite_at_fr() {
    let mut t = txn(Method::Invite, INVITE, vec![live("b0", "udp:10.0.0.1:5060", BState::Proceeding, 0)]);
    t.fr_inv = 30_000;
    let tm = tm_with(t);
    let io = fire(&tm, TimerKind::FinalResponse, "b0");
    assert_eq!(upstream(&io), ["SIP/2.0 408 Request Timeout"]);
}

#[test]
fn cancel_timeout_gives_up_an_unanswered_branch() {
    let tm = tm_with(txn(Method::Invite, INVITE, vec![live("b0", "udp:10.0.0.1:5060", BState::Proceeding, 0)]));
    let io = fire(&tm, TimerKind::CancelTimeout, "b0");
    assert_eq!(upstream(&io), ["SIP/2.0 408 Request Timeout"]);
    // Already final: nothing.
    assert!(fire(&tm, TimerKind::CancelTimeout, "b0").is_empty());
}

#[test]
fn a_parked_transaction_times_out_with_500() {
    let mut t = txn(Method::Invite, INVITE, vec![]);
    t.timer_id = Some(b"susp1".to_vec().into());
    let tm = tm_with(t);
    let io = fire(&tm, TimerKind::FinalResponse, "susp1");
    assert_eq!(upstream(&io), ["SIP/2.0 500 Server Internal Error - Suspended Too Long"]);
    assert!(fire(&tm, TimerKind::FinalResponse, "susp1").is_empty(), "answered once");
}

#[test]
fn wait_timer_deletes_the_transaction_and_unknown_ids_are_ignored() {
    let tm = tm_with(txn(Method::Options, OPTIONS, vec![live("b0", "udp:10.0.0.1:5060", BState::Completed, 0)]));
    assert!(fire(&tm, TimerKind::Retransmit, "nope").is_empty());
    assert_eq!(tm.txns.len(), 1);
    assert!(fire(&tm, TimerKind::Wait, "b0").is_empty());
    assert_eq!(tm.txns.len(), 0);
}

#[test]
fn timer_ticks_round_up() {
    let cases: &[(u64, u64)] = &[(0, 0), (1, 1), (19, 1), (20, 1), (21, 2), (500, 25), (u64::MAX, u64::MAX.div_ceil(20))];
    for &(ms, ticks) in cases {
        assert_eq!(ms_to_ticks(ms), ticks, "{ms} ms");
    }
}

// ------------------------------------------------------------ parameters

#[test]
fn defaults_match_the_readme() {
    let tm = Tm::default();
    let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
    assert_eq!((ld(&tm.fr_timer), ld(&tm.fr_inv_timer), ld(&tm.wait_timer)), (30_000, 120_000, 5_000));
    assert_eq!((ld(&tm.t1), ld(&tm.t2)), (500, 4_000));
    assert_eq!(tm.failure_reply_mode.load(Ordering::Relaxed), 3);
    assert!(!tm.fork_by_q.load(Ordering::Relaxed) && tm.auto_100.load(Ordering::Relaxed));
    assert_eq!(*lock(&tm.contacts_avp), "tm_contacts");
    assert_eq!(*lock(&tm.contact_flows_avp), "tm_contact_flows");
    let params = tm.params().unwrap();
    let default_of = |n: &str| params.iter().find(|p| p.name == n).map(|p| p.default.to_string());
    for (name, want) in [
        ("fr_timer", "30s"),
        ("fr_inv_timer", "120s"),
        ("wait_timer", "5s"),
        ("retr_timer1", "500ms"),
        ("retr_timer2", "4s"),
        ("max_branches", "12"),
        ("failure_reply_mode", "3"),
        ("fork_by_q", "false"),
    ] {
        assert_eq!(default_of(name).as_deref(), Some(want), "{name}");
    }
}

#[test]
fn timer_params_have_kamailio_minimums() {
    let tm = Tm::default();
    let set = |n: &str, v: i64| tm.set_param(n, &Arg::Int(v));
    let cases: &[(&str, i64, &AtomicU64, u64)] = &[
        ("fr_timer", 0, &tm.fr_timer, 100),
        ("fr_timer", 99, &tm.fr_timer, 100),
        ("fr_timer", 5_000, &tm.fr_timer, 5_000),
        ("fr_inv_timer", 50, &tm.fr_inv_timer, 100),
        ("fr_inv_timer", 60_000, &tm.fr_inv_timer, 60_000),
        ("wait_timer", 1, &tm.wait_timer, 100),
        ("wt_timer", 2_000, &tm.wait_timer, 2_000),
        ("retr_timer1", 1, &tm.t1, 10),
        ("retr_timer1", 250, &tm.t1, 250),
        ("retr_timer2", 9, &tm.t2, 10),
        ("retr_timer2", 8_000, &tm.t2, 8_000),
    ];
    for &(name, v, cell, want) in cases {
        set(name, v).unwrap();
        assert_eq!(cell.load(Ordering::Relaxed), want, "{name}={v}");
    }
    assert!(set("fr_timer", -1).unwrap_err().contains("fr_timer"));
    assert!(set("retr_timer1", -5).is_err());
}

#[test]
fn failure_reply_mode_is_clamped_to_0_3() {
    let tm = Tm::default();
    for (v, want) in [(0, 0), (2, 2), (3, 3), (7, 3), (-1, 0)] {
        tm.set_param("failure_reply_mode", &Arg::Int(v)).unwrap();
        assert_eq!(tm.failure_reply_mode.load(Ordering::Relaxed), want, "{v}");
    }
}

#[test]
fn avp_params_accept_the_xavp_form_and_unknown_params_fail() {
    let tm = Tm::default();
    tm.set_param("contacts_avp", &Arg::Str("$xavp(my_contacts)".into())).unwrap();
    tm.set_param("contact_flows_avp", &Arg::Str("flows".into())).unwrap();
    assert_eq!(*lock(&tm.contacts_avp), "my_contacts");
    assert_eq!(*lock(&tm.contact_flows_avp), "flows");
    tm.set_param("fork_by_q", &Arg::Int(1)).unwrap();
    assert!(tm.fork_by_q.load(Ordering::Relaxed));
    assert_eq!(tm.set_param("fr_tmer", &Arg::Int(1)).unwrap_err(), "tm: unknown parameter \"fr_tmer\"");
    assert!(tm.set_param("fr_timer", &Arg::Str("x".into())).is_err());
}

// ----------------------------------------------------------- error replies

#[test]
fn tm_error_replies_are_kamailios() {
    type Reply = (u16, &'static str);
    let cases: &[(Reply, Reply)] = &[
        (E_TOO_MANY_BRANCHES, (500, "Forking capacity exceeded (12/TM)")),
        (E_SEND, (477, "Unfortunately error on sending to next hop occurred (477/TM)")),
        (E_BAD_ADDRESS, (478, "Unresolvable destination (478/TM)")),
        (E_UNSPEC, (500, "I'm terribly sorry, server error occurred (1/TM)")),
    ];
    for (got, want) in cases {
        assert_eq!(got, want);
    }
}

#[test]
fn class_index_and_code_of() {
    let cases: &[(u16, Option<usize>)] =
        &[(100, None), (199, None), (200, Some(0)), (302, Some(1)), (486, Some(2)), (503, Some(3)), (699, Some(4)), (700, None), (0, None)];
    for &(c, want) in cases {
        assert_eq!(class_index(c), want, "{c}");
    }
    assert_eq!(code_of(b"SIP/2.0 486 Busy Here\r\n"), 486);
    assert_eq!(code_of(b"SIP/2.0 4x6 Busy\r\n"), 0);
    assert_eq!(code_of(b"SIP/2.0"), 0);
    assert_eq!(code_of(b""), 0);
}

#[test]
fn server_key_is_branch_and_lowercased_sent_by() {
    let arena = Bump::new();
    let req = "OPTIONS sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP Proxy.Example.COM:5070;branch=z9hG4bKAbC\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n";
    let mut m = Msg::parse(req.as_bytes(), &arena).unwrap();
    m.parse_headers(HdrFlags::EOH).unwrap();
    let via = m.via1.unwrap();
    assert_eq!(txn_branch(&via).as_deref(), Some(&b"z9hG4bKAbC|proxy.example.com:5070"[..]));
    let req = "OPTIONS sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n";
    let mut m = Msg::parse(req.as_bytes(), &arena).unwrap();
    m.parse_headers(HdrFlags::EOH).unwrap();
    assert_eq!(txn_branch(&m.via1.unwrap()), None, "RFC 2543 requests have no transaction key");
}

#[test]
fn handle_labels_are_32_bit() {
    for h in [0u64, 1, 2, 0xFFFF_FFFF, u64::MAX] {
        assert!(label_of(h) <= 0xFFFF_FFFF, "{h}");
    }
    assert_ne!(label_of(1), label_of(2));
}

// ------------------------------------------- script functions on the context

/// Run `f` on a Ctx for `msg`.
fn with_ctx<R>(msg: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
    let arena = Bump::new();
    let mut m = Msg::parse(msg.as_bytes(), &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &NoNet, None, dest(UP), 0);
    f(&mut ctx)
}

fn contact(uri: &str, q: Option<u16>) -> Contact {
    Contact { uri: uri.as_bytes().to_vec(), q, ..Default::default() }
}

/// The contacts XAVP as (uri, q_flag).
fn loaded(ctx: &mut Ctx<'_, '_>) -> Vec<(String, i64)> {
    let items = ctx.ext_mut::<TxnVars>().xavps.get("tm_contacts").cloned().unwrap_or_default();
    items
        .iter()
        .map(|m| {
            let uri = match m.get("uri") {
                Some(Val::Str(s)) => s.to_string(),
                _ => String::new(),
            };
            let flag = match m.get("q_flag") {
                Some(Val::Int(f)) => *f,
                _ => -1,
            };
            (uri, flag)
        })
        .collect()
}

/// R-URI and destination set after `t_next_contacts()`.
fn targets(ctx: &Ctx<'_, '_>) -> (String, Vec<String>) {
    (text(ctx.ruri()), ctx.branches.iter().map(|b| text(&b.uri)).collect())
}

#[test]
fn load_contacts_orders_by_q_and_marks_group_ends() {
    with_ctx(INVITE, |ctx| {
        // R-URI without q: Kamailio's -1, after every given q, q=0 included.
        ctx.branches = vec![
            contact("sip:half1@x", Some(500)),
            contact("sip:top@x", Some(1000)),
            contact("sip:zero@x", Some(0)),
            contact("sip:half2@x", Some(500)),
            contact("sip:none@x", None),
        ];
        assert_eq!(load_contacts(ctx, "tm_contacts", "tm_contact_flows", LoadMode::Standard), 1);
        assert!(ctx.branches.is_empty(), "the destination set is cleared");
        let want: Vec<(String, i64)> =
            [("sip:top@x", 1), ("sip:half1@x", 0), ("sip:half2@x", 1), ("sip:zero@x", 1), ("sip:b@example.com", 0), ("sip:none@x", 1)]
                .iter()
                .map(|(u, f)| (u.to_string(), *f))
                .collect();
        assert_eq!(loaded(ctx), want);
        let mut groups = Vec::new();
        while next_contacts(ctx, "tm_contacts") == 1 {
            groups.push(targets(ctx));
        }
        let g = |r: &str, b: &[&str]| (r.to_string(), b.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(groups, [g("sip:top@x", &[]), g("sip:half1@x", &["sip:half2@x"]), g("sip:zero@x", &[]), g("sip:b@example.com", &["sip:none@x"])]);
        assert_eq!(next_contacts(ctx, "tm_contacts"), -2);
        assert!(!ctx.ext_mut::<TxnVars>().xavps.contains_key("tm_contacts"), "the XAVP is removed once empty");
    });
}

#[test]
fn load_contacts_with_one_target_does_nothing() {
    with_ctx(INVITE, |ctx| {
        assert_eq!(load_contacts(ctx, "tm_contacts", "tm_contact_flows", LoadMode::Standard), 1);
        assert!(ctx.ext::<TxnVars>().is_none_or(|v| v.xavps.is_empty()));
        assert_eq!(next_contacts(ctx, "tm_contacts"), -2);
    });
}

#[test]
fn load_contacts_proportional_marks_every_contact_as_its_own_group() {
    with_ctx(INVITE, |ctx| {
        ctx.ruri_q = Some(0);
        ctx.branches = vec![contact("sip:a@x", Some(300)), contact("sip:b@x", Some(700))];
        assert_eq!(load_contacts(ctx, "tm_contacts", "tm_contact_flows", LoadMode::Proportional), 1);
        let l = loaded(ctx);
        assert_eq!(l.len(), 3);
        assert!(l.iter().all(|(_, f)| *f == 1));
        // q = 0 comes last.
        assert_eq!(l[2].0, "sip:b@example.com");
    });
}

#[test]
fn load_contacts_keeps_extra_flows_of_one_instance_for_next_contact_flow() {
    with_ctx(INVITE, |ctx| {
        let flow =
            |uri: &str, reg: u32| Contact { uri: uri.as_bytes().to_vec(), instance: Some(b"<urn:uuid:1>".to_vec()), reg_id: Some(reg), ..Default::default() };
        ctx.branches = vec![flow("sip:f1@x", 1), flow("sip:f2@x", 2), contact("sip:other@x", Some(100))];
        assert_eq!(load_contacts(ctx, "c", "f", LoadMode::Standard), 1);
        let flows = ctx.ext_mut::<TxnVars>().xavps.get("f").cloned().unwrap_or_default();
        assert_eq!(flows.len(), 1);
        assert!(matches!(flows[0].get("uri"), Some(Val::Str(s)) if s.as_bytes() == b"sip:f2@x"));
        assert_eq!(next_contact_flow(ctx, "f"), 1);
        assert_eq!(text(ctx.ruri()), "sip:f2@x");
        assert_eq!(ctx.ext::<sip_core::module::RuriFlow>().and_then(|f| f.reg_id), Some(2));
        assert_eq!(next_contact_flow(ctx, "f"), -1);
        assert_eq!(next_contact_flow(ctx, "missing"), -1);
    });
}

#[test]
fn next_contacts_groups_a_script_built_xavp_by_equal_q() {
    with_ctx(INVITE, |ctx| {
        let it = |u: &str, q: i64| -> Item { [("uri".to_string(), Val::str(u.as_bytes())), ("q".to_string(), Val::Int(q))].into_iter().collect() };
        ctx.ext_mut::<TxnVars>().xavps.insert("tm_contacts".into(), vec![it("sip:a@x", 900), it("sip:b@x", 900), it("sip:c@x", 100)]);
        assert_eq!(next_contacts(ctx, "tm_contacts"), 1);
        assert_eq!(targets(ctx), ("sip:a@x".to_string(), vec!["sip:b@x".to_string()]));
        assert_eq!(next_contacts(ctx, "tm_contacts"), 1);
        assert_eq!(targets(ctx), ("sip:c@x".to_string(), vec![]));
        assert_eq!(next_contacts(ctx, "tm_contacts"), -2);
    });
}

#[test]
fn contact_items_round_trip() {
    let mut d = dest("tls:10.0.0.9:5061");
    d.conn = Some(7);
    let c = Contact {
        uri: b"sip:u@h".to_vec(),
        dst: Some(d),
        q: Some(250),
        path: Some(b"<sip:edge;lr>".to_vec()),
        instance: Some(b"<urn:uuid:x>".to_vec()),
        reg_id: Some(3),
    };
    assert_eq!(from_item(&to_item(&c)), Some(c));
    assert_eq!(from_item(&Item::new()), None, "an item needs a uri");
    assert_eq!(dest_from_str("bogus"), None);
}

// ------------------------------------------- exported functions and $T_*

fn registry() -> Registry {
    let mut reg = Registry::default();
    Arc::new(Tm::default()).register(&mut reg).unwrap();
    reg
}

/// Call exported function `name` with literal `args`.
fn call(reg: &Registry, ctx: &mut Ctx<'_, '_>, name: &str, args: &[Arg]) -> i32 {
    let e = reg.get(name).unwrap();
    let fixed = (e.fixup)(args).unwrap();
    (e.func)(ctx, &*fixed)
}

fn fixup_err(reg: &Registry, name: &str, args: &[Arg]) -> bool {
    (reg.get(name).unwrap().fixup)(args).is_err()
}

fn in_failure(code: u16, timeout: bool) -> InFailure {
    InFailure { skey: (Arc::from(&b"k"[..]), Method::Invite), code, timeout, added: false, replied: false, drop: 3, tm_error: None }
}

#[test]
fn t_check_status_is_an_anchored_regex_on_the_winning_or_current_reply() {
    let reg = registry();
    let cases: &[(&str, u16, i32)] = &[
        ("486|408|5[0-9][0-9]", 486, 1),
        ("486|408|5[0-9][0-9]", 503, 1),
        ("486|408|5[0-9][0-9]", 404, -1),
        ("48", 486, -1),
        ("86", 486, -1),
        ("4[0-9][0-9]", 486, 1),
        ("[3-6][0-9][0-9]", 200, -1),
    ];
    for &(re, code, want) in cases {
        let got = with_ctx(INVITE, |ctx| {
            ctx.ext.push(Box::new(in_failure(code, false)));
            call(&reg, ctx, "t_check_status", &[Arg::Str(re.into())])
        });
        assert_eq!(got, want, "{re:?} on {code}");
    }
    let r = text(&reply(180, "Ringing", ""));
    assert_eq!(with_ctx(&r, |ctx| call(&reg, ctx, "t_check_status", &[Arg::Str("1[0-9][0-9]".into())])), 1);
    assert_eq!(with_ctx(INVITE, |ctx| call(&reg, ctx, "t_check_status", &[Arg::Str("[0-9]+".into())])), -1, "a request has no status");
    assert!(fixup_err(&reg, "t_check_status", &[Arg::Str("(".into())]));
}

#[test]
fn t_branch_timeout_and_t_drop_replies_in_a_failure_route() {
    let reg = registry();
    for (timeout, want) in [(true, 1), (false, -1)] {
        let got = with_ctx(INVITE, |ctx| {
            ctx.ext.push(Box::new(in_failure(408, timeout)));
            call(&reg, ctx, "t_branch_timeout", &[])
        });
        assert_eq!(got, want);
    }
    assert_eq!(with_ctx(INVITE, |ctx| call(&reg, ctx, "t_branch_timeout", &[])), -1);
    // No mode: 1 (all); "l": 2 (last relay); "n": 0 (none).
    let cases: &[(&[&str], u8)] = &[(&[], 1), (&["l"], 2), (&["n"], 0), (&["a"], 1)];
    for &(a, want) in cases {
        let args: Vec<Arg> = a.iter().map(|s| Arg::Str(s.to_string())).collect();
        let got = with_ctx(INVITE, |ctx| {
            ctx.ext.push(Box::new(in_failure(486, false)));
            assert_eq!(call(&reg, ctx, "t_drop_replies", &args), 1);
            ctx.ext::<InFailure>().map(|f| f.drop)
        });
        assert_eq!(got, Some(want), "{a:?}");
    }
    assert_eq!(with_ctx(INVITE, |ctx| call(&reg, ctx, "t_drop_replies", &[])), -1, "outside a failure route");
}

#[test]
fn fixups_refuse_bad_literals() {
    let reg = registry();
    assert!(fixup_err(&reg, "t_reply", &[Arg::Int(199), Arg::Str("x".into())]));
    assert!(fixup_err(&reg, "t_reply", &[Arg::Int(700), Arg::Str("x".into())]));
    assert!(!fixup_err(&reg, "t_reply", &[Arg::Int(200), Arg::Str("OK".into())]));
    assert!(!fixup_err(&reg, "t_reply", &[Arg::Int(699), Arg::Str("x".into())]));
    assert!(fixup_err(&reg, "t_load_contacts", &[Arg::Int(2)]));
    assert!(!fixup_err(&reg, "t_load_contacts", &[Arg::Int(1)]));
    assert!(fixup_err(&reg, "t_relay", &[Arg::Str("udp:1.2.3.4:5060".into()), Arg::Str("x".into())]));
    assert!(fixup_err(&reg, "t_drop_replies", &[Arg::Str("l".into()), Arg::Str("n".into())]));
}

#[test]
fn t_reply_code_follows_the_route_kind() {
    let reg = registry();
    let pv = |ctx: &mut Ctx<'_, '_>| (reg.pvs().get("T_reply_code").unwrap().get)(ctx, &PvParam::default());
    let r = text(&reply(183, "Session Progress", ""));
    assert!(matches!(with_ctx(&r, pv), Val::Int(183)), "reply route: the reply's status");
    assert!(matches!(with_ctx(INVITE, pv), Val::Null), "request route: $null");
    let got = with_ctx(INVITE, |ctx| {
        ctx.ext.push(Box::new(in_failure(486, false)));
        pv(ctx)
    });
    assert!(matches!(got, Val::Int(486)), "failure route: the winning reply");
    let got = with_ctx(INVITE, |ctx| {
        ctx.ext.push(Box::new(in_failure(486, false)));
        ctx.ext.push(Box::new(AwaitResult(Some(E_BAD_ADDRESS))));
        pv(ctx)
    });
    assert!(matches!(got, Val::Int(478)), "an immediate relay failure first");
    let got = with_ctx(&r, |ctx| {
        ctx.ext.push(Box::new(LocalReplyCode(408)));
        pv(ctx)
    });
    assert!(matches!(got, Val::Int(408)), "tm:local-response: the local reply");
}
