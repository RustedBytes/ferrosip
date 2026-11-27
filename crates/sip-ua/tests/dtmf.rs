//! SIP INFO DTMF, flagged when the peer also negotiated RTP telephone-event.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers outside #[test] fns")]

mod sim;

use sim::*;
use sip_ua::*;

fn with_te() -> Vec<u8> {
    b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\n".to_vec()
}

fn info(net: &Net, n: usize) -> InfoEvent {
    match net.events(n).iter().rev().find(|e| matches!(e.event, UaEvent::Info(_))).map(|e| e.event.clone()) {
        Some(UaEvent::Info(i)) => i,
        other => panic!("{other:?}"),
    }
}

#[test]
fn info_dtmf_both_ways_with_the_rtp_flag() {
    let mut net = Net::new();
    net.add("10.0.0.1:5060", 1);
    net.add("10.0.0.2:5060", 2);
    // A offers telephone-event; B's answer doesn't.
    let a = net.submit(0, originate("10.0.0.2", Some(with_te()))).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.incoming_leg(1).is_some()));
    let b = net.incoming_leg(1).unwrap();
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("plain")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Ack(_)))));

    net.submit(0, UaCommand::SendDtmf(DtmfRequest { leg: a, dtmf: Dtmf { digit: '5', duration_ms: Some(200) } })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Info(_)))));
    let i = info(&net, 1);
    assert_eq!(i.dtmf, Some(Dtmf { digit: '5', duration_ms: Some(200) }));
    assert!(i.rtp_dtmf_negotiated, "B saw telephone-event in A's offer");

    net.submit(1, UaCommand::SendDtmf(DtmfRequest { leg: b, dtmf: Dtmf { digit: '#', duration_ms: None } })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Info(_)))));
    let i = info(&net, 0);
    assert_eq!(i.dtmf.map(|d| d.digit), Some('#'));
    assert!(!i.rtp_dtmf_negotiated, "B's answer had no telephone-event");
    assert_eq!(i.content_type.as_deref(), Some("application/dtmf-relay"));

    assert!(matches!(
        net.submit(0, UaCommand::SendDtmf(DtmfRequest { leg: a, dtmf: Dtmf { digit: 'x', duration_ms: None } })),
        Err(CommandError::InvalidArgument(_))
    ));
}
