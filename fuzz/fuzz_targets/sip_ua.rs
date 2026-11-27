//! sip-ua: owned-message parsing must round-trip, and the engine must
//! survive any datagram, out of dialog and in the middle of a call.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sip_ua::*;

const INVITE: &[u8] = b"INVITE sip:ua@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.2:5060;branch=z9hG4bKf1;rport\r\n\
From: <sip:a@x>;tag=ft\r\nTo: <sip:ua@x>\r\nCall-ID: fz\r\nCSeq: 1 INVITE\r\nContact: <sip:a@127.0.0.2>\r\n\
Content-Type: application/sdp\r\nContent-Length: 30\r\n\r\nv=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n";

fuzz_target!(|data: &[u8]| {
    let lim = Limits::default();
    if let Ok(m) = SipMessage::parse(data, &lim) {
        let again = SipMessage::parse(&m.to_bytes(), &lim).expect("our own serialization parses");
        assert_eq!(again, m, "serialize/parse round trip");
    }
    let local = "127.0.0.1:5060".parse().unwrap();
    let cfg = UaConfig { local: vec![(Proto::Udp, local)], ..UaConfig::default() };
    let mut e = UaEngine::with_entropy(cfg, Box::new(SeededEntropy::new(1)), IdAllocator::new());
    let src = Dest::new(Proto::Udp, "127.0.0.2:5060".parse().unwrap());
    // Out of any dialog.
    e.handle_message(data, src, 0);
    // In a confirmed call (the fuzzer can reach the dialog: Call-ID fz, tag ft).
    e.handle_message(INVITE, src, 1);
    while let Some(ev) = e.poll_event() {
        if let UaEvent::IncomingInvite(_) = ev.event {
            let answer = b"v=0\r\no=- 2 2 IN IP4 0.0.0.0\r\ns=-\r\nm=audio 0 RTP/AVP 0\r\n".to_vec();
            let _ = e.submit(UaCommand::Accept(AcceptRequest { leg: ev.leg, sdp: Some(answer), headers: vec![] }), 2);
        }
    }
    e.handle_message(data, src, 3);
    e.handle_timeout(100_000);
    while e.poll_transmit().is_some() || e.poll_event().is_some() {}
});
