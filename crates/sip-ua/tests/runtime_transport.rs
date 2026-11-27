//! The engine on ferrosip's transport layer (`sip-transport`): calls over
//! TCP, TLS, WS and WSS on loopback, with the callee's BYE going back over
//! the connection the call came in on.

#![cfg(feature = "transport")]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, reason = "test helpers outside #[test] fns")]

use sip_transport::{Config, Listen, TcpOpts, TlsFiles};
use sip_ua::runtime::{Resolver, RuntimeConfig, spawn_transport};
use sip_ua::*;
use std::path::PathBuf;
use std::time::Duration;

struct NoDns;
impl Resolver for NoDns {
    fn resolve(&self, r: &ResolveRequest) -> Result<Vec<Dest>, String> {
        Err(format!("no DNS for {}", r.host))
    }
}

fn wait(rx: &std::sync::mpsc::Receiver<EventEnvelope>, what: &str, f: impl Fn(&UaEvent) -> bool) -> EventEnvelope {
    loop {
        let e = rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| panic!("timed out waiting for {what}"));
        if f(&e.event) {
            return e;
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn certs() -> Option<TlsFiles> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../etc/tls");
    let f = |n: &str| dir.join(n);
    if !f("server.pem").exists() {
        eprintln!("skipping TLS/WSS: run etc/tls/gen-certs.sh");
        return None;
    }
    Some(TlsFiles { cert: Some(f("server.pem")), key: Some(f("server.key.pem")), ca: Some(f("ca.pem")), ..TlsFiles::default() })
}

fn sdp() -> Vec<u8> {
    b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n".to_vec()
}

fn call_over(proto: Proto, scheme: &str, tls: TlsFiles) {
    let (pa, pb) = (free_port(), free_port());
    let name = proto.via_name().to_ascii_lowercase();
    let tcfg = |port: u16| Config {
        listen: vec![Listen::parse(&format!("{name}:127.0.0.1:{port}")).unwrap()],
        udp_workers: 1,
        tcp: TcpOpts { readers: 1, ..TcpOpts::default() },
        tls: tls.clone(),
        advertise_ip: None,
    };
    let a = spawn_transport(UaConfig::default(), &tcfg(pa), Box::new(NoDns), RuntimeConfig::default()).unwrap();
    let b = spawn_transport(UaConfig::default(), &tcfg(pb), Box::new(NoDns), RuntimeConfig::default()).unwrap();
    let o = OriginateRequest {
        request_uri: format!("{scheme}:bob@127.0.0.1:{pb};transport={name}"),
        from: "<sip:alice@127.0.0.1>".into(),
        sdp: Some(sdp()),
        ..Default::default()
    };
    let acc = a.submit(UaCommand::Originate(Box::new(o))).unwrap();
    let inv = wait(b.events(), "INVITE", |e| matches!(e, UaEvent::IncomingInvite(_)));
    let UaEvent::IncomingInvite(ii) = &inv.event else { panic!() };
    assert_eq!(ii.source.proto, proto, "{name}");
    assert_eq!(ii.source.conn.is_some(), proto.is_stream(), "{name}: connection id on stream transports only");
    let via = ii.headers.iter().find(|h| h.name.eq_ignore_ascii_case("via")).unwrap();
    assert!(via.value.starts_with(&format!("SIP/2.0/{} ", proto.via_name())), "{name}: {}", via.value);
    b.submit(UaCommand::Accept(AcceptRequest { leg: inv.leg, sdp: Some(sdp()), headers: vec![] })).unwrap();
    let ok = wait(a.events(), "2xx", |e| matches!(e, UaEvent::Accepted(_)));
    assert_eq!(ok.leg, acc.leg);
    wait(b.events(), "ACK", |e| matches!(e, UaEvent::Ack(_)));
    // The callee hangs up: its BYE must use the inbound connection.
    b.submit(UaCommand::Hangup(HangupRequest { leg: inv.leg, reason: None, code: None })).unwrap();
    wait(a.events(), "BYE", |e| matches!(e, UaEvent::RemoteBye(_)));
    wait(a.events(), "end A", |e| matches!(e, UaEvent::Terminated(_)));
    wait(b.events(), "end B", |e| matches!(e, UaEvent::Terminated(_)));
    a.shutdown();
    b.shutdown();
}

#[test]
fn calls_over_tcp_and_ws() {
    call_over(Proto::Tcp, "sip", TlsFiles::default());
    call_over(Proto::Ws, "sip", TlsFiles::default());
}

#[test]
fn calls_over_tls_and_wss() {
    let Some(tls) = certs() else { return };
    call_over(Proto::Tls, "sip", tls.clone());
    call_over(Proto::Wss, "sip", tls);
}

#[test]
fn udp_through_the_transport_layer() {
    call_over(Proto::Udp, "sip", TlsFiles::default());
}
