//! RFC 3325 / RFC 3323: asserted identity only within the trust domain.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, reason = "test helpers outside #[test] fns")]

mod sim;

use sim::*;
use sip_ua::*;

fn call_with_identity(trust_a: &[&str], trust_b: &[&str]) -> (Net, InboundInvite) {
    let (ta, tb) = (TrustPolicy::new(trust_a).unwrap(), TrustPolicy::new(trust_b).unwrap());
    let mut net = Net::new();
    net.add_with("10.0.0.1:5060", 1, |c| UaConfig { trust: ta, ..c });
    net.add_with("10.0.0.2:5060", 2, |c| UaConfig { trust: tb, ..c });
    let o = OriginateRequest {
        request_uri: "sip:bob@10.0.0.2".into(),
        from: "<sip:anonymous@anonymous.invalid>".into(),
        sdp: Some(sdp("o")),
        asserted_identity: vec!["sip:+15551234@example.com".into(), "tel:+15551234".into()],
        privacy: vec!["id".into()],
        ..Default::default()
    };
    net.submit(0, UaCommand::Originate(Box::new(o))).unwrap();
    assert!(net.run_until(1_000, |n| n.incoming_leg(1).is_some()));
    let UaEvent::IncomingInvite(ii) = net.find(1, |e| matches!(e, UaEvent::IncomingInvite(_))).unwrap().event else { panic!() };
    (net, ii)
}

#[test]
fn identity_crosses_a_trusted_hop() {
    let (net, ii) = call_with_identity(&["10.0.0.0/24"], &["10.0.0.1"]);
    let inv = net.sent("INVITE")[0].msg();
    assert_eq!(inv.values("P-Asserted-Identity").len(), 2);
    assert!(ii.trusted_source);
    assert_eq!(ii.asserted_identity, vec!["<sip:+15551234@example.com>", "<tel:+15551234>"]);
    assert_eq!(ii.privacy, vec!["id"]);
}

#[test]
fn identity_never_leaves_the_trust_domain_or_enters_from_outside() {
    // A doesn't trust B: the header is removed on the wire.
    let (mut net, ii) = call_with_identity(&[], &["10.0.0.1"]);
    let inv = net.sent("INVITE")[0].msg();
    assert!(inv.header("P-Asserted-Identity").is_none());
    assert_eq!(inv.header("Privacy"), Some("id"));
    assert_eq!(net.engine(0).stats().identity_stripped, 1);
    assert!(ii.asserted_identity.is_empty());

    // B doesn't trust the sender: a PAI it receives is not an identity.
    let (_net, ii) = call_with_identity(&["10.0.0.2"], &[]);
    assert!(!ii.trusted_source);
    assert!(ii.asserted_identity.is_empty());
    assert!(ii.headers.iter().any(|h| h.name == "P-Asserted-Identity"), "still visible as a raw header");

    // The policy can't be bypassed with free-form headers.
    let o = OriginateRequest {
        request_uri: "sip:bob@10.0.0.2".into(),
        from: "<sip:a@x>".into(),
        headers: vec![Header::new("P-Asserted-Identity", "<sip:boss@example.com>")],
        ..Default::default()
    };
    assert!(matches!(net.submit(0, UaCommand::Originate(Box::new(o))), Err(CommandError::InvalidArgument(_))));
    let o = OriginateRequest { request_uri: "sip:bob@10.0.0.2".into(), from: "<sip:a@x>".into(), privacy: vec!["everything".into()], ..Default::default() };
    assert!(matches!(net.submit(0, UaCommand::Originate(Box::new(o))), Err(CommandError::InvalidArgument(_))));
}
