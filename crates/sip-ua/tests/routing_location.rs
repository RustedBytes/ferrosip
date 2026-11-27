//! `routing::UsrlocContacts`: registered contacts from ferrosip's usrloc
//! become originate targets (best q first, NAT-safe next hop, Path).

#![cfg(feature = "location")]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, reason = "test helpers outside #[test] fns")]

mod sim;

use mod_location::store::{Contact, Usrloc};
use sim::*;
use sip_ua::routing::{ContactLookup, UsrlocContacts};
use sip_ua::*;
use std::sync::Arc;

fn contact(uri: &str, q: Option<u16>, received: Dest, path: Option<&str>, modified: u64) -> Contact {
    Contact {
        uri: uri.as_bytes().to_vec(),
        expires_at: u64::MAX,
        q,
        callid: b"reg".to_vec(),
        cseq: 1,
        received,
        user_agent: Vec::new(),
        instance: None,
        reg_id: None,
        last_modified: modified,
        path: path.map(|p| p.as_bytes().to_vec()),
        cflags: 0,
        flags: 0,
        methods: u32::MAX,
        ruid: format!("r-{uri}"),
    }
}

#[test]
fn registered_contacts_route_outbound_legs() {
    let ul = Arc::new(Usrloc::default());
    let nat = Dest::new(Proto::Udp, addr("10.0.0.2:5060"));
    let mut tcp = Dest::new(Proto::Tcp, addr("198.51.100.4:40211"));
    tcp.conn = Some(42);
    ul.update(b"alice", |v, _| {
        v.push(contact("sip:alice@192.168.1.10:5060", Some(500), nat, None, 1));
        v.push(contact("sip:alice@phone.invalid;transport=tcp", Some(900), tcp, Some("<sip:edge1.example;lr>,<sip:edge2.example;lr>"), 2));
        v.push(contact("sip:alice@old.invalid", Some(500), nat, None, 0));
    });
    let lookup = UsrlocContacts(ul);
    let t = lookup.lookup("sip:alice@example.com");
    let uris: Vec<&str> = t.iter().map(|x| x.request_uri.as_str()).collect();
    assert_eq!(uris, vec!["sip:alice@phone.invalid;transport=tcp", "sip:alice@192.168.1.10:5060", "sip:alice@old.invalid"]);
    assert_eq!(t[0].next_hop, Some(tcp));
    assert_eq!(t[0].next_hop.unwrap().conn, Some(42), "the registration's connection (RFC 5626 flow)");
    assert_eq!(t[0].route_set, vec!["<sip:edge1.example;lr>", "<sip:edge2.example;lr>"]);
    assert!(lookup.lookup("sip:nobody@example.com").is_empty());

    // The private address in the Contact is not reachable: the INVITE goes
    // to where the REGISTER came from.
    let mut net = Net::new();
    net.add("10.0.0.1:5060", 1);
    net.add("10.0.0.2:5060", 2);
    let mut o = OriginateRequest { from: "<sip:bob@example.com>".into(), sdp: Some(sdp("o")), ..Default::default() };
    t[1].apply_to(&mut o);
    net.submit(0, UaCommand::Originate(Box::new(o))).unwrap();
    assert!(net.run_until(1_000, |n| n.incoming_leg(1).is_some()));
    let UaEvent::IncomingInvite(ii) = net.find(1, |e| matches!(e, UaEvent::IncomingInvite(_))).unwrap().event else { panic!() };
    assert_eq!(ii.request_uri, "sip:alice@192.168.1.10:5060");
}
