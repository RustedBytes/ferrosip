//! Inputs the `sip_ua` fuzz target (fuzz/fuzz_targets/sip_ua.rs) once
//! failed on, kept as regression tests.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers outside #[test] fns")]

use sip_ua::*;

fn roundtrip(data: &[u8]) {
    let lim = Limits::default();
    if let Ok(m) = SipMessage::parse(data, &lim) {
        let bytes = m.to_bytes();
        let again = SipMessage::parse(&bytes, &lim).unwrap_or_else(|e| panic!("re-parse: {e}\n{}", String::from_utf8_lossy(&bytes)));
        assert_eq!(again, m, "serialize/parse round trip\n{}", String::from_utf8_lossy(&bytes));
    }
}

#[test]
fn fuzz_inputs_round_trip() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fuzz_inputs");
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        roundtrip(&std::fs::read(&p).unwrap());
    }
}
