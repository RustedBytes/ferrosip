//! WebSocket: frame parser (both directions), server and client handshakes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sip_transport::ws;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let _ = ws::parse_frame(&mut buf, 65_535, true, true);
    let mut buf = data.to_vec();
    let _ = ws::parse_frame(&mut buf, 65_535, false, false);
    let _ = ws::server_handshake(data, &ws::WsOpts { allowed_origins: vec!["https://a.example".into()], deflate: true });
    let _ = ws::client_handshake(data, "dGhlIHNhbXBsZSBub25jZQ==");
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ws::negotiate_deflate(s);
    }
});
