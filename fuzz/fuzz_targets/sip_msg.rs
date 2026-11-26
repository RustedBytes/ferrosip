//! SIP message parsing: what every UDP worker and TCP reader runs on
//! untrusted bytes, plus the URI / name-addr / Contact helpers and stream
//! framing.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sip_parser::{HdrFlags, HdrKind, Msg, uri};

fuzz_target!(|data: &[u8]| {
    let _ = sip_parser::stream_frame(data, 65_535);
    let arena = bumpalo::Bump::new();
    let Ok(mut m) = Msg::parse(data, &arena) else { return };
    let _ = m.parse_headers(HdrFlags::VIA);
    let _ = m.parse_headers(HdrFlags::EOH);
    let _ = (m.method(), m.status(), m.ruri(), m.body(), m.eoh_offset());
    if let Some(r) = m.ruri() {
        let _ = uri::parse_uri(r);
    }
    for h in m.headers.iter() {
        let (u, params) = uri::name_addr(h.body);
        let _ = uri::parse_uri(u);
        let _ = uri::param(params, b"tag");
        if h.kind == HdrKind::Contact {
            for c in uri::split_list(h.body) {
                let _ = uri::parse_contact(c);
            }
        }
    }
});
