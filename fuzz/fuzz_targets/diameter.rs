//! Diameter: message and AVP decoding (peers are remote), the cdp XML config.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sip_diameter::Msg::frame_len(data);
    if let Some(m) = sip_diameter::Msg::decode(data) {
        let _ = m.result();
        for a in &m.avps {
            let _ = a.group_avps();
            let _ = (a.as_str(), a.as_u32());
        }
        let _ = m.encode();
    }
    let _ = sip_diameter::decode_avps(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sip_diameter::parse_xml_config(s);
    }
});
