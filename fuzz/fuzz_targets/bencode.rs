//! bencode (rtpengine ng replies).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((b, _)) = mod_media::bencode::B::decode(data) {
        let mut out = Vec::new();
        b.encode(&mut out);
    }
});
