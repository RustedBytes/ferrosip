//! DNS responses (from the network) and JSON paths (from the script).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 2 {
        let id = u16::from_be_bytes([data[0], data[1]]);
        let _ = sip_core::dns::parse(data, id);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let doc: serde_json::Value = serde_json::json!({"a": {"b": [1, {"c": "x"}]}, "n": 5});
        let _ = sip_core::json::get(&doc, s);
        let mut w = serde_json::Value::Null;
        if s.len() < 64 {
            let _ = sip_core::json::slot(&mut w, s);
        }
    }
});
