//! Pseudo-variable templates and transformations (script strings).
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, OnceLock};

fn reg() -> &'static sip_core::Registry {
    static R: OnceLock<sip_core::Registry> = OnceLock::new();
    R.get_or_init(|| {
        let mut r = sip_core::Registry::default();
        r.load(Arc::new(sip_core::corefns::CoreModule)).expect("core module");
        r
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sip_core::pv::parse_fmt(s, reg().pvs());
        let _ = sip_core::pv::parse_pv(s, reg().pvs());
    }
});
