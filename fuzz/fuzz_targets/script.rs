//! The routing-script preprocessor, lexer and parser (config files,
//! cfg.reload), and the formatter: whatever preprocesses and parses must
//! format, keep its tokens (checked inside `format`) and be stable when
//! formatted again.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sip_script::parse(s);
        let Ok(pp) = sip_script::preprocess::preprocess_standalone(s) else { return };
        if sip_script::parse(&pp.text).is_ok() {
            let once = sip_script::fmt::format(s).expect("a script that parses must format");
            assert_eq!(sip_script::fmt::format(&once).as_deref(), Ok(once.as_str()), "format is idempotent");
        }
    }
});
