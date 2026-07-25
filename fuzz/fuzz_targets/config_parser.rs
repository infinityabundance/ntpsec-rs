#![no_main]

use libfuzzer_sys::fuzz_target;
use ntpsec_rs_core::ntp_config::*;

fuzz_target!(|data: &[u8]| {
    // Fuzz the config parser with arbitrary input — must not panic
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_config(s);
    }
});
