#![no_main]

use libfuzzer_sys::fuzz_target;
use ntpsec_rs_core::nts_extens::ExtensionField;

fuzz_target!(|data: &[u8]| {
    // Fuzz extension field decode — must not panic on arbitrary input
    if data.len() < 4 {
        return;
    }
    // Decode a single extension field from the data
    if let Some((field, remaining)) = ExtensionField::decode(data) {
        let _ = field.field_type;
        let _ = field.payload.len();
        let _ = field.wire_size();
        // Round-trip encode
        let encoded = field.encode();
        let _ = encoded.len();
        // Decode remaining data too, if any
        if remaining.len() >= 4 {
            let _ = ExtensionField::decode(remaining);
        }
    }
});
