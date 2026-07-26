#![no_main]

use libfuzzer_sys::fuzz_target;
use ntpsec_rs_core::ntp_control::*;

fuzz_target!(|data: &[u8]| {
    // Fuzz Mode 6 control message decode — must not panic on arbitrary input
    if let Some((msg, after_header)) = ControlMessage::decode(data) {
        let _ = msg.sequence;
        let _ = msg.status;
        let _ = msg.associd;
        let _ = msg.offset;
        let _ = msg.count;
        let oc = msg.decode_opcode();
        let _ = oc.response;
        let _ = oc.error;
        let _ = oc.more;
        let _ = oc.op;

        // Build error response (must not panic)
        let err_resp = build_error_response(&msg, 1);
        let _ = err_resp.len();

        // Build control fragments (must not panic)
        if !after_header.is_empty() {
            let fragments = build_control_fragments(
                msg.sequence,
                oc.op,
                msg.status,
                msg.associd,
                msg.li_vn_mode,
                after_header,
                100,
            );
            let _ = fragments.len();
        }

        // Encode var list from after_header as pseudo-var names/values
        if after_header.len() >= 4 {
            let end = after_header.len().min(64);
            let sample = &after_header[..end];
            let key = format!("fuzz_{}", sample[0]);
            let val = format!("{}", sample.len());
            let vars = [("fuzz", "1")];
            let _encoded = encode_var_list(&vars);
        }
    }
});
