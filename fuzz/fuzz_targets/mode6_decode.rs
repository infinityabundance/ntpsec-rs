#![no_main]

use libfuzzer_sys::fuzz_target;
use ntpsec_rs_core::ntp_control::*;

fuzz_target!(|data: &[u8]| {
    // Fuzz Mode 6 control message decode — must not panic on arbitrary input
    if data.len() < 12 {
        return;
    }
    let (msg, after_header) = match ControlMessage::decode(data) {
        Some(v) => v,
        None => return,
    };
    let _ = msg.sequence;
    let _ = msg.status;
    let _ = msg.associd;
    let _ = msg.offset;
    let _ = msg.count;
    let _ = msg.opcode;
    let oc = msg.decode_opcode();
    let _ = oc.response;
    let _ = oc.error;
    let _ = oc.more;
    let _ = oc.op;
});
