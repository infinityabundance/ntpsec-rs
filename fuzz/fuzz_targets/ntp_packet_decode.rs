#![no_main]

use libfuzzer_sys::fuzz_target;
use ntpsec_rs_core::ntp_types::{NtpPacket, NtpTs64};

fuzz_target!(|data: &[u8]| {
    // Fuzz NTP packet decode — must not panic on arbitrary input
    if data.len() < 48 {
        // Minimum valid NTP packet is 48 bytes
        return;
    }
    let pkt = NtpPacket::decode_header(data);
    // Basic field extraction must not panic
    let _ = pkt.leap();
    let _ = pkt.version();
    let _ = pkt.mode();
    let _ = pkt.stratum;
    let _ = pkt.poll;
    let _ = pkt.precision;
    let _ = pkt.root_delay;
    let _ = pkt.root_dispersion;
    let _ = pkt.reference_id;
    let _ = pkt.reference_time;
    let _ = pkt.originate_time;
    let _ = pkt.receive_time;
    let _ = pkt.transmit_time;

    // Encode round-trip must not panic
    let encoded = pkt.encode_header();
    let _ = encoded.len();
});
