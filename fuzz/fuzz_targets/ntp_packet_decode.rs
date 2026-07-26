#![no_main]

use libfuzzer_sys::fuzz_target;
use ntpsec_rs_core::ntp_types::{NtpPacket, NtpTs64};

fuzz_target!(|data: &[u8]| {
    // Fuzz NTP packet decode — must not panic on arbitrary input
    // Also exercise tail parsing (MAC, extension fields)
    use ntpsec_rs_core::ntp_proto::split_packet_tail;
    use ntpsec_rs_core::nts_extens::ExtensionField;

    // Always try to parse header even for short inputs (will fail gracefully)
    if let Ok(pkt) = NtpPacket::decode_header(data) {
        // Basic field extraction must not panic
        let _ = pkt.leap_indicator();
        let _ = pkt.version();
        let _ = pkt.mode();
        let _ = pkt.stratum;
        let _ = pkt.poll;
        let _ = pkt.root_delay;
        let _ = pkt.root_dispersion;
        let _ = pkt.reference_id;
        let _ = pkt.reference_ts;
        let _ = pkt.originate_ts;
        let _ = pkt.receive_ts;
        let _ = pkt.transmit_ts;

        // Encode round-trip must not panic
        let encoded = pkt.encode_header();
        let _ = encoded.len();

        // If there's data past the 48-byte header, exercise tail parsing
        if data.len() > 48 {
            let _ = split_packet_tail(data);
            // Try to decode the first extension field from the tail
            if data.len() >= 52 {
                let tail = &data[48..];
                let _ = ExtensionField::decode(tail);
            }
        }
    }
});
