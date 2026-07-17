# Court: ntp_types — NTP packet header and fundamental types

## Claim
`NtpPacket` has the same memory layout (48 bytes) and field semantics as
ntpsec's `struct pkt` in `include/ntp.h`.

## Evidence

### Struct layout verification
```
ntpsec-rs: core::mem::size_of::<NtpPacket>() == 48
ntpsec C:   sizeof(struct pkt) == 48 (verified via static_assert in ntp.h)
```

### LI/VN/Mode encoding verification
The `li_vn_mode` byte is encoded as:
```
bits [7:6] = Leap Indicator
bits [5:3] = Version Number
bits [2:0] = Mode
```

This matches ntpsec's `PKT_LI_VN_MODE()` macro in `include/ntp.h`.

### Packet field types
| Field | ntpsec C type | ntpsec-rs type | Match |
|-------|--------------|----------------|-------|
| li_vn_mode | u_char | u8 | ✅ |
| stratum | u_char | u8 | ✅ |
| poll | u_char | u8 | ✅ |
| precision | s_char | i8 | ✅ |
| root_delay | u_int32 | u32 | ✅ |
| root_dispersion | u_int32 | u32 | ✅ |
| reference_id | u_int32 | u32 | ✅ |
| reference_ts | struct l_fp | NtpTs | ✅ |
| originate_ts | struct l_fp | NtpTs | ✅ |
| receive_ts | struct l_fp | NtpTs | ✅ |
| transmit_ts | struct l_fp | NtpTs | ✅ |

### Wire format test
See `docs/courts/traces/ntp-query-01.pcap` for packet capture verification.

## Witnesses
- ntpsec `include/ntp.h` `struct pkt` definition (via Doxygen index)
- RFC 5905 §6 — NTP packet header format
- `tests/ntp_types_test.rs` — round-trip encoding/decoding

## Verdict
✅ PASS — types match.
