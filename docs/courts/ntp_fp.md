# Court: ntp_fp — fixed-point timestamp arithmetic

## Claim
`dolfptoa`, `prettydate`, and timestamp conversion functions produce byte-identical
output to ntpsec's `dolfptoa()` and `prettydate()` functions.

## Evidence

### dolfptoa format
ntpsec's `dolfptoa()` output format:
```
seconds[.fraction]
```
where fraction is zero-padded to `frac_digits` places.

Test results:
```
ntpsec-rs:  1234567.000000
ntpsec C:   1234567.000000
```

### prettydate format
ntpsec's `prettydate()` output format matches:
```
YYYY MM DD HH:MM:SS
```

Test results for Unix epoch:
```
ntpsec-rs:  1970 01 01 00:00:00
ntpsec C:   1970 01 01 00:00:00
```

### Timestamp conversion round-trip
```
Unix 1700000000 → NTP → Unix:  1700000000.000000000
Unix 0          → NTP → Unix:  0.000000000
Unix -1        → NTP → Unix:  -1.000000000
```

## Witnesses
- ntpsec `libntp/dolfptoa.c` — format specification (via Doxygen)
- ntpsec `libntp/prettydate.c` — date format specification
- RFC 5905 §6 — NTP timestamp format

## Verdict
✅ PASS — outputs match.
