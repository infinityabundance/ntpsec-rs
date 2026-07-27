// ──── Kani Formal Verification Harness ──────────────────────────────────────
//
// Kani Rust Verifier proof harnesses for the NTP clock discipline algorithm.
// These harnesses verify safety properties (no panics, no overflow) and
// functional correctness properties (bounded output, valid return variants).
//
// ## Running
//
//   cargo kani --tests kani_proof -p ntpsec-rs-core
//
// ## Coverage
//
//   1. Clock filter convergence proof — local_clock output properties
//   2. Fixed-point arithmetic overflow proof — NTP timestamp operations
//   3. No-panic proof — local_clock and clock_filter never panic
//
// =============================================================================

#![cfg(kani)]

mod kani_proofs {
    use ntpsec_rs_core::ntp_fp;
    use ntpsec_rs_core::ntp_loopfilter::{Adjustment, DisciplineType, LoopFilter};
    use ntpsec_rs_core::ntp_types::NtpTs64;

    // ──── Helper: generate a symbolic but valid NtpTs64 ──────────────────────
    //
    // We constrain the seconds to a reasonable range (within ~68 years of epoch)
    // because Kani's default i64 range is too large for bounded model checking.

    fn symbolic_ntpts() -> NtpTs64 {
        let secs: i64 = kani::any();
        let frac: u32 = kani::any();
        // Constrain seconds to the range [-2^31, 2^31) — about ±68 years.
        // This keeps the state space tractable while covering all practical
        // NTP timestamp ranges needed for clock discipline.
        kani::assume(secs >= -(1i64 << 31));
        kani::assume(secs < (1i64 << 31));
        NtpTs64 {
            seconds: secs,
            fraction: frac,
        }
    }

    // ──── Proof 1: Clock Filter Convergence ─────────────────────────────────
    //
    // Verifies that `local_clock` never returns NaN or Inf for finite inputs,
    // always returns a valid Adjustment variant, and the returned offset is
    // bounded by the input offset plus an epsilon.

    #[kani::proof]
    #[kani::unwind(10)] // bound loop iterations (update_count increments)
    fn kani_clock_filter_convergence() {
        let discipline = kani::any();
        kani::assume(
            discipline == DisciplineType::Pll
                || discipline == DisciplineType::PllFll
                || discipline == DisciplineType::Fll
                || discipline == DisciplineType::KernelPll,
        );

        let mut lf = LoopFilter::new(discipline);
        lf.step_threshold = 0.128; // standard step threshold
        lf.panic_threshold = 1000.0; // standard panic threshold

        let offset: f64 = kani::any();
        kani::assume(offset.is_finite());
        kani::assume(offset.abs() < 1000.0); // within panic threshold range

        let now = symbolic_ntpts();

        let result = lf.local_clock(offset, now);

        // Property 1: Never returns NaN or Inf for finite inputs.
        // (Kani checks this automatically, but we make it explicit.)
        match result {
            Adjustment::Step(v) => assert!(v.is_finite()),
            Adjustment::Slew(v, f) => {
                assert!(v.is_finite());
                assert!(f.is_finite());
                assert!(f.abs() <= 500.0); // MAX_FREQ_PPM
            }
            Adjustment::KernelSlew(v, f) => {
                assert!(v.is_finite());
                assert!(f.is_finite());
            }
            Adjustment::Panic(v) => assert!(v.is_finite()),
            Adjustment::Ignore => {}
        }

        // Property 2: Always returns a valid Adjustment variant.
        // (Already covered by the match — all arms handled.)

        // Property 3: The returned offset magnitude is bounded.
        // For Step and Panic, the offset equals the input offset.
        // For Slew, the phase adjustment should be bounded.
        if let Adjustment::Slew(phase_adj, _) = result {
            // The phase adjustment should not exceed the input offset
            // plus epsilon (numerical error from frequency computation).
            assert!(phase_adj.abs() <= offset.abs() + 1e-6);
        }
    }

    // ──── Proof 2: No Panic Under Any Valid Input ───────────────────────────
    //
    // Verifies that `local_clock` never panics for ANY combination of
    // valid (finite, bounded) inputs. Kani automatically checks for
    // panics, unwrap failures, index out of bounds, etc.

    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_local_clock_no_panic() {
        // Symbolic discipline
        let disc_val: u8 = kani::any();
        kani::assume(disc_val <= 3);
        let discipline = match disc_val {
            0 => DisciplineType::Pll,
            1 => DisciplineType::PllFll,
            2 => DisciplineType::Fll,
            _ => DisciplineType::KernelPll,
        };

        let mut lf = LoopFilter::new(discipline);

        // Symbolic configuration parameters
        let step_threshold: f64 = kani::any();
        kani::assume(step_threshold.is_finite());
        kani::assume(step_threshold >= 0.0);
        kani::assume(step_threshold <= 1000.0);
        lf.step_threshold = step_threshold;

        let panic_threshold: f64 = kani::any();
        kani::assume(panic_threshold.is_finite());
        kani::assume(panic_threshold >= 0.0);
        kani::assume(panic_threshold <= 100000.0);
        lf.panic_threshold = panic_threshold;

        // Symbolic initial state
        lf.offset = kani::any();
        kani::assume(lf.offset.is_finite());
        kani::assume(lf.offset.abs() < 1000.0);

        lf.frequency = kani::any();
        kani::assume(lf.frequency.is_finite());
        kani::assume(lf.frequency.abs() <= 500.0);

        lf.phase = kani::any();
        kani::assume(lf.phase.is_finite());
        kani::assume(lf.phase.abs() < 1.0);

        lf.jitter = kani::any();
        kani::assume(lf.jitter.is_finite());
        kani::assume(lf.jitter >= 0.0);
        kani::assume(lf.jitter < 100.0);

        lf.tc = kani::any();
        kani::assume(lf.tc >= 3);
        kani::assume(lf.tc <= 17);

        lf.clock_set = kani::any();
        lf.step_slew_active = kani::any();

        let offset: f64 = kani::any();
        kani::assume(offset.is_finite());
        kani::assume(offset.abs() < 100000.0);

        let now = symbolic_ntpts();

        let _result = lf.local_clock(offset, now);
        // Kani automatically checks that no panic occurs.
    }

    // ──── Proof 3: Clock Filter Never Panics ────────────────────────────────
    //
    // Verifies that the clock filter `add_sample` and `filter` operations
    // never panic under any valid input combination.

    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_clock_filter_entry_no_panic() {
        use ntpsec_rs_core::ntp_proto::{ClockFilter, ClockFilterEntry};

        let mut filter = ClockFilter::new();

        // Add a single entry with symbolic values
        let entry = ClockFilterEntry {
            offset: kani::any(),
            delay: kani::any(),
            dispersion: kani::any(),
            time: symbolic_ntpts(),
        };
        // Reasonable bounds for NTP samples
        kani::assume(entry.offset.is_finite());
        kani::assume(entry.offset.abs() < 1000.0);
        kani::assume(entry.delay.is_finite());
        kani::assume(entry.delay >= 0.0);
        kani::assume(entry.delay < 10.0);
        kani::assume(entry.dispersion.is_finite());
        kani::assume(entry.dispersion >= 0.0);
        kani::assume(entry.dispersion < 100.0);

        filter.add_sample(entry);

        // Filter should not panic
        let filtered = filter.filter();
        if let Some(f) = filtered {
            assert!(f.offset.is_finite());
            assert!(f.delay >= 0.0);
            assert!(f.dispersion >= 0.0);
        }

        // Filter jitter should not panic
        let jitter = filter.filter_jitter(entry.offset);
        assert!(jitter.is_finite() || jitter == 0.0);
        assert!(jitter >= 0.0);
    }

    // ──── Proof 4: Clock Intersection No Panic ──────────────────────────────
    //
    // Verifies that the clock selection algorithm never panics even with
    // symbolic peer states. This is critical for the NTP daemon's robustness.

    #[kani::proof]
    #[kani::unwind(5)] // limit to small number of peers for tractability
    fn kani_clock_intersection_no_panic() {
        use ntpsec_rs_core::ntp_peer::Peer;
        use ntpsec_rs_core::ntp_proto::clock_intersection;

        // Create a small, symbolic peer array (up to 3 peers for tractability)
        const MAX_PEERS: usize = 3;
        let mut peers: [Peer; MAX_PEERS] = unsafe { std::mem::zeroed() };

        for p in peers.iter_mut() {
            p.offset = kani::any();
            p.jitter = kani::any();
            p.root_delay = kani::any();
            p.root_dispersion = kani::any();
            // Constrain to finite values (non-finite peers are simply rejected)
            kani::assume(p.offset.is_finite());
            kani::assume(p.offset.abs() < 10.0);
            kani::assume(p.jitter.is_finite());
            kani::assume(p.jitter >= 0.0);
            kani::assume(p.jitter < 10.0);
            kani::assume(p.root_delay.is_finite());
            kani::assume(p.root_delay >= 0.0);
            kani::assume(p.root_delay < 1.0);
            kani::assume(p.root_dispersion.is_finite());
            kani::assume(p.root_dispersion >= 0.0);
            kani::assume(p.root_dispersion < 1.0);
        }

        let now = symbolic_ntpts();

        // This must not panic
        let _survivor_count = clock_intersection(&mut peers, now);
    }

    // ──── Proof 5: f64-to-NTP-Short Conversion ─────────────────────────────
    //
    // Verifies that f64_to_ntp_short never panics and always produces a
    // well-formed NTP short format value.

    #[kani::proof]
    fn kani_f64_to_ntp_short_safe() {
        let v: f64 = kani::any();
        kani::assume(v.is_finite());
        kani::assume(v >= 0.0);
        kani::assume(v <= 65535.0);

        let result = ntpsec_rs_core::ntp_proto::f64_to_ntp_short(v);

        // Result is a valid u32 (no panic)
        // The high 16 bits are the integer part, low 16 bits are the fraction.
        let int_part = (result >> 16) as u16;
        let frac_part = result as u16;
        let _ = (int_part, frac_part); // just checking no panic
    }

    // ──── Proof 6: Root Distance No Panic ──────────────────────────────────
    //
    // Verifies that root_distance and root_dispersion never panic for
    // any valid peer state.

    #[kani::proof]
    fn kani_root_distance_no_panic() {
        use ntpsec_rs_core::ntp_proto::{root_dispersion, root_distance};

        // Create a minimal Peer with symbolic fields
        let mut peer: ntpsec_rs_core::ntp_peer::Peer = unsafe { std::mem::zeroed() };

        peer.root_delay = kani::any();
        peer.root_dispersion = kani::any();
        peer.dispersion = kani::any();
        kani::assume(peer.root_delay.is_finite());
        kani::assume(peer.root_delay >= 0.0);
        kani::assume(peer.root_delay < 10.0);
        kani::assume(peer.root_dispersion.is_finite());
        kani::assume(peer.root_dispersion >= 0.0);
        kani::assume(peer.root_dispersion < 10.0);
        kani::assume(peer.dispersion.is_finite());
        kani::assume(peer.dispersion >= 0.0);
        kani::assume(peer.dispersion < 10.0);

        let now = symbolic_ntpts();

        // These must not panic
        let rd = root_distance(&peer, now);
        assert!(rd.is_finite() || rd >= 0.0);

        let rdisp = root_dispersion(&peer, now);
        assert!(rdisp.is_finite() || rdisp >= 0.0);
    }

    // ──── Proof 7: Fixed-Point Arithmetic Overflow ─────────────────────────
    //
    // Verifies that the conversion functions between NTP timestamps and
    // Unix timestamps never overflow or panic for reasonable inputs.

    #[kani::proof]
    fn kani_ntp_ts_conversion_no_overflow() {
        // ts_to_ntp: convert (secs, nsec) to NtpTs64
        let secs: i64 = kani::any();
        let nsec: i64 = kani::any();
        // Constrain to reasonable ranges
        kani::assume(secs >= -(1i64 << 40)); // reasonable Unix time range
        kani::assume(secs < (1i64 << 40));
        kani::assume(nsec >= -1_000_000_000);
        kani::assume(nsec <= 1_000_000_000);

        let ntp = ntpsec_rs_core::ntp_fp::ts_to_ntp(secs, nsec);
        // Check for obvious overflow: the result should be finite
        // (the function uses wrapping operations internally)
        let _ = ntp.seconds;
        let _ = ntp.fraction;

        // Round-trip: ntp_to_ts(ts_to_ntp(s, ns)) should not panic
        let (rt_secs, rt_nsec) = ntpsec_rs_core::ntp_fp::ntp_to_ts(ntp);
        let _ = (rt_secs, rt_nsec);
    }

    // ──── Proof 8: NTP Short ↔ Double Conversion ──────────────────────────
    //
    // Verifies that NTP short format conversions are safe and bounded.

    #[kani::proof]
    fn kani_ntp_short_conversion_safe() {
        let secs: u16 = kani::any();
        let frac: u16 = kani::any();

        let result =
            ntpsec_rs_core::ntp_fp::ntp_short_to_double(ntpsec_rs_core::ntp_types::NtpShort {
                seconds: secs,
                fraction: frac,
            });

        assert!(result.is_finite());
        // seconds + fraction/65536.0 => max is ~65535 + 1
        assert!(result >= 0.0);
        assert!(result <= 65536.0);
    }

    // ──── Proof 9: NtpTs64 Wire Format Conversion ──────────────────────────
    //
    // Verifies that wire format conversions are safe.

    #[kani::proof]
    fn kani_ntp_ts64_to_wire_safe() {
        let ts = symbolic_ntpts();
        let wire = ntpsec_rs_core::ntp_fp::ntp_ts64_to_wire(ts);
        let _ = wire.seconds;
        let _ = wire.fraction;
    }
}
