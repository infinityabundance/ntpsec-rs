// ──── ntp_sandbox.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_sandbox.c
//
// Seccomp-BPF sandboxing for Linux. Drops privileges and installs a
// seccomp filter that restricts system calls.
//
// ## Oracle
//   - ntpsec ntpd/ntp_sandbox.c (17K)
// =============================================================================

// Stub — seccomp sandbox.
// Feature-gated behind `--cfg sandbox`.
