// =============================================================================
// ntpsec-rs-core — Forensic Rust reconstruction of the NTPsec time-discipline
// brain.  Deterministic, side-effect-free, court-backed.
//
// This crate contains the reimplemented logic of every ntpsec C translation
// unit that can be reasoned about without touching a real clock, real network
// sockets, or real filesystem.  Host mutation lives behind trait boundaries in
// ntpsec-rs-io; the core stays pure.
//
// ## Ported-module key
//
// Each module is a forensic reconstruction of the corresponding ntpsec C file,
// developed by:
//
//   1. Deep Doxygen index of the ntpsec oracle to extract every function
//      signature, type definition, constant, and macro.
//   2. Deterministic-trace replay — captured ntpsec packet receipts are replayed
//      through the Rust code and outputs are compared byte-for-byte.
//   3. Protocol-spec cross-check — NTP RFCs (RFC 5905, 5906, 5907, 5908, 7821,
//      7822, 8573, NTS RFC 8915) and NIST known-answer tests classify where
//      ntpsec policy differs from generic protocol truth.
//   4. Court-backed evidence — every admitted behavior links to a reproducible
//      court in docs/courts/.
//
// =============================================================================

// ──── Re-exports ────────────────────────────────────────────────────────────
// The facade crate re-exports the public API.  Here we just define it.

pub mod binio;
pub mod gpstolfp;
pub mod ieee754io;
pub mod ntp_assert;
pub mod ntp_auth;
pub mod ntp_calendar;
pub mod ntp_config;
pub mod ntp_control;
pub mod ntp_debug;
pub mod ntp_dns;
pub mod ntp_endian;
pub mod ntp_filegen;
pub mod ntp_fp;
pub mod ntp_io;
pub mod ntp_leapsec;
pub mod ntp_lists;
pub mod ntp_loopfilter;
pub mod ntp_malloc;
pub mod ntp_monitor;
pub mod ntp_net;
pub mod ntp_packetstamp;
pub mod ntp_peer;
pub mod ntp_proto;
pub mod ntp_recvbuff;
pub mod ntp_refclock;
pub mod ntp_restrict;
pub mod ntp_sandbox;
pub mod ntp_scanner;
pub mod ntp_signd;
pub mod ntp_stdlib;
pub mod ntp_syscall;
pub mod ntp_syslog;
pub mod ntp_timer;
pub mod ntp_types;
pub mod ntp_util;
pub mod nts;
pub mod nts_client;
pub mod nts_cookie;
pub mod nts_extens;
pub mod nts_server;
pub mod parse;
pub mod refclock_generic;
pub mod refclock_gpsd;
pub mod refclock_local;
pub mod refclock_nmea;
pub mod refclock_pps;
pub mod refclock_pps_api;
pub mod refclock_shm;
pub mod timespecops;

// ──── Python-client reconstructions ─────────────────────────────────────────
// The ntpclients/*.py tools are reimplemented as separate crates; the logic
// they share with the daemon lives here.
pub mod control_client;
pub mod leap_query;
pub mod ntpdig_proto;

// =============================================================================
// Re-export the top-level preamble types so users see a unified API.
// =============================================================================

pub use binio::*;
pub use control_client::*;
pub use control_client::*;
pub use gpstolfp::*;
pub use ieee754io::*;
pub use leap_query::*;
pub use leap_query::*;
pub use ntp_assert::*;
pub use ntp_auth::*;
pub use ntp_calendar::*;
pub use ntp_config::*;
pub use ntp_control::*;
pub use ntp_debug::*;
pub use ntp_dns::*;
pub use ntp_endian::*;
pub use ntp_filegen::*;
pub use ntp_fp::*;
pub use ntp_io::*;
pub use ntp_leapsec::*;
pub use ntp_lists::*;
pub use ntp_loopfilter::*;
pub use ntp_malloc::*;
pub use ntp_monitor::*;
pub use ntp_net::*;
pub use ntp_packetstamp::*;
pub use ntp_peer::*;
pub use ntp_proto::*;
pub use ntp_recvbuff::*;
pub use ntp_refclock::*;
pub use ntp_restrict::*;
pub use ntp_sandbox::*;
pub use ntp_scanner::*;
pub use ntp_signd::*;
pub use ntp_stdlib::*;
pub use ntp_syscall::*;
pub use ntp_syslog::*;
pub use ntp_timer::*;
pub use ntp_types::*;
pub use ntp_util::*;
pub use ntpdig_proto::*;
pub use ntpdig_proto::*;
pub use nts::*;
pub use nts_client::*;
pub use nts_cookie::*;
pub use nts_extens::*;
pub use nts_server::*;
pub use parse::*;
pub use refclock_generic::*;
pub use refclock_gpsd::*;
pub use refclock_local::*;
pub use refclock_nmea::*;
pub use refclock_pps::*;
pub use refclock_pps_api::*;
pub use refclock_shm::*;
pub use timespecops::*;
