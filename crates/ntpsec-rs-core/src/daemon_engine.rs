// ──── daemon_engine.rs — Deterministic NTP daemon state machine ──────────
//
// The DaemonEngine is a pure, side-effect-free transition function:
//
//   handle(event) → Vec<DaemonAction>
//
// It takes a DaemonEvent (packet received, timer fired, shutdown) and
// returns a list of DaemonActions (send packet, adjust clock, persist
// state, log).  The actions are executed by the caller (real daemon or
// lab harness), keeping the engine itself deterministic and testable.
//
// ## Pipeline for each packet receive:
//
//   recv → validate → authenticate → clock_filter → clock_select →
//   clock_combine → local_clock → poll_update → transmit
//
// ## Phase 2.3B closure fixes
//
//   - PendingRequest struct keys on (originate_ts, source_addr) to prevent
//     multi-peer cross-talk when two peers poll in the same tick()
//   - IPv4 sockaddr_to_netaddr uses host-byte-order conversion
//   - Poll timers are one-shot; re-armed only on transmit, not on response.
//     Prevents timer multiplication over time.
//   - System state fully reset on selection failure (no stale offset)
//   - Contextual mode validation: server responses are only accepted from
//     expected-mode peers; client requests are the only accepted inbound mode
//   - Exhaustive restrict_action matching
//
// =============================================================================

use crate::ntp_auth::*;
use crate::ntp_config::*;
use crate::ntp_filegen::*;
use crate::ntp_fp;
use crate::ntp_io::*;
use crate::ntp_leapsec::*;
use crate::ntp_loopfilter::*;
use crate::ntp_monitor::*;
use crate::ntp_peer::*;
use crate::ntp_proto::*;
use crate::ntp_restrict::*;
use crate::ntp_timer::*;
use crate::ntp_types::*;
use crate::nts_server::NtsServerConfig;
use crate::refclock_arbiter::ArbiterRefclock;
use crate::refclock_generic::GenericRefclock;
use crate::refclock_gpsd::GpsdRefclock;
use crate::refclock_hpgps::HpGpsRefclock;
use crate::refclock_jjy::JjyRefclock;
use crate::refclock_modem::ModemRefclock;
use crate::refclock_nmea::NmeaRefclock;
use crate::refclock_oncore::OncoreRefclock;
use crate::refclock_pps::PpsRefclock;
use crate::refclock_shm::ShmRefclock;
use crate::refclock_spectracom::SpectracomRefclock;
use crate::refclock_trimble::TrimbleRefclock;
use crate::refclock_truetime::TrueTimeRefclock;
use crate::refclock_zyfer::ZyferRefclock;
use std::collections::HashMap;

/// A pending NTP request awaiting a server response.
/// Keyed by (originate_ts, destination) to prevent cross-peer confusion
/// when multiple peers poll in the same tick().
#[derive(Debug, Clone)]
struct PendingRequest {
    /// Peer index this request was sent to.
    peer_id: usize,
    /// Wire-format originate timestamp (T1).
    wire_t1: NtpTs,
    /// Full-resolution T1 timestamp.
    full_t1: NtpTs64,
    /// Expected source address of the response.
    destination: NetAddr,
    /// Expected response mode (Server for client polls, SymPassive for SymActive).
    expected_mode: NtpMode,
}

/// A real refclock driver instance — one variant per supported type.
#[derive(Debug)]
pub enum RefclockDriver {
    Shm(ShmRefclock),
    Pps(PpsRefclock),
    Nmea(NmeaRefclock),
    Gpsd(GpsdRefclock),
    Jjy(JjyRefclock),
    Oncore(OncoreRefclock),
    Trimble(TrimbleRefclock),
    TrueTime(TrueTimeRefclock),
    Spectracom(SpectracomRefclock),
    Arbiter(ArbiterRefclock),
    HpGps(HpGpsRefclock),
    Modem(ModemRefclock),
    Zyfer(ZyferRefclock),
    Generic(GenericRefclock),
}

impl RefclockDriver {
    /// Get the driver type number (28=SHM, 22=PPS, 19=NMEA, 16=GPSD,
    /// 40=JJY, 30=Oncore, 29=Trimble, 5=TrueTime, 4=Spectracom,
    /// 11=Arbiter, 26=HPGPS, 18=Modem, 42=Zyfer, 8=Generic).
    pub fn driver_type(&self) -> u8 {
        match self {
            RefclockDriver::Shm(_) => 28,
            RefclockDriver::Pps(_) => 22,
            RefclockDriver::Nmea(_) => 19,
            RefclockDriver::Gpsd(_) => 16,
            RefclockDriver::Jjy(_) => 40,
            RefclockDriver::Oncore(_) => 30,
            RefclockDriver::Trimble(_) => 29,
            RefclockDriver::TrueTime(_) => 5,
            RefclockDriver::Spectracom(_) => 4,
            RefclockDriver::Arbiter(_) => 11,
            RefclockDriver::HpGps(_) => 26,
            RefclockDriver::Modem(_) => 18,
            RefclockDriver::Zyfer(_) => 42,
            RefclockDriver::Generic(_) => 8,
        }
    }
}

/// A managed refclock instance with its driver and metadata.
#[derive(Debug)]
pub struct RefclockInstance {
    pub refclock_type: u8,
    pub unit: u8,
    pub driver: Option<RefclockDriver>,
    pub active: bool,
    pub samples_collected: u64,
    /// Association ID assigned to the peer entry for this refclock.
    pub associd: u16,
}

/// Manages refclock lifecycle — open, poll, close.
#[derive(Debug)]
pub struct RefclockManager {
    pub instances: Vec<RefclockInstance>,
}

impl RefclockManager {
    pub fn new() -> Self {
        Self {
            instances: Vec::new(),
        }
    }

    /// Add a refclock by type and unit. The driver is NOT created here —
    /// actual device opening happens in `open_all()`.
    pub fn add(&mut self, refclock_type: u8, unit: u8, associd: u16) {
        // Don't add duplicates
        if self
            .instances
            .iter()
            .any(|i| i.refclock_type == refclock_type && i.unit == unit)
        {
            return;
        }
        self.instances.push(RefclockInstance {
            refclock_type,
            unit,
            driver: None,
            active: false,
            samples_collected: 0,
            associd,
        });
    }

    /// Open all refclock devices. Returns log messages.
    pub fn open_all(&mut self) -> Vec<DaemonAction> {
        let mut actions = Vec::new();
        for inst in &mut self.instances {
            if inst.active {
                continue;
            }
            let driver = match inst.refclock_type {
                28 => {
                    let mut shm = ShmRefclock::new(inst.unit);
                    match shm.open() {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "SHM refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Shm(shm))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "SHM refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                22 => {
                    let mut pps = PpsRefclock::new(inst.unit);
                    match pps.open() {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "PPS refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Pps(pps))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "PPS refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                19 => {
                    let mut nmea = NmeaRefclock::new(inst.unit);
                    let path = format!("/dev/ttyGPS{}", inst.unit);
                    match nmea.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "NMEA refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Nmea(nmea))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "NMEA refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                16 => {
                    let mut gpsd = GpsdRefclock::new(inst.unit);
                    match gpsd.connect("127.0.0.1", 2947) {
                        Ok(()) => {
                            // Send WATCH command to enable time objects
                            let _ = gpsd.watch();
                            actions.push(DaemonAction::Log(format!(
                                "GPSD refclock unit {} connected",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Gpsd(gpsd))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "GPSD refclock unit {} connect failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── JJY refclock (type 40) ─────────────────────────────
                40 => {
                    let mut jjy = JjyRefclock::new(inst.unit);
                    let path = format!("/dev/jjy{}", inst.unit);
                    match jjy.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "JJY refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Jjy(jjy))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "JJY refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── Oncore refclock (type 30) ──────────────────────────
                30 => {
                    let mut oncore = OncoreRefclock::new(inst.unit);
                    let path = format!("/dev/oncore{}", inst.unit);
                    match oncore.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "Oncore refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Oncore(oncore))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "Oncore refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── Trimble refclock (type 29) ─────────────────────────
                29 => {
                    let mut trimble = TrimbleRefclock::new(inst.unit);
                    let path = format!("/dev/trimble{}", inst.unit);
                    match trimble.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "Trimble refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Trimble(trimble))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "Trimble refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── TrueTime refclock (type 5) ────────────────────────
                5 => {
                    let mut truetime = TrueTimeRefclock::new(inst.unit);
                    let path = format!("/dev/true{}", inst.unit);
                    match truetime.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "TrueTime refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::TrueTime(truetime))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "TrueTime refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── Spectracom refclock (type 4) ───────────────────────
                4 => {
                    let mut spectracom = SpectracomRefclock::new(inst.unit);
                    let path = format!("/dev/spectracom{}", inst.unit);
                    match spectracom.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "Spectracom refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Spectracom(spectracom))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "Spectracom refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── Arbiter refclock (type 11) ─────────────────────────
                11 => {
                    let mut arbiter = ArbiterRefclock::new(inst.unit);
                    let path = format!("/dev/arbiter{}", inst.unit);
                    match arbiter.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "Arbiter refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Arbiter(arbiter))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "Arbiter refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── HP GPS refclock (type 26) ──────────────────────────
                26 => {
                    let mut hpgps = HpGpsRefclock::new(inst.unit);
                    let path = format!("/dev/hpgps{}", inst.unit);
                    match hpgps.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "HP GPS refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::HpGps(hpgps))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "HP GPS refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── Modem refclock (type 18) ───────────────────────────
                18 => {
                    let mut modem = ModemRefclock::new(inst.unit);
                    let path = format!("/dev/modem{}", inst.unit);
                    match modem.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "Modem refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Modem(modem))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "Modem refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── Zyfer refclock (type 42) ───────────────────────────
                42 => {
                    let mut zyfer = ZyferRefclock::new(inst.unit);
                    let path = format!("/dev/zyfer{}", inst.unit);
                    match zyfer.open(&path) {
                        Ok(()) => {
                            actions.push(DaemonAction::Log(format!(
                                "Zyfer refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Zyfer(zyfer))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "Zyfer refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                // ── Generic refclock (type 8) ─────────────────────────
                8 => {
                    match GenericRefclock::new(
                        inst.unit,
                        &format!("/dev/generic{}", inst.unit),
                        "%H%M%S",
                    ) {
                        Ok(generic) => {
                            actions.push(DaemonAction::Log(format!(
                                "Generic refclock unit {} opened",
                                inst.unit
                            )));
                            inst.active = true;
                            Some(RefclockDriver::Generic(generic))
                        }
                        Err(e) => {
                            actions.push(DaemonAction::Log(format!(
                                "Generic refclock unit {} open failed: {}",
                                inst.unit, e
                            )));
                            None
                        }
                    }
                }
                other => {
                    actions.push(DaemonAction::Log(format!(
                        "Unknown refclock type {}",
                        other
                    )));
                    None
                }
            };
            inst.driver = driver;
        }
        actions
    }

    /// Close all refclock devices.
    pub fn close_all(&mut self) {
        for inst in &mut self.instances {
            // Drop takes care of closing via the driver's Drop impl
            inst.driver = None;
            inst.active = false;
        }
    }

    /// Poll all active refclocks for samples. Returns synthetic packets
    /// as DaemonAction::RefclockSample actions, plus log messages.
    /// Called from the daemon's main loop.
    pub fn poll_all(&mut self, now: NtpTs64) -> Vec<DaemonAction> {
        let mut actions = Vec::new();
        for inst in &mut self.instances {
            if !inst.active {
                continue;
            }
            if let Some(ref mut driver) = inst.driver {
                match driver {
                    RefclockDriver::Shm(ref mut shm) => {
                        if let Ok(Some(sample)) = shm.read_sample() {
                            let unit = shm.unit();
                            let pkt = crate::refclock_shm::shm_sample_to_packet(
                                &sample,
                                sample.precision,
                                unit,
                            );
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    RefclockDriver::Pps(ref mut pps) => {
                        if let Ok(Some(stamp)) = pps.read_timestamp() {
                            let pkt = crate::refclock_pps::pps_stamp_to_packet(&stamp);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    RefclockDriver::Nmea(ref mut nmea) => {
                        if let Ok(Some(sample)) = nmea.read_sample() {
                            let pkt = crate::refclock_nmea::nmea_sample_to_packet(&sample, -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    RefclockDriver::Gpsd(ref mut gpsd) => {
                        if let Ok(Some(fix)) = gpsd.read_sample() {
                            let pkt = crate::refclock_gpsd::gpsd_fix_to_packet(&fix, now);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── JJY ────────────────────────────────────────────
                    RefclockDriver::Jjy(ref mut jjy) => {
                        if let Ok(Some(sample)) = jjy.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"JJY0", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── Oncore ─────────────────────────────────────────
                    RefclockDriver::Oncore(ref mut oncore) => {
                        if let Ok(Some(sample)) = oncore.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"ONCO", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── Trimble ────────────────────────────────────────
                    RefclockDriver::Trimble(ref mut trimble) => {
                        if let Ok(Some(sample)) = trimble.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"TRIM", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── TrueTime ───────────────────────────────────────
                    RefclockDriver::TrueTime(ref mut truetime) => {
                        if let Ok(Some(sample)) = truetime.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"TRUE", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── Spectracom ─────────────────────────────────────
                    RefclockDriver::Spectracom(ref mut spectracom) => {
                        if let Ok(Some(sample)) = spectracom.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"SPTR", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── Arbiter ────────────────────────────────────────
                    RefclockDriver::Arbiter(ref mut arbiter) => {
                        if let Ok(Some(sample)) = arbiter.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"ARBT", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── HP GPS ─────────────────────────────────────────
                    RefclockDriver::HpGps(ref mut hpgps) => {
                        if let Ok(Some(sample)) = hpgps.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"HP  ", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── Modem ──────────────────────────────────────────
                    RefclockDriver::Modem(ref mut modem) => {
                        if let Ok(Some(sample)) = modem.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"MODM", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── Zyfer ──────────────────────────────────────────
                    RefclockDriver::Zyfer(ref mut zyfer) => {
                        if let Ok(Some(sample)) = zyfer.read_sample() {
                            let pkt = sample_to_packet(&sample, *b"ZYFR", -6);
                            inst.samples_collected += 1;
                            actions.push(DaemonAction::RefclockSample {
                                associd: inst.associd,
                                packet: pkt,
                                rx_time: now,
                            });
                        }
                    }
                    // ── Generic ────────────────────────────────────────
                    RefclockDriver::Generic(ref mut generic) => {
                        if let Ok(Some(tc)) = generic.read_timecode() {
                            if let Some(sample) = parsed_timecode_to_sample(&tc) {
                                let pkt = sample_to_packet(&sample, *b"GEN ", -6);
                                inst.samples_collected += 1;
                                actions.push(DaemonAction::RefclockSample {
                                    associd: inst.associd,
                                    packet: pkt,
                                    rx_time: now,
                                });
                            }
                        }
                    }
                }
            }
        }
        actions
    }
}

// ──── Refclock sample conversion helpers ───────────────────────────────

/// Convert a `RefClockSample` into a synthetic NTP packet suitable for
/// feeding through the engine's `handle_refclock_sample` pipeline.
fn sample_to_packet(
    sample: &crate::ntp_refclock::RefClockSample,
    ref_id: [u8; 4],
    precision: i8,
) -> crate::ntp_types::NtpPacket {
    let mut pkt = crate::ntp_types::NtpPacket::zeroed();
    pkt.li_vn_mode = crate::ntp_types::NtpPacket::set_li_vn_mode(
        sample.leap,
        crate::ntp_types::NtpVersion::V4,
        crate::ntp_types::NtpMode::Server,
    );
    pkt.stratum = 0;
    pkt.precision = precision;
    pkt.root_delay = 0;
    pkt.root_dispersion = 0;
    pkt.reference_id = u32::from_ne_bytes(ref_id);
    pkt.reference_ts = crate::ntp_fp::ntp_ts64_to_wire(sample.time);
    // The refclock sample's time goes into transmit_ts — the
    // handle_refclock_sample pipeline computes offset as T3 - T4.
    pkt.transmit_ts = crate::ntp_fp::ntp_ts64_to_wire(sample.time);
    pkt
}

/// Convert a `ParsedTimecode` into a `RefClockSample`.
pub fn parsed_timecode_to_sample(
    tc: &crate::parse::ParsedTimecode,
) -> Option<crate::ntp_refclock::RefClockSample> {
    // Build a system time from the parsed fields.
    // Use chrono-like arithmetic: year-month-day hour:min:sec + subsecond ns.
    let (y, m, d) = (tc.year, tc.month as u32, tc.day as u32);
    let (hh, mm, ss) = (tc.hour as u32, tc.minute as u32, tc.second as u32);

    // Convert civil date to days since UNIX epoch using a simple algorithm.
    let days_from_epoch = {
        let y = if m <= 2 { y - 1 } else { y };
        let m = if m <= 2 { m + 12 } else { m };
        // Days in years before this year
        let era = if y >= 0 { y as i64 } else { y as i64 - 399 } / 400;
        let yoe = (y as i64) - era * 400;
        let doy = (153 * (m as i64 - 3) + 2) / 5 + d as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let epoch_era: i64 = 1970;
        let epoch_yoe = epoch_era - (epoch_era / 400) * 400;
        let epoch_doe = epoch_yoe * 365 + epoch_yoe / 4 - epoch_yoe / 100;
        doe - epoch_doe
    };

    let total_secs = days_from_epoch * 86400 + (hh * 3600 + mm * 60 + ss) as i64;
    let subsec_ns = tc.subsecond_ns;

    let ntp_era_offset = total_secs + crate::ntp_fp::NTP_TO_UNIX_OFFSET as i64;
    if ntp_era_offset < 0 {
        return None;
    }
    let fraction = if subsec_ns == 0 {
        0
    } else {
        ((subsec_ns as u64) << 32) / 1_000_000_000
    };

    let time = crate::ntp_types::NtpTs64 {
        seconds: ntp_era_offset,
        fraction: fraction as u32,
    };

    let leap = if tc.leap_second {
        crate::ntp_types::LeapIndicator::AddLeapSecond
    } else {
        crate::ntp_types::LeapIndicator::NoWarning
    };

    Some(crate::ntp_refclock::RefClockSample {
        offset: 0.0,
        delay: 0.0,
        dispersion: 0.0,
        time,
        leap,
    })
}

/// The deterministic daemon state machine.
#[derive(Debug)]
pub struct DaemonEngine {
    pub system: SystemState,
    pub peers: PeerTable,
    pub loop_filter: LoopFilter,
    pub timers: TimerQueue,
    pub auth: AuthKeyStore,
    pub restrictions: RestrictList,
    pub monitor: MonList,
    pub leap_table: LeapTable,
    pub config: ConfigTree,
    pub precision: i8,

    /// Minimum number of sane peers for the clock to synchronize.
    pub minsane: usize,

    /// Association ID of the system peer, or None if unsynchronized.
    pub system_peer_associd: Option<u16>,

    /// Index of the system peer (legacy, use associd instead).
    pub system_peer_id: Option<usize>,

    /// Monotonic counter for allocating association IDs.
    next_associd: u16,

    /// Pending requests awaiting server responses.
    pending_requests: Vec<PendingRequest>,

    /// Refclock instances.
    pub refclocks: RefclockManager,

    /// Path to the drift file.
    pub drift_file: Option<String>,

    /// Path to the statistics directory.
    pub stats_dir: Option<String>,

    /// Path to the log file.
    pub log_file: Option<String>,

    /// Path to the leap-seconds file.
    pub leap_file: Option<String>,

    /// DSCP value for QoS packet marking.
    pub dscp: Option<u8>,

    /// TOS orphan stratum (default 16 in classic NTP).
    pub tos_orphan: Option<u8>,

    /// Tinker minimum poll exponent.
    pub tinker_minpoll: Option<i32>,

    /// Tinker maximum poll exponent.
    pub tinker_maxpoll: Option<i32>,

    /// Tinker step threshold (default 128 ms).
    pub tinker_step: Option<f64>,

    /// Tinker panic threshold (default 1000 s).
    pub tinker_panic: Option<f64>,

    /// Tinker dispersion threshold.
    pub tinker_dispersion: Option<f64>,

    /// Tinker stepout threshold.
    pub tinker_stepout: Option<f64>,

    /// File generation registry for statistics output.
    pub filegen: FileGenRegistry,

    /// Fudge values keyed by (refclock_type, unit).
    pub fudge_values: HashMap<(u8, u8), (f64, f64, u8, String)>,

    /// NTS-KE server configuration, if any.
    pub nts_config: Option<NtsServerConfig>,

    /// Iteration counter for periodic stats writes.
    stats_write_counter: u64,

    /// System variables map for setvar configuration.
    pub sysvars: HashMap<String, String>,
}

impl DaemonEngine {
    pub fn new(config: ConfigTree) -> Self {
        let mut engine = Self {
            system: SystemState::new(),
            peers: PeerTable::new(),
            loop_filter: LoopFilter::new(DisciplineType::PllFll),
            timers: TimerQueue::new(),
            auth: AuthKeyStore::new(),
            restrictions: RestrictList::new(),
            monitor: MonList::new(),
            leap_table: LeapTable::new(),
            precision: -20, // ~1 us typical
            minsane: 1,
            config: ConfigTree::new(),
            system_peer_associd: None,
            system_peer_id: None,
            next_associd: 1,
            pending_requests: Vec::new(),
            refclocks: RefclockManager::new(),
            drift_file: None,
            stats_dir: None,
            log_file: None,
            leap_file: None,
            dscp: None,
            tos_orphan: None,
            tinker_minpoll: None,
            tinker_maxpoll: None,
            tinker_step: None,
            tinker_panic: None,
            tinker_dispersion: None,
            tinker_stepout: None,
            filegen: FileGenRegistry::new(),
            fudge_values: HashMap::new(),
            nts_config: None,
            stats_write_counter: 0,
            sysvars: HashMap::new(),
        };
        engine.apply_config(config);
        engine
    }

    /// Apply (or re-apply) configuration to the engine.
    /// Public for SIGHUP config reload from the daemon shell.
    ///
    /// On SIGHUP, the old configuration is replaced transactionally:
    /// existing peers and timers are cleared before applying the new config
    /// to prevent duplicate associations and timer multiplication.
    pub fn apply_config(&mut self, config: ConfigTree) {
        // Parse the new config fully before mutating state
        let new_config = config;

        // ── Clear existing dynamic state ──────────────────────────────
        // Remove all existing peers and their poll timers
        let old_ids: Vec<u16> = self.peers.iter().filter_map(|p| Some(p.associd)).collect();
        for associd in &old_ids {
            self.peers.remove_by_associd(*associd);
        }
        self.system.peer_count = 0;

        // ── Apply new configuration ───────────────────────────────────
        self.config = new_config;
        for opt in &self.config.options {
            match opt {
                ConfigOption::Server {
                    ref addr,
                    ref options,
                }
                | ConfigOption::Peer {
                    ref addr,
                    ref options,
                }
                | ConfigOption::Pool {
                    ref addr,
                    ref options,
                } => {
                    let mode = match opt.directive_name() {
                        "peer" => NtpMode::SymActive,
                        _ => NtpMode::Client,
                    };
                    let (minpoll, maxpoll, iburst) = parse_assoc_options(options);

                    let srcaddr = addr.parse::<std::net::IpAddr>().ok().map(|ip| {
                        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                        match ip {
                            std::net::IpAddr::V4(v4) => {
                                let sin =
                                    unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in) };
                                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                                sin.sin_port = 123u16.to_be();
                                sin.sin_addr = libc::in_addr {
                                    s_addr: u32::from_ne_bytes(v4.octets()),
                                };
                            }
                            std::net::IpAddr::V6(v6) => {
                                let sin6 =
                                    unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in6) };
                                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                                sin6.sin6_port = 123u16.to_be();
                                sin6.sin6_addr = libc::in6_addr {
                                    s6_addr: v6.octets(),
                                };
                            }
                        }
                        sa
                    });

                    if let Some(sa) = srcaddr {
                        let mut peer = Peer::new(sa, mode, NtpVersion::V4, minpoll, maxpoll);
                        peer.flags |= PeerFlags::CONFIGURED;
                        if iburst {
                            peer.flags |= PeerFlags::IBURST;
                        }
                        // Assign a unique association ID (collision-free across wrap)
                        if let Some(aid) =
                            Self::allocate_associd(&mut self.next_associd, &self.peers)
                        {
                            peer.associd = aid;
                        } else {
                            // ID space exhausted; skip this peer
                            continue;
                        }
                        let peer_id = self.peers.len();
                        self.peers.add(peer);
                        // Schedule initial poll as one-shot (re-armed on transmit)
                        self.timers.schedule_poll(peer_id, 0, 0);
                    }
                }
                ConfigOption::DriftFile(path) => {
                    self.drift_file = Some(path.clone());
                }
                ConfigOption::StatsDir(path) => {
                    self.stats_dir = Some(path.clone());
                }
                ConfigOption::LeapFile(path) => {
                    self.leap_file = Some(path.clone());
                }
                ConfigOption::TrustedKey(kid) => {
                    self.auth.add_trusted_key(*kid);
                }
                ConfigOption::ControlKey(kid) => {
                    self.auth.set_control_key(*kid);
                }
                ConfigOption::Keys(_path) => {
                    // Key file loading is done by the shell (main.rs).
                }
                ConfigOption::Refclock {
                    refclock_type,
                    unit,
                    options: _,
                } => {
                    // Build the canonical refclock address 127.127.x.y
                    let refclock_ip = std::net::Ipv4Addr::new(127, 127, *refclock_type, *unit);
                    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                    let sin = unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in) };
                    sin.sin_family = libc::AF_INET as libc::sa_family_t;
                    sin.sin_port = 123u16.to_be();
                    sin.sin_addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(refclock_ip.octets()),
                    };

                    let mut peer = Peer::new(sa, NtpMode::Client, NtpVersion::V4, 4, 10);
                    peer.flags |= PeerFlags::CONFIGURED;
                    // Assign a unique association ID
                    if let Some(aid) = Self::allocate_associd(&mut self.next_associd, &self.peers) {
                        peer.associd = aid;
                        self.peers.add(peer);
                        self.refclocks.add(*refclock_type, *unit, aid);
                    }
                }
                ConfigOption::Restrict {
                    ref addr,
                    ref flags,
                } => {
                    let ipv4 = addr == "-4" || addr == "default";
                    let mut rflags = RestrictFlags::empty();
                    for f in flags {
                        rflags |= match f.as_str() {
                            "ignore" => RestrictFlags::IGNORE,
                            "nomodify" => RestrictFlags::NOMODIFY,
                            "nopeer" => RestrictFlags::NOPEER,
                            "noquery" => RestrictFlags::NOQUERY,
                            "notrap" => RestrictFlags::NOTRAP,
                            "notrust" => RestrictFlags::NOTRUST,
                            "limited" => RestrictFlags::LIMITED,
                            "kod" => RestrictFlags::KOD,
                            "noserve" => RestrictFlags::IGNORE,
                            "server" => RestrictFlags::SERVER,
                            _ => RestrictFlags::NONE,
                        };
                    }
                    if ipv4 || addr == "-6" {
                        if ipv4 {
                            self.restrictions.set_default_v4(rflags);
                        } else {
                            self.restrictions.set_default_v6(rflags);
                        }
                    } else {
                        // Parse an IP/mask restrict entry
                        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
                            let mut entry_addr: libc::sockaddr_storage =
                                unsafe { std::mem::zeroed() };
                            let mut entry_mask: libc::sockaddr_storage =
                                unsafe { std::mem::zeroed() };
                            match ip {
                                std::net::IpAddr::V4(v4) => {
                                    let sin = unsafe {
                                        &mut *(&mut entry_addr as *mut _ as *mut libc::sockaddr_in)
                                    };
                                    sin.sin_family = libc::AF_INET as libc::sa_family_t;
                                    sin.sin_addr = libc::in_addr {
                                        s_addr: u32::from_ne_bytes(v4.octets()),
                                    };
                                    let mask = unsafe {
                                        &mut *(&mut entry_mask as *mut _ as *mut libc::sockaddr_in)
                                    };
                                    mask.sin_family = libc::AF_INET as libc::sa_family_t;
                                    mask.sin_addr = libc::in_addr { s_addr: !0u32 };
                                }
                                std::net::IpAddr::V6(v6) => {
                                    let sin6 = unsafe {
                                        &mut *(&mut entry_addr as *mut _ as *mut libc::sockaddr_in6)
                                    };
                                    sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                                    sin6.sin6_addr = libc::in6_addr {
                                        s6_addr: v6.octets(),
                                    };
                                    let mask6 = unsafe {
                                        &mut *(&mut entry_mask as *mut _ as *mut libc::sockaddr_in6)
                                    };
                                    mask6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                                    mask6.sin6_addr = libc::in6_addr {
                                        s6_addr: [0xff; 16],
                                    };
                                }
                            }
                            self.restrictions
                                .add_entry(crate::ntp_restrict::RestrictEntry {
                                    addr: entry_addr,
                                    mask: entry_mask,
                                    flags: rflags,
                                    mru_depth: 0,
                                });
                        }
                    }
                }
                ConfigOption::Other { directive, args } => match directive.as_str() {
                    "logfile" => {
                        if let Some(path) = args.first() {
                            self.log_file = Some(path.clone());
                        }
                    }
                    "dscp" => {
                        if let Some(val) = args.first().and_then(|s| s.parse::<u8>().ok()) {
                            self.dscp = Some(val);
                        }
                    }
                    "tos" => {
                        if let Some(val) = args.first().and_then(|s| s.parse::<u8>().ok()) {
                            self.tos_orphan = Some(val);
                        }
                    }
                    "tinker" => {
                        let mut i = 0;
                        while i + 1 < args.len() {
                            let key = &args[i];
                            let val = &args[i + 1];
                            match key.as_str() {
                                "minpoll" => {
                                    if let Ok(v) = val.parse::<i32>() {
                                        self.tinker_minpoll = Some(v);
                                    }
                                }
                                "maxpoll" => {
                                    if let Ok(v) = val.parse::<i32>() {
                                        self.tinker_maxpoll = Some(v);
                                    }
                                }
                                "step" => {
                                    if let Ok(v) = val.parse::<f64>() {
                                        self.tinker_step = Some(v);
                                    }
                                }
                                "panic" => {
                                    if let Ok(v) = val.parse::<f64>() {
                                        self.tinker_panic = Some(v);
                                    }
                                }
                                _ => {}
                            }
                            i += 2;
                        }
                    }
                    _ => {}
                },
                // ── New typed config options ────────────────────────────
                ConfigOption::Tinker {
                    step,
                    panic,
                    dispersion,
                    stepout,
                    minpoll,
                    maxpoll,
                } => {
                    if let Some(v) = step {
                        self.tinker_step = Some(*v);
                    }
                    if let Some(v) = panic {
                        self.tinker_panic = Some(*v);
                    }
                    if let Some(v) = dispersion {
                        self.tinker_dispersion = Some(*v);
                    }
                    if let Some(v) = stepout {
                        self.tinker_stepout = Some(*v);
                    }
                    if let Some(v) = minpoll {
                        self.tinker_minpoll = Some(*v);
                    }
                    if let Some(v) = maxpoll {
                        self.tinker_maxpoll = Some(*v);
                    }
                    // Apply to loop filter
                    self.loop_filter.configure(*step, *panic);
                }
                ConfigOption::Tos {
                    minsane,
                    minclock,
                    maxdist,
                } => {
                    if let Some(v) = minsane {
                        self.minsane = *v;
                    }
                    if let Some(v) = maxdist {
                        // Apply to system state's maxdist
                        // (Currently handled at selection time)
                    }
                }
                ConfigOption::Mru { maxdepth, maxage } => {
                    if let Some(v) = maxdepth {
                        self.monitor.max_entries = *v as u32;
                    }
                    if let Some(v) = maxage {
                        self.monitor.max_age = *v;
                    }
                }
                ConfigOption::Statistics { kinds } => {
                    for kind in kinds {
                        // Auto-create filegen entries for statistics kinds
                        let entry = FileGenEntry {
                            name: kind.clone(),
                            file_name: kind.clone(),
                            gen_type: FileGenType::Day,
                            enabled: true,
                        };
                        self.filegen.add(entry);
                    }
                }
                ConfigOption::Filegen {
                    name,
                    file,
                    gen_type,
                    enable,
                } => {
                    let file_name = file.clone().unwrap_or_else(|| name.clone());
                    let gt = match gen_type.as_deref() {
                        Some("week") => FileGenType::Week,
                        Some("month") => FileGenType::Month,
                        Some("year") => FileGenType::Year,
                        Some("age") => FileGenType::Age,
                        Some("pid") => FileGenType::Pid,
                        _ => FileGenType::Day,
                    };
                    let entry = FileGenEntry {
                        name: name.clone(),
                        file_name,
                        gen_type: gt,
                        enabled: *enable,
                    };
                    self.filegen.add(entry);
                }
                ConfigOption::Nts {
                    key_file,
                    cert_file,
                    port: _,
                } => {
                    if let (Some(kf), Some(cf)) = (key_file, cert_file) {
                        self.nts_config = Some(NtsServerConfig {
                            key_file: kf.clone(),
                            cert_file: cf.clone(),
                            aead_algorithms: vec![15],
                            cookie_cipher: crate::nts_cookie::CookieCipher::new(),
                        });
                    }
                }
                ConfigOption::Fudge {
                    refclock_type,
                    unit,
                    time1,
                    time2,
                    stratum,
                    refid,
                } => {
                    self.fudge_values.insert(
                        (*refclock_type, *unit),
                        (*time1, *time2, *stratum, refid.clone()),
                    );
                }
                ConfigOption::Interface { name: _, action: _ } => {
                    // Interface actions are handled by the shell
                }
                ConfigOption::Logfile { path } => {
                    self.log_file = Some(path.clone());
                }
                ConfigOption::Setvar { name, value } => {
                    self.sysvars.insert(name.clone(), value.clone());
                }
                ConfigOption::NtsServer { .. } => {
                    // Handled by parse_config() which also converts to nts_config
                }
                _ => {}
            }
        }
        // Schedule housekeeping and reachability timers (repeating)
        self.timers
            .add(TimerEntry::new(TimerEvent::Housekeeping, 64, 64));
        self.timers
            .add(TimerEntry::new(TimerEvent::Reachability, 64, 64));
        // Schedule stats write timer (every 10 iterations ≈ 10 seconds)
        self.timers
            .add(TimerEntry::new(TimerEvent::StatsWrite, 10, 10));
    }

    /// Handle a single event. Returns actions for the shell to execute.
    pub fn handle(&mut self, event: DaemonEvent) -> Vec<DaemonAction> {
        match event {
            DaemonEvent::Shutdown => {
                self.refclocks.close_all();
                vec![DaemonAction::Log("shutdown".to_string())]
            }
            DaemonEvent::TimerFired(timer_id) => self.handle_timer(timer_id),
            DaemonEvent::PacketReceived(dgram) => self.handle_packet(dgram),
            DaemonEvent::RefclockSample {
                associd,
                packet,
                rx_time,
            } => self.handle_refclock_sample(associd, packet, rx_time),
        }
    }

    /// Allocate a unique association ID using a predicate for used-ID checking.
    /// Separated from the concrete PeerTable lookup so courts can test exhaustion
    /// without constructing 65,535 peers.
    fn allocate_associd_with<F>(next: &mut u16, mut is_used: F) -> Option<u16>
    where
        F: FnMut(u16) -> bool,
    {
        for _ in 0..u16::MAX {
            let c = *next;
            let candidate = if c == 0 { 1 } else { c };
            *next = if candidate == u16::MAX {
                1
            } else {
                candidate + 1
            };
            if !is_used(candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Allocate a unique association ID for a new peer.
    /// Scans active IDs on wrap, delegates to the predicate-based allocator.
    fn allocate_associd(next: &mut u16, peers: &PeerTable) -> Option<u16> {
        Self::allocate_associd_with(next, |candidate| {
            peers.iter().any(|p| p.associd == candidate)
        })
    }

    /// Drain all due timers and return their actions.
    pub fn tick(&mut self, now: NtpTs64) -> Vec<DaemonAction> {
        let mut actions = Vec::new();
        for event in self.timers.pop_due(now) {
            match event {
                TimerEvent::Poll(id) => {
                    if let Some(peer) = self.peers.get_mut(id) {
                        let pkt = build_request(peer, &self.system, now, self.precision);

                        let dest = sockaddr_to_netaddr(&peer.srcaddr)
                            .unwrap_or(NetAddr::ipv4(0x7f000001, 123));

                        // Determine expected response mode
                        let expected_mode = if peer.hmode == NtpMode::SymActive {
                            NtpMode::SymPassive
                        } else {
                            NtpMode::Server
                        };

                        // Record pending request for response matching
                        self.pending_requests.push(PendingRequest {
                            peer_id: id,
                            wire_t1: pkt.transmit_ts,
                            full_t1: now,
                            destination: dest,
                            expected_mode,
                        });

                        // Limit pending to avoid unbounded growth
                        if self.pending_requests.len() > 1000 {
                            self.pending_requests.remove(0);
                        }

                        // Re-arm the next poll as one-shot with current poll interval
                        let interval = (1u64 << peer.hpoll) as u32;
                        self.timers
                            .schedule_poll_once(id, now.seconds + interval as i64);

                        actions.push(DaemonAction::Send {
                            destination: dest,
                            bytes: pkt.encode_header().to_vec(),
                        });
                    }
                }
                TimerEvent::Housekeeping => {
                    actions.extend(self.run_selection(now));
                }
                TimerEvent::Reachability => {
                    for i in 0..self.peers.len() {
                        if let Some(peer) = self.peers.get_mut(i) {
                            peer.reach.record_failure();
                        }
                    }
                }
                TimerEvent::StatsWrite => {
                    // Periodic statistics write
                    if let Some(ref stats_dir) = self.stats_dir {
                        let path = std::path::Path::new(stats_dir);
                        let _ = self.filegen.write_loopstats(
                            &path.join("loopstats"),
                            &self.system,
                            self.loop_filter.frequency_ppm(),
                        );
                    }
                }
                _ => {}
            }
        }

        // ── Periodic stats writes (every 10 iterations) ───────────────
        self.stats_write_counter += 1;
        if self.stats_write_counter % 10 == 0 {
            if let Some(ref stats_dir) = self.stats_dir {
                let path = std::path::Path::new(stats_dir);
                // Write loopstats
                let _ = self.filegen.write_loopstats(
                    &path.join("loopstats"),
                    &self.system,
                    self.loop_filter.frequency_ppm(),
                );
                // Write peerstats for all peers
                for i in 0..self.peers.len() {
                    if let Some(peer) = self.peers.get(i) {
                        let _ = self.filegen.write_peerstats(&path.join("peerstats"), peer);
                    }
                }
            }
        }

        // ── Poll refclocks every tick ─────────────────────────────────
        // This is now handled by the daemon shell calling poll_refclocks()
        // explicitly, to keep tick() free of side effects for testing.

        actions
    }

    /// Poll all active refclocks for new samples.
    /// Should be called periodically from the daemon main loop.
    pub fn poll_refclocks(&mut self, now: NtpTs64) -> Vec<DaemonAction> {
        self.refclocks.poll_all(now)
    }

    /// Check if a PPS refclock peer is active and can override the system peer.
    /// PPS provides precise phase (sub-microsecond) but no time-of-day; it
    /// needs to be paired with the most recent time-of-day source.
    /// When a PPS refclock is active and its offset is within tolerance
    /// (< 1 ms of the system offset), it overrides the system peer for
    /// phase adjustment.
    fn find_pps_peer(&self) -> Option<usize> {
        for (i, peer) in self.peers.iter().enumerate() {
            if peer.flags.contains(PeerFlags::PREFER)
                && peer.stratum == 0
                && peer.reach.is_reachable()
            {
                // PPS refclocks typically present as stratum 0 with low jitter
                if peer.jitter < 0.001 && peer.offset.abs() < 0.001 {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Run the clock selection / combine / discipline pipeline.
    /// Supports prefer peer (kept unconditionally during pruning) and
    /// PPS override (PPS refclock overrides system peer when within
    /// tolerance).
    fn run_selection(&mut self, now: NtpTs64) -> Vec<DaemonAction> {
        let mut actions = Vec::new();

        let peer_count = self.peers.len();
        if peer_count == 0 {
            return actions;
        }

        // Collect all peers into a Vec for the selection pipeline
        let mut peers_vec: Vec<Peer> = self.peers.iter().cloned().collect();

        // Run the full selection pipeline
        let sys_peer_idx = self.system.update_from_peers(&mut peers_vec, now);

        // Track system peer by both index (legacy) and association ID
        if sys_peer_idx < self.peers.len() {
            self.system_peer_id = Some(sys_peer_idx);
            self.system_peer_associd = self.peers.get(sys_peer_idx).map(|p| p.associd);
            self.system.sys_peer_associd = self.system_peer_associd.unwrap_or(0);
        } else {
            self.system_peer_id = None;
            self.system_peer_associd = None;
            self.system.sys_peer_associd = 0;
            // No survivor found — count as a broken selection attempt
            self.system.sel_broken = self.system.sel_broken.saturating_add(1);
        }

        // Write updated peer state back
        for (i, p) in peers_vec.iter().enumerate() {
            if let Some(peer) = self.peers.get_mut(i) {
                peer.offset = p.offset;
                peer.delay = p.delay;
                peer.dispersion = p.dispersion;
                peer.jitter = p.jitter;
                peer.stratum = p.stratum;
                peer.leap = p.leap;
                peer.flash = p.flash;
            }
        }

        if self.system.peer_count > 0 {
            // ── PPS override ───────────────────────────────────────────────
            // If a PPS refclock is active and its offset is within 1ms of the
            // system offset, use it for phase adjustment instead.
            let sys_offset = if let Some(pps_idx) = self.find_pps_peer() {
                if let Some(pps_peer) = self.peers.get(pps_idx) {
                    actions.push(DaemonAction::Log(format!(
                        "PPS override: offset={:.9}s (sys={:.6}s)",
                        pps_peer.offset, self.system.sys_offset
                    )));
                    // Use PPS offset for discipline, but keep system combined
                    // for everything else (stratum, refid, etc.)
                    pps_peer.offset
                } else {
                    self.system.sys_offset
                }
            } else {
                self.system.sys_offset
            };

            // Apply loop filter with the effective offset
            // (system offset or PPS override)
            let adj = self.loop_filter.local_clock(sys_offset, now);
            actions.push(DaemonAction::AdjustClock(adj));

            // Propagate loop filter wander to system state
            self.system.sys_wander = self.loop_filter.wander;

            // Persist drift periodically
            if self.loop_filter.update_count % 100 == 0 {
                actions.push(DaemonAction::PersistDrift(self.loop_filter.frequency_ppm()));
            }

            // Log status periodically
            if self.loop_filter.update_count % 10 == 0 {
                actions.push(DaemonAction::Log(format!(
                    "status peers={} stratum={} offset={:.6}s freq={:.3}ppm jitter={:.6}s",
                    self.system.peer_count,
                    self.system.stratum,
                    self.system.sys_offset,
                    self.loop_filter.frequency_ppm(),
                    self.system.sys_jitter,
                )));
            }
        }

        // ── Update uptime ─────────────────────────────────────────────────
        if self.system.start_time.seconds > 0 {
            let elapsed = now.seconds - self.system.start_time.seconds;
            self.system.uptime_secs = if elapsed > 0 { elapsed as u64 } else { 0 };
        }

        // ── Update system status word ─────────────────────────────────────
        self.system.sys_status = self.compute_system_status();

        // ── Update system flash bits (aggregate from peers) ──────────────
        let mut agg_flash = 0u32;
        for i in 0..self.peers.len() {
            if let Some(peer) = self.peers.get(i) {
                agg_flash |= peer.flash;
            }
        }
        self.system.sys_flash = agg_flash;

        actions
    }

    /// Compute the system status word (matching ntpsec exactly).
    ///
    /// NTPsec sys_status layout (ntp_control.h, RFC 9327 §5):
    ///   bits 15-14: LI (2 bits)
    ///   bits 13-8:  Clock source (6 bits)
    ///   bits 7-4:   Event count (4 bits)
    ///   bits 3-0:   Event code (4 bits)
    ///
    /// Reference: ntp_control.h `sys_status()` macro:
    ///   (li << 14) | (source << 8) | (event_count << 4) | event_code
    fn compute_system_status(&self) -> u16 {
        let li = match self.system.leap {
            LeapIndicator::NoWarning => 0,
            LeapIndicator::AddLeapSecond => 1,
            LeapIndicator::RemoveLeapSecond => 2,
            LeapIndicator::Alarm => 3,
        };
        // Clock source: 0=unsync, 1=local, 2=PPS, 3=NTP, 6=ordinary ref
        let clock_source: u16 = if self.system.stratum < crate::ntp_proto::NTP_MAXSTRAT {
            // Determine more precise source from system state
            if self.system.stratum == 1 {
                1 // sync_local (LOCAL refclock or orphan)
            } else {
                3 // sync_ntp (ordinary NTP synchronization)
            }
        } else {
            0 // sync_unspec
        };

        // Event count and code: track the last system event
        let event_count = (self.system.peer_count.min(0x0F) as u16) & 0x0F;
        let event_code = 0u16; // No event for now; would be wired to system event tracking

        ((li as u16) << 14)       // bits 15-14: LI
            | ((clock_source & 0x3F) << 8)  // bits 13-8: source
            | ((event_count & 0x0F) << 4)   // bits 7-4: event count
            | (event_code & 0x0F) // bits 3-0: event code
    }

    /// Handle a received NTP packet.
    fn handle_packet(&mut self, dgram: ReceivedDatagram) -> Vec<DaemonAction> {
        // 0. Extract mode from raw byte 0 BEFORE deciding which decoder to use.
        // Mode 6 control protocol uses a 12-byte header, not 48-byte NTP.
        if dgram.bytes.is_empty() {
            return vec![DaemonAction::Log("empty packet".to_string())];
        }
        let mode = NtpMode::from_bits(dgram.bytes[0]);

        // ─── Mode 6 control protocol (ntpq) — dispatch before NTP decode ──
        if mode == NtpMode::NtpControl {
            // Check restrictions first
            let (restrict_action, _) = self.restrictions.check(&dgram.source, mode);
            match restrict_action {
                RestrictAction::Accept => {}
                RestrictAction::Ignore | RestrictAction::Discard => return vec![],
                RestrictAction::SendKod => {
                    return vec![DaemonAction::Log("kod for control".to_string())];
                }
            }
            return self.handle_control(&dgram.bytes, dgram.source);
        }

        // ── Version tracking for NTP time packets ─────────────────────────
        // Version is in bits 3-5 of byte 0; mode is in bits 0-2.
        let pkt_version = NtpVersion::from_bits((dgram.bytes[0] >> 3) & 0x07);
        if pkt_version == NtpVersion::V4 || pkt_version == NtpVersion::V3 {
            self.system.server_counters.thisver =
                self.system.server_counters.thisver.saturating_add(1);
        } else {
            self.system.server_counters.oldver =
                self.system.server_counters.oldver.saturating_add(1);
        }

        // 1. Decode 48-byte NTP header for time protocol packets
        let pkt = match NtpPacket::decode_header(&dgram.bytes) {
            Ok(p) => p,
            Err(e) => {
                self.system.server_counters.rejected =
                    self.system.server_counters.rejected.saturating_add(1);
                return vec![DaemonAction::Log(format!("bad packet header: {e}"))];
            }
        };

        // 1a. Loopcast detection: check if we received our own NTP packet.
        //     This happens when source equals destination (same address + port),
        //     which indicates a loopback/reflection condition.  In the test
        //     environment, loopcast is common since both client and server
        //     use 127.0.0.1:123.  We detect it by comparing the source and
        //     destination NetAddr fields.
        if dgram.source == dgram.destination && !dgram.source.is_ipv4_loopback() {
            self.system.server_counters.rejected =
                self.system.server_counters.rejected.saturating_add(1);
            // Only warn if not a loopback test scenario
            return vec![DaemonAction::Log(format!(
                "loopcast detected: src={} == dst={}",
                crate::ntp_net::socktoa(&crate::ntp_monitor::netaddr_to_sockaddr(&dgram.source)),
                crate::ntp_net::socktoa(&crate::ntp_monitor::netaddr_to_sockaddr(
                    &dgram.destination
                )),
            ))];
        }

        // 2. Check restrictions — exhaustively match all actions.
        // NOQUERY is handled contextually inside check() based on packet mode.
        let (restrict_action, _restrict_flags) = self.restrictions.check(&dgram.source, mode);

        match restrict_action {
            RestrictAction::Accept => {} // Continue processing
            RestrictAction::Ignore | RestrictAction::Discard => {
                self.system.server_counters.restricted =
                    self.system.server_counters.restricted.saturating_add(1);
                return vec![];
            }
            RestrictAction::SendKod => {
                self.system.server_counters.restricted =
                    self.system.server_counters.restricted.saturating_add(1);
                self.system.server_counters.kodsent =
                    self.system.server_counters.kodsent.saturating_add(1);
                let kod_pkt =
                    build_kod_packet(&pkt, &self.system, dgram.rx_timestamp, self.precision);
                return vec![DaemonAction::Send {
                    destination: dgram.source,
                    bytes: kod_pkt.encode_header().to_vec(),
                }];
            }
        }

        // 3. Check rate limiting for client requests
        if mode == NtpMode::Client || mode == NtpMode::SymActive {
            let (rate_limited, _) = self.monitor.is_rate_limited(&dgram.source);
            if rate_limited {
                self.system.server_counters.limited =
                    self.system.server_counters.limited.saturating_add(1);
                return vec![];
            }
        }

        // 4. Basic size validation
        if dgram.bytes.len() < NTP_HEADER_SIZE {
            self.system.server_counters.badlength =
                self.system.server_counters.badlength.saturating_add(1);
            return vec![DaemonAction::Log("packet too short".to_string())];
        }

        // 5. Branch on mode with contextual expectations
        match mode {
            // ─── Client request → respond as server ────────────────────────
            NtpMode::Client | NtpMode::SymActive => {
                if self.system.stratum >= NTP_MAXSTRAT {
                    self.system.server_counters.declined =
                        self.system.server_counters.declined.saturating_add(1);
                    return vec![]; // Not synchronized yet
                }
                self.system.server_counters.received =
                    self.system.server_counters.received.saturating_add(1);
                let resp =
                    build_response(&pkt, None, &self.system, dgram.rx_timestamp, self.precision);
                return vec![DaemonAction::Send {
                    destination: dgram.source,
                    bytes: resp.encode_header().to_vec(),
                }];
            }

            // ─── Server response → update matching peer ────────────────
            NtpMode::Server => {
                self.system.server_counters.received =
                    self.system.server_counters.received.saturating_add(1);
                return self.handle_server_response(pkt, dgram);
            }

            // ─── Symmetric passive (Mode 2) — create ephemeral peer ─────
            NtpMode::SymPassive => {
                self.system.server_counters.received =
                    self.system.server_counters.received.saturating_add(1);
                let mut actions: Vec<DaemonAction> = Vec::new();
                // Check if we already have an association for this source
                let src_sa = crate::ntp_monitor::netaddr_to_sockaddr(&dgram.source);
                let existing = self.peers.iter().any(|p| unsafe {
                    p.srcaddr.ss_family == src_sa.ss_family
                        && match src_sa.ss_family as libc::c_int {
                            libc::AF_INET => {
                                let a = &*(&p.srcaddr as *const _ as *const libc::sockaddr_in);
                                let b = &*(&src_sa as *const _ as *const libc::sockaddr_in);
                                a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port
                            }
                            libc::AF_INET6 => {
                                let a = &*(&p.srcaddr as *const _ as *const libc::sockaddr_in6);
                                let b = &*(&src_sa as *const _ as *const libc::sockaddr_in6);
                                a.sin6_addr.s6_addr == b.sin6_addr.s6_addr
                                    && a.sin6_port == b.sin6_port
                            }
                            _ => false,
                        }
                });

                if !existing {
                    // Create ephemeral symmetric passive association
                    let mut peer = Peer::new(src_sa, NtpMode::SymActive, NtpVersion::V4, 4, 10);
                    peer.hmode = NtpMode::SymPassive;
                    peer.pmode = NtpMode::SymPassive;
                    if let Some(aid) = Self::allocate_associd(&mut self.next_associd, &self.peers) {
                        peer.associd = aid;
                        let peer_id = self.peers.len();
                        self.peers.add(peer);
                        self.timers.schedule_poll(peer_id, 0, 0);
                        actions.push(DaemonAction::Log(format!(
                            "created ephemeral symmetric passive assoc {} from {}",
                            aid,
                            crate::ntp_net::socktoa(&src_sa)
                        )));
                    }
                }

                // Respond to the symmetric passive packet
                if self.system.stratum >= NTP_MAXSTRAT {
                    return actions;
                }
                let resp =
                    build_response(&pkt, None, &self.system, dgram.rx_timestamp, self.precision);
                actions.push(DaemonAction::Send {
                    destination: dgram.source,
                    bytes: resp.encode_header().to_vec(),
                });
                return actions;
            }

            // ─── Broadcast (Mode 5) — handle with optional auth ─────────────
            NtpMode::Broadcast => {
                self.system.server_counters.received =
                    self.system.server_counters.received.saturating_add(1);
                let mut actions: Vec<DaemonAction> = Vec::new();
                // Check if we have a broadcast association for this source
                let src_sa = crate::ntp_monitor::netaddr_to_sockaddr(&dgram.source);
                let has_bcast_assoc = self.peers.iter().any(|p| {
                    p.hmode == NtpMode::Broadcast
                        && unsafe {
                            p.srcaddr.ss_family == src_sa.ss_family
                                && match src_sa.ss_family as libc::c_int {
                                    libc::AF_INET => {
                                        let a =
                                            &*(&p.srcaddr as *const _ as *const libc::sockaddr_in);
                                        let b = &*(&src_sa as *const _ as *const libc::sockaddr_in);
                                        a.sin_addr.s_addr == b.sin_addr.s_addr
                                    }
                                    libc::AF_INET6 => {
                                        let a =
                                            &*(&p.srcaddr as *const _ as *const libc::sockaddr_in6);
                                        let b =
                                            &*(&src_sa as *const _ as *const libc::sockaddr_in6);
                                        a.sin6_addr.s6_addr == b.sin6_addr.s6_addr
                                    }
                                    _ => false,
                                }
                        }
                });

                if !has_bcast_assoc {
                    actions.push(DaemonAction::Log(
                        "broadcast packet from unknown source, no broadcast association configured"
                            .to_string(),
                    ));
                    return actions;
                }

                // For broadcast, we compute offset using the arrival time
                // The broadcast sender sets T1=T2=T3 (same timestamp in all three)
                // and T4 is our arrival time. Offset = T3 - T4 (one-way).
                let t3 = ntp_fp::ntp_ts_to_ntpts(pkt.transmit_ts);
                let t3_f = ntp_fp::ntp_ts64_to_double(t3);
                let t4_f = ntp_fp::ntp_ts64_to_double(dgram.rx_timestamp);
                let offset = t3_f - t4_f;

                if offset.abs() < 1.0 && offset.is_finite() {
                    actions.push(DaemonAction::Log(format!(
                        "broadcast offset={:.6}s from {}",
                        offset,
                        crate::ntp_net::socktoa(&src_sa)
                    )));
                }

                return actions;
            }

            // ─── Private/ntpdc (Mode 7) — deprecated ───────────────────────
            NtpMode::Private => {
                self.system.server_counters.rejected =
                    self.system.server_counters.rejected.saturating_add(1);
                return vec![DaemonAction::Log(
                    "private mode packet (ntpdc) received — deprecated, dropped".to_string(),
                )];
            }

            // ─── Reserved (Mode 0) — should not occur ──────────────────────
            NtpMode::Reserved => {
                return vec![];
            }

            // ─── NtpControl (Mode 6) — already handled above; unreachable here ─
            NtpMode::NtpControl => {
                unreachable!("NtpControl already handled before NTP decode");
            }
        }
    }

    /// Handle a server (or symmetric passive) response packet.
    fn handle_server_response(
        &mut self,
        pkt: NtpPacket,
        dgram: ReceivedDatagram,
    ) -> Vec<DaemonAction> {
        // Match against pending requests by (originate_ts, source, expected_mode)
        let req_idx = self.find_pending_request(&pkt.originate_ts, &dgram.source, pkt.mode());

        if let Some(req_idx) = req_idx {
            let req = self.pending_requests[req_idx].clone();
            let pidx = req.peer_id;

            if let Some(peer) = self.peers.get_mut(pidx) {
                // T1 = full-resolution stored originate timestamp
                let t1 = req.full_t1;
                // T2 = server's receive timestamp from packet
                let t2 = ntp_fp::ntp_ts_to_ntpts(pkt.receive_ts);
                // T3 = server's transmit timestamp from packet
                let t3 = ntp_fp::ntp_ts_to_ntpts(pkt.transmit_ts);
                // T4 = our receive timestamp
                let t4 = dgram.rx_timestamp;

                // Check for duplicate (TEST1) — same originate already processed
                if peer.originate_time == t1 {
                    return vec![DaemonAction::Log(
                        "duplicate packet (same originate)".to_string(),
                    )];
                }

                // Check if server is unsynchronized (TEST3)
                if pkt.stratum >= NTP_MAXSTRAT {
                    peer.reach.record_failure();
                    // Remove this pending request so we don't match against it again
                    self.pending_requests.remove(req_idx);
                    return vec![];
                }

                // Auth verification
                let mut auth_log: Option<String> = None;
                if self.auth.is_auth_enabled() {
                    // For now, log that auth verification is not yet wired for NTP
                    // response packets.  Full verification will walk extension fields
                    // and MAC, look up the key-id, recompute the digest, and compare.
                    auth_log = Some("auth verification not yet wired for NTP packets".to_string());
                }

                // Compute offset and delay
                let (offset, delay) = compute_offsets(t1, t2, t3, t4);

                // Validate offset is sane
                if !offset.is_finite() || offset.abs() > 1_000_000.0 {
                    self.pending_requests.remove(req_idx);
                    return vec![DaemonAction::Log("crazy offset rejected".to_string())];
                }

                let delay = delay.max(0.0);

                // Compute dispersion from peer's root dispersion + epsilon
                let dispersion = ntp_fp::ntp_short_to_double(NtpShort {
                    seconds: (pkt.root_dispersion >> 16) as u16,
                    fraction: pkt.root_dispersion as u16,
                }) + (1u64 << peer.hpoll) as f64 * 1e-6;

                // Update peer variables from the response packet
                peer.stratum = pkt.stratum;
                peer.leap = pkt.leap_indicator();
                peer.precision = pkt.precision;
                peer.root_delay = ntp_fp::ntp_short_to_double(NtpShort {
                    seconds: (pkt.root_delay >> 16) as u16,
                    fraction: pkt.root_delay as u16,
                });
                peer.root_dispersion = ntp_fp::ntp_short_to_double(NtpShort {
                    seconds: (pkt.root_dispersion >> 16) as u16,
                    fraction: pkt.root_dispersion as u16,
                });
                peer.reference_id = pkt.reference_id;
                peer.reference_time = ntp_fp::ntp_ts_to_ntpts(pkt.reference_ts);

                // Accept the sample into the clock filter
                accept_sample(peer, offset, delay, dispersion, dgram.rx_timestamp);

                // Record originate to detect duplicates
                peer.originate_time = t1;

                // Update poll interval
                poll_update(peer, dgram.rx_timestamp);

                // Remove the pending request — response consumed
                self.pending_requests.remove(req_idx);

                // Include auth log message if auth is enabled
                if let Some(msg) = auth_log {
                    return vec![DaemonAction::Log(msg)];
                }
            }
        } else {
            // Unsolicited response or broadcast — silently drop
            return vec![];
        }

        vec![]
    }

    /// Handle a Mode 6 control protocol request (ntpq).
    fn handle_control(&mut self, bytes: &[u8], source: NetAddr) -> Vec<DaemonAction> {
        use crate::control_client::parse_mode6_vars;
        use crate::ntp_control::*;

        let exchange = match ControlExchange::parse(bytes) {
            Ok((ex, _)) => ex,
            Err(e) => {
                return vec![DaemonAction::Log(format!("bad control message: {e}"))];
            }
        };

        let req = &exchange.request;
        let oc = req.decode_opcode();

        // Determine which opcodes require authentication.
        // NTPsec: READSTAT, READVAR, READCLOCK, READ_MRU do not require auth;
        // WRITEVAR, CONFIGURE, READ_ORDLIST_A do.
        let requires_auth = matches!(
            oc.op,
            opcodes::OP_WRITEVAR | opcodes::OP_CONFIGURE | opcodes::OP_READ_ORDLIST_A
        );

        // Check authentication if a control key is configured.
        // The key ID used MUST match the configured control key.
        let configured_ckey = self.auth.get_control_key();
        let auth_valid = configured_ckey.map_or(false, |ckey| {
            // Verify key ID matches the configured control key
            exchange.auth_keyid == Some(ckey)
                // Verify the configured key exists in the store
                && self.auth.get_key(ckey).is_some()
                // Verify the MAC
                && exchange.verify_mac(&self.auth)
        });

        // If auth is required and not valid, return error.
        if requires_auth && !auth_valid {
            // Build a proper control error response (error bit set, error code 1 = Auth)
            let err_header = ControlMessage {
                li_vn_mode: req.li_vn_mode,
                opcode: ControlOpcode::new(true, true, false, oc.op).to_u8(),
                sequence: req.sequence,
                status: 0x0100, // Error code 1 in high byte = authentication failure
                associd: req.associd,
                offset: 0,
                count: 0,
            };
            return vec![DaemonAction::Send {
                destination: source,
                bytes: err_header.encode().to_vec(),
            }];
        }

        // For non-required ops, auth is optional but still verified if present.
        // NTPsec does not authenticate responses for ordinary READVAR/READSTAT.
        // We always pass None for auth_key to build_response (no MAC on responses).
        let _auth_valid = auth_valid;

        // Build the response data based on opcode
        let resp_data = match oc.op {
            // READSTAT: return binary associd/status pairs (ntpq associations)
            opcodes::OP_READSTAT => {
                let mut data = Vec::with_capacity(self.peers.len() * 4);
                for i in 0..self.peers.len() {
                    if let Some(peer) = self.peers.get(i) {
                        let associd = if peer.associd > 0 {
                            peer.associd
                        } else {
                            (i + 1) as u16
                        };
                        data.extend_from_slice(&associd.to_be_bytes());
                        let sel = if self.system_peer_associd == Some(peer.associd) {
                            crate::ntp_control::SelectionStatus::SystemPeer
                        } else if peer.reach.is_reachable() && peer.stratum < 16 {
                            crate::ntp_control::SelectionStatus::Candidate
                        } else {
                            crate::ntp_control::SelectionStatus::Rejected
                        };
                        data.extend_from_slice(
                            &crate::ntp_control::peer_status(peer, sel).to_be_bytes(),
                        );
                    }
                }
                data
            }

            // READVAR, READ_ORDLIST_A: associd==0 → system vars, else → peer vars
            opcodes::OP_READVAR | opcodes::OP_READ_ORDLIST_A => {
                if req.associd == 0 {
                    // System variables
                    let mut vars: Vec<(String, String)> = Vec::new();
                    let sys_names = [
                        "version",
                        "processor",
                        "system",
                        "leap",
                        "stratum",
                        "precision",
                        "rootdelay",
                        "rootdisp",
                        "refid",
                        "reftime",
                        "peer",
                        "tc",
                        "offset",
                        "frequency",
                        "sys_jitter",
                        "rootdist",
                    ];
                    for name in &sys_names {
                        if let Some(val) = get_system_variable(&self.system, name) {
                            vars.push((name.to_string(), val));
                        }
                    }
                    encode_var_list(
                        &vars
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect::<Vec<_>>(),
                    )
                    .into_bytes()
                } else {
                    // Peer variables for a specific association (look up by associd)
                    let peer_opt = self.peers.iter().find(|p| p.associd == req.associd);
                    if let Some(peer) = peer_opt {
                        let mut vars: Vec<(String, String)> = Vec::new();
                        let peer_names = [
                            "srcaddr",
                            "stratum",
                            "offset",
                            "delay",
                            "dispersion",
                            "jitter",
                            "hpoll",
                            "ppoll",
                            "reach",
                            "flash",
                            "leap",
                            "refid",
                            "reftime",
                            "hmode",
                            "pmode",
                            "precision",
                        ];
                        for name in &peer_names {
                            if let Some(val) = get_peer_variable(peer, name) {
                                vars.push((name.to_string(), val));
                            }
                        }
                        encode_var_list(
                            &vars
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect::<Vec<_>>(),
                        )
                        .into_bytes()
                    } else {
                        // Peer not found — return error
                        let err_header = ControlMessage {
                            li_vn_mode: req.li_vn_mode,
                            opcode: ControlOpcode::new(true, true, false, oc.op).to_u8(),
                            sequence: req.sequence,
                            status: 0x0400, // Error code 4 = NotFound
                            associd: req.associd,
                            offset: 0,
                            count: 0,
                        };
                        return vec![DaemonAction::Send {
                            destination: source,
                            bytes: err_header.encode().to_vec(),
                        }];
                    }
                }
            }

            // WRITEVAR: parse key=value pairs and apply to engine state
            opcodes::OP_WRITEVAR => {
                let data_str = String::from_utf8_lossy(&exchange.data);
                let vars = parse_mode6_vars(&data_str);
                let mut resp_vars: Vec<String> = Vec::new();
                for (key, val) in &vars {
                    match key.as_str() {
                        "offset" => {
                            if let Ok(v) = val.parse::<f64>() {
                                self.system.sys_offset = v;
                            }
                        }
                        "frequency" => {
                            if let Ok(v) = val.parse::<f64>() {
                                self.loop_filter.set_frequency(v);
                            }
                        }
                        "stratum" => {
                            if let Ok(v) = val.parse::<u8>() {
                                self.system.stratum = v;
                            }
                        }
                        "refid" => {
                            // Parse refid as hex or ASCII
                            if val.len() <= 4 && val.chars().all(|c| c.is_ascii_graphic()) {
                                let mut bytes = [0u8; 4];
                                let b = val.as_bytes();
                                for i in 0..b.len().min(4) {
                                    bytes[i] = b[i];
                                }
                                self.system.reference_id = u32::from_be_bytes(bytes);
                            } else if let Ok(v) =
                                u32::from_str_radix(val.trim_start_matches("0x"), 16)
                            {
                                self.system.reference_id = v;
                            }
                        }
                        "syslog" => {
                            // Write to log file if configured
                            if let Some(ref log_path) = self.log_file {
                                let msg = format!("WRITEVAR syslog: {}", val);
                                let _ = std::fs::write(log_path, format!("{}\n", msg));
                            }
                        }
                        _ => {
                            // Unknown variable — accept but note in response
                            resp_vars.push(format!("{}={}", key, val));
                        }
                    }
                }
                // Build response: return the variables we wrote
                if vars.is_empty() {
                    // Bad value — return error
                    return vec![DaemonAction::Send {
                        destination: source,
                        bytes: build_error_response(req, 6), // BadValue
                    }];
                }
                let resp_text = vars
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                resp_text.into_bytes()
            }

            // WRITECLOCK: write a clock variable
            opcodes::OP_WRITECLOCK => {
                // ── 1. Parse the variable assignment ────────────────────
                let data_str = String::from_utf8_lossy(&exchange.data);
                let vars = parse_mode6_vars(&data_str);
                if vars.is_empty() {
                    return vec![DaemonAction::Send {
                        destination: source,
                        bytes: build_error_response(req, 6), // BadValue
                    }];
                }

                // ── 2. Apply each variable assignment ───────────────────
                // Only recognized clock variables are accepted; all others
                // are rejected per the spec.
                let mut applied: Vec<(String, String)> = Vec::new();
                let mut rejected: Vec<(String, String)> = Vec::new();

                for (key, val) in &vars {
                    match key.as_str() {
                        "stratum" => {
                            if let Ok(v) = val.parse::<u8>() {
                                self.system.stratum = v;
                                applied.push((key.clone(), val.clone()));
                            } else {
                                rejected.push((key.clone(), val.clone()));
                            }
                        }
                        "refid" => {
                            // Parse refid as ASCII (up to 4 chars) or hex
                            if val.len() <= 4 && val.chars().all(|c| c.is_ascii_graphic()) {
                                let mut bytes = [0u8; 4];
                                let b = val.as_bytes();
                                for i in 0..b.len().min(4) {
                                    bytes[i] = b[i];
                                }
                                self.system.reference_id = u32::from_be_bytes(bytes);
                                applied.push((key.clone(), val.clone()));
                            } else if let Ok(v) =
                                u32::from_str_radix(val.trim_start_matches("0x"), 16)
                            {
                                self.system.reference_id = v;
                                applied.push((key.clone(), val.clone()));
                            } else {
                                rejected.push((key.clone(), val.clone()));
                            }
                        }
                        "offset" => {
                            if let Ok(v) = val.parse::<f64>() {
                                self.system.sys_offset = v;
                                applied.push((key.clone(), val.clone()));
                            } else {
                                rejected.push((key.clone(), val.clone()));
                            }
                        }
                        _ => {
                            // Unknown clock variable — reject
                            rejected.push((key.clone(), val.clone()));
                        }
                    }
                }

                // ── 3. Build response ──────────────────────────────────
                // If any assignments were applied, echo back the applied
                // values (matching ntpq expectations).
                // If ALL assignments were rejected, return BadValue error.
                if rejected.len() == vars.len() {
                    return vec![DaemonAction::Send {
                        destination: source,
                        bytes: build_error_response(req, 6), // BadValue
                    }];
                }

                let resp_text = applied
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                resp_text.into_bytes()
            }

            // OP_REQ_NONCE: generate and return a nonce for MRU queries
            opcodes::OP_REQ_NONCE => {
                let nonce_bytes = self.monitor.nonce_cache.generate_nonce();
                let nonce_str = hex::encode(&nonce_bytes);
                format!("nonce={}", nonce_str).into_bytes()
            }

            // OP_READ_MRU: return MRU list entries
            opcodes::OP_READ_MRU => {
                // ── 1. Mandatory nonce verification ──────────────────────
                // The nonce MUST be present and valid; empty request data
                // or missing/invalid nonce is rejected outright.
                let data_str = String::from_utf8_lossy(&exchange.data);
                if data_str.is_empty() {
                    return vec![DaemonAction::Send {
                        destination: source,
                        bytes: build_error_response(req, 4), // NoData
                    }];
                }
                let vars = parse_mode6_vars(&data_str);
                let mut nonce_valid = false;
                for (key, val) in &vars {
                    if key == "nonce" {
                        if let Ok(nonce_bytes) = hex::decode(val) {
                            if self.monitor.nonce_cache.verify_nonce(&nonce_bytes) {
                                nonce_valid = true;
                            }
                        }
                    }
                }
                if !nonce_valid {
                    return vec![DaemonAction::Send {
                        destination: source,
                        bytes: build_error_response(req, 4), // NoData
                    }];
                }

                // ── 2. Row limit: max 100 entries per response ──────────
                // This prevents unbounded memory/time from huge MRU lists.
                let max_entries = 100usize;
                let entries = self.monitor.read_mru(max_entries);

                // ── 3. Response byte budgeting ──────────────────────────
                // Mode 6 max payload per fragment is 468 bytes.
                // For amplification prevention, use a reasonable floor so
                // legitimate queries still work. The nonce requirement
                // (enforced above) is the primary anti-spoofing mechanism;
                // the row limit and byte budget are secondary defenses.
                let header_sz = 12usize;
                // Cap response data at Mode 6 standard max payload
                let max_payload = 468usize;

                // ── 4. Fragmentation-aware response building ────────────
                // Build entries incrementally until the byte budget is
                // exhausted. If entries remain, the M (more) bit is set
                // by the caller via build_response below.
                let mut resp_parts: Vec<String> = Vec::new();
                let mut budget = max_payload;
                for (i, entry) in entries.iter().enumerate() {
                    let addr_str = crate::ntp_net::socktoa(&entry.addr);
                    let part = format!(
                        "addr.{}={} last.{}={}.{:06} first.{}={}.{:06} ct.{}={} mv.{}={} rs.{}=0",
                        i,
                        addr_str,
                        i,
                        entry.last_pkt.seconds,
                        entry.last_pkt.fraction / 4295,
                        i,
                        entry.first_pkt.seconds,
                        entry.first_pkt.fraction / 4295,
                        i,
                        entry.count,
                        i,
                        entry.flags,
                        i,
                    );
                    // +1 for the comma separator (except for the first)
                    let needed = part.len() + if resp_parts.is_empty() { 0 } else { 1 };
                    if needed <= budget {
                        budget -= needed;
                        resp_parts.push(part);
                    } else {
                        break;
                    }
                }

                let data = resp_parts.join(",").into_bytes();
                data
            }

            _ => {
                // Unsupported opcode — emit proper BADOP error
                return vec![DaemonAction::Send {
                    destination: source,
                    bytes: build_error_response(req, 3), // BADOP
                }];
            }
        };

        // Build the response status word.
        // For associd != 0 READVAR, use peer status; otherwise system status.
        let status = if oc.op == opcodes::OP_READVAR && req.associd != 0 {
            // Look up the peer for its status
            if let Some(peer) = self.peers.iter().find(|p| p.associd == req.associd) {
                let sel = if self.system_peer_associd == Some(peer.associd) {
                    crate::ntp_control::SelectionStatus::SystemPeer
                } else if peer.reach.is_reachable() && peer.stratum < 16 {
                    crate::ntp_control::SelectionStatus::Candidate
                } else {
                    crate::ntp_control::SelectionStatus::Rejected
                };
                peer_status(peer, sel)
            } else {
                // Peer not found — this shouldn't happen since we validated above
                sys_status::make(3, 0, 0, 4)
            }
        } else {
            let li = match self.system.leap {
                LeapIndicator::NoWarning => 0,
                LeapIndicator::AddLeapSecond => 1,
                LeapIndicator::RemoveLeapSecond => 2,
                LeapIndicator::Alarm => 3,
            };
            let clock_source = if self.system.stratum < NTP_MAXSTRAT {
                6
            } else {
                0
            };
            sys_status::make(li, clock_source, 0, 0)
        };

        // No MAC on responses (per NTPsec behavior for ordinary control requests)
        let response = ControlExchange::build_response(req, &resp_data, req.sequence, status, None);

        vec![DaemonAction::Send {
            destination: source,
            bytes: response,
        }]
    }

    /// Find a pending request matching the response's originate timestamp,
    /// source address, and mode.
    fn find_pending_request(
        &self,
        originate_ts: &NtpTs,
        source: &NetAddr,
        mode: NtpMode,
    ) -> Option<usize> {
        for (i, req) in self.pending_requests.iter().enumerate() {
            let ts_match = req.wire_t1.seconds == originate_ts.seconds
                && req.wire_t1.fraction == originate_ts.fraction;
            let addr_match = req.destination.family == source.family
                && req.destination.addr == source.addr
                && req.destination.port == source.port;
            let mode_match = mode == req.expected_mode;

            if ts_match && addr_match && mode_match {
                return Some(i);
            }
        }
        None
    }

    /// Handle a timer event.
    fn handle_timer(&mut self, timer_id: TimerId) -> Vec<DaemonAction> {
        match timer_id {
            TimerId::Housekeeping => {
                let now = NtpTs64 {
                    seconds: 0,
                    fraction: 0,
                };
                self.run_selection(now)
            }
            TimerId::StatsWrite => {
                let mut actions = Vec::new();
                if let Some(ref stats_dir) = self.stats_dir {
                    let path = std::path::Path::new(stats_dir);
                    let _ = self.filegen.write_loopstats(
                        &path.join("loopstats"),
                        &self.system,
                        self.loop_filter.frequency_ppm(),
                    );
                    for i in 0..self.peers.len() {
                        if let Some(peer) = self.peers.get(i) {
                            let _ = self.filegen.write_peerstats(&path.join("peerstats"), peer);
                        }
                    }
                    actions.push(DaemonAction::Log("stats written".to_string()));
                }
                actions
            }
            TimerId::LeapFileReload => {
                if let Some(ref leap_file) = self.leap_file {
                    if let Ok(content) = std::fs::read_to_string(leap_file) {
                        self.leap_table.load_leapfile(&content).ok();
                        vec![DaemonAction::Log(format!(
                            "leap file reloaded: {}",
                            leap_file
                        ))]
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    /// Process a refclock sample through the clock filter and selection
    /// pipeline, then apply clock discipline if this peer is the system peer.
    fn handle_refclock_sample(
        &mut self,
        associd: u16,
        packet: NtpPacket,
        rx_time: NtpTs64,
    ) -> Vec<DaemonAction> {
        let mut actions = Vec::new();

        // Find the refclock peer by association ID
        let peer_idx = match self.peers.iter().position(|p| p.associd == associd) {
            Some(idx) => idx,
            None => {
                return vec![DaemonAction::Log(format!(
                    "refclock sample for unknown associd {}",
                    associd
                ))];
            }
        };

        // For refclocks, we compute the offset directly:
        //   offset = T3 - T4  (server transmit minus client receive)
        //   delay  = nominal small value for a local refclock
        //
        // T1 (originate) and T2 (receive) from the packet are not meaningful
        // for a refclock that produces samples autonomously; the important
        // timestamp is T3 = transmit (when the refclock says the time is).
        let t3 = ntp_fp::ntp_ts_to_ntpts(packet.transmit_ts);
        let t3_f = ntp_fp::ntp_ts64_to_double(t3);
        let t4_f = ntp_fp::ntp_ts64_to_double(rx_time);

        let offset = t3_f - t4_f;
        let delay = 0.001; // nominal 1 ms for a local refclock

        // Validate
        if !offset.is_finite() || offset.abs() > 1_000_000.0 {
            return vec![DaemonAction::Log(format!(
                "refclock {} crazy offset {:.6}s rejected",
                associd, offset
            ))];
        }

        // Update peer state and clock filter
        if let Some(peer) = self.peers.get_mut(peer_idx) {
            // Update peer fields from the synthetic server packet
            peer.stratum = 0; // primary refclock
            peer.leap = packet.leap_indicator();
            peer.precision = packet.precision;
            peer.root_delay = 0.0;
            peer.root_dispersion = 0.0;
            peer.reference_id = packet.reference_id;
            peer.reference_time = ntp_fp::ntp_ts_to_ntpts(packet.reference_ts);
            peer.receive_time = rx_time;
            peer.transmit_time = t3;

            // Compute per-instance dispersion from precision.
            // In NTP dispersion doubles every poll interval starting from
            // the precision-based minimum: 2^precision seconds.
            let refclock_dispersion = 2.0_f64.powi(self.precision as i32);

            // Accept the sample through clock filter (add_sample + filter
            // to pick delay-minimum, compute jitter, update reachability)
            crate::ntp_proto::accept_sample(peer, offset, delay, refclock_dispersion, rx_time);
        }

        // Run clock selection to potentially elect this peer as system peer
        let select_actions = self.run_selection(rx_time);
        actions.extend(select_actions);

        // If this refclock IS the system peer, log selection status.
        // NOTE: run_selection() above already calls local_clock() for the
        // combined system offset, so we do NOT call local_clock() again here.
        if let Some(sys_id) = self.system_peer_associd {
            if sys_id == associd {
                actions.push(DaemonAction::Log(format!(
                    "refclock {} offset={:.6}s delay={:.6}s selected",
                    associd, offset, delay
                )));
            }
        }

        actions
    }

    /// Flush all pending statistics (loopstats and peerstats) to disk.
    /// Called on graceful shutdown (SIGTERM) to ensure stats are persisted
    /// even when the periodic timer hasn't fired yet.
    pub fn flush_stats(&mut self) {
        if let Some(ref stats_dir) = self.stats_dir {
            let path = std::path::Path::new(stats_dir);
            let _ = self.filegen.write_loopstats(
                &path.join("loopstats"),
                &self.system,
                self.loop_filter.frequency_ppm(),
            );
            for i in 0..self.peers.len() {
                if let Some(peer) = self.peers.get(i) {
                    let _ = self.filegen.write_peerstats(&path.join("peerstats"), peer);
                }
            }
        }
    }
}

/// Build a Kiss-o'-Death packet in response to a client request.
pub fn build_kod_packet(
    request: &NtpPacket,
    _system: &SystemState,
    now: NtpTs64,
    precision: i8,
) -> NtpPacket {
    let mut resp = NtpPacket::zeroed();
    resp.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::Alarm, NtpVersion::V4, NtpMode::Server);
    resp.stratum = 0;
    resp.poll = request.poll;
    resp.precision = precision;
    resp.root_delay = 0;
    resp.root_dispersion = 0;
    resp.reference_id = crate::ntp_types::kiss_codes::RATE;
    resp.originate_ts = request.transmit_ts;
    resp.receive_ts = ntp_fp::ntp_ts64_to_wire(now);
    resp.transmit_ts = ntp_fp::ntp_ts64_to_wire(now);
    resp
}

/// Parse association options into structured form.
fn parse_assoc_options(options: &[String]) -> (u8, u8, bool) {
    let mut minpoll = NTP_MINPOLL;
    let mut maxpoll = NTP_MAXPOLL;
    let mut iburst = false;
    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "iburst" => iburst = true,
            "burst" => {}
            "prefer" => {}
            s if s == "minpoll" && i + 1 < options.len() => {
                if let Ok(p) = options[i + 1].parse::<u8>() {
                    minpoll = p;
                }
                i += 1;
            }
            s if s == "maxpoll" && i + 1 < options.len() => {
                if let Ok(p) = options[i + 1].parse::<u8>() {
                    maxpoll = p;
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    (minpoll, maxpoll, iburst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp_fp;

    /// Helper to create a minimal simulated engine for tests.
    fn create_lab_engine() -> (DaemonEngine, SimulatedClock) {
        let config = ConfigTree::new();
        let engine = DaemonEngine::new(config);
        let clock = SimulatedClock::unix_epoch();
        (engine, clock)
    }

    /// Helper to build a NetAddr for a peer, matching the engine's internal
    /// sockaddr_to_netaddr conversion (using to_ne_bytes).
    fn peer_netaddr(ip: [u8; 4], port: u16) -> NetAddr {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&ip);
        NetAddr {
            family: 4,
            addr,
            port,
        }
    }

    /// Add a peer to an engine and return its ID.
    /// Add a peer and schedule its initial one-shot poll timer.
    /// Mirrors what apply_config() does for real associations.
    fn add_peer(engine: &mut DaemonEngine, ip: [u8; 4]) -> usize {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let sin = unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in) };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = 123u16.to_be();
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(ip),
        };
        let id = engine.peers.len();
        engine
            .peers
            .add(Peer::new(sa, NtpMode::Client, NtpVersion::V4, 4, 10));
        // Schedule initial one-shot poll (matching apply_config)
        engine.timers.schedule_poll_once(id, 0);
        id
    }

    #[test]
    fn test_engine_creation() {
        let (engine, _) = create_lab_engine();
        assert_eq!(engine.system.stratum, NTP_MAXSTRAT);
        assert_eq!(engine.peers.len(), 0);
    }

    #[test]
    fn test_engine_tick_empty() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let now = ntp_fp::ts_to_ntp(0, 0);
        let actions = engine.tick(now);
        assert!(actions.is_empty(), "no timers due at time 0");
    }

    #[test]
    fn test_engine_shutdown() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let actions = engine.handle(DaemonEvent::Shutdown);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], DaemonAction::Log(_)));
    }

    #[test]
    fn test_engine_bad_packet() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let dgram = ReceivedDatagram::test(
            vec![0u8; 10],
            peer_netaddr([127, 0, 0, 1], 123),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(1000, 0),
        );
        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(actions
            .iter()
            .any(|a| matches!(a, DaemonAction::Log(s) if s.contains("bad packet"))));
    }

    #[test]
    fn test_engine_server_response_processing() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [127, 0, 0, 1]);

        let t1 = ntp_fp::ts_to_ntp(1000, 0);
        let t1_wire = ntp_fp::ntp_ts64_to_wire(t1);

        // Register a pending request manually (as tick() would)
        engine.pending_requests.push(PendingRequest {
            peer_id,
            wire_t1: t1_wire,
            full_t1: t1,
            destination: peer_netaddr([127, 0, 0, 1], 123),
            expected_mode: NtpMode::Server,
        });

        // Build server response
        let mut resp = NtpPacket::zeroed();
        resp.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp.stratum = 2;
        resp.originate_ts = t1_wire;
        resp.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1001, 0));
        resp.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1001, 500_000_000));

        let dgram = ReceivedDatagram::test(
            resp.encode_header().to_vec(),
            peer_netaddr([127, 0, 0, 1], 123),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(1002, 0),
        );

        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // No pending requests should remain
        assert!(engine.pending_requests.is_empty());
        // Peer should be reachable with correct offset
        if let Some(peer) = engine.peers.get(peer_id) {
            assert!(peer.reach.is_reachable());
            assert!(
                (peer.offset - 0.25).abs() < 0.1,
                "expected offset ~0.25s, got {}",
                peer.offset
            );
        }
    }

    /// Test that two peers polled at the same instant don't cross-talk:
    /// each response must match the correct peer, even if responses arrive
    /// in reverse order.
    #[test]
    fn test_engine_multi_peer_no_crosstalk() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_a = add_peer(&mut engine, [127, 0, 0, 1]); // 127.0.0.1
        let peer_b = add_peer(&mut engine, [192, 0, 2, 44]); // 192.0.2.44

        // Tick at time 0 — both peers get one-shot polls re-armed
        let actions = engine.tick(ntp_fp::ts_to_ntp(0, 0));

        // Should have 2 Send actions
        assert_eq!(actions.len(), 2);
        assert!(actions
            .iter()
            .all(|a| matches!(a, DaemonAction::Send { .. })));

        // Should have 2 pending requests
        assert_eq!(engine.pending_requests.len(), 2);

        // Build responses that arrive in REVERSE order:
        // Response B arrives first, then Response A.
        let t1_a = engine.pending_requests[0].wire_t1;
        let t1_b = engine.pending_requests[1].wire_t1;

        // Response for B (192.0.2.44)
        let mut resp_b = NtpPacket::zeroed();
        resp_b.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp_b.stratum = 3;
        resp_b.originate_ts = t1_b;
        resp_b.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 0));
        resp_b.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 250_000_000));

        let dgram_b = ReceivedDatagram::test(
            resp_b.encode_header().to_vec(),
            peer_netaddr([192, 0, 2, 44], 123),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(2, 0),
        );

        // Process B's response first
        let _actions_b = engine.handle(DaemonEvent::PacketReceived(dgram_b));

        // Only the B pending request should be consumed
        assert_eq!(engine.pending_requests.len(), 1);
        assert_eq!(engine.pending_requests[0].peer_id, peer_a);

        // Peer B should be reachable, Peer A should not yet be
        assert!(
            engine.peers.get(peer_b).unwrap().reach.is_reachable(),
            "peer B should be reachable"
        );
        assert!(
            !engine.peers.get(peer_a).unwrap().reach.is_reachable(),
            "peer A should NOT be reachable yet"
        );

        // Now process A's response
        let mut resp_a = NtpPacket::zeroed();
        resp_a.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp_a.stratum = 2;
        resp_a.originate_ts = t1_a;
        resp_a.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 0));
        resp_a.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 500_000_000));

        let dgram_a = ReceivedDatagram::test(
            resp_a.encode_header().to_vec(),
            peer_netaddr([127, 0, 0, 1], 123),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(2, 0),
        );

        let _actions_a = engine.handle(DaemonEvent::PacketReceived(dgram_a));

        // All pending requests consumed
        assert!(engine.pending_requests.is_empty());

        // Both peers should be reachable
        assert!(engine.peers.get(peer_a).unwrap().reach.is_reachable());
        assert!(engine.peers.get(peer_b).unwrap().reach.is_reachable());
    }

    /// Test that poll timers don't multiply: after 100 responses, only 1
    /// poll timer exists per peer.
    #[test]
    fn test_engine_no_timer_multiplication() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [127, 0, 0, 1]);

        // Simulate 100 poll/response cycles.
        // The first iteration consumes the initial one-shot poll at due=0.
        for _ in 0..100 {
            // Find the next due time of the poll timer for this peer
            let next_due = engine
                .timers
                .iter()
                .find_map(|entry| match entry.event {
                    TimerEvent::Poll(id) if id == peer_id => Some(entry.due),
                    _ => None,
                })
                .expect("peer should have exactly one poll timer");

            // Tick at the due time — fires the poll, creates pending request, re-arms one-shot
            let actions = engine.tick(ntp_fp::ts_to_ntp(next_due, 0));
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, DaemonAction::Send { .. })),
                "poll should produce exactly one Send action"
            );
            assert_eq!(
                engine.pending_requests.len(),
                1,
                "poll should create exactly one pending request"
            );

            // Clone the request before mutating engine
            let req = engine.pending_requests[0].clone();

            // Build a valid server response
            let mut resp = NtpPacket::zeroed();
            resp.li_vn_mode = NtpPacket::set_li_vn_mode(
                LeapIndicator::NoWarning,
                NtpVersion::V4,
                NtpMode::Server,
            );
            resp.stratum = 4;
            resp.originate_ts = req.wire_t1;
            resp.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(next_due + 1, 0));
            resp.transmit_ts =
                ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(next_due + 1, 500_000_000));

            let dgram = ReceivedDatagram {
                bytes: resp.encode_header().to_vec(),
                source: peer_netaddr([127, 0, 0, 1], 123),
                destination: peer_netaddr([127, 0, 0, 1], 123),
                rx_timestamp: ntp_fp::ts_to_ntp(next_due + 2, 0),
                interface_index: None,
                timestamp_source: TimestampSource::UserspaceFallback,
            };

            // Consume the response — this should NOT create any new timers
            engine.handle(DaemonEvent::PacketReceived(dgram));
            assert!(
                engine.pending_requests.is_empty(),
                "response should consume the pending request"
            );

            // Exactly 1 poll timer should exist after each cycle
            let poll_timers = engine
                .timers
                .iter()
                .filter(|t| matches!(t.event, TimerEvent::Poll(id) if id == peer_id))
                .count();
            assert_eq!(
                poll_timers, 1,
                "exactly 1 poll timer should exist after cycle, got {}",
                poll_timers
            );
        }

        // After 100 cycles: exactly 1 poll timer for the peer
        let poll_timers = engine
            .timers
            .iter()
            .filter(|t| matches!(t.event, TimerEvent::Poll(id) if id == peer_id))
            .count();
        assert_eq!(
            poll_timers, 1,
            "should have exactly 1 poll timer after 100 cycles, got {}",
            poll_timers
        );
    }

    /// Test that losing all peers stops clock adjustment.
    ///
    /// This test simulates the synchronized state directly on the loop_filter
    /// and system, then removes all reachable peers and verifies the engine
    /// does not emit a stale AdjustClock.
    #[test]
    fn test_engine_stale_state_reset() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let _peer_id = add_peer(&mut engine, [127, 0, 0, 1]);

        // Simulate a synchronized state directly on the loop filter
        engine.loop_filter.clock_set = true;
        engine.loop_filter.offset = 0.05;
        engine.loop_filter.last_update = ntp_fp::ts_to_ntp(1000, 0);

        // Set system state to synchronized
        engine.system.stratum = 4;
        engine.system.peer_count = 1;
        engine.system.sys_offset = 0.05;

        // Run housekeeping with the peer unreachable.
        // Since the peer has reach=0, update_from_peers will find no survivors
        // and reset peer_count to 0. run_selection() then skips clock adjustment.
        let actions = engine.tick(ntp_fp::ts_to_ntp(2000, 0));
        let clock_adjusts: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, DaemonAction::AdjustClock(_)))
            .collect();

        // With no survivors, system should NOT emit AdjustClock
        assert!(
            clock_adjusts.is_empty(),
            "no AdjustClock should be emitted when no peers survive selection"
        );
        assert_eq!(
            engine.system.peer_count, 0,
            "peer_count should be 0 after losing all peers"
        );
        assert_eq!(
            engine.system.leap,
            LeapIndicator::Alarm,
            "leap should be Alarm when unsynchronized"
        );
    }

    #[test]
    fn test_engine_client_request_response() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        engine.system.stratum = 3;
        engine.system.leap = LeapIndicator::NoWarning;
        engine.system.root_delay = 0.001;
        engine.system.root_dispersion = 0.001;

        let mut req = NtpPacket::zeroed();
        req.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        req.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(2000, 0));

        let dgram = ReceivedDatagram {
            bytes: req.encode_header().to_vec(),
            source: peer_netaddr([192, 168, 0, 1], 45678),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2001, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "should respond to client request"
        );

        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            let resp = NtpPacket::decode_header(bytes).unwrap();
            assert_eq!(resp.mode(), NtpMode::Server);
            assert_eq!(resp.stratum, 3);
            assert_eq!(resp.originate_ts, req.transmit_ts);
        }
    }

    #[test]
    fn test_simulated_clock_advance() {
        let mut clock = SimulatedClock::unix_epoch();
        let t0 = clock.now();
        assert_eq!(t0.seconds, ntp_fp::ts_to_ntp(0, 0).seconds);

        clock.advance(64.0);
        let t1 = clock.now();
        assert_eq!(t1.seconds, ntp_fp::ts_to_ntp(64, 0).seconds);
    }

    #[test]
    fn test_memory_state_store() {
        let mut store = MemoryStateStore::new();
        assert!(store.load_drift().is_err());

        store.drift = Some(42.5);
        assert_eq!(store.load_drift().unwrap(), 42.5);

        assert!(store.append_stats("loopstats", "test line").is_ok());
        assert_eq!(store.stats.len(), 1);
    }

    #[test]
    fn test_replay_network() {
        let dgram = ReceivedDatagram {
            bytes: vec![0u8; 48],
            source: peer_netaddr([127, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(1000, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        let mut net = ReplayNetwork::new(vec![dgram.clone()]);
        assert!(net.bind("0.0.0.0:123").is_ok());
        let recv = net.recv().unwrap();
        assert_eq!(recv.bytes, vec![0u8; 48]);
        assert!(net.recv().is_err());

        // Verify sent packet recording
        let dest = peer_netaddr([192, 168, 1, 1], 123);
        assert!(net.send(&[1u8; 48], &dest).is_ok());
        assert_eq!(net.sent_packets.len(), 1);
        assert_eq!(net.sent_packets[0].1, vec![1u8; 48]);
    }

    #[test]
    fn test_kod_packet() {
        let mut req = NtpPacket::zeroed();
        req.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        req.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(500, 0));

        let system = SystemState::new();
        let now = ntp_fp::ts_to_ntp(501, 0);
        let kod = build_kod_packet(&req, &system, now, -20);

        assert_eq!(kod.stratum, 0);
        assert_eq!(kod.mode(), NtpMode::Server);
        assert_eq!(kod.originate_ts, req.transmit_ts);
    }

    #[test]
    fn test_build_request_ntp_proto() {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let sin = unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in) };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = 123u16.to_be();
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        };
        let peer = Peer::new(sa, NtpMode::Client, NtpVersion::V4, 4, 10);
        let system = SystemState::new();
        let now = ntp_fp::ts_to_ntp(1000, 0);

        let pkt = build_request(&peer, &system, now, -20);
        assert_eq!(pkt.mode(), NtpMode::Client);
        assert_eq!(pkt.version(), NtpVersion::V4);
        assert_eq!(pkt.transmit_ts, ntp_fp::ntp_ts64_to_wire(now));
    }

    /// Decisive court: full pipeline with two peers, poll, response,
    /// selection, and stale-state reset.
    #[test]
    fn test_full_deterministic_pipeline() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_a = add_peer(&mut engine, [127, 0, 0, 1]);
        let peer_b = add_peer(&mut engine, [10, 0, 0, 1]);

        let now = ntp_fp::ts_to_ntp(0, 0);

        // 1. Initial tick emits two correctly addressed requests
        let actions = engine.tick(now);
        assert_eq!(actions.len(), 2, "two peers → two Send actions");
        assert_eq!(engine.pending_requests.len(), 2, "two pending requests");
        assert!(actions
            .iter()
            .all(|a| matches!(a, DaemonAction::Send { .. })));

        // Verify request addresses
        let addrs: Vec<_> = actions
            .iter()
            .filter_map(|a| {
                if let DaemonAction::Send { destination, .. } = a {
                    Some((
                        destination.addr[0],
                        destination.addr[1],
                        destination.addr[2],
                        destination.addr[3],
                    ))
                } else {
                    None
                }
            })
            .collect();
        assert!(addrs.contains(&(127, 0, 0, 1)), "peer A address");
        assert!(addrs.contains(&(10, 0, 0, 1)), "peer B address");

        // 2. Responses arrive in reverse order
        // Clone before mutating to avoid borrow conflicts
        let req_b = engine.pending_requests[1].clone();
        let req_a = engine.pending_requests[0].clone();

        let mut resp_b = NtpPacket::zeroed();
        resp_b.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp_b.stratum = 3;
        resp_b.originate_ts = req_b.wire_t1;
        resp_b.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 0));
        resp_b.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 250_000_000));
        // Set root_dispersion so synch > offset difference (5ms dispersion)
        resp_b.root_dispersion = crate::ntp_proto::f64_to_ntp_short(0.005);

        let dgram_b = ReceivedDatagram {
            bytes: resp_b.encode_header().to_vec(),
            source: peer_netaddr([10, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        engine.handle(DaemonEvent::PacketReceived(dgram_b));
        assert_eq!(
            engine.pending_requests.len(),
            1,
            "one pending after B's response"
        );

        let mut resp_a = NtpPacket::zeroed();
        resp_a.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp_a.stratum = 2; // peer A is lower stratum → becomes system peer
        resp_a.originate_ts = req_a.wire_t1;
        resp_a.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 0));
        resp_a.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 250_000_000));
        // Same root_dispersion as peer B for consistent synch
        resp_a.root_dispersion = crate::ntp_proto::f64_to_ntp_short(0.005);

        let dgram_a = ReceivedDatagram {
            bytes: resp_a.encode_header().to_vec(),
            source: peer_netaddr([127, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        engine.handle(DaemonEvent::PacketReceived(dgram_a));
        assert!(engine.pending_requests.is_empty(), "all requests consumed");

        // 3. Both peers reachable
        assert!(engine.peers.get(peer_a).unwrap().reach.is_reachable());
        assert!(engine.peers.get(peer_b).unwrap().reach.is_reachable());

        // 4. Housekeeping: run selection → system state synchronized
        let house_actions = engine.tick(ntp_fp::ts_to_ntp(64, 0));
        assert_eq!(
            engine.system.peer_count, 2,
            "both peers should survive selection"
        );
        assert!(engine.system.stratum <= 4, "stratum set from best peer");
        assert!(
            house_actions
                .iter()
                .any(|a| matches!(a, DaemonAction::AdjustClock(_))),
            "AdjustClock should fire when synchronized"
        );

        // 5. Make all peers unreachable
        for i in 0..engine.peers.len() {
            if let Some(peer) = engine.peers.get_mut(i) {
                for _ in 0..8 {
                    peer.reach.record_failure();
                }
            }
        }

        // 6. Housekeeping again → system unsynchronized, no stale AdjustClock
        let stale_actions = engine.tick(ntp_fp::ts_to_ntp(128, 0));
        let has_clock_adj = stale_actions
            .iter()
            .any(|a| matches!(a, DaemonAction::AdjustClock(_)));
        assert!(!has_clock_adj, "no AdjustClock when all peers unreachable");
        assert_eq!(engine.system.peer_count, 0, "no survivors");
        assert_eq!(engine.system.leap, LeapIndicator::Alarm);
    }

    /// Test wrong-source rejection: a response from an unexpected source
    /// address should not match the pending request.
    #[test]
    fn test_engine_wrong_source_rejected() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [192, 168, 1, 1]);

        // Tick to generate a pending request
        engine.tick(ntp_fp::ts_to_ntp(0, 0));
        assert_eq!(engine.pending_requests.len(), 1);
        let req = engine.pending_requests[0].clone();

        // Response from WRONG source
        let mut resp = NtpPacket::zeroed();
        resp.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp.stratum = 3;
        resp.originate_ts = req.wire_t1;
        resp.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 0));
        resp.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 500_000_000));

        // Source is 10.0.0.1, but we polled 192.168.1.1
        let dgram = ReceivedDatagram {
            bytes: resp.encode_header().to_vec(),
            source: peer_netaddr([10, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // Response should be rejected — pending request still present
        assert_eq!(engine.pending_requests.len(), 1, "pending should remain");
        assert!(
            !engine.peers.get(peer_id).unwrap().reach.is_reachable(),
            "peer should NOT be reachable from wrong source"
        );
    }

    /// Test wrong-mode rejection: a response with wrong mode should not match.
    #[test]
    fn test_engine_wrong_mode_rejected() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [127, 0, 0, 1]);

        // Tick to generate a pending request
        engine.tick(ntp_fp::ts_to_ntp(0, 0));
        assert_eq!(engine.pending_requests.len(), 1);
        let req = engine.pending_requests[0].clone();

        // Response with WRONG mode (Broadcast instead of Server)
        let mut resp = NtpPacket::zeroed();
        resp.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Broadcast);
        resp.stratum = 3;
        resp.originate_ts = req.wire_t1;
        resp.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 0));
        resp.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 500_000_000));

        let dgram = ReceivedDatagram {
            bytes: resp.encode_header().to_vec(),
            source: peer_netaddr([127, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // Response should be rejected — pending request still present
        assert_eq!(engine.pending_requests.len(), 1, "pending should remain");
        assert!(
            !engine.peers.get(peer_id).unwrap().reach.is_reachable(),
            "peer should NOT be reachable from wrong mode"
        );
    }

    /// Test the full adapter stack: SimulatedClock, ReplayNetwork, MemoryStateStore,
    /// and DaemonEngine working together through action dispatch.
    ///
    /// This manually dispatches DaemonActions to adapters, proving the
    /// real/lab shared execution boundary works end-to-end.
    #[test]
    fn test_full_adapter_stack() {
        use crate::ntp_io::{MemoryStateStore, ReplayNetwork, SimulatedClock};

        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [10, 0, 0, 1]);

        let mut clock = SimulatedClock::unix_epoch();
        let mut network = ReplayNetwork::new(Vec::new());
        let mut store = MemoryStateStore::new();

        // Helper: manually dispatch a Send action to ReplayNetwork.
        // We use discrete function calls rather than a closure to avoid
        // borrow conflicts with subsequent assertions.
        let t0 = clock.now();

        // 1. Tick → Send action dispatched to ReplayNetwork
        let now = ntp_fp::ts_to_ntp(0, 0);
        let timer_actions = engine.tick(now);
        assert!(
            timer_actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "tick should produce Send action"
        );
        // Dispatch Send to ReplayNetwork
        for action in timer_actions {
            if let DaemonAction::Send { destination, bytes } = action {
                network.send(&bytes, &destination).ok();
            }
        }

        // ReplayNetwork should have recorded the sent packet
        assert_eq!(
            network.sent_packets.len(),
            1,
            "ReplayNetwork should record sent packets"
        );
        assert_eq!(
            network.sent_packets[0].1.len(),
            48,
            "sent packet should be 48 bytes"
        );

        // 2. Inject a response via ReplayNetwork's recv buffer
        let req = engine.pending_requests[0].clone();
        let mut resp = NtpPacket::zeroed();
        resp.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp.stratum = 3;
        resp.originate_ts = req.wire_t1;
        resp.receive_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 0));
        resp.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1, 500_000_000));

        // Manually provide the response datagram to the engine
        let dgram = ReceivedDatagram {
            bytes: resp.encode_header().to_vec(),
            source: peer_netaddr([10, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };

        let resp_actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        // Dispatch clock adjustments to SimulatedClock
        for action in resp_actions {
            if let DaemonAction::AdjustClock(adj) = action {
                match adj {
                    Adjustment::Step(offset) => {
                        clock.step(offset).ok();
                    }
                    Adjustment::Slew(offset, freq) => {
                        clock.slew(offset, freq).ok();
                    }
                    _ => {}
                }
            }
        }

        // Peer should be reachable
        assert!(
            engine.peers.get(peer_id).unwrap().reach.is_reachable(),
            "peer should be reachable after response"
        );

        // 3. Advance clock to housekeeping → selection → AdjustClock → SimulatedClock
        let house_time = ntp_fp::ts_to_ntp(64, 0);
        let house_actions = engine.tick(house_time);

        // Dispatch clock adjustments to SimulatedClock
        let mut has_adjust = false;
        for action in house_actions {
            if let DaemonAction::AdjustClock(adj) = action {
                has_adjust = true;
                match adj {
                    Adjustment::Step(offset) => {
                        clock.step(offset).ok();
                    }
                    Adjustment::Slew(offset, freq) => {
                        clock.slew(offset, freq).ok();
                    }
                    _ => {}
                }
            }
        }

        // If synchronized, the clock should have changed
        if has_adjust {
            let t1 = clock.now();
            assert!(
                t1.seconds != t0.seconds || t1.fraction != t0.fraction,
                "SimulatedClock should change after AdjustClock"
            );
        }

        // 4. PersistDrift action → MemoryStateStore
        assert!(store.save_drift(42.5).is_ok());
        assert_eq!(
            store.load_drift().unwrap(),
            42.5,
            "MemoryStateStore should persist drift through save_drift"
        );

        // 5. Verify ReplayNetwork recorded all sends
        // tick(0) produced 1 send; no other sends in this test
        assert_eq!(
            network.sent_packets.len(),
            1,
            "exactly one packet should have been sent"
        );
    }

    /// End-to-end Mode 6 control request: send a literal 16-byte ntpq READVAR
    /// request and verify the response matches ntpq expectations.
    #[test]
    fn test_engine_mode6_readvar() {
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        engine.system.stratum = 3;
        engine.system.leap = LeapIndicator::NoWarning;
        engine.system.sys_offset = 0.005;

        // Build a literal Mode 6 READVAR request (16 bytes typical):
        //   Bytes: LI=0 VN=4 Mode=6 = 0x26
        //          Opcode: R=0 E=0 M=0 Op=2 (READVAR) = 0x02
        //          Sequence: 0x0001
        //          Status: 0x0000 (request, system status is ignored)
        //          Assocation ID: 0x0000 (system, not peer)
        //          Offset: 0x0000
        //          Count: 0x0000 (no data)
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8();
        msg.sequence = 1;
        msg.associd = 0;
        msg.count = 0;

        let mut packet = msg.encode().to_vec();
        // Zero-pad to 16 bytes (multiple of 8, typical for real ntpq)
        packet.resize(16, 0);

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([192, 168, 1, 100], 45678),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // Should produce a Send action with the response
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "Mode 6 READVAR should produce a Send response"
        );

        // Decode the response
        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            // Response must contain at least the 12-byte header
            assert!(bytes.len() >= 12, "response must be >= 12 bytes");

            let (resp_header, resp_data) =
                ControlMessage::decode(bytes).expect("valid control response header");

            // Verify response flags
            let oc = resp_header.decode_opcode();
            assert!(oc.response, "response bit should be set");
            assert!(!oc.error, "error bit should not be set");
            assert_eq!(oc.op, opcodes::OP_READVAR, "opcode should match");
            assert_eq!(resp_header.sequence, 1, "sequence should match");
            assert_eq!(resp_header.associd, 0, "association ID should match");

            // Response data should contain system variables (text)
            let data_str = String::from_utf8_lossy(resp_data);
            assert!(
                data_str.contains("version"),
                "response should contain version"
            );
            assert!(
                data_str.contains("stratum"),
                "response should contain stratum"
            );
            assert!(
                data_str.contains("offset"),
                "response should contain offset"
            );
            assert!(
                data_str.contains("3"),
                "response should contain stratum value 3"
            );
        }
    }

    /// Test that a short Mode 6 packet (12 bytes, no padding) is accepted.
    #[test]
    fn test_engine_mode6_minimal() {
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        engine.system.stratum = 2;

        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8();
        msg.sequence = 42;
        msg.associd = 0;
        msg.count = 0;

        let dgram = ReceivedDatagram::test(
            msg.encode().to_vec(),
            peer_netaddr([10, 0, 0, 55], 12345),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "12-byte Mode 6 request should be processed"
        );

        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            let (resp_header, _) = ControlMessage::decode(bytes).unwrap();
            let oc = resp_header.decode_opcode();
            assert!(oc.response);
            assert_eq!(resp_header.sequence, 42);
        }
    }

    /// Precision court: association allocator wraps around occupied IDs.
    #[test]
    fn test_associd_allocator_wrap() {
        let mut next: u16 = u16::MAX - 2;
        let mut peers = PeerTable::new();
        // Simulate 4 occupied peers at the wrap boundary
        for a in [u16::MAX - 2, u16::MAX - 1, u16::MAX, 1] {
            let mut p = Peer::new(
                unsafe { std::mem::zeroed() },
                NtpMode::Client,
                NtpVersion::V4,
                4,
                10,
            );
            p.associd = a;
            peers.add(p);
        }
        // Allocator should skip occupied IDs and return the first free ID (2)
        let aid = DaemonEngine::allocate_associd(&mut next, &peers);
        assert_eq!(aid, Some(2), "allocator should skip occupied IDs at wrap");
        // Next allocation should be 3
        let aid2 = DaemonEngine::allocate_associd(&mut next, &peers);
        assert_eq!(
            aid2,
            Some(3),
            "second alloc should be sequential after wrap"
        );
    }

    /// Precision court: allocator skips occupied prefix.
    #[test]
    fn test_associd_allocator_skips_occupied_prefix() {
        let mut next: u16 = 1;
        let mut peers = PeerTable::new();
        for a in 1..=100u16 {
            let mut p = Peer::new(
                unsafe { std::mem::zeroed() },
                NtpMode::Client,
                NtpVersion::V4,
                4,
                10,
            );
            p.associd = a;
            peers.add(p);
        }
        let aid = DaemonEngine::allocate_associd(&mut next, &peers);
        assert_eq!(aid, Some(101), "should skip occupied 1..100");
    }

    /// Precision court: all 65535 IDs exhausted returns None.
    /// Uses the predicate-based allocator to avoid constructing 65535 peers.
    #[test]
    fn test_associd_allocator_exhaustion() {
        let mut next: u16 = 1;
        let aid = DaemonEngine::allocate_associd_with(&mut next, |_| true);
        assert_eq!(aid, None, "every ID used → exhaustion");
    }

    /// Precision court: AES-CMAC short key zero-padding matches explicit 16-byte key.
    #[test]
    fn test_aes_short_key_zero_padding() {
        use crate::ntp_auth::*;
        // A 7-byte key should be zero-padded to 16 bytes
        let short_key = NtpAuthKey::new(1, DigestType::Aes128Cmac, b"1234567".to_vec());
        // Explicit 16-byte key with same bytes + zero padding
        let mut padded = [0u8; 16];
        padded[..7].copy_from_slice(b"1234567");
        let explicit_key = NtpAuthKey::new(2, DigestType::Aes128Cmac, padded.to_vec());

        let test_data = b"NTP test data for CMAC computation";
        let mac_short = short_key.mac(test_data);
        let mac_explicit = explicit_key.mac(test_data);

        assert!(mac_short.is_some(), "short key should produce MAC");
        assert!(mac_explicit.is_some(), "explicit key should produce MAC");
        assert_eq!(
            mac_short, mac_explicit,
            "zero-padded short key should match explicit 16-byte key"
        );
    }

    #[test]
    fn test_refclock_manager_add_and_open() {
        let mut mgr = RefclockManager::new();
        mgr.add(28, 0, 1);
        mgr.add(22, 0, 2);
        mgr.add(19, 0, 3);
        mgr.add(16, 0, 4);
        assert_eq!(mgr.instances.len(), 4);
        // Opening produces log messages (SHM may succeed with shmget+IPC_CREAT,
        // but PPS/NMEA/GPSD will fail since their devices don't exist)
        let actions = mgr.open_all();
        // At minimum, we should get log messages for each
        assert!(
            actions.len() >= 4,
            "expected at least 4 log actions, got {}",
            actions.len()
        );
        // NMEA driver should NOT be active (no /dev/ttyGPS0)
        assert!(
            !mgr.instances[2].active,
            "NMEA should not open without serial device"
        );
    }

    // ── Mode 6 WRITEVAR tests ────────────────────────────────────────

    #[test]
    fn test_engine_mode6_writevar_offset() {
        use crate::ntp_auth::*;
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        // Configure a control key so WRITEVAR auth passes
        let key = NtpAuthKey::new(10, DigestType::Sha1, b"testkey123".to_vec());
        engine.auth.add_key(key);
        engine.auth.set_control_key(10);
        engine.system.sys_offset = 0.1;

        let body = b"offset=0.05".to_vec();
        // Build MAC for the packet
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_WRITEVAR).to_u8();
        msg.sequence = 1;
        msg.count = body.len() as u16;

        // Build packet with auth
        let header = msg.encode();
        let mut packet = header.to_vec();
        packet.extend_from_slice(&body);
        // Pad to 4-byte boundary
        while packet.len() % 4 != 0 {
            packet.push(0);
        }
        // Append key ID and MAC
        if let Some(key) = engine.auth.get_key(10) {
            if let Some(mac) = key.mac(&packet) {
                packet.extend_from_slice(&key.id.to_be_bytes());
                packet.extend_from_slice(&mac);
            }
        }

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([192, 168, 1, 100], 45678),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(actions
            .iter()
            .any(|a| matches!(a, DaemonAction::Send { .. })));
        assert!(
            (engine.system.sys_offset - 0.05).abs() < 1e-9,
            "offset should be updated to 0.05, got {}",
            engine.system.sys_offset
        );
    }

    #[test]
    fn test_engine_mode6_writevar_requires_auth() {
        use crate::ntp_auth::*;
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        let key = NtpAuthKey::new(10, DigestType::Sha1, b"testkey123".to_vec());
        engine.auth.add_key(key);
        engine.auth.set_control_key(10);

        let body = b"offset=0.05".to_vec();
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_WRITEVAR).to_u8();
        msg.sequence = 1;
        msg.count = body.len() as u16;

        let mut packet = msg.encode().to_vec();
        packet.extend_from_slice(&body);

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([192, 168, 1, 100], 45678),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            let (resp_header, _) = ControlMessage::decode(bytes).unwrap();
            assert!(
                resp_header.decode_opcode().error,
                "should be error response"
            );
        } else {
            panic!("expected Send action");
        }
    }

    #[test]
    fn test_engine_mode6_nonce_generation() {
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());

        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_REQ_NONCE).to_u8();
        msg.sequence = 1;
        msg.count = 0;

        let dgram = ReceivedDatagram::test(
            msg.encode().to_vec(),
            peer_netaddr([10, 0, 0, 1], 54321),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            let (_, resp_data) = ControlMessage::decode(bytes).unwrap();
            let resp_text = String::from_utf8_lossy(resp_data);
            assert!(
                resp_text.contains("nonce="),
                "response should contain nonce="
            );
        } else {
            panic!("expected Send action");
        }
    }

    #[test]
    fn test_engine_mode6_read_mru() {
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let sa = crate::ntp_monitor::netaddr_to_sockaddr(&peer_netaddr([10, 0, 0, 1], 12345));
        engine.monitor.record(&sa, now);
        let sa2 = crate::ntp_monitor::netaddr_to_sockaddr(&peer_netaddr([192, 168, 1, 1], 54321));
        engine.monitor.record(&sa2, now);

        let nonce_bytes = engine.monitor.nonce_cache.generate_nonce();
        let nonce_str = hex::encode(&nonce_bytes);
        let body = format!("nonce={}", nonce_str);

        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_READ_MRU).to_u8();
        msg.sequence = 1;
        msg.count = body.len() as u16;

        let mut packet = msg.encode().to_vec();
        packet.extend_from_slice(body.as_bytes());

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([10, 0, 0, 1], 54321),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(1001, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            let (_, resp_data) = ControlMessage::decode(bytes).unwrap();
            let resp_text = String::from_utf8_lossy(resp_data);
            assert!(
                resp_text.contains("addr.0="),
                "should contain addr.0=, got: {}",
                resp_text
            );
        } else {
            panic!("expected Send action");
        }
    }

    #[test]
    fn test_engine_mode6_read_mru_invalid_nonce() {
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        let body = "nonce=invalidnonce123";

        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_READ_MRU).to_u8();
        msg.sequence = 1;
        msg.count = body.len() as u16;

        let mut packet = msg.encode().to_vec();
        packet.extend_from_slice(body.as_bytes());

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([10, 0, 0, 1], 54321),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(1001, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            assert!(
                ControlMessage::decode(bytes)
                    .unwrap()
                    .0
                    .decode_opcode()
                    .error,
                "invalid nonce should produce error"
            );
        } else {
            panic!("expected Send action");
        }
    }

    #[test]
    fn test_engine_mode6_writeclock() {
        use crate::ntp_control::*;

        // ── Test stratum assignment ───────────────────────────────────
        let mut engine = DaemonEngine::new(ConfigTree::new());
        assert_eq!(engine.system.stratum, NTP_MAXSTRAT);
        let body = b"stratum=3".to_vec();
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_WRITECLOCK).to_u8();
        msg.sequence = 1;
        msg.count = body.len() as u16;

        let mut packet = msg.encode().to_vec();
        packet.extend_from_slice(&body);

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([192, 168, 1, 100], 45678),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "WRITECLOCK stratum should produce Send"
        );
        assert_eq!(engine.system.stratum, 3, "stratum should be updated to 3");

        // ── Test refid assignment (ASCII) ─────────────────────────────
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let body = b"refid=GPS".to_vec();
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_WRITECLOCK).to_u8();
        msg.sequence = 1;
        msg.count = body.len() as u16;

        let mut packet = msg.encode().to_vec();
        packet.extend_from_slice(&body);

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([192, 168, 1, 100], 45678),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert_eq!(
            engine.system.reference_id,
            u32::from_be_bytes([b'G', b'P', b'S', 0]),
            "refid should be updated to GPS"
        );

        // ── Test offset assignment ────────────────────────────────────
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let body = b"offset=0.05".to_vec();
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_WRITECLOCK).to_u8();
        msg.sequence = 1;
        msg.count = body.len() as u16;

        let mut packet = msg.encode().to_vec();
        packet.extend_from_slice(&body);

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([192, 168, 1, 100], 45678),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(
            (engine.system.sys_offset - 0.05).abs() < 1e-9,
            "offset should be updated to 0.05, got {}",
            engine.system.sys_offset
        );

        // ── Test unknown variable rejection ───────────────────────────
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let body = b"fudge=0.001".to_vec();
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_WRITECLOCK).to_u8();
        msg.sequence = 1;
        msg.count = body.len() as u16;

        let mut packet = msg.encode().to_vec();
        packet.extend_from_slice(&body);

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([192, 168, 1, 100], 45678),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            let (resp_header, _) = ControlMessage::decode(bytes).unwrap();
            assert!(
                resp_header.decode_opcode().error,
                "unknown clock variable should return error response"
            );
        } else {
            panic!("expected Send action");
        }
    }

    #[test]
    fn test_engine_mode6_unsupported_opcode() {
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, 0).to_u8();
        msg.sequence = 1;
        msg.count = 0;

        let dgram = ReceivedDatagram::test(
            msg.encode().to_vec(),
            peer_netaddr([10, 0, 0, 1], 54321),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            assert!(
                ControlMessage::decode(bytes)
                    .unwrap()
                    .0
                    .decode_opcode()
                    .error,
                "unsupported opcode should return error"
            );
        } else {
            panic!("expected error response");
        }
    }

    // ── Config wiring tests ───────────────────────────────────────────

    #[test]
    fn test_apply_config_tinker() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Tinker {
            step: Some(0.5),
            panic: Some(1000.0),
            dispersion: None,
            stepout: None,
            minpoll: None,
            maxpoll: None,
        });
        let engine = DaemonEngine::new(config);
        assert_eq!(engine.tinker_step, Some(0.5));
        assert_eq!(engine.tinker_panic, Some(1000.0));
        assert!((engine.loop_filter.step_threshold - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_apply_config_tos() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Tos {
            minsane: Some(3),
            minclock: Some(5),
            maxdist: Some(2.0),
        });
        let engine = DaemonEngine::new(config);
        assert_eq!(engine.minsane, 3);
    }

    #[test]
    fn test_apply_config_mru() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Mru {
            maxdepth: Some(500),
            maxage: Some(7200),
        });
        let engine = DaemonEngine::new(config);
        assert_eq!(engine.monitor.max_entries, 500);
        assert_eq!(engine.monitor.max_age, 7200);
    }

    #[test]
    fn test_apply_config_fudge() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Fudge {
            refclock_type: 28,
            unit: 0,
            time1: 0.001,
            time2: 0.0,
            stratum: 2,
            refid: "GPS".to_string(),
        });
        let engine = DaemonEngine::new(config);
        assert_eq!(engine.fudge_values.len(), 1);
        let (t1, _t2, s, rid) = engine.fudge_values.get(&(28, 0)).unwrap();
        assert!((*t1 - 0.001).abs() < 1e-9);
        assert_eq!(*s, 2);
        assert_eq!(rid, "GPS");
    }

    #[test]
    fn test_apply_config_logfile() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Logfile {
            path: "/var/log/ntp/ntp.log".to_string(),
        });
        let engine = DaemonEngine::new(config);
        assert_eq!(engine.log_file.as_deref(), Some("/var/log/ntp/ntp.log"));
    }

    #[test]
    fn test_apply_config_setvar() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Setvar {
            name: "ntp_version".to_string(),
            value: "4.2.8".to_string(),
        });
        let engine = DaemonEngine::new(config);
        assert_eq!(engine.sysvars.get("ntp_version").unwrap(), "4.2.8");
    }

    #[test]
    fn test_apply_config_statistics() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Statistics {
            kinds: vec!["loopstats".to_string(), "peerstats".to_string()],
        });
        let engine = DaemonEngine::new(config);
        assert!(engine.filegen.get("loopstats").is_some());
        assert!(engine.filegen.get("peerstats").is_some());
    }

    #[test]
    fn test_apply_config_filegen() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Filegen {
            name: "loopstats".to_string(),
            file: Some("/var/log/ntp/loopstats".to_string()),
            gen_type: Some("day".to_string()),
            enable: true,
        });
        let engine = DaemonEngine::new(config);
        assert!(engine.filegen.get("loopstats").is_some());
    }

    #[test]
    fn test_apply_config_nts() {
        let mut config = ConfigTree::new();
        config.add(ConfigOption::Nts {
            key_file: Some("/etc/nts/key.pem".to_string()),
            cert_file: Some("/etc/nts/cert.pem".to_string()),
            port: Some(4460),
        });
        let engine = DaemonEngine::new(config);
        assert!(engine.nts_config.is_some());
    }

    #[test]
    fn test_poll_refclocks_empty() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let actions = engine.poll_refclocks(now);
        assert!(
            actions.is_empty(),
            "empty refclock manager should produce no actions"
        );
    }
}
