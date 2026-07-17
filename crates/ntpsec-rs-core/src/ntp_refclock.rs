// ──── ntp_refclock.rs ───────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_refclock.h, ntpd/ntp_refclock.c
//
// Reference clock base infrastructure: clock driver registration, I/O
// handling, and sample processing.
// =============================================================================

use crate::ntp_types::*;

/// Reference clock type identifier.
pub type RefClockId = u32;

/// Reference clock unit number (127.127.X.Y).
pub type RefClockUnit = u32;

/// A reference clock sample.
#[derive(Debug, Clone, Copy)]
pub struct RefClockSample {
    pub offset: f64,
    pub delay: f64,
    pub dispersion: f64,
    pub time: NtpTs64,
    pub leap: LeapIndicator,
}

/// Reference clock driver interface.
pub trait RefClockDriver: std::fmt::Debug {
    fn name(&self) -> &'static str;
    fn type_id(&self) -> RefClockId;
    fn poll(&mut self) -> Option<RefClockSample>;
    fn timeout(&self) -> u32;
}

/// Reference clock registry.
#[derive(Debug, Default)]
pub struct RefClockRegistry {
    drivers: Vec<Box<dyn RefClockDriver + Send>>,
}

impl RefClockRegistry {
    pub fn new() -> Self {
        Self {
            drivers: Vec::new(),
        }
    }

    pub fn register(&mut self, driver: Box<dyn RefClockDriver + Send>) {
        self.drivers.push(driver);
    }

    pub fn drivers(&self) -> &[Box<dyn RefClockDriver + Send>] {
        &self.drivers
    }
}
