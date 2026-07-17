// ──── ntp_syslog.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_syslog.h, libntp/msyslog.c
//
// NTPsec syslog integration. In the core, this is a trait that the IO layer
// wires to a real syslog; during replay/testing, it buffers log messages.
//
// ## Oracle
//   - ntpsec include/ntp_syslog.h
//   - ntpsec libntp/msyslog.c
// =============================================================================

use core::fmt;

/// Syslog severity levels matching ntpsec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogLevel {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl SyslogLevel {
    pub fn to_str(self) -> &'static str {
        match self {
            SyslogLevel::Emergency => "EMERG",
            SyslogLevel::Alert => "ALERT",
            SyslogLevel::Critical => "CRIT",
            SyslogLevel::Error => "ERROR",
            SyslogLevel::Warning => "WARNING",
            SyslogLevel::Notice => "NOTICE",
            SyslogLevel::Info => "INFO",
            SyslogLevel::Debug => "DEBUG",
        }
    }
}

impl fmt::Display for SyslogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

/// A syslog message buffer (used in deterministic testing to capture messages).
#[derive(Debug, Default)]
pub struct SyslogBuffer {
    pub messages: Vec<(SyslogLevel, String)>,
}

impl SyslogBuffer {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    pub fn log(&mut self, level: SyslogLevel, msg: &str) {
        self.messages.push((level, msg.to_string()));
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }

    pub fn contains(&self, level: SyslogLevel, substring: &str) -> bool {
        self.messages
            .iter()
            .any(|(l, m)| *l == level && m.contains(substring))
    }

    /// Format messages as ntpsec would: `LEVEL: message`
    pub fn format_all(&self) -> String {
        self.messages
            .iter()
            .map(|(lvl, msg)| format!("{}: {}", lvl, msg))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
