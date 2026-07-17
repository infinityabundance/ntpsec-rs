// ──── ntp_filegen.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_filegen.c
//
// Statistics file generation: manages `filegen` directives for loopstats,
// peerstats, and clockstats output files.
// =============================================================================

use crate::ntp_types::*;

/// File generation type (matches ntpsec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileGenType {
    Day,   // Rotate daily
    Week,  // Rotate weekly
    Month, // Rotate monthly
    Year,  // Rotate yearly
    Age,   // Age-based deletion
    Pid,   // Include PID in filename
}

/// File generation entry.
#[derive(Debug, Clone)]
pub struct FileGenEntry {
    pub name: String,
    pub file_name: String,
    pub gen_type: FileGenType,
    pub enabled: bool,
}

/// Statistics file generator registry.
#[derive(Debug, Default)]
pub struct FileGenRegistry {
    entries: Vec<FileGenEntry>,
}

impl FileGenRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: FileGenEntry) {
        self.entries.push(entry);
    }

    pub fn get(&self, name: &str) -> Option<&FileGenEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut FileGenEntry> {
        self.entries.iter_mut().find(|e| e.name == name)
    }
}
