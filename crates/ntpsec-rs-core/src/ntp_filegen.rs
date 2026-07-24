// ──── ntp_filegen.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_filegen.c
//
// Statistics file generation: manages `filegen` directives for loopstats,
// peerstats, and clockstats output files.
// =============================================================================

use std::io::Write;
use std::path::Path;

use crate::ntp_peer::Peer;
use crate::ntp_proto::SystemState;
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

    /// Write a loopstats entry: MJD secs offset freq_ppm jitter
    pub fn write_loopstats(
        &self,
        path: &Path,
        sys: &SystemState,
        freq_ppm: f64,
    ) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mjd = now.as_secs() / 86400 + 40587; // Modified Julian Date approx
        let secs = now.as_secs() % 86400;
        let content = format!(
            "{} {} {} {:.6} {:.3} {:.6}",
            mjd, secs, 0i64, sys.sys_offset, freq_ppm, sys.sys_jitter
        );
        write_stat_file(path, &content)
    }

    /// Write a peerstats entry: MJD secs associd offset delay dispersion reach
    pub fn write_peerstats(&self, path: &Path, peer: &Peer) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mjd = now.as_secs() / 86400 + 40587;
        let secs = now.as_secs() % 86400;
        let content = format!(
            "{} {} {} {:.6} {:.6} {:.6} {}",
            mjd,
            secs,
            peer.associd,
            peer.offset,
            peer.delay,
            peer.dispersion,
            peer.reach.register()
        );
        write_stat_file(path, &content)
    }
}

/// Open and write to a statistics file.
pub fn write_stat_file(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create stats dir '{}': {}", parent.display(), e))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open stats file '{}': {}", path.display(), e))?;
    writeln!(file, "{}", content)
        .map_err(|e| format!("cannot write to stats file '{}': {}", path.display(), e))?;
    Ok(())
}
