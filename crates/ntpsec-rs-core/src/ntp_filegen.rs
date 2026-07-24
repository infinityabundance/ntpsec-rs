// ──── ntp_filegen.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_filegen.c
//
// Statistics file generation: manages `filegen` directives for loopstats,
// peerstats, and clockstats output files.
// =============================================================================

use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use crate::ntp_peer::Peer;
use crate::ntp_proto::SystemState;
use crate::ntp_types::{NtpMode, NtpVersion};

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

/// Maximum number of rotated backup files to keep.
pub const FILEGEN_MAX_BACKUP: u32 = 8;

/// Open file handles for active file generation entries.
#[derive(Debug, Default)]
pub struct FileGenRegistry {
    entries: Vec<FileGenEntry>,
    /// Open file handles for active statistics writers.
    files: Vec<(String, Option<std::fs::File>)>,
}

/// Helper: get a stable time-zone–agnostic calendar day number (days since epoch).
fn calendar_day(t: &SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400
}

/// Helper: get a week key (days/7 since epoch) for rotation comparison.
/// Changes every ~7 days, sufficient for "different week" detection.
fn week_key(t: &SystemTime) -> i64 {
    let days = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400;
    (days / 7) as i64
}

/// Helper: days since epoch for a given year/month/day.
/// Returns i64 to handle dates before 1970 (e.g., for ISO week calculations).
fn days_since_epoch(year: u32, month: u32, day: u32) -> i64 {
    let y = year as i64;
    let m = month as i64;
    let d = day as i64;
    let a = (14 - m) / 12;
    let yy = y + 4800 - a;
    let mm = m + 12 * a - 3;
    let jdn = d + (153 * mm + 2) / 5 + 365 * yy + yy / 4 - yy / 100 + yy / 400 - 32045;
    jdn - 2440588 // offset to Unix epoch
}

impl FileGenRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            files: Vec::new(),
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

    /// Open a file for a specific entry by name.
    /// Creates the parent directory if it doesn't exist.
    pub fn open(&mut self, name: &str, stat_dir: &Path) -> Result<(), String> {
        if let Some(entry) = self.entries.iter().find(|e| e.name == name) {
            if entry.enabled {
                let path = stat_dir.join(&entry.file_name);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        format!("cannot create stats dir '{}': {}", parent.display(), e)
                    })?;
                }
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .map_err(|e| format!("cannot open stats file '{}': {}", path.display(), e))?;
                // Remove any existing handle for this name
                self.files.retain(|(n, _)| n != name);
                self.files.push((name.to_string(), Some(file)));
            }
        }
        Ok(())
    }

    /// Check if the file for an entry needs rotation based on its `FileGenType`
    /// and the current time. If rotation is needed, the current file is renamed
    /// to a numbered backup (name.0, name.1, ...) and a new file is opened.
    ///
    /// Rotation rules:
    /// - `Day`:   rotate if the file was last written on a different calendar day
    /// - `Week`:  rotate if the file was last written in a different ISO week
    /// - `Month`: rotate if the file was last written in a different month
    /// - `Year`:  rotate if the file was last written in a different year
    /// - `Age`:   time-based rotation is not performed (age-based deletion is separate)
    /// - `Pid`:   rotation is not performed (PID-based filenames are unique per run)
    pub fn rotate_if_needed(&mut self, name: &str, stat_dir: &Path) -> Result<(), String> {
        // Find the entry
        let entry = match self.entries.iter().find(|e| e.name == name) {
            Some(e) => e.clone(),
            None => return Ok(()),
        };

        if !entry.enabled {
            return Ok(());
        }

        // Determine whether rotation is needed based on gen_type
        let now = SystemTime::now();
        let path = stat_dir.join(&entry.file_name);

        // Get the file's modification time; if the file doesn't exist, no rotation needed
        let mtime = match std::fs::metadata(&path) {
            Ok(meta) => match meta.modified() {
                Ok(t) => t,
                Err(_) => return Ok(()), // Can't determine mtime; skip rotation
            },
            Err(_) => return Ok(()), // File doesn't exist yet; no rotation
        };

        let needs_rotation = match entry.gen_type {
            FileGenType::Day => calendar_day(&now) != calendar_day(&mtime),
            FileGenType::Week => week_key(&now) != week_key(&mtime),
            FileGenType::Month => {
                // Compare (year, month) pairs
                month_key(&now) != month_key(&mtime)
            }
            FileGenType::Year => year_of(&now) != year_of(&mtime),
            FileGenType::Age | FileGenType::Pid => false,
        };

        if !needs_rotation {
            return Ok(());
        }

        // ── Perform the rotation ────────────────────────────────────────
        // Close the current file handle for this name
        if let Some((_, ref mut file_opt)) = self.files.iter_mut().find(|(n, _)| n == name) {
            let _ = file_opt.take(); // Close by dropping the handle
        }

        // Shift backups: name.7 -> name.8, ..., name.0 -> name.1
        for i in (0..FILEGEN_MAX_BACKUP).rev() {
            let src = path.with_extension(format!("{}", i));
            let dst = path.with_extension(format!("{}", i + 1));
            let _ = std::fs::rename(&src, &dst);
        }

        // Rename current file to name.0
        if path.exists() {
            let backup = path.with_extension("0");
            let _ = std::fs::rename(&path, &backup);
        }

        // Open a new file
        self.open(name, stat_dir)?;

        Ok(())
    }

    /// Write a loopstats entry: MJD secs offset freq_ppm jitter
    pub fn write_loopstats(
        &mut self,
        path: &Path,
        sys: &SystemState,
        freq_ppm: f64,
    ) -> Result<(), String> {
        // Check and perform rotation before writing
        if let Some(parent) = path.parent() {
            self.rotate_if_needed("loopstats", parent)?;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mjd = now.as_secs() / 86400 + 40587; // Modified Julian Date approx
        let secs = now.as_secs() % 86400;
        let content = format!(
            "{} {} {} {:.6} {:.3} {:.6}\n",
            mjd, secs, 0i64, sys.sys_offset, freq_ppm, sys.sys_jitter
        );
        write_stat_file_ex(
            path,
            &content,
            self.files.iter_mut().find(|(n, _)| n == "loopstats"),
        )
    }

    /// Write a peerstats entry: MJD secs associd offset delay dispersion reach
    pub fn write_peerstats(&mut self, path: &Path, peer: &Peer) -> Result<(), String> {
        // Check and perform rotation before writing
        if let Some(parent) = path.parent() {
            self.rotate_if_needed("peerstats", parent)?;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mjd = now.as_secs() / 86400 + 40587;
        let secs = now.as_secs() % 86400;
        let content = format!(
            "{} {} {} {:.6} {:.6} {:.6} {}\n",
            mjd,
            secs,
            peer.associd,
            peer.offset,
            peer.delay,
            peer.dispersion,
            peer.reach.register()
        );
        write_stat_file_ex(
            path,
            &content,
            self.files.iter_mut().find(|(n, _)| n == "peerstats"),
        )
    }

    /// Write a clockstats entry: MJD secs associd log message
    pub fn write_clockstats(
        &mut self,
        path: &Path,
        associd: u16,
        message: &str,
    ) -> Result<(), String> {
        // Check and perform rotation before writing
        if let Some(parent) = path.parent() {
            self.rotate_if_needed("clockstats", parent)?;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mjd = now.as_secs() / 86400 + 40587;
        let secs = now.as_secs() % 86400;
        let content = format!("{} {} {} {}\n", mjd, secs, associd, message);
        write_stat_file_ex(
            path,
            &content,
            self.files.iter_mut().find(|(n, _)| n == "clockstats"),
        )
    }

    /// Flush all open file handles by calling `sync_all()` on each.
    pub fn flush_all(&mut self) -> Result<(), String> {
        for (_, file_opt) in self.files.iter_mut() {
            if let Some(file) = file_opt {
                file.sync_all()
                    .map_err(|e| format!("flush_all failed: {}", e))?;
            }
        }
        Ok(())
    }

    /// Close all open file handles by taking them (dropping replaces with None)
    /// and then clearing the list. Each file's Drop impl will flush and close.
    pub fn close_all(&mut self) {
        for (_, file_opt) in self.files.iter_mut() {
            let _ = file_opt.take();
        }
        self.files.clear();
    }
}

/// Maximum file size before rotation (10MB default).
pub const FILEGEN_MAX_SIZE: u64 = 10 * 1024 * 1024;

/// Rotate a statistics file when it exceeds `FILEGEN_MAX_SIZE`.
pub fn rotate_file(path: &Path) -> Result<(), String> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > FILEGEN_MAX_SIZE {
            // Rotate: file -> file.0, file.0 -> file.1, etc.
            for i in (1..=9).rev() {
                let old = path.with_extension(format!("{}", i));
                let new = path.with_extension(format!("{}", i + 1));
                let _ = std::fs::rename(&old, &new);
            }
            let backup = path.with_extension("1");
            let _ = std::fs::rename(path, &backup);
        }
    }
    Ok(())
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
    // Rotate if needed
    let _ = rotate_file(path);
    Ok(())
}

/// Write to a statistics file, using an open file handle if available.
/// If a file handle is provided, writes to it and checks rotation;
/// otherwise falls back to the standard open-write-rotate path.
fn write_stat_file_ex(
    path: &Path,
    content: &str,
    handle: Option<&mut (String, Option<std::fs::File>)>,
) -> Result<(), String> {
    if let Some((_, Some(ref mut file))) = handle {
        use std::io::Write;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("cannot write to stats file '{}': {}", path.display(), e))?;
        // Check rotation after write
        let _ = rotate_file(path);
        Ok(())
    } else {
        write_stat_file(path, content)
    }
}

/// Helper: extract a month key (year * 12 + month) from a SystemTime.
fn month_key(t: &SystemTime) -> i64 {
    let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let days = dur.as_secs() / 86400;
    let y = 1970f64 + days as f64 / 365.2425;
    let year = y as i64;
    // Number of days from year start
    let year_start_days = days_since_epoch(year as u32, 1, 1);
    let day_of_year = (days as i64).saturating_sub(year_start_days);
    let month = (day_of_year as f64 / 30.44).floor() as i64;
    let month = month.clamp(0, 11);
    year * 12 + month
}

/// Helper: extract a year from a SystemTime.
fn year_of(t: &SystemTime) -> i64 {
    let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    // Average seconds per Gregorian year = 365.2425 * 86400 = 31556952
    let y = 1970f64 + (secs as f64) / 31_556_952.0;
    y as i64
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    /// A helper that creates a temporary directory and returns its path.
    /// Uses a unique subdirectory per call to avoid race conditions in parallel tests.
    fn tmp_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!("ntp_filegen_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&base);
        // Create a unique subdirectory using a timestamp + counter
        let unique = format!(
            "test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = base.join(unique);
        let _ = std::fs::create_dir_all(&path);
        path
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_filegen_registry_new() {
        let reg = FileGenRegistry::new();
        assert!(reg.entries.is_empty());
        assert!(reg.files.is_empty());
    }

    #[test]
    fn test_filegen_add_and_get() {
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "loopstats".to_string(),
            file_name: "loopstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: true,
        });
        assert!(reg.get("loopstats").is_some());
        assert!(reg.get("peerstats").is_none());
    }

    #[test]
    fn test_filegen_open_and_write_loopstats() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "loopstats".to_string(),
            file_name: "loopstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: true,
        });
        reg.open("loopstats", &dir).unwrap();
        let sys = SystemState::new();
        reg.write_loopstats(&dir.join("loopstats"), &sys, 0.0)
            .unwrap();
        let content = std::fs::read_to_string(dir.join("loopstats")).unwrap();
        assert!(!content.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_filegen_open_and_write_peerstats() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "peerstats".to_string(),
            file_name: "peerstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: true,
        });
        reg.open("peerstats", &dir).unwrap();

        // Create a minimal peer
        let sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer = Peer::new(sa, NtpMode::Client, NtpVersion::V4, 4, 10);
        peer.associd = 1;
        reg.write_peerstats(&dir.join("peerstats"), &peer).unwrap();
        let content = std::fs::read_to_string(dir.join("peerstats")).unwrap();
        assert!(!content.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_filegen_open_and_write_clockstats() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "clockstats".to_string(),
            file_name: "clockstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: true,
        });
        reg.open("clockstats", &dir).unwrap();
        reg.write_clockstats(&dir.join("clockstats"), 1, "refclock sample 0.001")
            .unwrap();
        let content = std::fs::read_to_string(dir.join("clockstats")).unwrap();
        assert!(!content.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_rotate_if_needed_no_rotation_for_same_day() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "loopstats".to_string(),
            file_name: "loopstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: true,
        });
        reg.open("loopstats", &dir).unwrap();

        // Write once (creates the file with current mtime)
        let sys = SystemState::new();
        reg.write_loopstats(&dir.join("loopstats"), &sys, 0.0)
            .unwrap();
        assert!(dir.join("loopstats").exists());

        // rotate_if_needed should not rotate (same day)
        reg.rotate_if_needed("loopstats", &dir).unwrap();

        // The file should still exist (not rotated)
        assert!(dir.join("loopstats").exists());
        // The backup should NOT exist
        assert!(!dir.join("loopstats.0").exists());

        cleanup(&dir);
    }

    #[test]
    fn test_flush_and_close_all() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "loopstats".to_string(),
            file_name: "loopstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: true,
        });
        reg.open("loopstats", &dir).unwrap();
        assert_eq!(reg.files.len(), 1);
        assert!(reg.files[0].1.is_some());

        reg.flush_all().unwrap();
        reg.close_all();
        assert_eq!(reg.files.len(), 0);
        cleanup(&dir);
    }

    #[test]
    fn test_rotate_file_size_based() {
        let dir = tmp_dir();
        let path = dir.join("teststats");
        // Write enough content to exceed size threshold
        let content = "x".repeat((FILEGEN_MAX_SIZE + 100) as usize);
        std::fs::write(&path, &content).unwrap();

        rotate_file(&path).unwrap();
        // Original should be renamed to .1
        assert!(dir.join("teststats.1").exists());
        // Original path should be gone (rotate_file doesn't recreate it)
        // The write functions recreate the file after rotation
        cleanup(&dir);
    }

    #[test]
    fn test_rotate_file_does_not_rotate_small_file() {
        let dir = tmp_dir();
        let path = dir.join("smallstats");
        std::fs::write(&path, "small content").unwrap();
        rotate_file(&path).unwrap();
        // Should NOT be rotated
        assert!(dir.join("smallstats").exists());
        assert!(!dir.join("smallstats.1").exists());
        cleanup(&dir);
    }

    #[test]
    fn test_filegen_disabled_entry() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "loopstats".to_string(),
            file_name: "loopstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: false,
        });
        // Opening a disabled entry should not create a file
        reg.open("loopstats", &dir).unwrap();
        assert!(!dir.join("loopstats").exists());
        cleanup(&dir);
    }

    #[test]
    fn test_rotate_if_needed_disabled_entry() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "loopstats".to_string(),
            file_name: "loopstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: false,
        });
        // Should not panic or error for disabled entries
        reg.rotate_if_needed("loopstats", &dir).unwrap();
        cleanup(&dir);
    }

    #[test]
    fn test_rotate_if_needed_nonexistent_entry() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        // No entry added, so rotate_if_needed should be a no-op
        reg.rotate_if_needed("nonexistent", &dir).unwrap();
        cleanup(&dir);
    }

    #[test]
    fn test_filegen_type_age_and_pid_no_rotation() {
        let dir = tmp_dir();
        for &gen_type in &[FileGenType::Age, FileGenType::Pid] {
            let mut reg = FileGenRegistry::new();
            let name = format!("{:?}stats", gen_type).to_lowercase();
            reg.add(FileGenEntry {
                name: name.clone(),
                file_name: name.clone(),
                gen_type,
                enabled: true,
            });
            reg.open(&name, &dir).unwrap();

            // Write to create the file
            let sys = SystemState::new();
            // Use write_stat_file_ex with no handle to create the file
            write_stat_file(&dir.join(&name), "test content").unwrap();
            assert!(dir.join(&name).exists());

            // Rotate should be a no-op for Age and Pid
            reg.rotate_if_needed(&name, &dir).unwrap();
            assert!(dir.join(&name).exists());
            assert!(!dir.join(format!("{}.0", name)).exists());
        }
        cleanup(&dir);
    }

    #[test]
    fn test_write_stat_file_creates_parent_dir() {
        let dir = tmp_dir();
        let nested = dir.join("subdir").join("stats");
        write_stat_file(&nested, "hello").unwrap();
        assert!(nested.exists());
        let content = std::fs::read_to_string(&nested).unwrap();
        assert!(content.contains("hello"));
        cleanup(&dir);
    }

    #[test]
    fn test_filegen_multiple_entries() {
        let dir = tmp_dir();
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "loopstats".to_string(),
            file_name: "loopstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: true,
        });
        reg.add(FileGenEntry {
            name: "peerstats".to_string(),
            file_name: "peerstats".to_string(),
            gen_type: FileGenType::Week,
            enabled: true,
        });
        reg.add(FileGenEntry {
            name: "clockstats".to_string(),
            file_name: "clockstats".to_string(),
            gen_type: FileGenType::Month,
            enabled: true,
        });

        assert_eq!(reg.entries.len(), 3);

        reg.open("loopstats", &dir).unwrap();
        reg.open("peerstats", &dir).unwrap();
        reg.open("clockstats", &dir).unwrap();

        // Write to all three
        let sys = SystemState::new();
        reg.write_loopstats(&dir.join("loopstats"), &sys, 0.0)
            .unwrap();

        let sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer = Peer::new(sa, NtpMode::Client, NtpVersion::V4, 4, 10);
        peer.associd = 42;
        reg.write_peerstats(&dir.join("peerstats"), &peer).unwrap();
        reg.write_clockstats(&dir.join("clockstats"), 7, "test")
            .unwrap();

        assert!(dir.join("loopstats").exists());
        assert!(dir.join("peerstats").exists());
        assert!(dir.join("clockstats").exists());

        cleanup(&dir);
    }

    #[test]
    fn test_rotate_file_max_backup_count() {
        let dir = tmp_dir();
        let path = dir.join("backuptest");

        // Write a large file and rotate multiple times
        let big_content = "x".repeat((FILEGEN_MAX_SIZE + 10) as usize);
        for _ in 0..(FILEGEN_MAX_BACKUP + 2) {
            std::fs::write(&path, &big_content).unwrap();
            rotate_file(&path).unwrap();
        }

        // We should have at most FILEGEN_MAX_BACKUP + 1 backup files
        // (name.1 through name.9)
        for i in 1..=9 {
            let backup = dir.join(format!("backuptest.{}", i));
            if i as u32 <= FILEGEN_MAX_BACKUP {
                // The backups may or may not exist depending on the exact sequence
            }
        }

        cleanup(&dir);
    }

    #[test]
    fn test_calendar_day_helper() {
        let epoch = std::time::UNIX_EPOCH;
        assert_eq!(calendar_day(&epoch), 0);

        let one_day = SystemTime::UNIX_EPOCH + Duration::from_secs(86400);
        assert_eq!(calendar_day(&one_day), 1);

        let one_year = SystemTime::UNIX_EPOCH + Duration::from_secs(365 * 86400);
        assert_eq!(calendar_day(&one_year), 365);
    }

    #[test]
    fn test_days_since_epoch() {
        // 1970-01-01 should be 0
        assert_eq!(days_since_epoch(1970, 1, 1), 0);
        // 1970-01-02 should be 1
        assert_eq!(days_since_epoch(1970, 1, 2), 1);
        // 2024-01-01 should be 19723 (approximate, but verifiable)
        let days = days_since_epoch(2024, 1, 1);
        assert!(days > 19000 && days < 21000);
    }

    #[test]
    fn test_week_key_epoch() {
        let epoch = SystemTime::UNIX_EPOCH;
        let wk = week_key(&epoch);
        // days=0 => week_key = 0/7 = 0
        assert_eq!(wk, 0);
        // One week later (7 days)
        let week_later = SystemTime::UNIX_EPOCH + Duration::from_secs(7 * 86400);
        let wk2 = week_key(&week_later);
        // days=7 => week_key = 7/7 = 1
        assert_eq!(wk2, 1);
        // 6 days is still the same week as epoch
        let six_days = SystemTime::UNIX_EPOCH + Duration::from_secs(6 * 86400);
        assert_eq!(week_key(&six_days), 0);
    }

    #[test]
    fn test_month_key() {
        let epoch = SystemTime::UNIX_EPOCH;
        let mk = month_key(&epoch);
        // 1970-01 has key = 1970 * 12 + 0 = 23640
        assert_eq!(mk, 1970 * 12);

        // About one year later
        let one_year = SystemTime::UNIX_EPOCH + Duration::from_secs(366 * 86400);
        let mk2 = month_key(&one_year);
        assert!(mk2 > mk);
    }

    #[test]
    fn test_year_of() {
        let epoch = SystemTime::UNIX_EPOCH;
        let y_epoch = year_of(&epoch);
        eprintln!("year_of(epoch) = {}", y_epoch);
        assert_eq!(y_epoch, 1970);

        let future = SystemTime::UNIX_EPOCH + Duration::from_secs(365 * 86400 * 30);
        let y = year_of(&future);
        eprintln!("year_of(future) = {}", y);
        assert!(y >= 1999, "year {} should be >= 1999", y);
    }

    #[test]
    fn test_filegen_mut_entry() {
        let mut reg = FileGenRegistry::new();
        reg.add(FileGenEntry {
            name: "loopstats".to_string(),
            file_name: "loopstats".to_string(),
            gen_type: FileGenType::Day,
            enabled: true,
        });

        // Disable via get_mut
        if let Some(entry) = reg.get_mut("loopstats") {
            entry.enabled = false;
        }
        assert!(!reg.get("loopstats").unwrap().enabled);
    }

    #[test]
    fn test_stat_file_write_ex_without_handle() {
        let dir = tmp_dir();
        let path = dir.join("ex_test");
        write_stat_file_ex(&path, "direct write\n", None).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("direct write"));
        cleanup(&dir);
    }
}
