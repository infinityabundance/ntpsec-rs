// ──── ntp_timer.rs ──────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_timer.c (14K)
//
// NTP timer event system — manages poll timers, reachability updates,
// housekeeping, and periodic statistics output.
// =============================================================================

use crate::ntp_types::*;

/// Timer event types — matching ntpsec's timer event system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerEvent {
    /// Send a poll to a peer (peer index).
    Poll(usize),
    /// Update reachability registers for all peers.
    Reachability,
    /// Periodic housekeeping (clock selection, combine, etc.).
    Housekeeping,
    /// Reload the leap second file.
    LeapFileReload,
    /// Write statistics to filegen files.
    StatsWrite,
}

/// A scheduled timer entry.
#[derive(Debug, Clone)]
pub struct TimerEntry {
    pub event: TimerEvent,
    /// Absolute NTP seconds when this fires.
    pub due: i64,
    /// Repeating interval in seconds. 0 = one-shot.
    pub interval: u32,
}

impl TimerEntry {
    pub fn new(event: TimerEvent, due: i64, interval: u32) -> Self {
        Self {
            event,
            due,
            interval,
        }
    }

    /// Advance this entry to the next due time strictly after `now`.
    /// Returns the number of missed intervals (0 if none).
    pub fn advance_past(&mut self, now: i64) -> u64 {
        if self.interval == 0 || self.due > now {
            return 0;
        }
        let missed = ((now - self.due) / self.interval as i64 + 1) as u64;
        self.due += missed as i64 * self.interval as i64;
        missed
    }
}

/// Timer queue — manages scheduled events.
#[derive(Debug, Default)]
pub struct TimerQueue {
    entries: Vec<TimerEntry>,
}

impl TimerQueue {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: TimerEntry) {
        self.entries.push(entry);
    }

    /// Remove all entries matching a predicate.
    pub fn remove(&mut self, predicate: impl Fn(&TimerEvent) -> bool) {
        self.entries.retain(|e| !predicate(&e.event));
    }

    /// Schedule a poll for a peer (repeating).
    pub fn schedule_poll(&mut self, peer_id: usize, now: i64, interval: u32) {
        self.add(TimerEntry::new(
            TimerEvent::Poll(peer_id),
            now + interval as i64,
            interval,
        ));
    }

    /// Schedule a single one-shot poll for a peer (interval=0, dropped after firing).
    pub fn schedule_poll_once(&mut self, peer_id: usize, due: i64) {
        self.add(TimerEntry::new(TimerEvent::Poll(peer_id), due, 0));
    }

    /// Pop all due events, advancing repeating entries past `now`.
    /// Returns the events that fired.
    pub fn pop_due(&mut self, now: NtpTs64) -> Vec<TimerEvent> {
        let now_secs = now.seconds;
        let mut fired = Vec::new();
        let mut keep = Vec::new();

        for mut entry in self.entries.drain(..) {
            if entry.due <= now_secs {
                fired.push(entry.event);
                if entry.interval > 0 {
                    entry.advance_past(now_secs);
                    keep.push(entry);
                }
                // one-shot entries (interval==0) are dropped
            } else {
                keep.push(entry);
            }
        }
        self.entries = keep;
        fired
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &TimerEntry> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_entry_new() {
        let entry = TimerEntry::new(TimerEvent::Poll(0), 1000, 64);
        assert_eq!(entry.due, 1000);
        assert_eq!(entry.interval, 64);
    }

    #[test]
    fn test_timer_advance_past() {
        let mut entry = TimerEntry::new(TimerEvent::Poll(0), 1000, 64);
        let missed = entry.advance_past(1100);
        assert!(missed >= 1);
        assert!(entry.due > 1100);
    }

    #[test]
    fn test_timer_queue_pop_due() {
        let mut queue = TimerQueue::new();
        queue.add(TimerEntry::new(TimerEvent::Poll(0), 100, 64));
        queue.add(TimerEntry::new(TimerEvent::Housekeeping, 200, 128));

        let now = NtpTs64 {
            seconds: 150,
            fraction: 0,
        };
        let fired = queue.pop_due(now);
        assert_eq!(fired.len(), 1);
        assert!(matches!(fired[0], TimerEvent::Poll(0)));

        // Entry should have been re-added for the next interval
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_timer_one_shot_dropped() {
        let mut queue = TimerQueue::new();
        queue.add(TimerEntry::new(TimerEvent::Poll(0), 100, 0)); // one-shot
        let now = NtpTs64 {
            seconds: 200,
            fraction: 0,
        };
        let fired = queue.pop_due(now);
        assert_eq!(fired.len(), 1);
        assert_eq!(queue.len(), 0); // should be removed
    }

    #[test]
    fn test_schedule_poll() {
        let mut queue = TimerQueue::new();
        queue.schedule_poll(0, 1000, 64);
        assert_eq!(queue.len(), 1);
    }
}
