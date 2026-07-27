// ──── counting_alloc.rs — Counting allocator for zero-allocation verification ─
//
// Provides a `CountingAllocator` that wraps `std::alloc::System` and counts
// every allocation and deallocation.  Used by the allocation court test to
// verify that the NTP receive hot path performs zero heap allocations.
//
// ## Usage
//
// In your test binary:
//
// ```ignore
// use ntpsec_rs_core::counting_alloc::CountingAllocator;
//
// #[global_allocator]
// static A: CountingAllocator = CountingAllocator;
// ```
//
// Then call `CountingAllocator::reset()` before the measurement and
// `CountingAllocator::snapshot()` after to get the difference.
// =============================================================================

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A global allocator wrapper that counts all allocations and deallocations.
///
/// This is a zero-sized type; all state lives in `AtomicUsize` statics.
/// Safe to use as `#[global_allocator]` because:
/// - It delegates to `System` for the actual memory management
/// - Atomic counters are lock-free and thread-safe
/// - The type is `Send + Sync` (ZST with no interior mutable state)
pub struct CountingAllocator;

/// Total number of `alloc` calls since last reset.
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Total number of `dealloc` calls since last reset.
static FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Total number of bytes requested in `alloc` calls since last reset.
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

impl CountingAllocator {
    /// Reset all counters to zero. Call this before starting a measurement.
    pub fn reset() {
        ALLOC_COUNT.store(0, Ordering::SeqCst);
        FREE_COUNT.store(0, Ordering::SeqCst);
        ALLOC_BYTES.store(0, Ordering::SeqCst);
    }

    /// Take an atomic snapshot of all counters.
    pub fn snapshot() -> AllocSnapshot {
        AllocSnapshot {
            alloc_count: ALLOC_COUNT.load(Ordering::SeqCst),
            free_count: FREE_COUNT.load(Ordering::SeqCst),
            alloc_bytes: ALLOC_BYTES.load(Ordering::SeqCst),
        }
    }
}

/// A point-in-time snapshot of allocation counters.
#[derive(Debug, Clone, Copy)]
pub struct AllocSnapshot {
    pub alloc_count: usize,
    pub free_count: usize,
    pub alloc_bytes: usize,
}

impl AllocSnapshot {
    /// Compute the difference from an earlier snapshot.
    pub fn diff_since(&self, earlier: &AllocSnapshot) -> AllocSnapshot {
        AllocSnapshot {
            alloc_count: self.alloc_count.saturating_sub(earlier.alloc_count),
            free_count: self.free_count.saturating_sub(earlier.free_count),
            alloc_bytes: self.alloc_bytes.saturating_sub(earlier.alloc_bytes),
        }
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FREE_COUNT.fetch_add(1, Ordering::SeqCst);
        System.dealloc(ptr, layout)
    }
}
