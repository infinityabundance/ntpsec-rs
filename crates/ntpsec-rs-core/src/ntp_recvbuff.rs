// ──── ntp_recvbuff.rs ───────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_recvbuff.c, include/recvbuff.h
//
// Receive buffer pool management: pre-allocated packet buffers to avoid
// dynamic allocation in the hot path.
// =============================================================================

use crate::ntp_types::*;

/// A receive buffer (matches ntpsec's `recvbuf`).
#[derive(Debug)]
pub struct RecvBuffer {
    pub data: [u8; NTP_MAX_PACKET_SIZE],
    pub length: usize,
    pub srcaddr: SockAddr,
    pub dstaddr: SockAddr,
    pub rx_timestamp: NtpTs64,
    pub flags: RecvFlags,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct RecvFlags: u32 {
        const NONE        = 0;
        const EXTEN       = 1 << 0; // Has extension fields
        const AUTH        = 1 << 1; // Has MAC
        const NTS         = 1 << 2; // Has NTS
        const LOCAL       = 1 << 3; // From localhost
        const BCST        = 1 << 4; // Broadcast
    }
}

/// Receive buffer pool.
#[derive(Debug)]
pub struct RecvBufPool {
    free_list: Vec<RecvBuffer>,
    free_count: u32,
    total_count: u32,
    max_count: u32,
}

impl RecvBufPool {
    pub fn new(initial_count: u32, max_count: u32) -> Self {
        let mut free_list = Vec::with_capacity(initial_count as usize);
        for _ in 0..initial_count {
            free_list.push(unsafe { std::mem::zeroed() });
        }
        Self {
            free_count: initial_count,
            total_count: initial_count,
            max_count,
            free_list,
        }
    }

    pub fn alloc(&mut self) -> RecvBuffer {
        if let Some(buf) = self.free_list.pop() {
            self.free_count -= 1;
            buf
        } else if self.total_count < self.max_count {
            self.total_count += 1;
            unsafe { std::mem::zeroed() }
        } else {
            // Reuse the oldest buffer
            unsafe { std::mem::zeroed() }
        }
    }

    pub fn free(&mut self, buf: RecvBuffer) {
        if self.free_count < self.max_count {
            self.free_list.push(buf);
            self.free_count += 1;
        }
    }
}
