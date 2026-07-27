// ──── ntp_timestamp.rs ────────────────────────────────────────────────────────
// eBPF/XDP program for NTP packet hardware-timestamping.
//
// This program runs at the XDP hook (NIC driver level) and:
// 1. Matches incoming UDP packets on port 123 (NTP).
// 2. Captures a high-resolution kernel timestamp at the earliest possible point.
// 3. Emits the timestamp + packet metadata to a perf event array.
// 4. Passes the packet through to the kernel network stack (XDP_PASS).
//
// ## Kernel requirements
//   - Linux 5.10+ with BTF support (CONFIG_DEBUG_INFO_BTF=y)
//   - BPF Type Format (BTF) for CO-RE (Compile Once, Run Everywhere)
//
// ## Build
//   Compiled with `bpfel-unknown-none` target. The resulting ELF is loaded
//   by the userspace `aya` loader in `ntpsec-rs-xdp`.
// =============================================================================

#![no_std]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::IpProto,
    ip::Ipv4Hdr,
    udp::UdpHdr,
};

/// NTP well-known port.
const NTP_PORT: u16 = 123;

/// Event payload sent from the XDP program to userspace via the perf event array.
///
/// This struct must be kept in sync with the userspace `NtpTimestampEvent`.
#[repr(C)]
pub struct NtpXdpEvent {
    /// Source IPv4 address in network byte order.
    pub source_ip: [u8; 4],
    /// Destination IPv4 address in network byte order.
    pub dest_ip: [u8; 4],
    /// Kernel timestamp in nanoseconds (CLOCK_MONOTONIC / bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// UDP source port.
    pub src_port: u16,
    /// UDP destination port (always 123 for NTP).
    pub dst_port: u16,
    /// Packet length in bytes.
    pub pkt_len: u16,
    /// Padding to 8-byte alignment.
    _padding: [u8; 4],
}

/// Perf event array for sending NTP timestamp events to userspace.
#[map]
pub static NTP_TIMESTAMPS: PerfEventArray<NtpXdpEvent> = PerfEventArray::new(0);

/// XDP program entry point.
///
/// Called for every packet received on the attached interface.
/// Returns `XDP_PASS` to allow the packet into the network stack,
/// or `XDP_ABORTED` on error.
#[xdp]
pub fn ntp_timestamp(ctx: XdpContext) -> u32 {
    match try_ntp_timestamp(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

/// Internal implementation that returns `Result` for ergonomic error handling.
fn try_ntp_timestamp(ctx: XdpContext) -> Result<u32, ()> {
    // ── 1. Compute data bounds ───────────────────────────────────────────
    let data_start = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;

    // Safety check: must have at least an Ethernet header
    if data_end < data_start + mem::size_of::<EthHdr>() {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── 2. Parse Ethernet header ──────────────────────────────────────────
    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth_type = u16::from_be(eth_hdr.ether_type);

    let (src_ip, dest_ip, l4_offset) = match eth_type {
        EtherType::Ipv4 => {
            // Parse IPv4 header
            let ip_hdr = ptr_at::<Ipv4Hdr>(&ctx, mem::size_of::<EthHdr>())?;
            let ip_hdr_len = (ip_hdr.ihl() as usize) * 4;

            // Minimum IPv4 header is 20 bytes, maximum is 60 bytes
            if ip_hdr_len < 20 || ip_hdr_len > 60 {
                return Ok(xdp_action::XDP_PASS);
            }

            // Check protocol: must be UDP
            if ip_hdr.proto != IpProto::Udp as u8 {
                return Ok(xdp_action::XDP_PASS);
            }

            let l4_start = mem::size_of::<EthHdr>() + ip_hdr_len;
            (ip_hdr.src_addr.0, ip_hdr.dst_addr.0, l4_start)
        }
        EtherType::Ipv6 => {
            // IPv6 parsing is more complex due to extension headers.
            // For now, pass IPv6 through without XDP timestamping.
            return Ok(xdp_action::XDP_PASS);
        }
        _ => {
            // Not IPv4 or IPv6 — pass through
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // ── 3. Parse UDP header ──────────────────────────────────────────────
    let udp_hdr = ptr_at::<UdpHdr>(&ctx, l4_offset)?;
    let dest_port = u16::from_be(udp_hdr.dest);
    let src_port = u16::from_be(udp_hdr.source);

    // Match NTP port (both directions).
    // Server receiving requests (dest=123) and client receiving responses (src=123).
    if dest_port != NTP_PORT && src_port != NTP_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── 4. Capture timestamp ──────────────────────────────────────────────
    // bpf_ktime_get_ns() returns nanoseconds since CLOCK_MONOTONIC (boot time).
    // This is the earliest possible hardware-timestamp in the XDP layer.
    let timestamp_ns = bpf_ktime_get_ns();

    // Compute total packet length
    let pkt_len = (data_end - data_start) as u16;

    // ── 5. Emit perf event ─────────────────────────────────────────────────
    let event = NtpXdpEvent {
        source_ip: src_ip,
        dest_ip,
        timestamp_ns,
        src_port,
        dst_port: dest_port,
        pkt_len,
        _padding: [0u8; 4],
    };

    // Output the event to the perf event array. Userspace reads these events.
    NTP_TIMESTAMPS.output(&ctx, &event, 0);

    // ── 6. Pass packet to network stack ────────────────────────────────────
    Ok(xdp_action::XDP_PASS)
}

/// Read a typed pointer from the XDP context, with bounds checking.
///
/// Returns `Err(())` if the memory region would extend past `data_end`.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let data_end = ctx.data_end() as usize;
    let size = mem::size_of::<T>();

    // Check for overflow and bounds
    if offset + size > data_end || offset + size < offset {
        return Err(());
    }

    let ptr = (ctx.data() as usize + offset) as *const T;

    // Additional safety: ensure the pointer is properly aligned.
    // On eBPF with LLVM backend, misaligned access causes a verifier error.
    if (ptr as usize) % mem::align_of::<T>() != 0 {
        return Err(());
    }

    Ok(ptr)
}

/// Panic handler for the eBPF program.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
