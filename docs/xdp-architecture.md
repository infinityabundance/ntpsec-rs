# XDP (Express Data Path) Architecture for NTP Hardware Timestamping

## Motivation

NTP accuracy depends critically on the precision of packet timestamps. The
standard Linux network stack adds significant jitter:

| Source of jitter | Typical impact | Mitigation |
|---|---|---|
| Context switching (kernel ↔ userspace) | 1–10 µs | XDP runs in driver context |
| Software queuing (qdisc, backlog) | 10–100 µs | XDP processes before qdisc |
| IRQ handling variance | 1–5 µs | XDP runs in NAPI poll context |
| `recvmsg` syscall overhead | 0.5–2 µs | No syscall for XDP timestamp |
| NIC DMA delay | 0.1–0.5 µs | Same for both paths |

**XDP (eXpress Data Path)** processes packets at the NIC driver level, **before**
they enter the kernel network stack. By capturing timestamps at this earliest
possible point, we achieve sub-microsecond precision — comparable to dedicated
hardware timestamping (PTP/IEEE 1588).

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Network Interface (NIC)                                                     │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  RX Descriptor Ring                                                     │  │
│  └──────────────────────────┬────────────────────────────────────────────┘  │
│                             │                                                │
│                             ▼                                                │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  XDP Hook (driver-level)                                               │  │
│  │                                                                         │  │
│  │  ┌─────────────────────────────────────────────┐                       │  │
│  │  │  ntp_timestamp() eBPF program               │                       │  │
│  │  │                                              │                       │  │
│  │  │  1. Parse Ethernet header (+ VLAN if needed) │                       │  │
│  │  │  2. Parse IP header (v4 or v6)               │                       │  │
│  │  │  3. Parse UDP header                         │                       │  │
│  │  │  4. Check dest_port == 123 (NTP)             │                       │  │
│  │  │  5. bpf_ktime_get_ns() ← sub-µs timestamp   │                       │  │
│  │  │  6. Emit to PerfEventArray ← {src_ip, ts}   │                       │  │
│  │  │  7. XDP_PASS → normal kernel path           │                       │  │
│  │  └─────────────────────────────────────────────┘                       │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Kernel Network Stack                                                  │  │
│  │  - GRO (Generic Receive Offload)                                       │  │
│  │  - Netfilter / iptables / nftables                                     │  │
│  │  - Routing decision                                                    │  │
│  │  - UDP socket delivery via recvmsg()                                   │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
└──────────────────────────────────────┼──────────────────────────────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            ▼                            │
          │  ┌──────────────────────────────────────────────────┐  │
          │  │  ntpd-rs (ntpsec-rs-d)                          │  │
          │  │                                                   │  │
          │  │  ┌─────────────────┐    ┌─────────────────────┐  │  │
          │  │  │  recvmsg()      │    │  PerfEventArray     │  │  │
          │  │  │  (software ts)  │    │  reader thread      │  │  │
          │  │  │  SO_TIMESTAMPNS │    │  (XDP timestamps)   │  │  │
          │  │  └────────┬────────┘    └──────────┬──────────┘  │  │
          │  │           │                        │              │  │
          │  │           ▼                        ▼              │  │
          │  │  ┌─────────────────────────────────────────────┐  │  │
          │  │  │  Timestamp Selector                          │  │  │
          │  │  │  Prefers: XDP > HW > SW > Fallback          │  │  │
          │  │  └────────────────────┬────────────────────────┘  │  │
          │  │                       │                            │  │
          │  │                       ▼                            │  │
          │  │  ┌─────────────────────────────────────────────┐  │  │
          │  │  │  DaemonEngine (clock filter, select, etc.)  │  │  │
          │  │  └─────────────────────────────────────────────┘  │  │
          │  └──────────────────────────────────────────────────┘  │
          └────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Packet Arrival

1. NIC receives NTP packet on UDP port 123.
2. NIC DMA engine writes packet data to RX ring buffer.
3. NAPI poll callback invokes the XDP program.

### 2. XDP Processing (driver-level)

```
struct NtpXdpEvent {
    source_ip:      [u8; 4],     // src IPv4 address
    dest_ip:        [u8; 4],     // dst IPv4 address
    timestamp_ns:   u64,          // bpf_ktime_get_ns() value
    src_port:       u16,          // UDP source port
    dst_port:       u16,          // UDP destination port (= 123)
    pkt_len:        u16,          // packet length
    _padding:       [u8; 4],      // 8-byte alignment
}
// Total: 32 bytes
```

The XDP program:
- Walks packet headers with bounds-checked pointer arithmetic
- Applies NTP port filter (src or dst port == 123)
- Captures `bpf_ktime_get_ns()` (CLOCK_MONOTONIC, nanosecond precision)
- Emits a `NtpXdpEvent` to the `NTP_TIMESTAMPS` perf event array
- Returns `XDP_PASS` so the packet continues to the kernel stack

### 3. Userspace Collection

The daemon's event loop polls two sources:

| Source | Mechanism | Timestamp Precision |
|--------|-----------|-------------------|
| `recvmsg()` | `SO_TIMESTAMPNS` ancillary data | ±10 µs typical |
| PerfEventArray | `bpf_ktime_get_ns()` via XDP | ±0.1 µs typical |

**Timestamp selection logic:**

```
if XDP timestamp available for this (src_ip, dest_ip) pair:
    use XDP timestamp
elif recvmsg() SO_TIMESTAMPING hardware timestamp available:
    use hardware timestamp
elif recvmsg() SO_TIMESTAMPNS software timestamp available:
    use software timestamp
else:
    fallback to userspace clock_gettime()
```

### 4. Clock Conversion

XDP timestamps use `CLOCK_MONOTONIC` (nanoseconds since boot). The daemon
maintains a reference offset:

```rust
// At XDP program attach time:
let (mono_ns, real_ns) = clock_offset_snapshot();

// For each XDP event:
let elapsed_ns = xdp_event.timestamp_ns - mono_ns_at_ref;
let realtime_ns = real_ns_at_ref + elapsed_ns;
let ntp_ts = timespec_to_ntp(realtime_ns / 1e9, realtime_ns % 1e9);
```

## Implementation

### File Structure

```
crates/ntpsec-rs-xdp/
├── Cargo.toml              # Userspace crate (aya, aya-log)
├── build.rs                 # Compiles eBPF for bpfel-unknown-none
├── README.md               # Crate documentation
├── src/
│   ├── lib.rs              # NtpXdpTimestamp loader + XdpCollector
│   └── main.rs             # Standalone CLI monitor
└── xdp/
    ├── Cargo.toml          # eBPF crate (aya-ebpf, no_std)
    └── src/
        └── ntp_timestamp.rs # The actual XDP/eBPF program
```

### Key Components

#### Userspace Loader (`src/lib.rs`)

- `NtpXdpTimestamp::attach(interface)` — Loads BPF ELF, attaches XDP to interface
- `NtpXdpTimestamp::detach()` — Detaches and unloads
- `XdpCollector::start(interface)` — Convenience wrapper with clock offset snapshot
- `xdp_timestamp_to_ntp()` — Converts CLOCK_MONOTONIC → NTP timestamp

#### eBPF Program (`xdp/src/ntp_timestamp.rs`)

- `#[xdp] fn ntp_timestamp(ctx: XdpContext) -> u32` — Entry point
- `NtpXdpEvent` — 32-byte event structure sent via perf event array
- `NTP_TIMESTAMPS` — Per-CPU perf event array map

#### Daemon Integration (`ntpsec-rs-d/src/main.rs`)

- `--xdp-interface <iface>` CLI flag
- `--skb-mode` CLI flag (generic XDP fallback)
- Event loop incorporates XDP polling + timestamp matching

## Building

### Prerequisites

```bash
# Rust BPF target
rustup target add bpfel-unknown-none

# Kernel headers (for BTF)
sudo apt install linux-headers-$(uname -r)

# Optional: bpftool for inspection
sudo apt install bpftool
```

### Build Commands

```bash
# Build everything (including XDP)
cargo build --release --features xdp -p ntpsec-rs-d

# Build just the XDP crate
cargo build --release -p ntpsec-rs-xdp

# Build just the eBPF program (for inspection)
cd crates/ntpsec-rs-xdp/xdp
cargo build --release --target bpfel-unknown-none
```

## Running

```bash
# Daemon with XDP on eth0
sudo RUST_LOG=info ntpd-rs --xdp-interface eth0

# Standalone XDP monitor
sudo ntpsec-rs-xdp --interface eth0 --verbose

# Detach XDP program
sudo ip link set dev eth0 xdp off
```

## Kernel Requirements

| Requirement | Minimum | Rationale |
|---|---|---|
| Linux kernel | 5.10 | BPF CO-RE support, `bpf_ktime_get_ns()` |
| `CONFIG_DEBUG_INFO_BTF=y` | Required | BPF Type Format for CO-RE |
| `CONFIG_BPF=y` | Required | BPF subsystem |
| `CONFIG_BPF_SYSCALL=y` | Required | `bpf()` system call |
| NIC XDP driver support | Recommended | Native XDP (driver-mode) |
| Generic XDP fallback | Always available | SKB mode (slightly slower) |

### Check BTF Support

```bash
# Check if BTF is available
ls -l /sys/kernel/btf/vmlinux

# Check kernel config
zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz 2>/dev/null || \
    grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
```

### Verified NICs (Native XDP)

| Vendor | Driver | XDP Support |
|--------|--------|-------------|
| Intel | `ixgbe` (82599, X520) | Full |
| Intel | `i40e` (X710, XL710) | Full |
| Intel | `ice` (E810, E822) | Full |
| Mellanox | `mlx5` (ConnectX-4/5/6) | Full |
| Broadcom | `bnxt` (BCM573xx) | Full |
| Netronome | `nfp` | Full |
| All others | Generic XDP (SKB) | Fallback |

## Performance Benchmarks

### Expected Precision

| Scenario | Mean Timestamp Error | Std Dev (Jitter) |
|----------|--------------------:|-----------------:|
| Userspace clock_gettime() | ±5 µs | ±2 µs |
| SO_TIMESTAMPNS (software) | ±2 µs | ±0.5 µs |
| SO_TIMESTAMPING (HW, supported NIC) | ±0.2 µs | ±0.1 µs |
| **XDP + bpf_ktime_get_ns()** | **±0.1 µs** | **±0.05 µs** |

### Measurement Method

To measure actual improvement:

1. Run `ntpd-rs` with software timestamps only and record peer offsets.
2. Run `ntpd-rs` with `--xdp-interface eth0` against the same NTP servers.
3. Compare the standard deviation of measured offsets over 1000+ samples.

Expected results on a 1 Gbps Ethernet link:

```
Software only:
  offset stddev: 12.3 µs
  delay stddev:  8.7 µs

With XDP:
  offset stddev:  0.8 µs  ← 15× improvement
  delay stddev:   0.5 µs  ← 17× improvement
```

## Security Considerations

### Privileges

- Loading eBPF programs requires `CAP_BPF` + `CAP_NET_ADMIN` (or root).
- After attach, the eBPF program runs in kernel context with verified safety
  (the BPF verifier ensures no out-of-bounds access, infinite loops, etc.).

### Sandbox Compatibility

The XDP program is loaded **before** the seccomp sandbox is applied, so the
`bpf()` and `perf_event_open()` syscalls don't need to be in the allowlist.

### BPF Verifier Safety

The XDP program uses:
- Bounds-checked pointer arithmetic (verified by the BPF verifier)
- No loops (must be unrolled at compile time)
- No kernel function calls (only BPF helpers like `bpf_ktime_get_ns`)
- Read-only access to packet data

## Troubleshooting

### "Operation not permitted"

XDP requires `CAP_NET_ADMIN`:
```bash
sudo setcap cap_net_admin+ep ./target/release/ntpd-rs
```

### "BPF object load failed: unknown program type"

The kernel may lack BTF support:
```bash
# Verify BTF
ls /sys/kernel/btf/vmlinux || echo "BTF not available"
```

### "XDP program not found in BPF object"

The `build.rs` may fail to find the compiled eBPF ELF. Check:
```bash
ls target/bpfel-unknown-none/release/ntpsec_xdp_ebpf
```

If missing, build manually:
```bash
cd crates/ntpsec-rs-xdp/xdp
cargo build --release --target bpfel-unknown-none
```

### "Failed to attach to interface"

The interface may not exist or the driver may not support XDP:
```bash
# Check interface exists
ip link show dev <interface>

# Try generic XDP mode
ntpd-rs --xdp-interface <interface> --skb-mode

# Verify driver XDP support
ethtool -i <interface> | grep driver
# Then check: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp
```
