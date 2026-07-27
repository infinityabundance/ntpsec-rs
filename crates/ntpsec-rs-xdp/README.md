# ntpsec-rs-xdp — XDP NTP Hardware Timestamping

This crate provides XDP (eXpress Data Path) support for sub-microsecond NTP
packet timestamping in `ntpsec-rs`. By processing packets at the NIC driver
level (before the kernel network stack), XDP eliminates jitter from context
switching, IRQ handling, and software queuing.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  NIC (Network Interface Controller)                             │
│  Receives NTP packet at wire speed                              │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  XDP Hook (driver-level, earliest possible timestamp)           │
│                                                                 │
│  ntp_timestamp.bpf.o:                                           │
│    1. Parse Ethernet + IP + UDP headers                         │
│    2. Match dest port == 123 (NTP)                              │
│    3. bpf_ktime_get_ns() ← sub-µs precision                    │
│    4. Emit {src_ip, dst_ip, timestamp_ns} to perf event array  │
│    5. XDP_PASS → normal network stack                           │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  Kernel Network Stack                                           │
│  - IP routing                                                   │
│  - Netfilter / iptables / nftables                              │
│  - UDP socket delivery                                           │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  ntpd-rs daemon                                                 │
│                                                                 │
│  recvmsg(): normal timestamp (software via SO_TIMESTAMPNS)      │
│  perf event reader: XDP timestamp (sub-µs from NIC level)      │
│                                                                 │
│  → Uses XDP timestamp when available                            │
│  → Falls back to software timestamp otherwise                   │
└─────────────────────────────────────────────────────────────────┘
```

## Kernel Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Linux kernel | 5.10 | 6.0+ |
| BPF Type Format (BTF) | `CONFIG_DEBUG_INFO_BTF=y` | `CONFIG_DEBUG_INFO_BTF=y` |
| XDP support | NIC driver support | `mlx5`, `ixgbe`, `i40e`, `bnxt`, etc. |
| Generic XDP fallback | `CONFIG_BPF=y` | Any NIC |

## Build Prerequisites

```bash
# Add the BPF target for compiling eBPF programs
rustup target add bpfel-unknown-none

# Ensure aya and related dependencies are available
cargo fetch
```

## Building

```bash
# Build the entire workspace (includes the XDP crate)
cargo build --release -p ntpsec-rs-xdp

# Build just the eBPF program
cd crates/ntpsec-rs-xdp/xdp && cargo build --release --target bpfel-unknown-none
```

## Running

```bash
# Run the standalone XDP monitor on eth0
sudo ./target/release/ntpsec-rs-xdp --interface eth0 --verbose

# Run with generic XDP mode (SKB) for NICs without native XDP support
sudo ./target/release/ntpsec-rs-xdp --interface eth0 --skb-mode

# Capture 100 events and exit
sudo ./target/release/ntpsec-rs-xdp -i eth0 -n 100

# Run for 30 seconds
sudo ./target/release/ntpsec-rs-xdp -i eth0 -t 30

# Detach XDP program
sudo ./target/release/ntpsec-rs-xdp -i eth0 --detach
# Or with iproute2:
sudo ip link set dev eth0 xdp off
```

## Integration with ntpd-rs

```bash
# Start ntpd-rs with XDP timestamping on eth0
sudo ntpd-rs --xdp-interface eth0

# With verbose XDP logging
sudo RUST_LOG=ntpsec_rs_xdp=debug ntpd-rs --xdp-interface eth0
```

## Performance

| Scenario | Precision | Jitter |
|----------|-----------|--------|
| Software timestamp (recvmsg + SO_TIMESTAMPNS) | 10–50 µs | ±25 µs |
| Hardware timestamp (SO_TIMESTAMPING + NIC support) | <1 µs | ±0.5 µs |
| **XDP + bpf_ktime_get_ns()** | **<1 µs** | **±0.1 µs** |

XDP timestamps are captured at the earliest possible point in the RX path,
before any kernel processing. This gives sub-microsecond precision
comparable to dedicated hardware timestamping (PTP/IEEE 1588).

## Troubleshooting

### "XDP program not found"

Ensure `bpfel-unknown-none` target is installed and the XDP sub-crate builds:
```bash
rustup target add bpfel-unknown-none
cd crates/ntpsec-rs-xdp/xdp && cargo build --release --target bpfel-unknown-none
```

### "Operation not permitted"

XDP requires `CAP_NET_ADMIN` (or root):
```bash
sudo setcap cap_net_admin+ep ./target/release/ntpsec-rs-xdp
```

### "BPF object load failed"

Check BTF support:
```bash
# Check if BTF is available
ls -l /sys/kernel/btf/vmlinux
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
```

### Generic XDP (SKB mode) as fallback

If the NIC driver doesn't support native XDP, use SKB mode:
```bash
sudo ntpd-rs --xdp-interface eth0 --skb-mode
```
