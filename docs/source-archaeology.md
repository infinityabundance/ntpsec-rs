# Source Archaeology: NTPsec C Code Atlas

This document records the deep structural analysis of the NTPsec C codebase
(v1.3.3, commit `master`). It is an archaeological map — extracted via Doxygen
indexing, grep patterns, and structural analysis — never by reading verbatim
C source into the Rust implementation.

## Repository layout (upstream ntpsec)

```
ntpsec/
├── include/          # 42 header files
│   ├── ntp.h         # Main ntp types (25K)
│   ├── ntpd.h        # Daemon globals (16K)
│   ├── ntp_types.h   # Sized integer types
│   ├── ntp_fp.h      # Fixed-point arithmetic
│   ├── ntp_calendar.h # Calendar computations
│   ├── ntp_control.h # Mode 6 control protocol
│   ├── ntp_proto.h   # (inline in ntp_proto.c)
│   ├── ntp_io.h      # I/O dispatch
│   ├── ntp_net.h     # Network address handling
│   ├── ntp_refclock.h# Reference clock interface
│   ├── nts.h         # NTS structures (8K)
│   ├── nts2.h        # NTS internal structures
│   └── ...
├── libntp/           # 28 C files (core library)
├── libparse/         # 17 C files (reference clock parsing)
├── libaes_siv/       # AES-SIV encryption (3 C files + test)
├── libjsmn/          # JSON parser (vendored)
├── ntpd/             # Daemon — the main loop
│   ├── ntpd.c         # Main entry, startup, signal handlers
│   ├── ntp_proto.c    # Protocol engine (84K — largest file)
│   ├── ntp_io.c       # I/O event loop (72K)
│   ├── ntp_control.c  # Mode 6 control protocol (106K)
│   ├── ntp_config.c   # Configuration parser (72K)
│   ├── ntp_loopfilter.c # Clock discipline (39K)
│   ├── ntp_parser.y   # Bison grammar (30K)
│   ├── ntp_scanner.c  # Lexical analyzer (25K)
│   ├── ntp_peer.c     # Association management (19K)
│   ├── ntp_timer.c    # Timer event loop (14K)
│   ├── ntp_leapsec.c  # Leap second handling (25K)
│   ├── ntp_util.c     # Utility functions (25K)
│   ├── ntp_restrict.c # Access restrictions (17K)
│   ├── ntp_monitor.c  # Monitoring (15K)
│   ├── ntp_sandbox.c  # Seccomp sandbox (17K)
│   ├── ntp_refclock.c # Reference clock base (29K)
│   ├── ntp_filegen.c  # Statistics file generation (13K)
│   ├── ntp_dns.c      # DNS resolution (5K)
│   ├── ntp_signd.c    # Samba signing (9K)
│   ├── ntp_recvbuff.c # Receive buffer pool (3K)
│   ├── ntp_packetstamp.c # Hardware timestamping (13K)
│   ├── nts.c          # NTS core (14K)
│   ├── nts_client.c   # NTS client (26K)
│   ├── nts_server.c   # NTS server (19K)
│   ├── nts_cookie.c   # NTS cookies (12K)
│   ├── nts_extens.c   # NTS extension fields (12K)
│   ├── refclock_*.c   # 16 refclock drivers
│   └── keyword-gen.c  # Keyword generation (20K)
├── ntpclients/       # 12 Python client scripts
│   ├── ntpq.py        # Query tool (73K)
│   ├── ntpdig.py      # NTP query tool (20K)
│   ├── ntpmon.py      # Monitor tool (21K)
│   ├── ntpviz.py      # Visualization (76K)
│   ├── ntpsweep.py    # Network sweep (8K)
│   ├── ntptrace.py    # Trace tool (5K)
│   ├── ntpwait.py     # Wait tool (5K)
│   ├── ntplogtemp.py  # Temperature logging (10K)
│   ├── ntploggps.py   # GPS logging (8K)
│   ├── ntpleapfetch   # Leap second fetch (shell, 14K)
│   ├── ntpkeygen.py   # Key generation (4K)
│   └── ntpsnmpd.py    # SNMP agent (48K)
├── ntpfrob/          # System utilities (6 C files)
├── ntptime/          # Kernel time management (1 C file)
├── pylib/            # Python library (7 modules)
├── tests/            # C and Python tests
├── docs/             # AsciiDoc documentation
├── etc/              # Systemd units, config examples
└── packaging/        # RPM/SUSE packaging
```

## Key architectural insights

### 1. The config parser: Bison + hand-written scanner

ntpsec uses a two-stage config parser:

1. **`ntp_scanner.c`**: A hand-written lexical analyzer that tokenizes the config
   file. It handles include files, comment stripping, and keyword recognition.
2. **`ntp_parser.y`**: A Bison grammar that parses the token stream into config
   data structures stored in a global `config_tree`.

The Rust reimplementation uses a `nom`-based parser for the same grammar but
with error recovery that matches ntpsec's behavior.

**Config directive count**: 93 directives recognized (verified against `ntpd -?`).

### 2. The protocol engine: ntp_proto.c (84K)

This is the heart of ntpd. It handles:

- Packet receive/transmit (all modes: client, server, symmetric, broadcast)
- Clock filter processing (8-sample shift register)
- Clock selection algorithm (intersection/distance)
- Clock clustering algorithm (jitter-weighted pruning)
- Clock combining algorithm (weighted average of survivors)
- Loop filter (PI controller: phase and frequency updates)
- Poll interval management (adaptive minpoll/maxpoll)
- Reachability register management
- Authentication verification
- NTS extension field processing
- Rate limiting (Kiss-o'-Death responses)

The control flow:

```
receive() → process_packet() → clock_filter() → clock_select() → clock_combine()
  → local_clock() → poll_update() → transmit()
```

### 3. The control protocol: ntp_control.c (106K)

Mode 6 management protocol used by ntpq. It implements:

- Read/write/list variables for system, peer, clock
- Authentication for write operations
- Asynchronous response paging
- Error handling with matching ntpsec error codes

### 4. The I/O layer: ntp_io.c (72K)

Event-driven I/O using `select()`/`poll()`. Handles:

- Multiple UDP sockets per interface
- Socket creation, binding, and interface discovery
- Packet timestamping via `SO_TIMESTAMPNS`
- Interrupt-driven (signal-based) I/O on some platforms

### 5. NTS (Network Time Security): 5 files, ~80K

NTS is the biggest addition in ntpsec vs. classic NTP:

- **NTS-KE**: TLS-based key establishment (port 4460)
- **NTS Cookies**: AES-SIV encrypted state passed between client and server
- **NTS Extension Fields**: NTP extension fields for cookie transport

### 6. Loop filter: ntp_loopfilter.c (39K)

The clock discipline algorithm:

- **Type 1 (PLL-only)**: Phase-locked loop — adjusts frequency based on phase error
- **Type 2 (PLL/FLL)**: Hybrid phase/frequency-locked loop — ntpsec default
- **Type 3 (FLL-only)**: Frequency-locked loop
- **Type 4 (PLL/FLL with kernel PLL)**: Interactive with kernel discipline

### 7. Python clients: 12 tools as native Rust binaries

The ntpsec Python clients are rebuilt as native Rust binaries with identical
output format, CLI interface, and behavior. Each tool is a separate crate.

## Doxygen-extracted function signatures

See `docs/research/function-signatures/` for the complete Doxygen-extracted
signature database for each C translation unit.
