#!/usr/bin/env python3
"""Differential Fuzzing Harness for NTPsec (C) vs ntpsec-rs (Rust).

Generates mutated NTP packets and sends each one to BOTH daemons via UDP,
compares their responses, and reports divergences.

Usage:
    # Run 1000 iterations against running Docker containers
    python3 tests/docker/differential_fuzzer.py --iterations 1000

    # Run continuously until Ctrl+C
    python3 tests/docker/differential_fuzzer.py

    # With specific host/port overrides
    python3 tests/docker/differential_fuzzer.py --oracle 10.100.0.10 --candidate 10.100.0.20
"""

import argparse
import json
import logging
import os
import random
import signal
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NTP_PORT = 123
SOCKET_TIMEOUT = 5.0       # seconds before a recvfrom() is considered a timeout
RATE_LIMIT_DELAY = 0.01    # 10 ms minimum between sends (prevents flooding)
MAX_RESPONSE_BYTES = 4096  # max receive buffer size
NTP_EPOCH_OFFSET = 2208988800  # seconds between 1900-01-01 and 1970-01-01

# Default topology (matching docker-compose.yml)
DEFAULT_ORACLE_HOST = "127.0.0.1"      # mapped via docker port publishing or host networking
DEFAULT_CANDIDATE_HOST = "127.0.0.1"
DEFAULT_ORACLE_PORT = 123
DEFAULT_CANDIDATE_PORT = 123

# Stratum constants
STRATUM_UNSPECIFIED = 0   # KoD / kiss-o'-death
STRATUM_PRIMARY = 1
STRATUM_SECONDARY_MAX = 15
STRATUM_UNSYNC = 16

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("differential_fuzzer")
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                        datefmt="%H:%M:%S"))
logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Global statistics  (mutated from signal handlers and main loop)
# ---------------------------------------------------------------------------

class Stats:
    """Thread-safe (single-threaded) running statistics tracker."""

    def __init__(self) -> None:
        self.total: int = 0
        self.matches: int = 0
        self.mismatches: int = 0
        self.timeouts: int = 0
        self.errors: int = 0
        self.start_time: float = time.monotonic()
        self.running: bool = True

    @property
    def divergence_rate(self) -> float:
        compared = self.matches + self.mismatches
        return (self.mismatches / compared * 100.0) if compared > 0 else 0.0

    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    def snapshot(self) -> Dict[str, Any]:
        return {
            "total_packets": self.total,
            "matches": self.matches,
            "mismatches": self.mismatches,
            "timeouts": self.timeouts,
            "errors": self.errors,
            "divergence_rate_pct": round(self.divergence_rate, 4),
            "elapsed_seconds": round(self.elapsed(), 2),
        }

    def progress_line(self) -> str:
        rate = self.divergence_rate
        flag = " ⚠ DIVERGENCE" if rate > 0 else ""
        return (
            f"[{self.total:>8d} pkts] "
            f"match={self.matches:<6d} "
            f"mismatch={self.mismatches:<4d} "
            f"timeout={self.timeouts:<4d} "
            f"error={self.errors:<3d} "
            f"div={rate:.4f}%  "
            f"elapsed={self.elapsed():.1f}s{flag}"
        )


stats = Stats()


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def _signal_handler(signum: int, _frame) -> None:  # type: ignore[no-untyped-def]
    """Graceful shutdown on SIGINT / SIGTERM."""
    signame = signal.Signals(signum).name
    logger.info("Received %s — draining...", signame)
    stats.running = False


def _install_signal_handlers() -> None:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# Packet building  (mirrors oracle_harness.py)
# ---------------------------------------------------------------------------

def make_ntp_packet(
    mode: int = 3,
    version: int = 4,
    stratum: int = 2,
    poll: int = 6,
    precision: int = -20,
    root_delay: float = 0.0,
    root_disp: float = 0.0,
    ref_id: bytes = b"TEST",
    originate_ts: float = 0.0,
    receive_ts: float = 0.0,
    transmit_ts: float = 0.0,
    ref_ts: float = 0.0,
) -> bytes:
    """Build a 48-byte NTPv4 packet.

    All four NTP timestamps (reference, originate, receive, transmit)
    are packed at their standard offsets (16, 24, 32, 40).
    """
    li_vn_mode = (0 << 6) | ((version & 0x07) << 3) | (mode & 0x07)
    pkt = struct.pack("!BBBB", li_vn_mode, stratum & 0xFF, poll & 0xFF, precision & 0xFF)
    pkt += struct.pack("!I", int(root_delay * 65536.0) & 0xFFFFFFFF)
    pkt += struct.pack("!I", int(root_disp * 65536.0) & 0xFFFFFFFF)
    pkt += ref_id.ljust(4, b"\x00")[:4]
    for ts in [ref_ts, originate_ts, receive_ts, transmit_ts]:
        if isinstance(ts, (int, float)):
            seconds = int(ts) + NTP_EPOCH_OFFSET
            fraction = int((ts - int(ts)) * (2**32))
        else:
            seconds, fraction = 0, 0
        pkt += struct.pack("!II", seconds & 0xFFFFFFFF, fraction & 0xFFFFFFFF)
    return pkt


def _set_li_vn_mode(pkt: bytearray, leap: int, version: int, mode: int) -> None:
    """Rewrite the first byte of a packet in-place."""
    pkt[0] = ((leap & 0x03) << 6) | ((version & 0x07) << 3) | (mode & 0x07)


# ---------------------------------------------------------------------------
# Packet generation / mutation strategies
# ---------------------------------------------------------------------------

RANDOM_SEED = random.Random(os.urandom(8))


def random_ntp_packet() -> bytes:
    """Generate a structurally valid NTP packet with randomised fields."""
    mode = RANDOM_SEED.randint(1, 7)      # modes 1–7
    version = RANDOM_SEED.randint(1, 4)   # versions 1–4
    leap = RANDOM_SEED.randint(0, 3)
    stratum = RANDOM_SEED.randint(0, 16)
    poll = RANDOM_SEED.randint(0, 255)
    precision = RANDOM_SEED.randint(-30, -1)

    li_vn_mode = (leap << 6) | (version << 3) | mode
    pkt = bytearray(48)
    struct.pack_into("!BBBB", pkt, 0, li_vn_mode, stratum, poll, precision & 0xFF)
    # root_delay, root_disp
    struct.pack_into("!II", pkt, 4, RANDOM_SEED.randint(0, 0xFFFFFFFF),
                     RANDOM_SEED.randint(0, 0xFFFFFFFF))
    # ref_id
    ref_id = RANDOM_SEED.randbytes(4)
    pkt[12:16] = ref_id
    # timestamps — 4 × (seconds, fraction) = 32 bytes
    for offset in range(16, 48, 8):
        struct.pack_into("!II", pkt, offset,
                         RANDOM_SEED.randint(0, 0xFFFFFFFF),
                         RANDOM_SEED.randint(0, 0xFFFFFFFF))
    return bytes(pkt)


def bitflip_mutate(base: bytes, flip_count: Optional[int] = None) -> bytes:
    """Flip a small number of random bits in *base*.

    *flip_count* defaults to 1–4 bits; at least one bit flips.
    """
    if not base:
        return base
    buf = bytearray(base)
    n = flip_count if flip_count is not None else RANDOM_SEED.randint(1, 4)
    for _ in range(n):
        byte_idx = RANDOM_SEED.randint(0, len(buf) - 1)
        bit_idx = RANDOM_SEED.randint(0, 7)
        buf[byte_idx] ^= 1 << bit_idx
    return bytes(buf)


def boundary_packets() -> List[bytes]:
    """Return a list of boundary-value packets."""
    pkts: List[bytes] = []

    # All zeros (48-byte header, no extension)
    pkts.append(b"\x00" * 48)
    # All ones (48-byte header)
    pkts.append(b"\xff" * 48)

    # Extreme field values
    for mode in (0, 7):
        for version in (0, 7):
            for leap in (0, 3):
                pkts.append(make_ntp_packet(mode=mode, version=version,
                                            stratum=0, poll=0, precision=127,
                                            transmit_ts=float(RANDOM_SEED.randint(0, 2**32 - 1))))

    # Min / max stratums
    pkts.append(make_ntp_packet(mode=3, stratum=STRATUM_UNSPECIFIED, transmit_ts=3000.0))
    pkts.append(make_ntp_packet(mode=3, stratum=STRATUM_UNSYNC, transmit_ts=3001.0))

    # Min / max poll intervals
    pkts.append(make_ntp_packet(mode=3, poll=0, transmit_ts=3002.0))
    pkts.append(make_ntp_packet(mode=3, poll=255, transmit_ts=3003.0))

    # Precision extremes
    pkts.append(make_ntp_packet(mode=3, precision=-127, transmit_ts=3004.0))
    pkts.append(make_ntp_packet(mode=3, precision=127, transmit_ts=3005.0))

    # Saturated root delay / dispersion
    pkt = bytearray(make_ntp_packet(mode=3, transmit_ts=3006.0))
    struct.pack_into("!I", pkt, 4, 0xFFFFFFFF)   # root_delay = max
    pkts.append(bytes(pkt))
    struct.pack_into("!I", pkt, 8, 0xFFFFFFFF)   # root_disp = max
    pkts.append(bytes(pkt))

    # Timestamp extremes
    # Very old: seconds = 0
    pkt = bytearray(make_ntp_packet(mode=3, transmit_ts=3007.0))
    struct.pack_into("!II", pkt, 40, 0, 0)
    pkts.append(bytes(pkt))
    # Far future: max u32 seconds
    pkt = bytearray(make_ntp_packet(mode=3, transmit_ts=3008.0))
    struct.pack_into("!II", pkt, 40, 0xFFFFFFFF, 0xFFFFFFFF)
    pkts.append(bytes(pkt))

    return pkts


def truncated_packets() -> List[bytes]:
    """Return truncated / oversized packets."""
    pkts: List[bytes] = []
    # Empty
    pkts.append(b"")
    # Very short
    for length in (1, 4, 10, 20, 47):
        pkts.append(RANDOM_SEED.randbytes(length))
    # Just barely oversized (48 + 1)
    pkts.append(make_ntp_packet(mode=3, transmit_ts=3010.0) + b"\x00")
    # Large oversized (larger than a typical response)
    pkts.append(make_ntp_packet(mode=3, transmit_ts=3011.0) + RANDOM_SEED.randbytes(512))
    return pkts


def extension_field_packets() -> List[bytes]:
    """Return packets with various extension field patterns."""
    pkts: List[bytes] = []
    base = make_ntp_packet(mode=3, transmit_ts=3020.0)

    # Empty extension: type=0, length=4 (just the 4-byte header)
    pkts.append(base + struct.pack("!HH", 0, 4))

    # NTPv4-style extension: type=0x0101, length=N
    for ext_len in (8, 12, 16, 64):
        payload_len = ext_len - 4
        if payload_len < 0:
            continue
        pkts.append(base + struct.pack("!HH", 0x0101, ext_len) + RANDOM_SEED.randbytes(payload_len))

    # Reserved extension type
    pkts.append(base + struct.pack("!HH", 0xFFFF, 4))

    # Malformed extension length (odd / too small / too large)
    pkts.append(base + struct.pack("!HH", 0x0101, 3))       # under minimum
    pkts.append(base + struct.pack("!HH", 0x0101, 65535))   # absurdly large

    # Multiple extensions chained
    pkt = base
    for _ in range(3):
        pkt += struct.pack("!HH", 0x0101, 8) + RANDOM_SEED.randbytes(4)
    pkts.append(pkt)

    return pkts


def all_seed_packets() -> List[bytes]:
    """Return the full corpus of seed packets used to bootstrap mutations."""
    seeds: List[bytes] = []

    # All mode × version combinations
    for mode in range(1, 8):
        for version in range(1, 5):
            seeds.append(make_ntp_packet(
                mode=mode, version=version,
                transmit_ts=float(mode * 100 + version),
            ))

    # KoD packets
    for kod_name in (b"RATE", b"DENY", b"RSTR", b"DROP"):
        seeds.append(make_ntp_packet(mode=4, stratum=0, ref_id=kod_name,
                                     transmit_ts=float(RANDOM_SEED.randint(4000, 5000))))

    # All leap indicators
    for leap in range(4):
        pkt = bytearray(make_ntp_packet(mode=3, transmit_ts=float(5000 + leap)))
        pkt[0] = (leap << 6) | (4 << 3) | 3
        seeds.append(bytes(pkt))

    seeds.extend(boundary_packets())
    seeds.extend(truncated_packets())
    seeds.extend(extension_field_packets())

    return seeds


# ---------------------------------------------------------------------------
# Packet generator (infinite iterator)
# ---------------------------------------------------------------------------

_SEED_POOL = all_seed_packets()


def generate_packet() -> bytes:
    """Yield an infinite stream of mutated NTP packets."""
    # 40 % seeds (with bitflip), 30 % pure random, 20 % bitflip on random, 10 % truncated/edge
    roll = random.random()
    if roll < 0.40:
        seed = _SEED_POOL[RANDOM_SEED.randint(0, len(_SEED_POOL) - 1)]
        return bitflip_mutate(seed, flip_count=RANDOM_SEED.randint(1, 3))
    elif roll < 0.70:
        return random_ntp_packet()
    elif roll < 0.90:
        return bitflip_mutate(random_ntp_packet(), flip_count=RANDOM_SEED.randint(1, 6))
    else:
        return _SEED_POOL[RANDOM_SEED.randint(0, len(_SEED_POOL) - 1)]


# ---------------------------------------------------------------------------
# NTP transport  (mirrors oracle_harness.py patterns)
# ---------------------------------------------------------------------------

def send_ntp_packet(host: str, port: int, pkt: bytes) -> Optional[bytes]:
    """Send a raw NTP packet via UDP and return the response.

    Returns ``None`` on timeout.
    Returns a dict ``{"error": "..."}`` on socket-level failure.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        sock.sendto(pkt, (host, port))
        data, _addr = sock.recvfrom(MAX_RESPONSE_BYTES)
        return data
    except socket.timeout:
        return None
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        sock.close()


def decode_ntp_response(data: Optional[bytes]) -> Optional[Dict[str, Any]]:
    """Decode a raw NTP response into a dictionary of fields.

    Returns ``None`` when *data* is ``None`` (timeout).
    Returns a dict with ``{"truncated": True, "length": N}`` for
    responses shorter than 48 bytes.
    Returns a dict with ``{"error": "..."}`` on structural parse failure.
    """
    if data is None:
        return None
    if isinstance(data, dict):
        return data  # passthrough for error dicts
    if len(data) < 48:
        return {"truncated": True, "length": len(data)}

    try:
        li_vn_mode = data[0]
        leap = (li_vn_mode >> 6) & 0x03
        version = (li_vn_mode >> 3) & 0x07
        mode = li_vn_mode & 0x07
        stratum = data[1]
        poll = data[2]
        precision_raw = data[3]
        precision = precision_raw if precision_raw < 128 else precision_raw - 256
        root_delay_raw = struct.unpack_from("!I", data, 4)[0]
        root_disp_raw = struct.unpack_from("!I", data, 8)[0]
        ref_id = data[12:16]
        ref_secs = struct.unpack_from("!I", data, 16)[0]
        orig_secs = struct.unpack_from("!I", data, 24)[0]
        recv_secs = struct.unpack_from("!I", data, 32)[0]
        xmit_secs = struct.unpack_from("!I", data, 40)[0]
        total_length = len(data)

        return {
            "leap": leap,
            "version": version,
            "mode": mode,
            "stratum": stratum,
            "poll": poll,
            "precision": precision,
            "root_delay": root_delay_raw,
            "root_disp": root_disp_raw,
            "ref_id": ref_id.hex(),
            "ref_secs": ref_secs,
            "originate_secs": orig_secs,
            "receive_secs": recv_secs,
            "transmit_secs": xmit_secs,
            "total_length": total_length,
        }
    except (struct.error, IndexError) as exc:
        return {"error": f"decode failed: {exc}", "raw_hex": data[:48].hex()}


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

COMPARISON_FIELDS = [
    "mode", "stratum", "poll", "precision", "leap", "version",
]

TIMESTAMP_FIELDS = [
    "originate_secs", "receive_secs", "transmit_secs",
]


def compare_responses(
    pkt_index: int,
    oracle_resp: Optional[bytes],
    candidate_resp: Optional[bytes],
) -> Tuple[str, Optional[str], List[Dict[str, Any]]]:
    """Compare the responses from the two daemons.

    Returns (classification, detail_message, field_entries).

    Classification is one of ``"MATCH"``, ``"MISMATCH"``, ``"TIMEOUT"``.
    """
    entries: List[Dict[str, Any]] = []
    o_dec = decode_ntp_response(oracle_resp)
    c_dec = decode_ntp_response(candidate_resp)

    # -- 1. Response presence --
    o_has = oracle_resp is not None and not isinstance(oracle_resp, dict)
    c_has = candidate_resp is not None and not isinstance(candidate_resp, dict)
    entries.append(_field_entry(pkt_index, "has_response", o_has, c_has))

    # -- 2. Error presence --
    o_err = isinstance(oracle_resp, dict) and "error" in oracle_resp
    c_err = isinstance(candidate_resp, dict) and "error" in candidate_resp
    if o_err or c_err:
        entries.append(_field_entry(pkt_index, "socket_error",
                                    isinstance(oracle_resp, dict) and oracle_resp.get("error"),
                                    isinstance(candidate_resp, dict) and candidate_resp.get("error")))

    # -- 3. Truncated responses --
    o_trunc = isinstance(o_dec, dict) and o_dec.get("truncated", False)
    c_trunc = isinstance(c_dec, dict) and c_dec.get("truncated", False)
    if o_trunc or c_trunc:
        o_len = o_dec.get("length", 0) if o_trunc else (len(oracle_resp) if oracle_resp else 0)
        c_len = c_dec.get("length", 0) if c_trunc else (len(candidate_resp) if candidate_resp else 0)
        entries.append(_field_entry(pkt_index, "truncated", o_trunc, c_trunc))
        entries.append(_field_entry(pkt_index, "response_length", o_len, c_len))

    # -- 4. Full response field comparison --
    if (
        o_dec is not None
        and c_dec is not None
        and "error" not in o_dec
        and "error" not in c_dec
        and not o_dec.get("truncated", False)
        and not c_dec.get("truncated", False)
    ):
        for field in COMPARISON_FIELDS:
            o_val = o_dec.get(field)
            c_val = c_dec.get(field)
            if o_val is not None and c_val is not None:
                entries.append(_field_entry(pkt_index, field, o_val, c_val))

        for field in TIMESTAMP_FIELDS:
            o_val = o_dec.get(field)
            c_val = c_dec.get(field)
            if o_val is not None and c_val is not None:
                # Timestamps may differ by a few seconds due to clock skew / epoch handling
                entries.append(_field_entry(pkt_index, field, o_val, c_val, tolerance=2))

        # Compare root_delay / root_disp (as raw u32 values — may match exactly)
        for field in ("root_delay", "root_disp"):
            o_val = o_dec.get(field)
            c_val = c_dec.get(field)
            if o_val is not None and c_val is not None:
                entries.append(_field_entry(pkt_index, field, o_val, c_val))

    # -- 5. Overall classification --
    mismatches = sum(1 for e in entries if not e.get("match"))
    all_timeout = (o_has is False and c_has is False)

    if all_timeout and not o_trunc and not c_trunc:
        classification = "TIMEOUT"
        detail = "both sides timed out"
    elif mismatches == 0:
        classification = "MATCH"
        detail = None
    else:
        classification = "MISMATCH"
        mismatch_fields = [e["field"] for e in entries if not e.get("match")]
        detail = f"fields: {', '.join(mismatch_fields)}"

    return classification, detail, entries


def _field_entry(pkt_index: int, field: str, o_val: Any, c_val: Any,
                 tolerance: Optional[int] = None) -> Dict[str, Any]:
    """Build a single comparison entry, mirroring oracle_harness.compare_field."""
    if tolerance is not None and isinstance(o_val, (int, float)) and isinstance(c_val, (int, float)):
        match = abs(o_val - c_val) <= tolerance
    else:
        match = o_val == c_val
    return {
        "pkt_index": pkt_index,
        "field": field,
        "oracle": _serialize_val(o_val),
        "candidate": _serialize_val(c_val),
        "match": match,
        "tolerance": tolerance,
    }


def _serialize_val(val: Any) -> Any:
    """Convert non-serialisable values (e.g. bytes) to plain types."""
    if isinstance(val, bytes):
        return val.hex()
    return val


# ---------------------------------------------------------------------------
# Readiness check
# ---------------------------------------------------------------------------

def wait_for_daemon(host: str, port: int, name: str, max_attempts: int = 30) -> bool:
    """Send a simple NTP client packet and wait for a response.

    This is lighter-weight than the Mode-6 query used in oracle_harness.py,
    and works even if Mode 6 is not enabled.
    """
    probe = make_ntp_packet(mode=3, transmit_ts=float(time.time()))
    for attempt in range(1, max_attempts + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(probe, (host, port))
            resp, _addr = sock.recvfrom(128)
            sock.close()
            if resp and len(resp) >= 48:
                logger.info("%s ready (attempt %d/%d)", name, attempt, max_attempts)
                return True
        except socket.timeout:
            pass
        except Exception as exc:
            logger.debug("Readiness check for %s failed: %s", name, exc)
        finally:
            sock.close()
        time.sleep(1)
    logger.error("%s NOT REACHABLE after %d attempts", name, max_attempts)
    return False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_fuzzing_loop(oracle_host: str, oracle_port: int,
                     candidate_host: str, candidate_port: int,
                     max_iterations: Optional[int]) -> None:
    """Core fuzzing loop: generate, send, compare, report."""
    _install_signal_handlers()

    oracle_addr = f"{oracle_host}:{oracle_port}"
    candidate_addr = f"{candidate_host}:{candidate_port}"
    logger.info("Oracle:     %s", oracle_addr)
    logger.info("Candidate:  %s", candidate_addr)
    logger.info("Iterations: %s", str(max_iterations) if max_iterations else "unlimited (Ctrl+C to stop)")
    logger.info("Rate limit: %.0f ms between packets", RATE_LIMIT_DELAY * 1000)
    logger.info("Starting fuzzing loop...")

    iteration = 0
    next_progress = 1000  # print progress every 1000 iterations

    while stats.running:
        # Check iteration cap
        if max_iterations is not None and iteration >= max_iterations:
            logger.info("Reached --iterations %d limit", max_iterations)
            break

        try:
            pkt = generate_packet()

            # Send to both daemons
            oracle_resp = send_ntp_packet(oracle_host, oracle_port, pkt)
            candidate_resp = send_ntp_packet(candidate_host, candidate_port, pkt)

            # Classify
            classification, detail, entries = compare_responses(
                iteration, oracle_resp, candidate_resp,
            )

            # Update statistics
            stats.total += 1
            if classification == "MATCH":
                stats.matches += 1
            elif classification == "MISMATCH":
                stats.mismatches += 1
            elif classification == "TIMEOUT":
                stats.timeouts += 1
            else:
                stats.errors += 1

            # Log first mismatch details for debugging
            if classification == "MISMATCH" and stats.mismatches <= 5:
                logger.warning(
                    "MISMATCH #%d at pkt %d | %s",
                    stats.mismatches, iteration, detail or "?",
                )
                for e in entries:
                    if not e.get("match"):
                        logger.warning(
                            "  %s: oracle=%s candidate=%s%s",
                            e["field"], e["oracle"], e["candidate"],
                            f" (tol={e['tolerance']})" if e.get("tolerance") else "",
                        )

            # Progress line
            if iteration > 0 and iteration % next_progress == 0:
                logger.info(stats.progress_line())
                next_progress += 1000

            iteration += 1

        except Exception as exc:
            logger.exception("Unexpected error at iteration %d: %s", iteration, exc)
            stats.errors += 1

        # Rate limiting
        time.sleep(RATE_LIMIT_DELAY)

    # ── Shutdown summary ────────────────────────────────────────────────
    print_final_summary()


def print_final_summary() -> None:
    """Print final statistics to stdout as human-readable text and JSON."""
    snap = stats.snapshot()
    total_compared = snap["matches"] + snap["mismatches"]
    divergence_rate = snap["divergence_rate_pct"]

    # Machine-readable JSON summary → stdout
    summary = {
        "tool": "differential_fuzzer.py",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": snap["elapsed_seconds"],
        "total_packets_sent": snap["total_packets"],
        "responses_compared": total_compared,
        "matches": snap["matches"],
        "mismatches": snap["mismatches"],
        "timeouts": snap["timeouts"],
        "errors": snap["errors"],
        "divergence_rate_pct": divergence_rate,
        "exit_code": 1 if divergence_rate > 0 else 0,
    }

    # Separator line for readability
    print()
    print("=" * 62)
    print("  DIFFERENTIAL FUZZING RESULTS")
    print("=" * 62)
    print(f"  Total packets sent:     {snap['total_packets']:>8d}")
    print(f"  Responses compared:     {total_compared:>8d}")
    print(f"  Matches:                {snap['matches']:>8d}")
    print(f"  Mismatches:             {snap['mismatches']:>8d}")
    print(f"  Timeouts (both sides):  {snap['timeouts']:>8d}")
    print(f"  Errors:                 {snap['errors']:>8d}")
    print(f"  Divergence rate:        {divergence_rate:>8.4f}%")
    print(f"  Elapsed:                {snap['elapsed_seconds']:>8.1f}s")
    print("=" * 62)
    if divergence_rate > 0:
        print(f"  ⚠  DIVERGENCE DETECTED — {snap['mismatches']} mismatched packet(s)")
        print("=" * 62)
    else:
        print(f"  ✓  All responses match between oracle and candidate")
        print("=" * 62)

    # JSON blob for downstream tooling
    print()
    print(json.dumps(summary, indent=2))
    print()

    sys.exit(1 if divergence_rate > 0 else 0)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Differential fuzzer: feed identical mutated NTP packets to "
                    "NTPsec C (oracle) and ntpsec-rs (candidate) and compare responses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --iterations 1000\n"
            "  %(prog)s --oracle 10.100.0.10 --candidate 10.100.0.20\n"
            "  %(prog)s   # run until Ctrl+C\n"
        ),
    )
    parser.add_argument(
        "--oracle", "-o",
        default=os.environ.get("ORACLE_HOST", DEFAULT_ORACLE_HOST),
        help="NTPsec oracle host (default: %(default)s, env: ORACLE_HOST)",
    )
    parser.add_argument(
        "--oracle-port",
        type=int,
        default=int(os.environ.get("ORACLE_PORT", str(DEFAULT_ORACLE_PORT))),
        help="NTPsec oracle port (default: %(default)s, env: ORACLE_PORT)",
    )
    parser.add_argument(
        "--candidate", "-c",
        default=os.environ.get("RS_HOST", DEFAULT_CANDIDATE_HOST),
        help="ntpsec-rs candidate host (default: %(default)s, env: RS_HOST)",
    )
    parser.add_argument(
        "--candidate-port",
        type=int,
        default=int(os.environ.get("RS_PORT", str(DEFAULT_CANDIDATE_PORT))),
        help="ntpsec-rs candidate port (default: %(default)s, env: RS_PORT)",
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=None,
        help="Number of packets to send (default: unlimited)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=RATE_LIMIT_DELAY,
        help=f"Delay between packets in seconds (default: {RATE_LIMIT_DELAY})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Override global rate limit
    global RATE_LIMIT_DELAY  # noqa: PLW0603
    RATE_LIMIT_DELAY = args.rate_limit

    # Wait for daemons to be ready
    logger.info("Checking daemon readiness...")
    oracle_ready = wait_for_daemon(args.oracle, args.oracle_port, "NTPsec oracle")
    candidate_ready = wait_for_daemon(args.candidate, args.candidate_port, "ntpsec-rs")
    if not oracle_ready:
        logger.error("Oracle unreachable — aborting")
        sys.exit(2)
    if not candidate_ready:
        logger.error("Candidate unreachable — aborting")
        sys.exit(2)

    run_fuzzing_loop(
        oracle_host=args.oracle,
        oracle_port=args.oracle_port,
        candidate_host=args.candidate,
        candidate_port=args.candidate_port,
        max_iterations=args.iterations,
    )


if __name__ == "__main__":
    main()
