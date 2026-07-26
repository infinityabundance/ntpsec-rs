#!/usr/bin/env python3
"""ntpsec-rs Oracle Differential Test Harness.

Sends identical synthetic NTP packets to both NTPsec and ntpsec-rs,
then compares their responses and internal state via Mode 6 queries.

Records every comparison in a machine-readable residual ledger.

Usage:
  python3 oracle_harness.py [--json report.json]

Output:
  - stdout: human-readable summary
  - JSON file: machine-readable residual ledger with per-scenario comparisons
"""

import argparse
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime

# Network topology
ORACLE_HOST = os.environ.get("ORACLE_HOST", "ntpsec-oracle")
RS_HOST = os.environ.get("RS_HOST", "ntpsec-rs")
NTP_PORT = 123
MODE6_PORT = 123

# Residual ledger
ledger = {
    "timestamp": datetime.utcnow().isoformat(),
    "tool": "oracle_harness.py v1",
    "oracle": {"host": ORACLE_HOST, "version": "unknown"},
    "candidate": {"host": RS_HOST, "version": "unknown"},
    "scenarios": [],
    "summary": {"total": 0, "match": 0, "mismatch": 0, "error": 0},
}


def make_ntp_packet(mode=3, version=4, stratum=2, poll=6, precision=-20,
                     root_delay=0, root_disp=0, ref_id=b"TEST",
                     originate_ts=0, receive_ts=0, transmit_ts=0):
    """Build a 48-byte NTPv4 packet."""
    li_vn_mode = (0 << 6) | (version << 3) | mode
    pkt = struct.pack("!BBBB",
                      li_vn_mode, stratum, poll, precision & 0xFF)
    pkt += struct.pack("!I", int(root_delay * 65536))
    pkt += struct.pack("!I", int(root_disp * 65536))
    pkt += ref_id.ljust(4, b"\x00")[:4]
    for ts in [originate_ts, receive_ts, transmit_ts]:
        if isinstance(ts, (int, float)):
            seconds = int(ts) + 2208988800
            fraction = int((ts - int(ts)) * 2**32)
        else:
            seconds, fraction = 0, 0
        pkt += struct.pack("!II", seconds, fraction)
    return pkt


def query_mode6(host, port=123, associd=0):
    """Send Mode 6 READVAR, return parsed response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    seq = 1
    msg = struct.pack("!BBHHHH",
                      0x1E,  # LI=0, VN=4, mode=6
                      2,     # READVAR
                      0,     # seq hi
                      seq,   # seq lo
                      0,     # status
                      associd)
    msg += struct.pack("!HH", 0, 0)
    try:
        sock.sendto(msg, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if len(data) < 12:
            return {"error": "short response", "raw_length": len(data)}
        seq_hi, seq_lo = struct.unpack_from("!HH", data, 4)
        status = struct.unpack_from("!H", data, 8)[0]
        assoc = struct.unpack_from("!H", data, 10)[0]
        offset, count = struct.unpack_from("!HH", data, 12)
        var_data = data[16:16+count]
        text = var_data.decode("utf-8", errors="replace")
        vars_dict = {}
        for pair in text.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                vars_dict[k.strip()] = v.strip().strip('"')
        return {"seq": seq, "status": status, "associd": assoc,
                "data": text, "vars": vars_dict, "raw_length": len(data)}
    except socket.timeout:
        sock.close()
        return {"error": "timeout"}
    except Exception as e:
        sock.close()
        return {"error": str(e)}


def send_ntp_packet(host, port, pkt):
    """Send an NTP packet. Returns None on timeout/error."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(pkt, (host, port))
        data, addr = sock.recvfrom(1024)
        sock.close()
        return data
    except socket.timeout:
        sock.close()
        return None
    except Exception as e:
        sock.close()
        return {"error": str(e)}


def decode_ntp_response(data):
    """Decode a 48-byte NTP response into field dict."""
    if data is None:
        return None
    if isinstance(data, dict):
        return data
    if len(data) < 48:
        return {"truncated": True, "length": len(data)}
    leap = (data[0] >> 6) & 0x03
    version = (data[0] >> 3) & 0x07
    mode = data[0] & 0x07
    stratum = data[1]
    poll = data[2]
    precision = data[3] if data[3] < 128 else data[3] - 256
    root_delay = struct.unpack_from("!I", data, 4)[0]
    root_disp = struct.unpack_from("!I", data, 8)[0]
    ref_id = data[12:16]
    ref_secs = struct.unpack_from("!I", data, 16)[0]
    orig_secs = struct.unpack_from("!I", data, 24)[0]
    recv_secs = struct.unpack_from("!I", data, 32)[0]
    xmit_secs = struct.unpack_from("!I", data, 40)[0]
    return {
        "leap": leap, "version": version, "mode": mode,
        "stratum": stratum, "poll": poll, "precision": precision,
        "root_delay": root_delay, "root_disp": root_disp,
        "ref_id": ref_id.hex(),
        "originate_secs": orig_secs, "receive_secs": recv_secs,
        "transmit_secs": xmit_secs,
    }


def compare_field(scenario, field, oracle_val, candidate_val, tolerance=None):
    """Compare a single field and record in the ledger."""
    if tolerance and isinstance(oracle_val, (int, float)) and isinstance(candidate_val, (int, float)):
        match = abs(oracle_val - candidate_val) <= tolerance
    else:
        match = oracle_val == candidate_val

    entry = {
        "scenario": scenario,
        "field": field,
        "oracle": oracle_val if not isinstance(oracle_val, bytes) else oracle_val.hex(),
        "candidate": candidate_val if not isinstance(candidate_val, bytes) else candidate_val.hex(),
        "match": match,
    }
    if match:
        entry["classification"] = "MATCH"
    else:
        entry["classification"] = "MISMATCH"
    return entry


def test_scenario(name, pkt, oracle_host, candidate_host):
    """Run a single test scenario: send packet to both daemons, compare."""
    print(f"  [{name}] ", end="", flush=True)

    oracle_resp = send_ntp_packet(oracle_host, NTP_PORT, pkt)
    candidate_resp = send_ntp_packet(candidate_host, NTP_PORT, pkt)

    oracle_decoded = decode_ntp_response(oracle_resp)
    candidate_decoded = decode_ntp_response(candidate_resp)

    entries = []
    scenario_result = {"scenario": name, "fields": []}

    # Compare response presence
    entries.append(compare_field(name, "has_response",
                                 oracle_resp is not None and not isinstance(oracle_resp, dict),
                                 candidate_resp is not None and not isinstance(candidate_resp, dict)))

    if oracle_decoded and candidate_decoded and "error" not in oracle_decoded and "error" not in candidate_decoded:
        for field in ["mode", "stratum", "poll", "precision", "leap"]:
            o = oracle_decoded.get(field)
            c = candidate_decoded.get(field)
            if o is not None and c is not None:
                entries.append(compare_field(name, field, o, c))

        # Compare timestamps (with tolerance for NTP epoch differences)
        for field in ["originate_secs", "receive_secs", "transmit_secs"]:
            o = oracle_decoded.get(field)
            c = candidate_decoded.get(field)
            if o is not None and c is not None:
                entries.append(compare_field(name, field, o, c, tolerance=2))

    matches = sum(1 for e in entries if e.get("match"))
    mismatches = sum(1 for e in entries if not e.get("match"))
    scenario_result["fields"] = entries
    scenario_result["result"] = "MATCH" if mismatches == 0 else "MISMATCH"

    if mismatches == 0:
        print(f"✓ ({matches} fields match)")
    else:
        print(f"⚠ ({mismatches}/{matches+mismatches} fields mismatch)")
        for e in entries:
            if not e.get("match"):
                print(f"    {e['field']}: oracle={e['oracle']} candidate={e['candidate']}")

    return scenario_result, entries


def main():
    parser = argparse.ArgumentParser(description="NTPsec oracle differential test harness")
    parser.add_argument("--json", default="/tmp/oracle-report.json",
                        help="Path to write JSON report")
    args = parser.parse_args()

    print("=" * 60)
    print("ntpsec-rs Oracle Differential Test Harness")
    print(f"Oracle:    {ORACLE_HOST}")
    print(f"Candidate: {RS_HOST}")
    print("=" * 60)

    # Wait for daemons to be ready
    print("\n[0] Waiting for daemons...")
    for host, name in [(ORACLE_HOST, "NTPsec"), (RS_HOST, "ntpsec-rs")]:
        for attempt in range(30):
            state = query_mode6(host, MODE6_PORT, 0)
            if "vars" in state and state["vars"]:
                print(f"  {name} ready (attempt {attempt+1})")
                break
            time.sleep(1)
        else:
            print(f"  {name} NOT REACHABLE after 30s")

    # Get versions
    print("\n[1] Getting daemon versions...")
    oracle_state = query_mode6(ORACLE_HOST, MODE6_PORT, 0)
    rs_state = query_mode6(RS_HOST, MODE6_PORT, 0)
    oracle_ver = oracle_state.get("vars", {}).get("version", "unknown")
    rs_ver = rs_state.get("vars", {}).get("version", "unknown")
    ledger["oracle"]["version"] = oracle_ver
    ledger["candidate"]["version"] = rs_ver
    ledger["oracle"]["initial_state"] = oracle_state.get("vars", {})
    ledger["candidate"]["initial_state"] = rs_state.get("vars", {})
    print(f"  NTPsec oracle:  {oracle_ver}")
    print(f"  ntpsec-rs:      {rs_ver}")

    # Run test scenarios
    print("\n[2] Running packet scenarios...")
    time.sleep(1)

    scenarios = [
        ("Client request (mode 3)", make_ntp_packet(mode=3, transmit_ts=1000.0)),
        ("Symmetric active (mode 1)", make_ntp_packet(mode=1, transmit_ts=1001.0)),
        ("Symmetric passive (mode 2)", make_ntp_packet(mode=2, transmit_ts=1002.0)),
        ("Broadcast (mode 5)", make_ntp_packet(mode=5, transmit_ts=1003.0)),
        ("Unsynchronized (stratum=16)", make_ntp_packet(mode=3, stratum=16, transmit_ts=1004.0)),
        ("Bad version (VN=1)", make_ntp_packet(mode=3, version=1, transmit_ts=1005.0)),
    ]

    all_entries = []
    for name, pkt in scenarios:
        time.sleep(0.3)
        result, entries = test_scenario(name, pkt, ORACLE_HOST, RS_HOST)
        ledger["scenarios"].append(result)
        all_entries.extend(entries)

    # Query synchronized state
    print("\n[3] Querying system state via Mode 6...")
    time.sleep(1)

    oracle_state = query_mode6(ORACLE_HOST, MODE6_PORT, 0)
    rs_state = query_mode6(RS_HOST, MODE6_PORT, 0)

    key_vars = ["leap", "stratum", "offset", "frequency", "sys_jitter",
                 "peer", "tc", "rootdelay", "rootdisp", "rootdist",
                 "precision", "version", "processor", "system"]
    state_entries = []
    for var in key_vars:
        o_val = oracle_state.get("vars", {}).get(var, None)
        r_val = rs_state.get("vars", {}).get(var, None)
        if o_val is not None and r_val is not None:
            entry = compare_field("state_variables", var, o_val, r_val)
            state_entries.append(entry)

    # Peer state
    print("  [3b] Querying peer state...")
    oracle_peer = query_mode6(ORACLE_HOST, MODE6_PORT, 1)
    rs_peer = query_mode6(RS_HOST, MODE6_PORT, 1)

    peer_vars = ["srcaddr", "stratum", "offset", "delay", "dispersion",
                  "reach", "poll", "hpoll", "jitter", "flash"]
    for var in peer_vars:
        o_val = oracle_peer.get("vars", {}).get(var, None)
        r_val = rs_peer.get("vars", {}).get(var, None)
        if o_val is not None and r_val is not None:
            entry = compare_field("peer_variables", var, o_val, r_val)
            state_entries.append(entry)

    ledger["scenarios"].append({
        "scenario": "state_comparison",
        "result": "MATCH" if all(e.get("match") for e in state_entries) else "MISMATCH",
        "fields": state_entries
    })

    # Compute summary
    all_fields = all_entries + state_entries
    matches = sum(1 for e in all_fields if e.get("match"))
    mismatches = sum(1 for e in all_fields if not e.get("match"))
    ledger["summary"] = {
        "total": len(all_fields),
        "match": matches,
        "mismatch": mismatches,
        "error": 0,
    }

    # Print summary
    print(f"\n[4] Results:")
    print(f"  Total fields compared: {len(all_fields)}")
    print(f"  Matches:  {matches}")
    print(f"  Mismatches: {mismatches}")
    if mismatches > 0:
        print("\n  Mismatches:")
        for e in all_fields:
            if not e.get("match"):
                print(f"    {e['scenario']}/{e['field']}: {e['oracle']} vs {e['candidate']}")

    # Write JSON report
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w") as f:
        json.dump(ledger, f, indent=2, default=str)
    print(f"\n  JSON report: {args.json}")

    # Exit with code indicating mismatch count
    print(f"\n{'='*60}")
    print(f"Classification: {matches} match, {mismatches} mismatch")
    if mismatches == 0:
        print("RESULT: PASS")
    else:
        print(f"RESULT: {mismatches} MISMATCHES")
    print('=' * 60)

    sys.exit(mismatches)


if __name__ == "__main__":
    main()
