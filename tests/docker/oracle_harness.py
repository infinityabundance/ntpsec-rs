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
    "tool": "oracle_harness.py v2",
    "oracle": {"host": ORACLE_HOST, "version": "unknown"},
    "candidate": {"host": RS_HOST, "version": "unknown"},
    "scenarios": [],
    "summary": {"total": 0, "match": 0, "mismatch": 0, "error": 0},
}


# ---- Packet builders ----


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


# ---- Mode 6 helpers ----


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


def send_mode6(host, port=123, opcode=2, associd=0, data=b""):
    """Send a generic Mode 6 query and return parsed response.

    Supports arbitrary opcodes (READVAR=2, READ_ORDLIST_A=5, WRITEVAR=6, etc.)
    and optional payload bytes in *data* (appended after the offset/count
    header fields).

    Returns a dict with keys:
      - on success: status, associd, raw_length, raw_data (hex),
        plus "data" (text) and "vars" (parsed) when readable
      - on error: "error" key
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    seq = 1
    msg = struct.pack("!BBHHHH",
                      0x1E,  # LI=0, VN=4, mode=6
                      opcode,
                      0,     # seq hi
                      seq,   # seq lo
                      0,     # status
                      associd)
    msg += struct.pack("!HH", 0, len(data))
    msg += data
    try:
        sock.sendto(msg, (host, port))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        if len(resp) < 12:
            return {"error": "short response", "raw_length": len(resp)}
        seq_hi, seq_lo = struct.unpack_from("!HH", resp, 4)
        status = struct.unpack_from("!H", resp, 8)[0]
        assoc = struct.unpack_from("!H", resp, 10)[0]
        offset, count = struct.unpack_from("!HH", resp, 12)
        raw_data = resp[16:16+count]
        text = raw_data.decode("utf-8", errors="replace")
        vars_dict = {}
        for pair in text.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                vars_dict[k.strip()] = v.strip().strip('"')
        return {
            "status": status, "associd": assoc,
            "data": text, "vars": vars_dict,
            "raw_length": len(resp), "raw_data": raw_data.hex(),
        }
    except socket.timeout:
        sock.close()
        return {"error": "timeout"}
    except Exception as e:
        sock.close()
        return {"error": str(e)}


# ---- NTP transport helpers ----


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


# ---- Comparison infrastructure ----


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

    # Also compare truncated/error responses when both sides are truncated or errored
    if isinstance(oracle_decoded, dict) and isinstance(candidate_decoded, dict):
        if "truncated" in oracle_decoded and "truncated" in candidate_decoded:
            entries.append(compare_field(name, "truncated", True, True))
            entries.append(compare_field(name, "response_length",
                                         oracle_decoded.get("length"),
                                         candidate_decoded.get("length")))
        if "error" in oracle_decoded or "error" in candidate_decoded:
            o_err = oracle_decoded.get("error") if isinstance(oracle_decoded, dict) else None
            c_err = candidate_decoded.get("error") if isinstance(candidate_decoded, dict) else None
            # Compare presence of error, not message text (may differ)
            entries.append(compare_field(name, "has_error", o_err is not None, c_err is not None))

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


def test_mode6_scenario(name, oracle_host, candidate_host, opcode=2, associd=0, data=b""):
    """Run a Mode 6 query scenario, comparing responses from both daemons."""
    print(f"  [{name}] ", end="", flush=True)

    oracle_resp = send_mode6(oracle_host, MODE6_PORT, opcode, associd, data)
    candidate_resp = send_mode6(candidate_host, MODE6_PORT, opcode, associd, data)

    entries = []
    scenario_result = {"scenario": name, "fields": []}

    # Compare whether we got a valid response
    o_ok = isinstance(oracle_resp, dict) and "error" not in oracle_resp
    c_ok = isinstance(candidate_resp, dict) and "error" not in candidate_resp
    entries.append(compare_field(name, "has_valid_response", o_ok, c_ok))

    if o_ok and c_ok:
        # Compare status
        entries.append(compare_field(name, "status",
                                     oracle_resp.get("status"),
                                     candidate_resp.get("status")))
        # Compare associd
        entries.append(compare_field(name, "associd",
                                     oracle_resp.get("associd"),
                                     candidate_resp.get("associd")))
        # Compare raw length
        entries.append(compare_field(name, "response_length",
                                     oracle_resp.get("raw_length"),
                                     candidate_resp.get("raw_length"), tolerance=0))

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


def test_multi_packet_scenario(name, pkts, oracle_host, candidate_host):
    """Send multiple packets in sequence, compare each response.

    *pkts* is a list of (pkt_label, pkt_bytes) tuples.
    """
    print(f"  [{name}] ", end="", flush=True)

    entries = []
    scenario_result = {"scenario": name, "fields": []}

    for idx, (label, pkt) in enumerate(pkts):
        oracle_resp = send_ntp_packet(oracle_host, NTP_PORT, pkt)
        candidate_resp = send_ntp_packet(candidate_host, NTP_PORT, pkt)

        entries.append(compare_field(
            name, f"pkt{idx}_{label}_has_response",
            oracle_resp is not None and not isinstance(oracle_resp, dict),
            candidate_resp is not None and not isinstance(candidate_resp, dict)))

        if (oracle_resp and not isinstance(oracle_resp, dict) and
                candidate_resp and not isinstance(candidate_resp, dict)):
            # Compare key response fields
            o = decode_ntp_response(oracle_resp)
            c = decode_ntp_response(candidate_resp)
            if o and c and "error" not in o and "error" not in c:
                for field in ["mode", "stratum", "poll"]:
                    if field in o and field in c:
                        entries.append(compare_field(name, f"pkt{idx}_{label}_{field}", o[field], c[field]))
                entries.append(compare_field(name, f"pkt{idx}_{label}_transmit_secs",
                                             o.get("transmit_secs"), c.get("transmit_secs"), tolerance=2))

        time.sleep(0.2)

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


# ---- Main ----


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
        # --- Original 6 scenarios ---
        ("Client request (mode 3)", make_ntp_packet(mode=3, transmit_ts=1000.0)),
        ("Symmetric active (mode 1)", make_ntp_packet(mode=1, transmit_ts=1001.0)),
        ("Symmetric passive (mode 2)", make_ntp_packet(mode=2, transmit_ts=1002.0)),
        ("Broadcast (mode 5)", make_ntp_packet(mode=5, transmit_ts=1003.0)),
        ("Unsynchronized (stratum=16)", make_ntp_packet(mode=3, stratum=16, transmit_ts=1004.0)),
        ("Bad version (VN=1)", make_ntp_packet(mode=3, version=1, transmit_ts=1005.0)),

        # --- 7-9: Invalid/edge packets ---
        ("Empty packet (0 bytes)", b""),
        ("Truncated packet (10 bytes)", b"\x00" * 10),
        ("Corrupted mode byte (mode=7, reserved)", make_ntp_packet(mode=7, transmit_ts=1006.0)),

        # --- 10-11: KoD packets ---
        # KoD RATE: stratum=0, ref_id="RATE" encoded as four chars
        ("KoD RATE packet",
         make_ntp_packet(mode=4, stratum=0, ref_id=b"RATE", transmit_ts=1007.0)),
        # KoD DENY: stratum=0, ref_id="DENY"
        ("KoD DENY packet",
         make_ntp_packet(mode=4, stratum=0, ref_id=b"DENY", transmit_ts=1008.0)),

        # --- 12-13: Authentication (check daemon response) ---
        # KeyID=0 appended (invalid/unauthenticated key)
        ("Unauthenticated client with key=0",
         make_ntp_packet(mode=3, transmit_ts=1009.0) + struct.pack("!I", 0)),
        # Unknown keyid 9999 appended
        ("Client with unknown keyid",
         make_ntp_packet(mode=3, transmit_ts=1010.0) + struct.pack("!I", 9999)),

        # --- 14-15: Originate timestamp validation ---
        ("Wrong originate timestamp",
         make_ntp_packet(mode=3, originate_ts=999999.0, transmit_ts=1011.0)),
        ("Zero originate timestamp",
         make_ntp_packet(mode=3, originate_ts=0, transmit_ts=1012.0)),

        # --- 16-17: Extension fields ---
        # Empty extension: type=0, length=4 (just the 4-byte extension header)
        ("Packet with empty extension field",
         make_ntp_packet(mode=3, transmit_ts=1013.0) + struct.pack("!HH", 0, 4)),
        # Reserved extension field type 0xFFFF
        ("Packet with reserved extension field type",
         make_ntp_packet(mode=3, transmit_ts=1014.0) + struct.pack("!HH", 0xFFFF, 4)),
    ]

    all_entries = []
    for name, pkt in scenarios:
        time.sleep(0.3)
        result, entries = test_scenario(name, pkt, ORACLE_HOST, RS_HOST)
        ledger["scenarios"].append(result)
        all_entries.extend(entries)

    # --- 18-23: Mode 6 query scenarios ---
    print("\n[2b] Running Mode 6 query scenarios...")
    time.sleep(1)

    mode6_scenarios = [
        ("Mode 6 READVAR (associd=0) — system variables", 2, 0, b""),
        ("Mode 6 READVAR (associd=1) — peer variables", 2, 1, b""),
        ("Mode 6 READVAR (associd=65535) — invalid associd", 2, 65535, b""),
        ("Mode 6 READ_ORDLIST_A — list of associations", 5, 0, b""),
        ("Mode 6 with bad opcode (opcode=63, INVALID)", 63, 0, b""),
        ("Mode 6 unauthenticated WRITEVAR", 6, 0, b"minpoll=4"),
    ]

    for m6_name, opcode, associd, data in mode6_scenarios:
        time.sleep(0.3)
        result, entries = test_mode6_scenario(m6_name, ORACLE_HOST, RS_HOST,
                                              opcode=opcode, associd=associd, data=data)
        ledger["scenarios"].append(result)
        all_entries.extend(entries)

    # --- 24: Send client mode request then query peers ---
    print("\n[2c] Running chained scenario: client request → peer state...")
    time.sleep(0.5)
    # Send a client request
    client_pkt = make_ntp_packet(mode=3, transmit_ts=2000.0)
    send_ntp_packet(ORACLE_HOST, NTP_PORT, client_pkt)
    send_ntp_packet(RS_HOST, NTP_PORT, client_pkt)
    time.sleep(0.5)
    # Now query peer state
    oracle_peer = query_mode6(ORACLE_HOST, MODE6_PORT, 1)
    rs_peer = query_mode6(RS_HOST, MODE6_PORT, 1)

    scenario_24_result = {
        "scenario": "Send client request then query peers",
        "fields": [],
    }
    scenario_24_entries = []
    o_has_peer = "vars" in oracle_peer and bool(oracle_peer["vars"])
    c_has_peer = "vars" in rs_peer and bool(rs_peer["vars"])
    scenario_24_entries.append(
        compare_field("Send client request then query peers", "has_peer_state",
                      o_has_peer, c_has_peer))
    if o_has_peer and c_has_peer:
        for var in ["srcaddr", "stratum", "offset", "delay", "reach", "poll", "hpoll", "jitter"]:
            o_val = oracle_peer.get("vars", {}).get(var)
            r_val = rs_peer.get("vars", {}).get(var)
            if o_val is not None and r_val is not None:
                scenario_24_entries.append(
                    compare_field("Send client request then query peers", var, o_val, r_val))

    m24_matches = sum(1 for e in scenario_24_entries if e.get("match"))
    m24_mismatches = sum(1 for e in scenario_24_entries if not e.get("match"))
    scenario_24_result["fields"] = scenario_24_entries
    scenario_24_result["result"] = "MATCH" if m24_mismatches == 0 else "MISMATCH"
    ledger["scenarios"].append(scenario_24_result)
    all_entries.extend(scenario_24_entries)
    if m24_mismatches == 0:
        print(f"  [Send client request then query peers] ✓ ({m24_matches} fields match)")
    else:
        print(f"  [Send client request then query peers] ⚠ ({m24_mismatches}/{m24_matches+m24_mismatches} mismatch)")

    # --- 25: Multiple client requests with different timestamps ---
    print("  [Send multiple client requests with different timestamps] ", end="", flush=True)
    multi_pkts = [
        (f"ts={2001.0}", make_ntp_packet(mode=3, transmit_ts=2001.0)),
        (f"ts={2002.0}", make_ntp_packet(mode=3, transmit_ts=2002.0)),
        (f"ts={2003.0}", make_ntp_packet(mode=3, transmit_ts=2003.0)),
    ]
    result_25, entries_25 = test_multi_packet_scenario(
        "Send multiple client requests with different timestamps",
        multi_pkts, ORACLE_HOST, RS_HOST)
    ledger["scenarios"].append(result_25)
    all_entries.extend(entries_25)

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
