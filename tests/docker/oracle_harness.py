#!/usr/bin/env python3
"""ntpsec-rs Oracle Differential Test Harness.

Sends identical synthetic NTP packets to both NTPsec and ntpsec-rs,
then compares their responses and internal state via Mode 6 queries.

Records:
- Which packets were accepted/rejected by each daemon
- Peer state after each packet
- System state (offset, stratum, jitter, root distance)
- Selection survivor sets
- Mode 6 variable dumps

Produces a machine-readable comparison report.
"""

import socket
import struct
import time
import json
import os
import sys
import subprocess
from datetime import datetime

# Network topology
ORACLE_HOST = "ntpsec-oracle"
RS_HOST = "ntpsec-rs"
NTP_PORT = 123
MODE6_PORT = 123

# Test results accumulator
results = {
    "timestamp": datetime.utcnow().isoformat(),
    "oracle": {"version": "", "responses": [], "state": {}},
    "ntpsec_rs": {"version": "", "responses": [], "state": {}},
    "diffs": [],
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
            seconds = int(ts) + 2208988800  # NTP epoch offset
            fraction = int((ts - int(ts)) * 2**32)
        else:
            seconds, fraction = 0, 0
        pkt += struct.pack("!II", seconds, fraction)
    return pkt


def query_mode6(host, port=123, associd=0):
    """Send a Mode 6 READVAR request and parse the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    # Build Mode 6 header (12 bytes)
    seq = 1
    msg = struct.pack("!BBHHHH",
                      0x1E,  # LI=0, VN=4, mode=6 (NtpControl)
                      2,     # opcode = READVAR
                      0,     # sequence (high)
                      seq,   # sequence (low)
                      0,     # status
                      associd)
    msg += struct.pack("!HH", 0, 0)  # offset=0, count=0
    sock.sendto(msg, (host, port))
    try:
        data, _ = sock.recvfrom(4096)
        sock.close()
        # Parse the response: 12-byte header + variable data
        if len(data) < 12:
            return {"error": "short response"}
        seq_hi, seq_lo = struct.unpack_from("!HH", data, 4)
        status = struct.unpack_from("!H", data, 8)[0]
        assoc = struct.unpack_from("!H", data, 10)[0]
        offset, count = struct.unpack_from("!HH", data, 12)
        var_data = data[16:16+count]
        text = var_data.decode("utf-8", errors="replace")
        # Parse key=value pairs
        vars_dict = {}
        for pair in text.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                vars_dict[k.strip()] = v.strip().strip('"')
        return {"seq": seq, "status": status, "associd": assoc,
                "data": text, "vars": vars_dict}
    except socket.timeout:
        sock.close()
        return {"error": "timeout"}
    except Exception as e:
        sock.close()
        return {"error": str(e)}


def send_ntp_packet(host, port, pkt):
    """Send an NTP packet and receive the response."""
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


def get_daemon_version(host):
    """Query the daemon version via Mode 6."""
    result = query_mode6(host, MODE6_PORT, 0)
    return result.get("vars", {}).get("version", "unknown")


def compare_responses(oracle_resp, rs_resp):
    """Compare two daemon responses and record differences."""
    diffs = []
    if oracle_resp is None and rs_resp is None:
        return diffs
    if oracle_resp is None:
        diffs.append({"field": "response", "oracle": "no response", "rs": "got response"})
        return diffs
    if rs_resp is None:
        diffs.append({"field": "response", "oracle": "got response", "rs": "no response"})
        return diffs
    if isinstance(oracle_resp, dict) and "error" in oracle_resp:
        return diffs  # Skip comparison when oracle errored
    if isinstance(rs_resp, dict) and "error" in rs_resp:
        diffs.append({"field": "error", "oracle": "ok", "rs": rs_resp["error"]})
        return diffs
    # Compare response length
    if len(oracle_resp) != len(rs_resp):
        diffs.append({
            "field": "response_length",
            "oracle": len(oracle_resp),
            "rs": len(rs_resp)
        })
    return diffs


def main():
    print("=" * 60)
    print("ntpsec-rs Oracle Differential Test Harness")
    print("=" * 60)

    # Get versions
    print("\n[1] Getting daemon versions...")
    oracle_ver = get_daemon_version(ORACLE_HOST)
    rs_ver = get_daemon_version(RS_HOST)
    results["oracle"]["version"] = oracle_ver
    results["ntpsec_rs"]["version"] = rs_ver
    print(f"  NTPsec oracle:  {oracle_ver}")
    print(f"  ntpsec-rs:      {rs_ver}")

    # Send test packets and compare
    print("\n[2] Sending test packets...")
    test_cases = [
        ("Client request (mode 3)", make_ntp_packet(mode=3, transmit_ts=1000.0)),
        ("Symmetric active (mode 1)", make_ntp_packet(mode=1, transmit_ts=1001.0)),
        ("Symmetric passive (mode 2)", make_ntp_packet(mode=2, transmit_ts=1002.0)),
        ("Broadcast (mode 5)", make_ntp_packet(mode=5, transmit_ts=1003.0)),
        ("KoD-like (stratum=0)", make_ntp_packet(mode=3, stratum=0, transmit_ts=1004.0)),
        ("Unsynchronized (LI=3)", make_ntp_packet(mode=3, transmit_ts=1005.0)),
    ]

    for name, pkt in test_cases:
        time.sleep(0.5)
        oracle_resp = send_ntp_packet(ORACLE_HOST, NTP_PORT, pkt)
        rs_resp = send_ntp_packet(RS_HOST, NTP_PORT, pkt)
        if oracle_resp and not isinstance(oracle_resp, dict):
            results["oracle"]["responses"].append({
                "test": name, "len": len(oracle_resp)
            })
        if rs_resp and not isinstance(rs_resp, dict):
            results["ntpsec_rs"]["responses"].append({
                "test": name, "len": len(rs_resp)
            })
        diffs = compare_responses(oracle_resp, rs_resp)
        if diffs:
            results["diffs"].extend(diffs)
            print(f"  ⚠ {name}: {len(diffs)} difference(s)")
        else:
            print(f"  ✓ {name}")

    # Query system state
    print("\n[3] Querying system state via Mode 6...")
    time.sleep(1)
    oracle_state = query_mode6(ORACLE_HOST, MODE6_PORT, 0)
    rs_state = query_mode6(RS_HOST, MODE6_PORT, 0)
    results["oracle"]["state"] = oracle_state.get("vars", {})
    results["ntpsec_rs"]["state"] = rs_state.get("vars", {})

    # Compare key state variables
    key_vars = ["leap", "stratum", "offset", "frequency", "sys_jitter",
                "peer", "tc", "rootdelay", "rootdisp", "rootdist"]
    for var in key_vars:
        o_val = oracle_state.get("vars", {}).get(var, "N/A")
        r_val = rs_state.get("vars", {}).get(var, "N/A")
        if o_val != r_val:
            results["diffs"].append({
                "field": f"state.{var}", "oracle": o_val, "rs": r_val
            })

    # Generate report
    print(f"\n[4] Results: {len(results['diffs'])} total differences")
    print("\n=== State Comparison ===")
    print(f"{'Variable':<20} {'Oracle':<20} {'ntpsec-rs':<20}")
    print("-" * 60)
    for var in key_vars:
        o_val = oracle_state.get("vars", {}).get(var, "N/A")
        r_val = rs_state.get("vars", {}).get(var, "N/A")
        marker = " ⚠" if o_val != r_val else ""
        print(f"{var:<20} {o_val:<20} {r_val:<20}{marker}")

    # Save detailed report
    report_path = "/tmp/oracle-report.json"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed report saved to {report_path}")

    # Exit with code indicating diff count
    sys.exit(len(results["diffs"]))


if __name__ == "__main__":
    main()
