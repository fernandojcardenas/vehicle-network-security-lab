#!/usr/bin/env python3
"""Cross-checks vn-decode's J1939 layer against the independent can-j1939 package.

Both read the same CAN log; this script parses it itself (it does not reuse the C++ parser),
feeds every frame to can-j1939's data-link layer and collects the messages can-j1939 emits:
single frames plus reassembled transport-protocol (BAM) transfers. Then it compares that
stream with `vn-decode --json` message by message: priority, PGN, source address and payload
bytes must all match, in the same order. (can-j1939's subscriber callback does not report the
destination address, so that field is covered by the unit tests instead.)

can-j1939 is an active ECU stack, so by default it drops peer-to-peer frames addressed to
other nodes. Here its acceptance check is opened so it hears everything, like a passive
logger, which is how vn-decode listens.

Usage: crosscheck_j1939.py CAPTURE.csv VN_DECODE_OUTPUT.jsonl
"""

import json
import sys
import time

import j1939  # can-j1939 (MIT), https://github.com/juergenH87/python-can-j1939


def read_turku_csv(path):
    """Yields (timestamp_s, can_id, bytes) from the Turku truck CSV."""
    with open(path, newline="") as f:
        header = f.readline()
        assert header.startswith("timestamp;"), header
        for line in f:
            parts = line.rstrip("\r\n").split(";")
            if len(parts) < 3:
                continue
            ts = time.mktime(time.strptime(parts[0][:19], "%Y-%m-%d %H:%M:%S")) + float("0" + parts[0][19:])
            can_id = int(parts[1], 16)
            dlc = int(parts[2])
            data = bytes(int(b) for b in parts[3 : 3 + dlc])
            assert len(data) == dlc, line
            yield ts, can_id, data


def reference_messages(path):
    ecu = j1939.ElectronicControlUnit()
    ecu._is_message_acceptable = lambda dest_address: True  # listen to every destination
    ecu.j1939_dll._is_message_acceptable = lambda dest_address: True
    got = []

    def on_message(priority, pgn, sa, timestamp, data):
        got.append((priority, pgn, sa, bytes(data)))

    ecu.subscribe(on_message)
    frames = 0
    try:
        for ts, can_id, data in read_turku_csv(path):
            frames += 1
            ecu.notify(can_id, bytearray(data), ts)
    finally:
        ecu.stop()
    return frames, got


def ours(path):
    out = []
    with open(path) as f:
        for line in f:
            m = json.loads(line)
            out.append((m["pri"], m["pgn"], m["sa"], bytes.fromhex(m["data"]), m["tp"]))
    return out


def main():
    capture, ours_path = sys.argv[1], sys.argv[2]
    frames, ref = reference_messages(capture)
    mine = ours(ours_path)
    ref_tp = sum(1 for r in ref if len(r[3]) > 8)
    mine_tp = sum(1 for m in mine if m[4])
    print(f"frames read: {frames}")
    print(f"can-j1939 messages: {len(ref)} ({ref_tp} reassembled transfers)")
    print(f"vn-decode messages: {len(mine)} ({mine_tp} reassembled transfers)")

    mismatches = 0
    for i, (r, m) in enumerate(zip(ref, mine)):
        if r[:4] != m[:4]:
            mismatches += 1
            if mismatches <= 10:
                print(f"MISMATCH at message {i}: can-j1939 {r[0]} {r[1]} {r[2]} {r[3].hex()} "
                      f"vs vn-decode {m[0]} {m[1]} {m[2]} {m[3].hex()}")
    if len(ref) != len(mine):
        print(f"MISMATCH: message counts differ ({len(ref)} vs {len(mine)})")
        mismatches += 1
    print(f"field mismatches: {mismatches}")
    print("PASS" if mismatches == 0 else "FAIL")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
