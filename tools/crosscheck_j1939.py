#!/usr/bin/env python3
"""Cross-checks vn-decode's J1939 layer against the independent can-j1939 package.

Both read the same CAN log; this script parses it itself (it does not reuse the C++ parser),
feeds every frame to can-j1939's data-link layer and collects the messages can-j1939 emits:
single frames plus reassembled transport-protocol transfers (BAM and RTS/CTS). Then it compares that
stream with `vn-decode --json` message by message: priority, PGN, source address and payload
bytes must all match, in the same order. (can-j1939's subscriber callback does not report the
destination address, so that field is covered by the unit tests instead.)

can-j1939 is an active ECU stack, so three adjustments make it listen like a passive logger,
which is how vn-decode listens:

- its acceptance check is opened, so it hears peer-to-peer frames for every destination;
- its transmit function is replaced by one that does nothing. On an RTS it answers with its
  own CTS; with no bus attached that send fails and the transfer is never reassembled. With
  the no-op it still collects the data packets (which it accepts in order regardless of who
  sent the CTS), so connection-mode transfers are compared too;
- Requests (PGN 59904) and Address Claimed (PGN 60928) never reach its subscribers (it routes
  them to its own controller applications). Both are always single frames, so for those two
  groups vn-decode's messages are compared with the raw frames instead.

Usage: crosscheck_j1939.py CAPTURE VN_DECODE_OUTPUT.jsonl
CAPTURE is the Turku truck CSV or a candump -l log (for example from vn-sim).
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


def read_candump(path):
    """Yields (timestamp_s, can_id, bytes) from a candump -l log."""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stamp, _iface, frame = line.split()
            can_id, data = frame.split("#")
            yield float(stamp.strip("()")), int(can_id, 16), bytes.fromhex(data)


def read_capture(path):
    with open(path) as f:
        first = f.readline()
    return read_candump(path) if first.startswith("(") else read_turku_csv(path)


STACK_INTERNAL_PGNS = {59904, 60928}  # Request, Address Claimed: handled inside can-j1939


def raw_internal_frames(path):
    """(priority, PGN, source, payload) of every Request / Address Claimed frame in the capture."""
    out = []
    for _ts, can_id, data in read_capture(path):
        pf = (can_id >> 16) & 0xFF
        pgn = ((can_id >> 8) & 0x3FF00) if pf < 240 else ((can_id >> 8) & 0x3FFFF)
        if pgn in STACK_INTERNAL_PGNS:
            out.append(((can_id >> 26) & 7, pgn, can_id & 0xFF, bytes(data)))
    return out


def reference_messages(path):
    ecu = j1939.ElectronicControlUnit()
    # The data-link layer keeps its own reference to the acceptance check (taken when the ECU
    # was built), so that reference is the one to replace. Replacing ecu._is_message_acceptable
    # alone has no effect.
    ecu.j1939_dll._J1939_21__ecu_is_message_acceptable = lambda dest_address: True  # every destination
    ecu.j1939_dll._J1939_21__send_message = lambda *args, **kwargs: None  # never transmit
    got = []

    def on_message(priority, pgn, sa, timestamp, data):
        got.append((priority, pgn, sa, bytes(data)))

    ecu.subscribe(on_message)
    frames = 0
    try:
        for ts, can_id, data in read_capture(path):
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
    all_mine = ours(ours_path)
    mine = [m for m in all_mine if m[1] not in STACK_INTERNAL_PGNS]
    internal_mine = [m[:4] for m in all_mine if m[1] in STACK_INTERNAL_PGNS]
    internal_raw = raw_internal_frames(capture)
    ref_tp = sum(1 for r in ref if len(r[3]) > 8)
    mine_tp = sum(1 for m in mine if m[4])
    print("compared: every message except Requests and Address Claimed (checked against raw frames below)")
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
    internal_ok = internal_mine == internal_raw
    print(f"requests + address claims: {len(internal_mine)} vn-decode messages vs {len(internal_raw)} raw frames "
          f"-> {'identical' if internal_ok else 'DIFFERENT'}")
    mismatches += 0 if internal_ok else 1
    print(f"field mismatches: {mismatches}")
    print("PASS" if mismatches == 0 else "FAIL")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
