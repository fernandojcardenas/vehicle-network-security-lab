#!/usr/bin/env python3
"""Writes seed inputs for fuzz/fuzz_transport.cpp: one complete BAM and one complete RTS/CTS
transfer, in that fuzzer's 10-byte record layout (time step, selector, 8 data bytes)."""

import os
import sys


def rec(dt_ms, sel, data):
    return bytes([dt_ms, sel]) + bytes(data)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    # Selector bits: 0-1 kind (0 TP.CM, 1 TP.DT), 2-3 source index, 4-5 destination index
    # into {0x00, 0x03, 0xF9, 0xFF}.
    bam = rec(0, 0x30, [32, 20, 0, 3, 0xFF, 0xCA, 0xFE, 0x00])  # BAM of DM1 from 0x00
    bam += b"".join(rec(50, 0x31, [k] + [k * 7 + i for i in range(7)]) for k in (1, 2, 3))
    with open(os.path.join(out, "bam"), "wb") as f:
        f.write(bam)
    rts = rec(0, 0x08, [16, 21, 0, 3, 0xFF, 0xEC, 0xFE, 0x00])   # 0xF9 -> 0x00
    cts = rec(1, 0x20, [17, 3, 1, 0xFF, 0xFF, 0xEC, 0xFE, 0x00])  # 0x00 -> 0xF9
    dts = b"".join(rec(1, 0x09, [k] + [0x41] * 7) for k in (1, 2, 3))
    with open(os.path.join(out, "cmdt"), "wb") as f:
        f.write(rts + cts + dts)


if __name__ == "__main__":
    main()
