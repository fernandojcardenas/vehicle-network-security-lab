#!/usr/bin/env python3
"""Writes a seed input for fuzz/fuzz_truck.cpp: an RTS/CTS transfer to the engine, a request for
the vehicle ID, and an address claim for the engine's address with a low NAME. Record layout:
time step (ms), selector, destination/DLC byte, 8 data bytes."""

import os
import sys


def rec(dt_ms, sel, dlc_byte, data):
    return bytes([dt_ms, sel, dlc_byte]) + bytes(data)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    # selector: bits 0-2 group (0 TP.CM, 1 TP.DT, 2 Request, 3 Address Claimed), bits 3-5 source
    # index, bits 5-7 priority; DLC byte: bits 5-7 destination index, bits 0-3 DLC.
    # Addresses: 0 0x00, 1 0x03, 2 0x0B, 3 0x17, 4 0xEE, 5 0xF9, 6 0x80, 7 0xFF.
    seed = rec(0, 0xE8, 0x08, [16, 20, 0, 3, 255, 0xEC, 0xFE, 0])  # RTS 0xF9 -> engine
    seed += b"".join(rec(1, 0xE9, 0x08, [k] + [k] * 7) for k in (1, 2, 3))
    seed += rec(5, 0xEA, 0x03, [0xEC, 0xFE, 0, 0, 0, 0, 0, 0])  # request vehicle ID
    seed += rec(5, 0xC3, 0xE8, [1, 0, 0, 0, 0, 0, 0, 0])  # claim with a low NAME
    with open(os.path.join(out, "seed"), "wb") as f:
        f.write(seed)


if __name__ == "__main__":
    main()
