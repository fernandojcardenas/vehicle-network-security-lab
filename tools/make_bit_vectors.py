#!/usr/bin/env python3
"""Writes testdata/can-bit-vectors.txt: CAN frames with their CRC-15 and stuff-bit count,
computed by this script's own implementation, independent of the C++ one in
src/can/bit_timing.cpp (different code, different stuffing logic: this one watches the last
five bits of the output stream, stuff bits included). tests/bit_timing_test.cpp checks the C++
code against every line.

Line format: <x|s> <id hex> <data hex or -> <crc hex> <stuff bits>
"""

import random
import sys


def crc15(bits):
    crc = 0
    for b in bits:
        nxt = b ^ ((crc >> 14) & 1)
        crc = (crc << 1) & 0x7FFF
        if nxt:
            crc ^= 0x4599
    return crc


def bits_of(value, n):
    return [(value >> i) & 1 for i in range(n - 1, -1, -1)]


def frame_bits(extended, can_id, data):
    if extended:
        b = [0] + bits_of(can_id >> 18, 11) + [1, 1] + bits_of(can_id & 0x3FFFF, 18) + [0, 0, 0]
    else:
        b = [0] + bits_of(can_id, 11) + [0, 0, 0]
    b += bits_of(len(data), 4)
    for x in data:
        b += bits_of(x, 8)
    c = crc15(b)
    return b + bits_of(c, 15), c


def stuff_count(bits):
    out, count = [], 0
    for x in bits:
        out.append(x)
        if len(out) >= 5 and len(set(out[-5:])) == 1:
            out.append(1 - out[-1])
            count += 1
    return count


def main():
    rng = random.Random(20261008)
    lines = []
    special = [(True, 0, [0] * 8), (True, 0x1FFFFFFF, [0xFF] * 8), (False, 0, []), (False, 0x7FF, [0xFF] * 8),
               (True, 0x0CF00400, [0xF0, 0x7D, 0x8C, 0xE0, 0x2E, 0x00, 0xFF, 0xFF])]
    frames = special + [
        (ext, rng.getrandbits(29 if ext else 11), [rng.getrandbits(8) for _ in range(rng.randint(0, 8))])
        for ext in (rng.random() < 0.7 for _ in range(995))
    ]
    for ext, can_id, data in frames:
        bits, crc = frame_bits(ext, can_id, data)
        lines.append(f"{'x' if ext else 's'} {can_id:x} {bytes(data).hex() or '-'} {crc:x} {stuff_count(bits)}")
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
