#!/usr/bin/env python3
"""Compares candump -l logs frame by frame.

The first log is the reference. Every other log must contain exactly the same frames
(identifier and data bytes) in the same order; interface names and absolute timestamps may
differ. For each log the script also reports timing: each frame's time relative to the log's
first frame, compared with the reference's relative time (mean and worst difference).

Usage: compare_logs.py REFERENCE.log OTHER.log [...] [--external ID#DATA ...] [--require-frame ID#DATA ...]

--external names a frame injected from outside (for example with cansend). It must appear
exactly once in every log but is left out of the order comparison: the simulator stamps it
when it finishes on the simulated bus, the kernel when cansend wrote it, so it can sit a
frame or two apart in the two logs.
--require-frame checks that a frame (for example the simulator's answer to the injected
request) appears in every log. Exits 1 on any difference.
"""

import re
import statistics
import sys

LINE = re.compile(r"^\((\d+)\.(\d{1,6})\)\s+(\S+)\s+([0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})#([0-9A-Fa-f]*)\s*$")


def read(path):
    frames = []
    bad = 0
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            m = LINE.match(line)
            if not m:
                bad += 1
                continue
            t = int(m.group(1)) + int(m.group(2).ljust(6, "0")) / 1e6
            frames.append((t, m.group(4).upper(), m.group(5).upper()))
    return frames, bad


def main():
    args = sys.argv[1:]
    required, external = [], []
    for flag, into in (("--require-frame", required), ("--external", external)):
        while flag in args:
            i = args.index(flag)
            into.append(args[i + 1].upper())
            del args[i : i + 2]
    speed = 1.0  # the other logs were replayed this much faster than the reference
    if "--speed" in args:
        i = args.index("--speed")
        speed = float(args[i + 1])
        del args[i : i + 2]
    ref_path, others = args[0], args[1:]
    failures = 0

    def load(path):
        nonlocal failures
        frames, bad = read(path)
        for ext in external:
            n = sum(1 for _, i, d in frames if f"{i}#{d}" == ext)
            if n != 1:
                print(f"  FAIL: external frame {ext} appears {n} times in {path} (expected once)")
                failures += 1
        frames = [f for f in frames if f"{f[1]}#{f[2]}" not in external]
        return frames, bad

    ref, ref_bad = load(ref_path)
    print(f"reference {ref_path}: {len(ref)} frames (external frames set aside), {ref_bad} unparsed lines")
    failures += ref_bad > 0
    ref_keys = [(i, d) for _, i, d in ref]
    for want in required:
        if want not in {f"{i}#{d}" for i, d in ref_keys}:
            print(f"  FAIL: required frame {want} not in the reference")
            failures += 1
    for path in others:
        frames, bad = load(path)
        keys = [(i, d) for _, i, d in frames]
        same = keys == ref_keys
        print(f"{path}: {len(frames)} frames, {bad} unparsed lines -> {'identical frames, same order' if same else 'DIFFERENT'}")
        if not same:
            failures += 1
            for k, (a, b) in enumerate(zip(ref_keys, keys)):
                if a != b:
                    print(f"  first difference at frame {k}: {a} vs {b}")
                    break
            else:
                print(f"  one log is a prefix of the other ({len(ref_keys)} vs {len(keys)})")
        for want in required:
            if want not in {f"{i}#{d}" for i, d in keys}:
                print(f"  FAIL: required frame {want} missing")
                failures += 1
        failures += bad > 0
        if same and frames:
            r0, o0 = ref[0][0], frames[0][0]
            diffs = [abs((o - o0) - (r - r0) / speed) * 1e3 for (r, _, _), (o, _, _) in zip(ref, frames)]
            print(f"  timing vs reference (relative to first frame): mean {statistics.mean(diffs):.3f} ms, "
                  f"worst {max(diffs):.3f} ms")
    print("PASS" if failures == 0 else f"FAIL: {failures} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
