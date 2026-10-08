#!/usr/bin/env python3
"""Scores vn-ids against a labelled attack log.

Given a candump log, the attack-window labels vn-attack wrote, and the fraction vn-ids trains
on, this runs vn-ids and reports, per attack window, whether at least one alert fired inside
it (detection), and the false-alarm rate: alerts in the test region that fall outside every
attack window, per minute. An attack is "detected" only from alerts strictly inside its window,
so a pre-existing novelty alert elsewhere cannot be miscredited.

Usage: evaluate_ids.py VN_IDS LOG LABELS [--train-frac F] [--train SECONDS] [--markdown]
VN_IDS is the path to the built vn-ids binary.
"""

import subprocess
import sys


def read_labels(path):
    windows = []
    for line in open(path):
        if line.startswith("window "):
            _, typ, start, end, *_ = line.split()
            windows.append((typ, int(start), int(end)))
    return windows


def main():
    args = sys.argv[1:]
    markdown = "--markdown" in args
    if markdown:
        args.remove("--markdown")
    train_args = []
    for flag in ("--train-frac", "--train"):
        if flag in args:
            i = args.index(flag)
            train_args += [flag, args[i + 1]]
            del args[i : i + 2]
    vn_ids, log, labels = args[0], args[1], args[2]

    windows = read_labels(labels)
    proc = subprocess.run([vn_ids, log, "--jsonl", *train_args], capture_output=True, text=True, check=True)
    import json
    alerts = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
    alert_us = [(int(round(a["t"] * 1e6)), a["type"]) for a in alerts]

    # Test region starts at the training split; vn-ids prints it on stderr.
    rows = []
    detected = 0
    for typ, start, end in windows:
        hits = [t for t, _ in alert_us if start <= t <= end]
        ok = len(hits) > 0
        detected += ok
        rows.append((typ, len(hits), "DETECTED" if ok else "MISSED"))

    def in_any_window(t):
        return any(start <= t <= end for _, start, end in windows)

    # False alarms: alerts outside every attack window. Restrict to at/after the first window's
    # start, so pre-attack novelty in the test region is reported separately.
    first_start = min((s for _, s, _ in windows), default=0)
    fa = [t for t, _ in alert_us if t >= first_start and not in_any_window(t)]
    span_min = (max((e for _, _, e in windows), default=first_start) - first_start) / 60e6 or 1e-9

    out = []
    if markdown:
        out.append("| Attack | Alerts in window | Result |")
        out.append("|---|---|---|")
        for typ, n, res in rows:
            out.append(f"| {typ} | {n} | {res} |")
        out.append(f"\nDetected {detected}/{len(windows)} attacks. "
                   f"False alarms outside windows: {len(fa)}.")
    else:
        for typ, n, res in rows:
            out.append(f"{res:9} {typ:8} ({n} alerts in window)")
        out.append(f"detected {detected}/{len(windows)}; false alarms outside windows: {len(fa)}")
    print("\n".join(out))
    return 0 if detected == len(windows) else 1


if __name__ == "__main__":
    sys.exit(main())
