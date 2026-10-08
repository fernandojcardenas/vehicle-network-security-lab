#!/usr/bin/env python3
"""Physical-consistency checks of simulated truck traffic (vn-decode --json of a vn-sim log).

Each check compares two values that different simulated ECUs send in different parameter
groups, so it exercises the whole path: vehicle model -> encoder -> simulated bus -> passive
decoder. Tolerances come from the model's own design (sensor errors, quantization, message
timing) and were written down before the first run.

What this proves and what it does not: it shows the simulator's traffic is physically
coherent and that encoding and decoding agree. It cannot show that a parameter sits at the
position the SAE standard gives it, because the simulator and the decoder share one parameter
table: a wrong position would be encoded and decoded the same wrong way. That question is
answered against real traffic (tools/check_consistency.py on the Turku capture).

Usage: check_sim_physics.py SIM.jsonl [--markdown]
Exits 1 if a check fails.
"""

import bisect
import json
import math
import statistics
import sys
from collections import defaultdict

# Model constants (src/sim/vehicle.hpp)
FINAL_DRIVE = 2.85
TYRE_RADIUS_M = 0.510
ABS_ASSUMED_RADIUS_M = 0.5115
START_EPOCH_S = 1791460800  # TruckConfig::start_epoch_s


def load(path):
    series = defaultdict(list)  # (pgn, spn) -> [(t, value)]
    tp = []
    for line in open(path):
        m = json.loads(line)
        for spn, v in m.get("spn", {}).items():
            if isinstance(v, (int, float)):
                series[(m["pgn"], int(spn))].append((m["t"], float(v)))
        if m["pgn"] == 65254 and "time" in m:
            tp.append((m["t"], m["time"]))
    return series, tp


def at(series, t):
    """Most recent value at or before t (what a receiver would hold), or None."""
    i = bisect.bisect_right(series, (t, math.inf)) - 1
    return series[i][1] if i >= 0 else None


def integrate(series):
    total = 0.0
    for (t0, v0), (t1, _) in zip(series, series[1:]):
        total += v0 * (t1 - t0)
    return total


def main():
    path = sys.argv[1]
    md = "--markdown" in sys.argv
    s, td = load(path)
    rows, failures = [], 0

    def check(name, value_text, ok, tolerance):
        nonlocal failures
        failures += not ok
        rows.append((name, value_text, tolerance, "PASS" if ok else "FAIL"))

    wheel, tacho = s[(65265, 84)], s[(65132, 1624)]
    engine, in_shaft, out_shaft = s[(61444, 190)], s[(61442, 161)], s[(61442, 191)]
    engaged, shifting, ratio = s[(61442, 560)], s[(61442, 574)], s[(61445, 526)]
    tacho_shaft = s[(65132, 1623)]

    # 1. Two speed sensors. The ABS unit converts with a radius 0.3 % larger than the real one.
    expected = ABS_ASSUMED_RADIUS_M / TYRE_RADIUS_M
    ratios = [w / v for t, w in wheel if (v := at(tacho, t)) and v > 20]
    med = statistics.median(ratios)
    check("Wheel-based speed / tachograph speed, above 20 km/h", f"median {med:.5f} over {len(ratios)} samples",
          abs(med - expected) < 0.001, f"{expected:.5f} +/- 0.001 (the ABS unit's 0.3 % radius error)")

    # 2. Engine speed equals transmission input-shaft speed while the clutch is closed.
    diffs = []
    for t, rpm in engine:
        e, sh, inp = at(engaged, t), at(shifting, t), at(in_shaft, t)
        if e == 1 and sh == 0 and inp and inp > 700:
            diffs.append(abs(rpm - inp))
    med = statistics.median(diffs)
    p99 = sorted(diffs)[int(0.99 * (len(diffs) - 1))]
    check("Engine speed vs input-shaft speed, clutch closed", f"median abs. difference {med:.2f} rpm, 99th pct {p99:.1f} rpm "
          f"({len(diffs)} samples)", med < 2.0 and p99 < 15.0,
          "median < 2 rpm, 99th pct < 15 rpm (0.125 rpm steps; the two groups are sent 10 ms apart)")

    # 3. Input / output shaft = the gear ratio ETC2 reports.
    errs = []
    for t, inp in in_shaft:
        out, r, e, sh = at(out_shaft, t), at(ratio, t), at(engaged, t), at(shifting, t)
        if e == 1 and sh == 0 and out and out > 100 and r and r > 0.5:
            errs.append(abs(inp / out / r - 1))
    med = statistics.median(errs)
    check("Input / output shaft speed vs reported gear ratio", f"median error {100 * med:.3f} % ({len(errs)} samples)",
          med < 0.005, "< 0.5 % (ratio sent in 0.001 steps)")

    # 4. The tachograph's speed matches its own output-shaft speed through the final drive and tyre.
    errs = []
    for t, rpm in tacho_shaft:
        v = at(tacho, t)
        if v and v > 20:
            from_shaft = rpm / FINAL_DRIVE * 2 * math.pi * TYRE_RADIUS_M * 60 / 1000
            errs.append(abs(from_shaft / v - 1))
    med = statistics.median(errs)
    check("Tachograph speed vs its output-shaft speed", f"median error {100 * med:.3f} % ({len(errs)} samples)",
          med < 0.002, "< 0.2 %")

    # 5. Odometer increase vs integrated tachograph speed.
    odo = s[(65217, 917)]
    driven_odo = odo[-1][1] - odo[0][1]
    km_from_speed = integrate([(t, v / 3600) for t, v in tacho if odo[0][0] <= t <= odo[-1][0]])
    err = abs(driven_odo / km_from_speed - 1) if km_from_speed > 0 else 1
    check("Odometer (VDHR) increase vs integrated speed", f"{driven_odo:.3f} km vs {km_from_speed:.3f} km "
          f"({100 * err:.2f} %)", err < 0.01, "< 1 % (odometer counts in 5 m steps)")

    # 6. Total fuel used vs integrated fuel rate.
    fuel = s[(64777, 5054)]
    used = fuel[-1][1] - fuel[0][1]
    from_rate = integrate([(t, v / 3600) for t, v in s[(65266, 183)] if fuel[0][0] <= t <= fuel[-1][0]])
    err = abs(used / from_rate - 1) if from_rate > 0 else 1
    check("Total fuel used (HRLFC) vs integrated fuel rate", f"{used:.3f} L vs {from_rate:.3f} L ({100 * err:.2f} %)",
          err < 0.02, "< 2 % (rate sent in 0.05 L/h steps every 100 ms)")

    # 7. Time/Date matches the log clock (the simulator starts its clock at START_EPOCH_S).
    offsets = []
    for t, text in td:
        date, clock = text.rstrip("Z").split("T")
        y, mo, d = (int(x) for x in date.split("-"))
        hh, mm, ss = clock.split(":")
        days = (  # days from civil, as in the decoder
            (lambda y, m, d: (lambda era, yoe, doy: era * 146097 + yoe * 365 + yoe // 4 - yoe // 100 + doy - 719468)(
                (y if m > 2 else y - 1) // 400, (y if m > 2 else y - 1) % 400,
                (153 * (m - 3 if m > 2 else m + 9) + 2) // 5 + d - 1))(y, mo, d))
        offsets.append(t - (days * 86400 + int(hh) * 3600 + int(mm) * 60 + float(ss)))
    spread = max(offsets) - min(offsets)
    check("Time/Date vs log clock", f"offset {statistics.median(offsets):.3f} s, spread {spread:.3f} s "
          f"({len(offsets)} messages)", abs(statistics.median(offsets)) < 0.5 and spread < 0.5,
          "offset and spread < 0.5 s (0.25 s resolution)")

    if md:
        print("| Check | Result | Tolerance (set before the run) | |")
        print("|---|---|---|---|")
        for r in rows:
            print(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} |")
    else:
        for r in rows:
            print(f"{r[3]}  {r[0]}: {r[1]}  [tolerance {r[2]}]")
    print(f"\n{'PASS' if failures == 0 else 'FAIL'}: {failures} failed check(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
