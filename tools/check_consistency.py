#!/usr/bin/env python3
"""Physical-consistency checks of decoded J1939 traffic (vn-decode --json output).

These do not compare the decoder with another decoder; they compare what the truck says with
facts the decoder cannot know:

1. Clock: the truck's Time/Date message (PGN 65254) against the logger's own timestamps. If
   any of the six date/time fields were decoded from the wrong bits or with the wrong scale,
   the offset between the two clocks would not stay constant.
2. Timing: how often each parameter group repeats, against the rates the public FMS-Standard
   interface description specifies. A wrong PGN split (PDU1/PDU2, data page) would put
   traffic under the wrong group and break the rates.

Usage: check_consistency.py VN_DECODE_OUTPUT.jsonl [--markdown]
Exits 1 if a check fails.
"""

import datetime
import json
import statistics
import sys
from collections import defaultdict

# Repetition rates from the FMS-Standard interface description, v02.00 (2010), for the
# groups present in the test capture.
FMS_RATES_MS = {
    61443: ("EEC2", 50),
    61444: ("EEC1", 20),
    64777: ("HRLFC", 1000),
    65132: ("TCO1", 50),   # FMS allows 20 or 50 ms
    65217: ("VDHR", 1000),
    65253: ("HOURS", 1000),
    65260: ("VI", 10000),
    65262: ("ET1", 1000),
    65265: ("CCVS1", 100),
    65266: ("LFE1", 100),
    65269: ("AMB", 1000),
    65276: ("DD", 1000),
}
TOLERANCE = 0.05          # measured mean period within 5 % of the specified one
LOG_PAUSE_S = 20.0        # gaps longer than this are logger pauses, not message periods

# Documented deviations: the check reports them but does not fail on them.
KNOWN_DEVIATIONS = {
    65253: "HOURS is sent every 5 s by this truck's FMS gateway, not every 1 s",
}


def main():
    path = sys.argv[1]
    markdown = "--markdown" in sys.argv
    times = defaultdict(list)
    clock = []
    clock_errors = 0
    for line in open(path):
        m = json.loads(line)
        times[m["pgn"]].append(m["t"])
        if m["pgn"] == 65254:
            if "time" not in m:
                clock_errors += 1
                continue
            t = m["time"]  # "YYYY-MM-DDTHH:MM:SS.ssZ"
            # Parsed by hand (not strptime) so a decoder bug such as 75 seconds is measured, not rejected.
            date, clock_text = t.rstrip("Z").split("T")
            hh, mm, ss = clock_text.split(":")
            midnight = datetime.datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
            truck = midnight.timestamp() + int(hh) * 3600 + int(mm) * 60 + float(ss)
            clock.append(m["t"] - truck)

    failures = 0
    out = []
    p = out.append
    p("## Clock: truck Time/Date vs log timestamps\n")
    if clock:
        spread = max(clock) - min(clock)
        med = statistics.median(clock)
        zone_h = round(med / 3600)
        residual = med - zone_h * 3600
        ok = spread < 0.5
        # A constant offset alone is not enough: a field decoded with a constant error (say the
        # day off by one) also gives a constant offset. The offset must also be a real time
        # zone (UTC-12..UTC+14) plus a plausible clock difference (under 10 minutes).
        zone_ok = -12 <= zone_h <= 14 and abs(residual) < 600
        failures += (not ok) + (not zone_ok)
        p(f"- valid Time/Date messages: {len(clock)}; sent as error indicator: {clock_errors}")
        p(f"- log minus truck: median {med:.3f} s ({med / 3600:.4f} h), spread {spread:.3f} s "
          f"(field resolution 0.25 s) -> {'PASS' if ok else 'FAIL'}")
        p(f"- offset = time zone UTC{zone_h:+d} plus {residual:+.1f} s of clock difference -> "
          f"{'PASS' if zone_ok else 'FAIL (not a real time zone plus a small clock error)'}")
    else:
        p("- no valid Time/Date messages")
    p("\n## Timing: repetition rates vs FMS-Standard\n")
    p("| PGN | group | specified ms | measured ms | messages | result |")
    p("|---|---|---|---|---|---|")
    for pgn, (name, spec) in sorted(FMS_RATES_MS.items()):
        ts = sorted(times.get(pgn, []))
        gaps = [(b - a) * 1000 for a, b in zip(ts, ts[1:]) if b - a < LOG_PAUSE_S]
        if not gaps:
            p(f"| {pgn} | {name} | {spec} | - | {len(ts)} | not enough data |")
            continue
        mean = statistics.mean(gaps)
        ok = abs(mean - spec) <= TOLERANCE * spec
        if not ok and pgn in KNOWN_DEVIATIONS:
            result = f"deviation (documented: {KNOWN_DEVIATIONS[pgn]})"
        else:
            result = "PASS" if ok else "FAIL"
            failures += not ok
        p(f"| {pgn} | {name} | {spec} | {mean:.1f} | {len(ts)} | {result} |")
    p(f"\n{'PASS' if failures == 0 else 'FAIL'}: {failures} failed check(s)")
    text = "\n".join(out)
    print(text if markdown else text.replace("## ", "").replace("|---|---|---|---|---|---|\n", ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
