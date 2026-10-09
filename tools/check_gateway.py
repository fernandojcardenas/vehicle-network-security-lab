#!/usr/bin/env python3
"""Checks what crossed a live gateway run.

Reads a candump -l log captured on the gateway's output bus and the policy that was in force,
and verifies that every frame that crossed is permitted by a B>A rule, and that nothing
forbidden (in particular the injected attacker frame, PGN 0) got through. Exits 1 on any
violation.

Usage: check_gateway.py OUT.log POLICY
"""

import re
import sys

LINE = re.compile(r"^\((\d+)\.(\d+)\)\s+\S+\s+([0-9A-Fa-f]{8})#")


def pgn_of(can_id):
    pf = (can_id >> 16) & 0xFF
    return ((can_id >> 8) & 0x3FF00) if pf < 240 else ((can_id >> 8) & 0x3FFFF)


def allowed_ba_pgns(policy_path):
    """PGNs permitted B>A (None means a wildcard rule allows any)."""
    pgns, wildcard = set(), False
    for line in open(policy_path):
        line = line.split("#", 1)[0].strip()
        if not line.startswith("B>A"):
            continue
        tokens = line.split()
        pgn = None
        for t in tokens[1:]:
            if t.startswith("pgn="):
                v = t[4:]
                pgn = None if v == "*" else int(v, 0)
        if pgn is None:
            wildcard = True
        else:
            pgns.add(pgn)
    return pgns, wildcard


def main():
    out_path, policy_path = sys.argv[1], sys.argv[2]
    allowed, wildcard = allowed_ba_pgns(policy_path)
    seen = {}
    total = 0
    for line in open(out_path):
        m = LINE.match(line.strip())
        if not m:
            continue
        total += 1
        pgn = pgn_of(int(m.group(3), 16))
        seen[pgn] = seen.get(pgn, 0) + 1

    violations = [] if wildcard else [p for p in seen if p not in allowed]
    attacker_present = 0 in seen  # the injected PGN-0 command
    print(f"frames on the output bus: {total}; distinct PGNs: {sorted(seen)}")
    print(f"policy allows B>A PGNs: {sorted(allowed)}" + (" (plus a wildcard)" if wildcard else ""))
    ok = True
    if violations:
        print(f"FAIL: forbidden PGNs crossed the gateway: {sorted(violations)}")
        ok = False
    if attacker_present:
        print("FAIL: the attacker's PGN 0 command reached the protected bus")
        ok = False
    if total == 0:
        print("FAIL: nothing crossed the gateway at all (expected the allowed powertrain frames)")
        ok = False
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
