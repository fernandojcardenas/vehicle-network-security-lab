#!/usr/bin/env python3
"""Cross-checks the C++ SHA-256 and HMAC-SHA256 against Python's hashlib/hmac on random inputs.

Runs the `vn-mac` helper (built from this repo) over many random (key, message) pairs and
compares every digest and tag with the standard library. Independent implementation, so a bug
in either side shows up.

Usage: crosscheck_crypto.py path/to/vn-mac [N]
"""
import hashlib, hmac, os, subprocess, sys

vn_mac = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
rng = __import__("random").Random(20261009)
mismatches = 0
for _ in range(n):
    klen = rng.randint(0, 200)
    mlen = rng.randint(0, 2000)
    key = bytes(rng.getrandbits(8) for _ in range(klen))
    msg = bytes(rng.getrandbits(8) for _ in range(mlen))
    line = (key.hex() or "-") + " " + (msg.hex() or "-") + "\n"
    out = subprocess.run([vn_mac], input=line, capture_output=True, text=True, check=True)
    got_sha, got_hmac = out.stdout.split()
    exp_sha = hashlib.sha256(msg).hexdigest()
    exp_hmac = hmac.new(key, msg, hashlib.sha256).hexdigest()
    if got_sha != exp_sha or got_hmac != exp_hmac:
        mismatches += 1
        if mismatches <= 5:
            print(f"MISMATCH klen={klen} mlen={mlen}\n  sha  {got_sha} vs {exp_sha}\n  hmac {got_hmac} vs {exp_hmac}")
print(f"checked {n} random (key,message) pairs; {mismatches} mismatches")
sys.exit(1 if mismatches else 0)
