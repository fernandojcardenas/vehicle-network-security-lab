# M6 end-to-end demo (2026-10-09)

`scripts/demo.sh` runs the whole defensive story on the deterministic simulator
(seed 42) and asserts each layer fires. It is run by the `demo` CI job on every
push, so this output reproduces. Run it yourself with:

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVNSL_BUILD_TESTS=OFF
    cmake --build build --target vn-sim vn-attack vn-ids vn-secoc vn-gateway
    scripts/demo.sh build

Captured output:

```
== Baseline: 180 s of normal traffic from the simulated truck (seed 42) ==
  43728 frames of clean powertrain + body traffic

== Threat 1 - Spoofing a safety message (STRIDE: Spoofing / Tampering) ==
vn-attack: spoof injected 400 frames over [110, 130) s
  M3 (detect): run the passive IDS over the attacked log
  PASS  IDS raised alerts inside the spoof window (40 alerts)
  M4 (authenticate): protect the two safety PGNs, then replay the attack against them
vn-secoc: protected 2 PGN(s); added 3596 authenticator frames
  PASS  genuine authenticated traffic all verifies
vn-attack: spoof injected 400 frames over [60, 80) s
  PASS  SecOC rejected the spoofed safety message (no valid tag)

== Threat 2 - Replaying a captured authenticated message (STRIDE: Tampering / replay) ==
vn-attack: replay injected 5204 frames over [60, 80) s
  PASS  SecOC rejected the replay (stale freshness)

== Threat 3 - Command injection + flood from the diagnostic side (STRIDE: Elevation / DoS) ==
  vn-gateway: seen 4809, forwarded 4189, denied 620 (no-rule 620, rate 0)
  M5 (contain): check what crossed to the protected bus
  PASS  only the allowlisted powertrain PGNs crossed; the attacker's command was dropped

== All three layers held. Detect (M3), authenticate (M4), contain (M5). ==
```

What each assertion proves:

- **M3 detect** — the passive IDS, trained on the first 40 % of the drive, raised
  alerts strictly inside the injected spoof window (`detected 1/1` in
  `evaluate_ids.py`); a pre-existing novelty alert elsewhere cannot be miscredited.
- **M4 authenticate** — genuine authenticated traffic all verifies (no false
  rejects); the same spoof, run against the SecOC-protected log, is rejected (no
  valid tag); a replay of captured authenticated frames is rejected (stale
  freshness). `vn-secoc verify` exits non-zero when anything is rejected, so the
  demo inverts it: the attack *must* be caught.
- **M5 contain** — powertrain traffic plus an injected diagnostic-side command
  (PGN 0 from source 0xF9) is run through the default-deny gateway; only the eight
  allowlisted powertrain PGNs cross and the attacker's command is dropped
  (`check_gateway.py` exits non-zero on any forbidden PGN or if the attacker frame
  crosses).
