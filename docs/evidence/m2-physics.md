# M2 physics checks on simulated traffic (2026-10-08)

Command: `python3 tools/check_sim_physics.py sim.jsonl --markdown` on the same ten-minute run (seed 1, `--conflict`).

These check that the simulated traffic is physically coherent end to end (model, encoder, bus, decoder). They cannot check parameter positions against the SAE standard, because the simulator and the decoder share one parameter table.

| Check | Result | Tolerance (set before the run) | |
|---|---|---|---|
| Wheel-based speed / tachograph speed, above 20 km/h | median 1.00294 over 4334 samples | 1.00294 +/- 0.001 (the ABS unit's 0.3 % radius error) | PASS |
| Engine speed vs input-shaft speed, clutch closed | median abs. difference 0.00 rpm, 99th pct 4.8 rpm (22417 samples) | median < 2 rpm, 99th pct < 15 rpm (0.125 rpm steps; the two groups are sent 10 ms apart) | PASS |
| Input / output shaft speed vs reported gear ratio | median error 0.002 % (44333 samples) | < 0.5 % (ratio sent in 0.001 steps) | PASS |
| Tachograph speed vs its output-shaft speed | median error 0.021 % (8666 samples) | < 0.2 % | PASS |
| Odometer (VDHR) increase vs integrated speed | 7.895 km vs 7.895 km (0.00 %) | < 1 % (odometer counts in 5 m steps) | PASS |
| Total fuel used (HRLFC) vs integrated fuel rate | 2.364 L vs 2.364 L (0.01 %) | < 2 % (rate sent in 0.05 L/h steps every 100 ms) | PASS |
| Time/Date vs log clock | offset 0.035 s, spread 0.000 s (600 messages) | offset and spread < 0.5 s (0.25 s resolution) | PASS |

PASS: 0 failed check(s)
