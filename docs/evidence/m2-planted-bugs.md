# M2 planted-bug checks (2026-10-08)

Each bug was planted in a scratch copy (never committed). The simulator ran the
same ten-minute scenario (seed 1, `--conflict`) and the checks ran on its
output.

| Planted bug | Where | Check | Result |
|---|---|---|---|
| Connection-mode data packets numbered from 0 instead of 1 (broadcasts left correct) | `J1939Node::send_dt` | passive decoder; `tools/crosscheck_j1939.py` | **Caught.** The decoder completes 0 of 12 RTS/CTS transfers and reports 12 sequence errors and 23 orphan packets. The receiving tools never acknowledge, so each sender times out and aborts (12 aborts). The cross-check fails: 12 messages missing |
| Transmission reports output-shaft speed as input-shaft speed | truck ETC1 builder | `tools/check_sim_physics.py` | **Caught.** Engine vs input shaft: median difference 276 rpm (limit 2). Shaft ratio vs gear ratio: 21 % error (limit 0.5 %) |
| Wheel-based speed sent at half its value (a scale bug in one ECU) | truck CCVS1 builder | `tools/check_sim_physics.py` | **Caught.** Wheel / tachograph speed ratio 0.501 instead of 1.003 |

The first bug also shows what M3's detector will rely on: one broken sender
produces a burst of transport-layer anomalies (sequence errors, orphan
packets, aborts) that a healthy bus never shows.
