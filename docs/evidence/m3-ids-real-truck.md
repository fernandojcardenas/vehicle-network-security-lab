# M3 intrusion detection on real truck traffic (2026-10-08)

Validated on two real heavy trucks from the Colorado State University J1939 data
(Jeremy Daily's group). The logs are not in this repository; fetch them with
`python3 tools/fetch_csu.py all` (SHA-256 checked). See docs/data-sources.md.

The detector trains on the first 40% of each log and is tested on the rest. Attacks are
spliced into the test region with `vn-attack` and scored with `tools/evaluate_ids.py`.

## 2014 Kenworth T270, 30-minute slice (first 1,400,000 frames)

Clean held-out traffic (1280 s): 0 alerts.

| Attack (`--start 1600 --duration 30`) | Alert types raised in the window | Result |
|---|---|---|
| flood | unknown-source (30) | detected |
| spoof | value-out-of-range (30), impossible-jump (30) | detected |
| replay | impossible-jump (144), value-out-of-range (20), flood-rate (46) | detected |
| jump | value-out-of-range (1), impossible-jump (1) | detected |
| hijack | unexpected-pgn (30) | detected |

The T270 sends no address claims in training, so the hijack (a forged Address Claimed
from an existing address) is caught as a source sending a parameter group it never sent.
On the simulated truck, which does send claims, the same attack is caught as an
address-claim conflict (NAME mismatch); see m3-ids-simulated.md.

## False-alarm rate on full clean logs

On the complete logs, with no attack, the only alerts are genuine novel operational
states (the truck revving higher or opening the throttle more than in training):

- 2014 Kenworth T270, full 4.2-hour drive: trained on 1.7 h, 5 alerts over the 2.5-hour test.
- 2015 Kenworth T660, 7-minute drive: trained on 2.7 min, 10 alerts over the 4-minute test.

Both are accumulator- and drift-aware (odometer, fuel used, temperatures and the clock are
judged by their nature, not by a learned range), which removed about 99% of naive range
alerts (T660 went from 938 to 10, T270 from thousands to 5).
