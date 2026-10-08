# M1 physical-consistency checks (2026-10-08)

Command: `python3 tools/check_consistency.py ours.jsonl --markdown`

## Clock: truck Time/Date vs log timestamps

- valid Time/Date messages: 37; sent as error indicator: 3
- log minus truck: median 7267.738 s (2.0188 h), spread 0.421 s (field resolution 0.25 s) -> PASS
- offset = time zone UTC+2 plus +67.7 s of clock difference -> PASS

## Timing: repetition rates vs FMS-Standard

| PGN | group | specified ms | measured ms | messages | result |
|---|---|---|---|---|---|
| 61443 | EEC2 | 50 | 50.0 | 390 | PASS |
| 61444 | EEC1 | 20 | 20.0 | 972 | PASS |
| 64777 | HRLFC | 1000 | 1000.1 | 20 | PASS |
| 65132 | TCO1 | 50 | 50.0 | 389 | PASS |
| 65217 | VDHR | 1000 | 1000.0 | 20 | PASS |
| 65253 | HOURS | 1000 | 5000.3 | 4 | deviation (documented: HOURS is sent every 5 s by this truck's FMS gateway, not every 1 s) |
| 65260 | VI | 10000 | - | 2 | not enough data |
| 65262 | ET1 | 1000 | 1000.0 | 20 | PASS |
| 65265 | CCVS1 | 100 | 100.0 | 194 | PASS |
| 65266 | LFE1 | 100 | 100.0 | 194 | PASS |
| 65269 | AMB | 1000 | 1000.0 | 20 | PASS |
| 65276 | DD | 1000 | 1000.1 | 19 | PASS |

PASS: 0 failed check(s)
