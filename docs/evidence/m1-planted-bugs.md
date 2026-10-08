# M1 planted-bug checks (2026-10-08)

A check that never fails proves nothing. Each bug below was planted in a
scratch copy of the decoder (never committed). The decoder was rebuilt, the
real capture decoded, and the check run on the output.

| Planted bug | Check | Result |
|---|---|---|
| Transport payload keeps the 0xFF padding of the last packet (`take = 7` instead of the remaining size) | `tools/crosscheck_j1939.py` | **Caught**: 2 mismatches, both vehicle-identification transfers (PGN 65260), each 4 bytes too long. The 38 other transfers are exactly 21 bytes, which fills 3 packets with no padding, so they cannot show this bug |
| Time/Date day read linearly (`day_q / 4` instead of `(day_q + 3) / 4`) | `tools/check_consistency.py` | **Caught**: the offset stays constant, but at "UTC+26", not a real time zone |
| Time/Date seconds scaled 0.5 instead of 0.25 | `tools/check_consistency.py` | **Caught**: spread 59.5 s instead of 0.42 s |
| Time/Date minutes read from byte 3 instead of byte 2 | `tools/check_consistency.py` | **Caught**: spread 120 s, and a clock difference of 1268 s |

The day bug first passed the clock check, because a constant error in a field
still gives a constant offset. The check now also requires the offset to be a
real time zone (UTC−12 to UTC+14) plus less than 10 minutes of clock
difference. A first attempt at the minutes bug (masking with 0x1F) changed
nothing, because the truck's minutes (28–30) are below 32. It was replaced
with the byte swap above.
