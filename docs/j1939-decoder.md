# The J1939 decoder (M1)

## Layers

```
log line ──► can::Frame ──► j1939::Reassembler ──► j1939::Message ──► decode_signals / decode_dm1 / ...
             (candump or     (passive transport      (single frame or
              Turku CSV)      protocol listener)      reassembled payload)
```

### Identifier

A J1939 frame uses CAN's 29-bit identifier:
`priority (3) | EDP (1) | DP (1) | PF (8) | PS (8) | SA (8)`.
When PF is below 240 the group is PDU1: PS is the destination address and is
not part of the PGN. From 240 up the group is PDU2: PS is part of the PGN and
the message is broadcast. `decode_id` and `encode_id` are `constexpr` and
round-trip (tested on identifiers from the real capture).

### Transport protocol (J1939-21)

Messages longer than 8 bytes (up to 1785) are split into 7-byte packets:

- **BAM** (broadcast): one TP.CM announcement to everyone, then TP.DT packets
  50–200 ms apart. Nobody acknowledges.
- **RTS/CTS** (connection mode): the sender asks (RTS), the receiver grants a
  number of packets at a time (CTS) and can ask for packets again, and closes
  with EndOfMsgAck. Either side can abort.

`Reassembler` is a **passive** listener: it never sends anything, and it
follows transfers between any two nodes. That is what a logger or an intrusion
detector needs, and it is different from an ECU stack, which only takes part
in transfers addressed to itself.

Design choices, with the reason for each:

| Choice | Why |
|---|---|
| A session is keyed by (originator, destination); a second announcement on the same pair replaces the first and is counted | J1939 allows one transfer per direction per pair. A replacement is legal (a sender gave up), but frequent replacements are suspicious, so they are counted for M3 |
| Every announcement is checked: 9 ≤ size ≤ 1785, packets = ceil(size / 7), PGN ≤ 18 bits, a PDU1 PGN has a zero low byte, no transport PGN inside, BAM only to the global address, RTS never to it | An announcement is attacker-controlled. Nothing it claims is used until all of it agrees |
| The payload buffer is reserved at the announced size, never more than 1785 bytes | Bounded memory regardless of input |
| At most 64 open sessions (configurable); more are rejected and counted | A flood of announcements cannot grow memory without limit |
| Out-of-order packets drop the session; packets for no session are counted as orphans | A real bus almost never does either; both are signs of loss or injection |
| A CTS may move the next packet back (a retransmission) but never forward | Moving forward would accept a payload with a hole in it |
| Timeouts come from the frames' own timestamps, not the wall clock: 750 ms between BAM packets (T1), 1250 ms of silence in a connection (T2/T3) | Replaying a log gives the same result at any speed, and tests are deterministic |
| The message is emitted on the last data packet, not on EndOfMsgAck | A broadcast has no acknowledgement, and a passive listener should not depend on the receiver behaving |

### Signals

`spn_table()` holds 92 parameters (SPNs) from 18 parameter groups as data:
position (`start_bit`, `length`), scale, offset and unit. Bits are counted from
the least significant bit of byte 1, and multi-byte values are little-endian.
`extract_bits` rejects any field that runs past the end of the payload.

J1939-71 reserves the top of every range, and the decoder keeps those values
apart instead of turning them into numbers:

| Width | Valid | Reserved | Error indicator | Not available |
|---|---|---|---|---|
| 8 bits | 0–250 | 251–253 | 254 | 255 |
| 16 bits | 0–0xFAFF | 0xFB00–0xFDFF | 0xFE00–0xFEFF | 0xFF00–0xFFFF |
| 32 bits | 0–0xFAFFFFFF | 0xFB000000–0xFDFFFFFF | 0xFE000000–0xFEFFFFFF | 0xFF000000– |
| state fields | all others | | all ones minus one | all ones |

The difference matters on the real truck: parked, it sends engine speed as
"not available", not 0 rpm. And just after each logger restart it sends its
time and date as "error indicator" until its clock source is valid.

Three groups need more than a linear scale and have their own decoders:

- **DM1** (active trouble codes): lamp states, then 4 bytes per code (19-bit
  SPN, 5-bit failure mode, 7-bit occurrence count), skipping the "no codes"
  pattern and 0xFF padding. A payload that is not a whole number of codes is
  rejected.
- **Address Claimed**: the 64-bit NAME, split into its nine fields.
- **Time/Date**: the day of the month counts quarter days. Raw values 1–4
  mean the 1st, 5–8 the 2nd, and so on, so a linear `raw × 0.25` turns the
  26th into 25.5. The truck's clock check below caught exactly this.

## Verification

All of these run in CI on every push.

| Check | What it proves | Result |
|---|---|---|
| 41 unit tests (ASan + UBSan, GCC and Clang) | Parsers, identifier, every transport path including retransmission, aborts, timeouts and each kind of bad announcement, reserved ranges, DM1, NAME, Time/Date | All pass |
| 5 real-capture tests | Every one of 15,766 rows parses; transport counts are exact; the truck's clock agrees with the log | All pass |
| Cross-check against can-j1939 | The identifier and transport layers agree with an independent implementation on real traffic | 15,640 / 15,640 messages identical ([evidence](evidence/m1-crosscheck-can-j1939.md)) |
| Truck clock vs log clock | All six Time/Date fields decode correctly | Offset 2 h 1 min 7.7 s, spread 0.42 s ([evidence](evidence/m1-consistency.md)) |
| Message rates vs FMS-Standard | Traffic is split into the right parameter groups | 10 of 11 measurable groups match within 5 %; engine hours come every 5 s, not 1 s (documented) |
| Planted bugs | The checks above fail when the decoder is wrong | 4 of 4 caught ([evidence](evidence/m1-planted-bugs.md)) |
| libFuzzer, 3 targets × 60 s | No crash, leak or undefined behaviour on hostile input; parse → format → parse round-trips | Clean ([evidence](evidence/m1-fuzz.txt)) |
| clang-tidy, warnings as errors | | Clean |

### Limits of this verification

- The capture has no connection-mode (RTS/CTS) transfers, only broadcasts.
  RTS/CTS is covered by unit tests, not by real traffic or the cross-check.
- The truck is parked. Engine speed, torque, vehicle speed, fuel rate and
  temperatures are "not available" or constant, so their positions and scales
  are checked by unit tests only. The planned physical check (the wheel-speed
  sensor against the tachograph, engine speed against transmission input
  speed) needs a driving capture (M3).
- can-j1939 does not report the destination address to its subscribers, so
  the cross-check compares priority, PGN, source and payload. Destinations are
  covered by unit tests.
