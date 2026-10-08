# vehicle-network-security-lab

[![CI](https://github.com/fernandojcardenas/vehicle-network-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/fernandojcardenas/vehicle-network-security-lab/actions/workflows/ci.yml)

A security lab for heavy-vehicle networks, in C++20. It decodes SAE J1939, the
CAN protocol that trucks, buses and military ground vehicles use between their
engine, transmission, brakes and dashboard. Later milestones attack a simulated
vehicle bus, detect those attacks, authenticate messages and harden an
embedded-Linux gateway.

No hardware is needed. Input comes from real truck traffic (a public research
dataset) and, from M2, from a virtual CAN bus on Linux.

**Status:** M1 (J1939 decoder) done. See the [roadmap](docs/roadmap.md).

## Why

A modern vehicle is a network of computers that trust each other: any node on
the CAN bus can send any message, and nothing on the wire says who really sent
it. I work on electronics for a living (U.S. Coast Guard electronics
technician). This project goes from the bits on that bus to the defences
around it, in the same order an attacker or a defender would learn them.

## What works today (M1: J1939 decoder)

- Reads two log formats: can-utils `candump -l` logs and the CSV of the
  University of Turku truck dataset. Converts between them.
- Splits every 29-bit identifier into priority, PGN (parameter group number),
  source and destination address, handling PDU1 (addressed) and PDU2
  (broadcast) groups and both data pages.
- **Transport protocol** (J1939-21): reassembles messages longer than 8 bytes,
  both broadcast (BAM) and connection-mode (RTS/CTS, including retransmission
  requests). It listens passively, the way a logger or an intrusion detector
  does, and follows transfers between any pair of nodes.
- **Untrusted input:** every size and packet count an announcement claims is
  checked before use; payloads never exceed 1785 bytes; open transfers are
  capped; timeouts (750 ms for broadcast, 1250 ms for connections) drop stalled
  transfers. Every failure is counted by kind (timeouts, out-of-order packets,
  impossible announcements, aborts, orphan packets), because M3's intrusion
  detector will read those counters.
- **Signals:** 92 public parameters (SPNs) from 18 parameter groups: engine
  and transmission speeds and torques, vehicle speed from the wheels and from
  the tachograph, temperatures, fuel, distance, time/date and battery voltage,
  plus DM1 trouble codes and the ECU NAME from address claims. J1939's
  reserved ranges are kept apart: "not available", "error indicator" and
  "reserved" are never turned into numbers.
- `vn-decode`: one JSON object per message, a per-group summary with message
  rates and transport counters, or a candump log for replay.

```
$ vn-decode --summary testdata/turku-truck-2020-11-26-slice.csv | tail -3
single-frame messages 15600
BAM started 42, completed 40; RTS started 0, completed 0; CTS 0, EndOfMsgAck 0
transport problems: timeouts 2, sequence errors 0, bad announcements 0, aborts 0, replaced 0, orphan data 0, malformed 0, rejected (too many sessions) 0
```

The two timeouts are correct: in both cases the last packet of a transfer fell
into one of the logger's two pauses, so the transfer was never complete.

Details: [docs/j1939-decoder.md](docs/j1939-decoder.md).

## How it's checked

Unit tests are not enough for a decoder: they only check the decoder against
what its author believes. M1 is checked three more ways, all in CI, on 15,766
real frames from a heavy truck:

1. **Against an independent implementation.** The same capture goes through
   the [can-j1939](https://github.com/juergenH87/python-can-j1939) Python
   package. Both produce the same 15,640 messages (priority, PGN, source,
   payload), including all 40 reassembled transfers
   ([evidence](docs/evidence/m1-crosscheck-can-j1939.md)).
2. **Against the truck's own clock.** The truck broadcasts its date and time.
   Log time minus truck time stays at 2 h 1 min 7.7 s on all 37 valid
   messages, spread 0.42 s against the field's 0.25 s resolution. So all six
   date and time fields decode correctly, including J1939's quarter-day
   encoding of the day of the month. The check also showed that the dataset's
   timestamps are Finnish local time (UTC+2), and that the logger's clock was
   68 s off the truck's ([evidence](docs/evidence/m1-consistency.md)).
3. **Against the published message rates.** Each parameter group's measured
   repetition rate matches the FMS-Standard's specified rate (20 ms for EEC1,
   50 ms for EEC2 and the tachograph, 100 ms for vehicle speed, 1 s for
   temperatures). The exception: this truck sends engine hours every 5 s
   instead of every 1 s. It's reported, not hidden.

The checks were tested by planting bugs: including transport padding in
payloads, reading the day linearly, doubling the seconds scale and reading
minutes from the wrong byte. Each one is caught
([evidence](docs/evidence/m1-planted-bugs.md)).

What this capture can't check: the truck was parked (parking brake on, engine
values "not available"), so engine and vehicle-speed scaling are covered only
by unit tests for now. Comparing the wheel-speed and tachograph-speed sensors
against each other waits for a capture of the truck driving (M3).

Also: three libFuzzer targets (log parsers, transport reassembler, signal
decoders) run under ASan and UBSan on every push, and clang-tidy runs with
warnings as errors.

## Build

Needs CMake 3.24+ and a C++20 compiler (GCC 13 or Clang 18). GoogleTest is
downloaded at configure time.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
./build/vn-decode --summary testdata/turku-truck-2020-11-26-slice.csv
```

Options: `-DVNSL_SANITIZE=ON` (ASan + UBSan), `-DVNSL_BUILD_FUZZERS=ON`
(Clang only), `-DVNSL_WARNINGS_AS_ERRORS=ON`.

## Layout

```
include/vnsl/can/      CAN frame, candump and Turku CSV parsers
include/vnsl/j1939/    identifier, transport protocol, signals (SPN table, DM1, NAME, Time/Date)
src/                   implementation
apps/vn-decode/        command-line decoder
tests/                 unit tests and real-capture tests
fuzz/                  libFuzzer targets
tools/                 cross-check and consistency scripts, fuzz seeds
testdata/              15,766 real frames from a heavy truck (CC BY 4.0)
docs/                  design notes, ADRs, evidence from real runs
```

## Data and scope

Public data only. The test capture is a slice of the University of Turku's
*CAN bus dataset collected from a heavy-duty truck* (CC BY 4.0); see
[docs/data-sources.md](docs/data-sources.md). Parameter definitions come from
public sources (the FMS-Standard interface description and public J1939
summaries), not from the paid SAE J1939 Digital Annex, and cover only the
common parameters a fleet-management interface exposes.

## Licence

MIT (see [LICENSE](LICENSE)). Third-party material: [THIRD-PARTY.md](THIRD-PARTY.md).
