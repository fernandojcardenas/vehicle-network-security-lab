# vehicle-network-security-lab

[![CI](https://github.com/fernandojcardenas/vehicle-network-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/fernandojcardenas/vehicle-network-security-lab/actions/workflows/ci.yml)

A security lab for heavy-vehicle networks, in C++20. It decodes SAE J1939, the
CAN protocol that trucks, buses and military ground vehicles use between their
engine, transmission, brakes and dashboard. Later milestones attack a simulated
vehicle bus, detect those attacks, authenticate messages and harden an
embedded-Linux gateway.

No hardware is needed. Input comes from real truck traffic (a public research
dataset) and from a simulated truck that also runs live on a Linux virtual CAN
bus.

**Status:** M1 (J1939 decoder), M2 (virtual vehicle bus), M3 (attacks +
intrusion detection), M4 (message authentication) and M5 (hardened gateway)
done. See the [roadmap](docs/roadmap.md).

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

## A virtual truck on a virtual bus (M2)

- **Bus model:** a discrete-event simulation of one 250 kbit/s CAN bus, the
  real truck's speed. Each frame occupies the bus for its exact bit count: the
  real bit sequence is built, its CRC-15 computed, and stuff bits counted the
  way a CAN controller inserts them. When several nodes are ready, the lowest
  identifier wins arbitration and the others wait. Bus load, contested
  arbitrations and waiting times are measured, not estimated.
- **Six simulated nodes:** engine, transmission, brakes, instrument cluster,
  tachograph and a service tool. Each claims its address at power-up
  (J1939-81), defends it, and gives way if a node with a higher-priority NAME
  claims the same one. They answer requests (or refuse them with a negative
  acknowledgement) and send long messages by BAM, or by RTS/CTS as sender and
  receiver. An optional second service tool powers up at 10 s with the same
  address and has to move.
- **A vehicle model behind the numbers:** a 20-tonne truck on a repeating
  drive cycle. It pulls away through 12 gears, cruises at 60–85 km/h, brakes
  to a stop and parks. Engine speed, shaft speeds, gear ratio, two independent
  speed sensors, fuel, distance and temperatures all come from one physical
  state. The ABS unit deliberately reads 0.3 % high (a worn-tyre radius
  error), the way a real truck's wheel speed differs from its calibrated
  tachograph.
- **Deterministic:** the simulation never reads the wall clock, so a seed
  gives the same log byte for byte (checked in CI; GCC and Clang builds agree).
  macOS's standard library draws different random numbers, so a run there is
  equally repeatable but not identical to Linux.
- **Real SocketCAN:** `vn-sim --iface vcan0` runs the same simulation against
  the wall clock on a Linux CAN interface. Frames from outside (another
  program, a real device, an attacker in M3) are fed into the simulated bus,
  and the ECUs answer them. `vn-record` and `vn-replay` record and replay
  interfaces with kernel timestamps.

```
$ vn-sim --duration 600 --seed 1 --conflict --summary --out sim.log
simulated 600.0 s at 250 kbit/s: 146267 frames, bus load 13.7 %
arbitration: 15756 contested starts, 15943 frames waited; longest wait 6840 us; most queued 7
node            addr   frames claims   BAM   RTS  rxRTS  NACK
engine          0x00    54451      2   510    12      0     0
transmission    0x03    65976      2     0     0      0     1
...
service-tool-2  0x80        5      2     0     0      1     0
```

The second service tool asked for 0xF9, lost to the first tool's
higher-priority NAME and moved to 0x80.

The simulated bus is quieter than the real one: 13.7 % load and 244 frames a
second, against 47 % and 811 on the Turku truck, computed with the same bit
timing. The real truck's gateway also republishes dozens of proprietary
groups, which the simulator does not invent. So M3 will measure detection on
real traffic too: results on the quieter simulated bus alone would be too
optimistic.

Details: [docs/simulator.md](docs/simulator.md).

## Attacks and a detector that catches them (M3)

`vn-ids` is a passive intrusion detector. It learns one truck's normal
behaviour from a training window of that truck's own traffic, then flags
deviations in the rest. Every rule is explainable, and nothing is model-based
beyond the learned ranges:

- **Unknown source** — a frame from an address never seen in training.
- **Unexpected group** — a known ECU sending a parameter group it never sent.
- **Flood rate** — a message arriving far faster than its learned minimum gap.
- **Value out of range / impossible jump** — an operational signal (speed,
  rpm, torque, pressure) outside its learned envelope or changing faster than
  ever observed.
- **Transport anomaly** — the transport layer reporting a new failure
  (sequence error, orphan packet, abort), which a healthy bus never does.
- **Address-claim conflict** — an address claimed with a different NAME than
  before: a node being impersonated.

A signal is judged by its nature, which is what makes the false-alarm rate low
on real trucks: accumulators (odometer, fuel used, engine hours) only ever
grow, so a decrease is the anomaly; slow or environmental signals
(temperatures, fuel level, the clock, a driver's cruise setpoint) are not
range-checked at all. Without this, a naive range check raised 938 false
alarms on a 7-minute real drive; with it, 10.

`vn-attack` splices a labelled attack into any log (real or simulated), so the
same evaluation runs on both. Five attacks are covered: a bus **flood**, a
**spoofed** vehicle speed, a **replay** of earlier traffic, an impossible value
**jump**, and an address **hijack**.

On real truck traffic (2014 Kenworth T270, a 30-minute slice; the detector
trained on the first 40%):

| Attack | Detected by | 
|---|---|
| Flood | an unknown source address appearing |
| Spoof (200 km/h) | value out of range and an impossible jump |
| Replay | impossible jumps, out-of-range values and a doubled message rate |
| Jump (250 km/h) | value out of range and an impossible jump |
| Hijack | a source sending a group it never sent (an address-claim conflict on a truck that sends claims) |

All five detected, with zero false alarms over 1280 s of held-out clean
traffic from the same truck. On the full 4.2-hour T270 drive the only clean
alerts are 5 genuine novel operational states over 2.5 hours. The real logs
are fetched on demand (`tools/fetch_csu.py`, SHA-256 checked) and never stored
here. CI runs the whole attack-and-detect cycle on deterministic simulated
traffic every push. Evidence:
[simulated](docs/evidence/m3-ids-simulated.md),
[real trucks](docs/evidence/m3-ids-real-truck.md).

Details: [docs/ids.md](docs/ids.md).

## Authenticated messages (M4)

Detection (M3) notices an attack after it happens; authentication prevents it.
`vn-secoc` adds SecOC-style message authentication (AUTOSAR Secure Onboard
Communication) to chosen J1939 PGNs. For each protected message it emits one
companion CAN frame carrying a **freshness** value (a monotonic counter, for
anti-replay) and a **truncated MAC** over the data ID, source, freshness and
payload. A receiver recomputes the MAC with the shared key and checks the
freshness; anything else is rejected.

The MAC is HMAC-SHA256, truncated to 32 bits by default. SHA-256 and HMAC are
implemented here with no external crypto dependency, and checked against the
NIST and RFC 4231 test vectors and, every push, against Python's `hashlib` on
thousands of random inputs. (AUTOSAR SecOC usually uses AES-128-CMAC; the MAC
primitive is pluggable — see [ADR 0004](docs/adr/0004-secoc-message-authentication.md).)

This is what closes the loop with M3. Run the same attacks against a protected
log and they no longer get through:

| Attack | Why it fails authentication |
|---|---|
| Spoof (false speed) | the injected frame carries no valid tag — rejected as unauthenticated |
| Forge / alter a value | the MAC no longer matches — rejected as bad-mac |
| Replay an earlier message | its freshness counter is stale — rejected as stale |
| Wrong key | the MAC does not verify — rejected as bad-mac |

On real truck traffic (2015 Kenworth T660, two PGNs authenticated), every
genuine message verifies and a replay is rejected, at about 10% extra bus
bandwidth — one extra frame per authenticated message. Evidence:
[docs/evidence/m4-secoc.md](docs/evidence/m4-secoc.md). Details:
[docs/secoc.md](docs/secoc.md).

## A hardened gateway between two buses (M5)

A real defence puts a gateway between an untrusted bus (a diagnostic port, a
telematics unit) and the protected powertrain bus, and lets almost nothing
cross. `vn-gateway` is that gateway: **default-deny**. A frame is forwarded
only if a rule in a small text policy allows it, by direction, PGN and source,
and even an allowed message can be rate-capped so a flood cannot pass.

```
   bus A (untrusted)            vn-gateway            bus B (powertrain)
   diagnostic tool  -->  default-deny + rate limit  -->  engine, brakes, ...
                         only policy-permitted frames cross
```

On the real Kenworth T660, with a policy that allows the eight powertrain
report groups outward (each capped near its real rate) and nothing inward, the
gateway forwards the permitted reports and drops everything else, and a flood
of an allowed message is held to its cap. 1000 command frames injected from the
diagnostic side that reach the powertrain bus: zero.

The gateway is pure policy over the frames it sees, so it runs the same offline
over a log and live between two Linux `vcan` interfaces; CI exercises the live
path. It ships as a locked-down appliance (`deploy/`): an nftables default-deny
host firewall (syntax-checked in CI), an SELinux module confining the daemon to
CAN sockets (compiled in CI), and a Buildroot image that boots it under QEMU
with SELinux enforcing (the image build is a documented offline step, too heavy
for CI). Details: [docs/gateway.md](docs/gateway.md).

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

M2 adds four more checks, also in CI:

4. **Connection-mode transfers against can-j1939.** Ten simulated minutes
   (146,267 frames) go through the same cross-check: 145,159 messages
   identical, including all 522 reassembled transfers (510 broadcast, 12
   RTS/CTS). This closes M1's gap, since the real capture has no RTS/CTS
   traffic ([evidence](docs/evidence/m2-crosscheck-can-j1939.md)). Running it
   found a bug in the cross-check itself: the step meant to make can-j1939
   listen to every destination had never taken effect. M1's result is
   unaffected, because every addressed frame in the real capture goes to the
   global address.
5. **Physics.** Seven pairs of values that different ECUs send in different
   groups must agree. Examples: wheel speed against tachograph speed (the
   ABS unit's designed radius error is 0.294 %; the decoded traffic shows
   0.294 %), engine speed against
   input-shaft speed (median difference 0.00 rpm with the clutch closed), and
   the odometer against integrated speed. Tolerances were set before the
   first run ([evidence](docs/evidence/m2-physics.md)).
6. **Bit timing against a second implementation.** CRC-15 and stuff-bit
   counts for 1,000 frames match a separately written Python implementation,
   and the CRC matches the published CRC-15/CAN check value.
7. **Live on Linux.** A CI job loads the kernel's `vcan` module and runs the
   simulation live while can-utils' own `candump` and `vn-record` record it.
   All three logs must hold exactly the offline simulation's frames. A
   request injected with `cansend` must get the engine's answer, and a 4x
   replay must reproduce the log.

Planted bugs in the simulator and its sender (packet numbering off by one,
the wrong shaft speed, a wrong scale) are each caught
([evidence](docs/evidence/m2-planted-bugs.md)).

The physics checks share one limit, stated in the script itself: the
simulator and the decoder use the same parameter table, so a parameter at the
wrong position would be encoded and decoded the same wrong way. Positions are
checked against real traffic, not against the simulation.

Also: seven libFuzzer targets (log parsers, transport reassembler, signal
decoders, the simulated truck's active J1939 stack, the intrusion detector, the
SecOC verifier, and the gateway policy parser) run under ASan and UBSan on every
push, and clang-tidy runs with warnings as errors.

## Build

Needs CMake 3.24+ and a C++20 compiler (GCC 13 or Clang 18). GoogleTest is
downloaded at configure time.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
./build/vn-decode --summary testdata/turku-truck-2020-11-26-slice.csv
./build/vn-sim --duration 600 --seed 1 --conflict --summary --out sim.log
./build/vn-ids sim.log --train-frac 0.4          # learn normal, report anomalies
./build/vn-secoc protect sim.log --pgn 65265 --out prot.log   # authenticate a PGN
./build/vn-secoc verify prot.log --pgn 65265                  # check tags and freshness
./build/vn-gateway offline sim.log --policy deploy/gateway.policy --direction B>A --out fwd.log
```

Inject an attack and see it caught:

```
./build/vn-attack sim.log --attack spoof --start 200 --duration 20 --out attacked.log --labels a.labels
./build/vn-ids attacked.log --train-frac 0.4
python3 tools/evaluate_ids.py ./build/vn-ids attacked.log a.labels --train-frac 0.4
```

Live on a Linux virtual CAN bus (needs root for the first three lines):

```
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
./build/vn-sim --iface vcan0 --duration 60 --out live.log &
candump -L vcan0                      # or: ./build/vn-record vcan0
cansend vcan0 18EAFFF1#ECFE00         # ask everyone for the vehicle ID; the engine answers
```

Options: `-DVNSL_SANITIZE=ON` (ASan + UBSan), `-DVNSL_BUILD_FUZZERS=ON`
(Clang only), `-DVNSL_WARNINGS_AS_ERRORS=ON`.

## Layout

```
include/vnsl/can/      CAN frame, log parsers, bit timing (CRC-15, stuffing), SocketCAN (Linux)
include/vnsl/j1939/    identifier, transport protocol, signals (SPN table, DM1, NAME, Time/Date, encoding)
include/vnsl/sim/      bus simulator, active J1939 node, vehicle model, the simulated truck
include/vnsl/ids/      learned baseline, intrusion detector, attack injector
include/vnsl/crypto/   SHA-256 and HMAC-SHA256
include/vnsl/secoc/    SecOC-style protector and verifier
include/vnsl/gateway/  default-deny forwarding policy and gateway
src/                   implementation
deploy/                gateway policy, nftables + SELinux, Buildroot appliance
apps/                  vn-decode, vn-sim, vn-record, vn-replay, vn-ids, vn-attack, vn-secoc, vn-gateway
tests/                 unit tests and real-capture tests
fuzz/                  libFuzzer targets
tools/                 cross-check and consistency scripts, fuzz seeds
testdata/              15,766 real frames from a heavy truck (CC BY 4.0); CAN bit-timing vectors
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
