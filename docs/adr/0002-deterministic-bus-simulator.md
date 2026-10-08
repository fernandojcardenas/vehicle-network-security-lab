# ADR 0002: A deterministic bus simulator with exact bit timing, bridged to SocketCAN

Date: 2026-10-08
Status: Accepted

## Context

M3 (attacks and detection) needs traffic from a moving truck, with ECUs that
react to what is on the bus: they answer requests, defend addresses and run
transfers. The real capture is 20 seconds of a parked truck, and the dataset
cannot currently be downloaded in full. Linux has a virtual CAN bus (`vcan`),
but it has no notion of time on the wire: a `vcan` interface delivers frames
instantly, with no arbitration and no bus load, so a flooding attack would
look free. Neither the development sandbox nor a Mac can create `vcan`
interfaces anyway.

## Decision

Simulate the bus in-process as a discrete-event model, and bridge it to
SocketCAN instead of building on `vcan` alone.

- **Exact bit timing and arbitration.** Each frame's real bit sequence is
  built and its stuff bits counted, so bus load and the delay a flood causes
  come out of the model rather than an estimate. Arbitration follows CAN
  (lowest identifier wins; the sender keeps its own order).
- **Simulated time only.** Nothing reads the wall clock, so a seed reproduces
  a run byte for byte, and ten minutes of traffic take seconds to produce.
  Detection results in M3 will be reproducible.
- **Active nodes reuse the passive decoder.** Every simulated ECU validates
  its input with M1's hardened reassembler, and the active stack (address
  claim, requests, RTS/CTS) is fuzzed with injected frames.
- **A bridge, not a replacement.** `--iface` runs the same model against the
  wall clock on a real SocketCAN interface: completed frames go out, and
  frames from the interface are injected and arbitrate like any node. So
  can-utils, real tools and M3's attack programs can talk to the simulated
  truck over a real kernel interface.
- **Independent checks:** can-j1939 for every message, connection-mode
  transfers included; can-utils' `candump` for the live path; a separately
  written Python implementation for the bit timing.

## Consequences

- One parameter table drives both the simulator's encoder and the decoder.
  The simulator can't validate parameter positions, only coherence; real
  traffic remains the reference for positions.
- The simulated bus is quieter than a real one (no proprietary traffic). M3
  has to report detection on real traffic as well.
- Error frames and bus-off are not modelled. M3's attacks that rely on them
  (bus-off attacks) would need a model extension; flooding and spoofing do not.
- The live path is exercised only in CI on GitHub's Linux runners.
