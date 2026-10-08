# The virtual truck (M2)

```
          vehicle model (10 ms steps)
                    │ one physical state
   ┌────────┬───────┼────────┬───────────┬────────────┐
 engine  transmission brakes  cluster  tachograph  service tool(s)
  0x00      0x03      0x0B     0x17      0xEE         0xF9 (+0x80)
   └────────┴───────┴────────┴───────────┴────────────┘
             J1939Node: address claim, requests, BAM, RTS/CTS
                              │ frames
                   Simulator: one 250 kbit/s CAN bus
            (arbitration, exact bit timing, deterministic time)
                              │ every completed frame
          ┌───────────────────┼─────────────────────┐
     candump log         SocketCAN (vcan0)     passive observers
     (vn-sim --out)      (vn-sim --iface)      (decoder, M3 detector)
```

## The bus

`sim::Simulator` is a discrete-event simulation. Simulated time runs in
microseconds from 0 and nothing reads the wall clock, so a run is exactly
repeatable.

- **One frame at a time.** When the bus goes idle, every node's next frame
  (and any frame injected from outside) contends. The lowest identifier wins,
  as CAN's bitwise arbitration guarantees. Frames that become ready at the
  same instant arbitrate together, because arbitration runs as its own event
  after everything else queued for that instant.
- **Exact bit timing.** `can::frame_bits` builds the frame's real bit
  sequence: start of frame, identifier, SRR/IDE, control field, data, CRC-15.
  It counts the stuff bits a controller inserts (after five equal bits, one of
  the opposite value, which itself starts the next run), then adds the CRC
  delimiter, ACK, end of frame and 3-bit intermission. A frame's time on the
  bus is that count at the bit rate. An 8-byte J1939 frame takes 131–160 bits,
  so 524–640 µs at 250 kbit/s.
- **Delivery.** A frame reaches every other node, stamped with the time its
  last bit left the wire. Senders don't receive their own frames, as on a real
  controller with self-reception off.
- **Measured:** frames, on-wire bits, busy time (bus load), contested
  arbitrations, frames that waited, the longest wait, the deepest queue.

Bit timing is checked three ways: the CRC against the published CRC-15/CAN
check value (`123456789` gives 0x059E); CRC and stuff count for 1,000 frames
against `tools/make_bit_vectors.py`, a separately written implementation; and
every random frame's length against the textbook worst case (Tindell and
Burns).

## The J1939 nodes

`sim::J1939Node` is the active counterpart of M1's passive `Reassembler`: a
node that takes part in the network.

| Function | Behaviour |
|---|---|
| Address claim (J1939-81) | Claims its preferred address at power-up, then waits 250 ms before sending anything else. If another node claims the same address with a lower NAME, it moves to a free address in 128–247 when arbitrary-address capable, or sends Cannot Claim (source 254) and goes silent. It defends its address against weaker claims and answers requests for Address Claimed |
| Requests | A request for a group the node has is answered: point to point when the request was addressed to it, otherwise to everyone. A request addressed to it for a group it lacks gets a negative acknowledgement |
| Sending more than 8 bytes | To everyone by BAM, one packet every 50 ms; to one node by RTS/CTS, waiting up to 1.25 s (T3) for each CTS and for the EndOfMsgAck, then aborting with reason 3 (timeout) |
| Receiving RTS/CTS | Grants up to 16 packets per CTS, grants the next batch when the last packet of the current one arrives, and acknowledges with EndOfMsgAck |

Each node runs M1's passive reassembler on its own input, so incoming
transfers are validated by the same hardened code.

## The truck

| Node | Address | Sends |
|---|---|---|
| Engine | 0x00 | EEC1 20 ms, EEC2 50 ms, LFE1 100 ms, EFL/P1 500 ms, ET1, AMB, HOURS, LFC, HRLFC, VEP1, DM1 every 1 s; vehicle ID on request |
| Transmission | 0x03 | ETC1 10 ms, ETC2 100 ms |
| Brakes | 0x0B | EBC1 100 ms |
| Instrument cluster | 0x17 | CCVS1 100 ms, VDHR and DD every 1 s |
| Tachograph | 0xEE | TCO1 50 ms, TD 1 s |
| Service tool | 0xF9 | Requests: who is on the bus (address claims), the vehicle ID point to point every minute, engine hours from everyone, a group the transmission lacks (to get a NACK), and trouble codes after the fault |
| Second service tool (`--conflict`) | 0xF9, then 0x80 | Powers up at 10 s asking for 0xF9; loses to the first tool's lower NAME and moves |

Rates follow the FMS-Standard where it defines them, which also matches the
real truck in `testdata/`. At 90 s two illustrative trouble codes become
active: DM1 grows to 10 bytes, so it goes by BAM from then on, and the amber
warning lamp comes on. NAME fields use an illustrative manufacturer code, and
the vehicle ID `1VNSL00SIM0000001` is obviously not real.

## The vehicle model

`sim::VehicleModel` is a 20-tonne truck with a 12-speed automated gearbox
(0.5 s shifts, no drive torque during a shift), a 2.85 final drive, 0.51 m
tyres, 2500 N·m and 330 kW limits, rolling and air resistance. The
200-second drive cycle:

| Time in cycle | What happens |
|---|---|
| 0–8 s | Parked, idling; parking brake released at 6 s |
| 8–70 s | Pulls away and shifts up through the gears towards a target of 60–85 km/h (a new random target every cycle) |
| 70–150 s | Cruise control at the target |
| 150–175 s | Brakes to a stop |
| 175–200 s | Stopped; parking brake set at 180 s |

Everything an ECU reports comes from that one state, and the sensors have
independent errors. The tachograph is calibrated to the real tyre radius. The
ABS unit converts with a radius 0.294 % larger, so its wheel-based speed
reads 0.294 % high, as on a real truck with worn tyres. Fuel comes from
engine power and a fixed specific consumption; temperatures warm towards
operating values.

It is a plausible model, not a validated one. Its job is traffic whose values
agree with each other (engine speed with gear and shaft speeds, two speed
sensors with each other, fuel and distance with their rates), because those
are the relationships an intrusion detector can check. M3 spoofs one of them
and measures whether the detector notices.

## Live on SocketCAN

`vn-sim --iface vcan0` runs the same simulation against the wall clock:

- every frame the simulated nodes complete is written to the interface at its
  simulated time;
- every frame arriving from the interface is injected into the simulated bus
  at the current time, where it arbitrates and every ECU sees it.

So a frame sent with `cansend` (or, in M3, by an attacker program) reaches the
simulated ECUs, and they answer on the interface. Frames vn-sim injects are
not written back, so nothing loops. `vn-record` writes an interface to a
candump log with the kernel's receive timestamps; `vn-replay` sends a log at
its original timing (or faster), against absolute deadlines so lateness does
not accumulate.

Neither the development sandbox nor a Mac can create a `vcan` interface, so
the live path is tested only in CI, on GitHub's Ubuntu runners
(`.github/workflows/ci.yml`, job `vcan`):

1. The live run must carry exactly the frames of the offline run with the same
   seed, as recorded by can-utils' `candump` and by `vn-record`.
2. A global request for the vehicle ID, injected with `cansend`, must be
   answered with the engine's BAM announcement `1CECFF00#20120003FFECFE00`.
3. A 4x replay with `vn-replay` must reproduce the log.

## Verification summary

| Check | Result |
|---|---|
| 68 tests, ASan + UBSan, GCC and Clang (adds bit timing, the simulator, the J1939 node, the encoder) | All pass |
| Same seed twice, ten simulated minutes | Byte-identical (also between GCC and Clang builds) |
| Cross-check against can-j1939, ten simulated minutes | 145,159 / 145,159 messages identical, including 510 BAM and 12 RTS/CTS transfers; 29 requests and address claims identical to the raw frames ([evidence](evidence/m2-crosscheck-can-j1939.md)) |
| Physics, 7 checks | All pass ([evidence](evidence/m2-physics.md)) |
| Planted bugs | 3 of 3 caught ([evidence](evidence/m2-planted-bugs.md)) |
| Fuzzing the active stack with injected frames | Clean ([evidence](evidence/m2-fuzz.txt)) |
| Live on vcan | Checked in CI only (see above) |

### Limits

- The physics checks can't catch a parameter at the wrong position: the
  simulator and the decoder share one table, so encoding and decoding would
  agree on the same mistake. Positions are checked against real traffic
  (M1's clock and rate checks, and a driving capture in M3).
- The simulated bus carries 18 standard groups. A real truck adds many
  proprietary ones (47 % load on the Turku truck against 13.7 % here), so
  timing-based detection will be easier on simulated traffic than on real.
- Error frames, bus-off and retransmission after errors are not modelled. On a healthy bus none of them occur. M3 models
  flooding through arbitration, which the simulator does model.
