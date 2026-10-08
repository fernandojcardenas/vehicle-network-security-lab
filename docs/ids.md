# Attacks and intrusion detection (M3)

```
 training window of one truck's traffic          test window (later traffic)
            │ decoded messages                          │ decoded messages
            ▼                                            ▼
      ids::Baseline  ──────────────────────────▶  ids::Detector  ──▶ alerts
   (per-source groups,                          (rules vs the baseline,
    per-(source,PGN) rates,                      one alert per finding)
    per-signal ranges & rates,
    address NAMEs)
```

The detector is **passive**: it reads the same decoded stream a logger sees and
never transmits. It makes no claim to stop an attack, only to notice one, which
is what a monitor on a vehicle bus does.

## What "normal" is learned

`ids::Baseline` is built from a stretch of one truck's own traffic. It records
only what a bus observer can see:

- which **source addresses** transmit, and the **NAME** behind each (from
  Address Claimed);
- for each **(source, PGN)**, the message count and the shortest and mean gap
  between messages;
- for each **signal (SPN)**, the value range and the fastest rate of change
  seen between consecutive samples.

Nothing is hard-coded per truck model. Two real trucks disagree on final-drive
ratio, on which sensors they populate, and on which proprietary groups they
carry, so the baseline is always learned from the capture in front of it.

## How a signal is judged

A learned value range only means something for a bounded signal that the
vehicle actively drives. `j1939::signal_class` sorts every SPN into three kinds,
and the detector treats each differently:

| Class | Examples | Check |
|---|---|---|
| Operational | wheel speed, engine/shaft speed, torque, pedal, pressures | value within the learned range (plus a margin); rate of change within the learned maximum (times a factor) |
| Accumulator | odometer, trip and total fuel, engine hours and revolutions | only ever increases, so a **decrease** is the anomaly (a rollback or a stale replay) |
| Slow | coolant/oil/ambient temperatures, fuel and oil level, voltages, the time-of-day clock, average fuel economy, the cruise setpoint | not range-checked: these drift past any training window, or are a driver's choice |

This classification is the single biggest reason the false-alarm rate on real
trucks is low. A naive range check over every signal raised 938 alerts on a
7-minute real drive (the engine warming up, the odometer advancing, the clock
ticking); judging each signal by its nature brought that to 10, all of them
genuine novel operational states.

## The rules

| Alert | Fires when |
|---|---|
| `unknown-source` | a message from an address not seen in training |
| `unexpected-pgn` | a known source sends a parameter group it never sent in training |
| `flood-rate` | a (source, PGN) gap is below a fraction of its learned minimum and under 1 ms |
| `value-out-of-range` | an operational signal is outside its learned range (plus a margin), or an accumulator went backwards |
| `impossible-jump` | an operational signal changes faster than the learned maximum rate times a factor |
| `transport-anomaly` | the transport layer reports a new sequence error, orphan packet, bad announcement, abort, malformed frame, or rejected session |
| `address-claim-conflict` | Address Claimed for a known address carries a different NAME than training |

Repeat alerts of the same (type, source, PGN, signal) within one second are
collapsed to one, so a flood is a single finding rather than thousands.
Thresholds (`DetectorConfig`) are multiples of what the baseline observed,
chosen so clean held-out traffic is nearly silent while the attacks are not.

## Attacks

`ids::inject_attack` (and the `vn-attack` tool) splice a labelled attack into a
recorded frame stream. Because the injected frames are the only difference
between a clean and an attacked log, the attack window is exact ground truth
for scoring, and the same attack runs on real captures and on simulated ones.

| Attack | What it injects | Caught by |
|---|---|---|
| Flood | a new address (0xAA) sending the highest-priority PGN every 0.5 ms | `unknown-source` |
| Spoof | extra vehicle-speed frames at a genuine source's address, false 200 km/h | `value-out-of-range`, `impossible-jump` |
| Replay | a 20-second stretch of earlier real traffic re-sent later | `flood-rate` (rate doubles), `impossible-jump`, `value-out-of-range` |
| Jump | one wheel-speed frame at an impossible 250 km/h | `value-out-of-range`, `impossible-jump` |
| Hijack | Address Claimed for a genuine address with a forged NAME | `address-claim-conflict`, or `unexpected-pgn` on a truck that sends no claims |

A real bus flood also starves lower-priority traffic through arbitration; the
simulator models that (M2), so a flood there raises bus load as well as the
alert.

## Evaluation

Scored two ways. `tools/evaluate_ids.py` runs the detector and reports, per
attack window, whether an alert fired inside it, and how many alerts fell
outside every window (false alarms).

- **Simulated (in CI, every push).** Five minutes of `vn-sim` traffic, each
  attack injected into the test region. All five detected; the clean run
  raises a bounded number of novelty alerts (asserted small), none inside an
  attack window. See [evidence](evidence/m3-ids-simulated.md).
- **Real trucks (offline, reproducible).** Two Colorado State University J1939
  drives, fetched by `tools/fetch_csu.py` (SHA-256 checked, never committed).
  On a 30-minute slice of the 2014 Kenworth T270, all five attacks detected
  with zero false alarms over 1280 s of held-out clean traffic; on the full
  4.2-hour drive, 5 clean alerts over 2.5 hours, all genuine novel operational
  states. See [evidence](evidence/m3-ids-real-truck.md).

## Limits

- **Range-learning needs representative training.** A signal that reaches a
  value the training window never saw is flagged, even when legitimate. On a
  single short accelerating drive this produces a few alerts; the detector is
  meant to be trained on a representative capture of the vehicle.
- **No per-frame source authentication.** CAN carries no sender identity, so
  spoofing from a genuine address is caught by content and timing, not by
  proof of origin. M4 adds authenticated messages.
- **The detector is passive.** It reports; it does not block. A gateway that
  acts on these alerts is M5.
- **Simulated attacks are cleaner than real ones.** The simulated bus carries
  18 standard groups; a real truck adds proprietary traffic and noise, so the
  real-truck evaluation is the one that matters for the false-alarm rate.
