# ADR 0003: A passive, per-truck learned intrusion detector with explainable rules

Date: 2026-10-08
Status: Accepted

## Context

M3 needs to detect attacks on a J1939 bus and to measure that detection
honestly. CAN has no sender authentication, so a monitor cannot prove who sent
a frame; it can only judge traffic against what is normal. Two design axes:
how "normal" is defined (fixed rules, a per-vehicle learned model, or a machine-
learning model), and what the detector is scored against.

## Decision

A passive detector that learns one truck's normal behaviour from a window of
its own traffic, then applies explainable rules against that baseline. No
machine-learning model.

- **Learned per truck, not hard-coded.** Real trucks differ in final-drive
  ratio, populated sensors and proprietary groups (confirmed on two Colorado
  State University captures), so fixed thresholds would not transfer. The
  baseline records source addresses and NAMEs, per-(source, PGN) rates, and
  per-signal ranges and rates of change.
- **Rules, not a trained model.** Every alert states why it fired, which a
  safety reviewer and an interviewer can both follow, and there is no training
  pipeline to carry in CI. (The user chose this over adding an ML model.)
- **Signals judged by their nature.** A learned range is meaningful only for a
  bounded operational signal. Accumulators (odometer, fuel used, hours) are
  checked for going backwards; slow/environmental signals and driver setpoints
  are not range-checked. This cut false alarms on a real drive from 938 to 10.
- **Attacks with ground-truth labels.** `inject_attack` splices labelled
  attack frames into any log, so the attack window is exact ground truth and
  the same five attacks (flood, spoof, replay, jump, hijack) score on real and
  simulated traffic alike.
- **Scored on real trucks, not only simulated.** The simulated bus is cleaner
  than a real one, so the real-truck false-alarm rate is the figure that
  counts. Real logs are fetched on demand with a checksum, never redistributed.

## Consequences

- The detector must be trained on a representative capture; a signal that only
  appears in the test window is flagged even when legitimate (a handful of
  alerts on a single short drive). This is documented, not hidden.
- Spoofing from a genuine address is caught by content and timing, not by
  origin. Authenticated messages are M4; a gateway that acts on alerts is M5.
- CI runs the full attack-and-detect cycle on deterministic simulated traffic
  every push; the real-truck validation is a documented, reproducible offline
  step with its results captured as evidence.
