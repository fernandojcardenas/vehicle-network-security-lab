# ADR 0006: A STRIDE threat model backed by an executable demo

Date: 2026-10-09
Status: Accepted

## Context

M1–M5 each answer a specific weakness of a heavy-vehicle CAN network, but the
project had no single document that set the defences against a structured list
of threats and said, plainly, what is covered and what is not. M6 is that
synthesis. The questions: what framing to use, and how to keep a threat model
from becoming a page of claims no one checks.

## Decision

Use **STRIDE** as the framing, and back the model with an **executable demo that
CI runs**, not prose alone.

- **STRIDE per threat category.** For each of Spoofing, Tampering, Repudiation,
  Information disclosure, Denial of service and Elevation of privilege, the model
  names the concrete J1939/CAN weakness, the milestone(s) that mitigate it, and
  the residual risk. STRIDE is well understood by the security audience this
  portfolio is for and maps cleanly onto a message bus.
- **Attacker model first.** The model fixes an attacker who reaches the
  body/diagnostic bus (malicious dongle, telematics, infotainment pivot) but not
  the powertrain bus directly — the gateway is the boundary. This keeps the
  analysis concrete instead of hand-waving at "an attacker".
- **An executable, asserted demo.** `scripts/demo.sh` runs detect → authenticate
  → contain end to end on the deterministic simulator and exits non-zero if any
  layer fails to fire. A `demo` CI job runs it every push. This matches the
  project's rule that every claim is backed by a real run: the threat model's
  "M3 detects, M4 rejects, M5 contains" is exercised, not asserted on faith.
- **Honest residual risk.** Every STRIDE row ends with what is left over
  (unprotected PGNs, no payload inspection, no confidentiality, on-bus DoS on a
  single physical bus). Overclaiming coverage would be the worst outcome for a
  security document.

## Consequences

- The project now reads as one argument: the attacks are real CAN weaknesses, and
  each milestone addresses named STRIDE categories, with gaps stated.
- The demo adds a 9th-style CI job but no new runtime dependency — it composes the
  existing binaries on the simulator, so it is deterministic and fast.
- The model is deliberately not a pen-test report: it reasons about the design, and
  points to the per-milestone evidence and ADRs for the engineering detail.
