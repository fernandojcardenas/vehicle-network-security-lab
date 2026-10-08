# ADR 0001: A passive J1939 decoder written from public specifications

Date: 2026-10-08
Status: Accepted

## Context

The lab needs to read J1939 traffic before it can attack or defend it. Good
open-source J1939 stacks exist: the Linux kernel's own `can-j1939` socket
family, and the `can-j1939` Python package. Both are ECU stacks: they take part
in the network, claim an address and only reassemble transfers addressed to
themselves. The parameter definitions themselves (the SAE J1939 Digital Annex)
are a paid, copyrighted document.

## Decision

Write the decoder in C++20 as a passive listener, from public sources.

- **Passive**, because the later milestones (an intrusion detector, a
  gateway) have to see every transfer between every pair of nodes and must
  never transmit by accident. Transport-layer failures (timeouts, out-of-order
  packets, impossible announcements, replaced sessions) are counted, not just
  dropped, because they are detection features.
- **Own code**, because parsing untrusted bus traffic safely is the point of
  the project: every claimed size checked before use, bounded memory and
  sessions, fuzzing under sanitizers.
- **Public parameter definitions only**: the FMS-Standard interface
  description and public J1939-71 summaries. The table is small (92 SPNs) and
  is checked against real traffic where possible, rather than copied in bulk.
- **can-j1939 as an independent reference in CI**, with its acceptance filter
  opened so it hears every destination. Agreement with an implementation
  written by someone else is stronger evidence than tests written by the same
  author as the decoder.
- **Timeouts from frame timestamps**, not the wall clock, so replaying a log
  is deterministic at any speed.

## Consequences

- No kernel dependency for decoding: it runs on macOS, in a sandbox without
  CAN support, and on logs. The SocketCAN backend arrives in M2 as one more
  frame source.
- The parameter table covers fleet-management parameters, not the full annex.
  Proprietary groups (for example PGN 65450 on the test truck) are reassembled
  and passed through as raw bytes.
- Real traffic without connection-mode transfers leaves RTS/CTS checked only
  by unit tests until M2's simulated network produces some.
