# ADR 0004: SecOC-style message authentication with HMAC-SHA256

Date: 2026-10-09
Status: Accepted

## Context

J1939 has no sender authentication: any node can send any PGN, and the M3
detector can only notice a forged or replayed command after it is on the bus.
M4 adds prevention. The industry approach for CAN is AUTOSAR SecOC: a freshness
value plus a truncated MAC carried with each protected message. The choices are
the MAC primitive, how the authenticator travels on J1939, and whether to pull
in a crypto library.

## Decision

Implement SecOC-style authentication with a self-contained HMAC-SHA256, carried
in a companion CAN frame.

- **HMAC-SHA256, implemented here, truncated to 32 bits.** SHA-256 and HMAC are
  small, fully specified, and have public test vectors, so an own implementation
  can be validated with confidence (NIST digests, RFC 4231, and a per-push
  cross-check against Python's hashlib on random inputs). This keeps the lab
  with no external crypto dependency, matching the decoder's "own code, checked
  against a reference" discipline.
- **AUTOSAR SecOC structure.** The MAC covers data ID (PGN), source, a 4-byte
  freshness counter and the payload; the wire authenticator carries the low
  freshness byte and the truncated tag. This is the SecOC construction; only the
  MAC primitive differs from the AES-128-CMAC an OEM would typically pick, and
  that primitive is the single pluggable piece.
- **Companion frame.** An 8-byte J1939 frame is full, so the authenticator
  travels as one extra frame on a proprietary PGN. The cost is therefore exactly
  one frame per protected message, which is measurable and reported.
- **Freshness truncation with a reconstruction window.** Sending only the low
  counter byte saves bus space; the receiver reconstructs the full counter and,
  on failure, scans backward to distinguish a stale replay from a random bad tag.

## Consequences

- An attacker without the key cannot forge (bad-mac), alter (bad-mac), replay
  (stale) or inject unsigned (unauthenticated) a message on a protected PGN.
  This is demonstrated by running M3's own attacks against a protected log.
- Authentication costs one frame per message (~7-10% of bus bits for two
  high-rate PGNs); a real deployment protects a small safety-relevant set.
- Key management, the standardized J1939-91C wire format, and AES-CMAC are out
  of scope and documented as such in docs/secoc.md.
- Authentication is not encryption; the payload stays in clear, which matches
  the J1939 threat model (forged/replayed commands, not eavesdropping).
