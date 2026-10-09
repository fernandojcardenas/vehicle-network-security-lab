# Message authentication (M4)

M3 detects an attack after the fact. M4 stops one class of attack outright: an
attacker who does not hold the key cannot get a message accepted on a protected
PGN. `vn-secoc` adds SecOC-style authentication (AUTOSAR Secure Onboard
Communication) to chosen J1939 parameter groups.

```
 sender                                             receiver
 ──────                                             ────────
 genuine frame (PGN P, payload) ───────────────▶   hold as "awaiting"
 companion authenticator frame:                     recompute MAC with the key,
   data-PGN │ freshness-low │ truncated MAC ──────▶ check it and that freshness advanced
                                                     → accepted / bad-mac / stale / unauthenticated
```

## What is authenticated, and how it travels

For each protected message the sender computes

```
tag = HMAC-SHA256( key, PGN(3) ‖ source(1) ‖ freshness(4, big-endian) ‖ payload )
```

and transmits a **companion frame** on a proprietary PGN (0xFF77) carrying the
data PGN, the low byte of the freshness counter, and the first 4 bytes of the
tag — 7 bytes, one ordinary CAN frame. Including the PGN and source in the MAC
binds the tag to who sent what, so a valid tag cannot be lifted onto a
different message. The freshness counter is per PGN and never repeats, which is
what defeats replay.

Defaults (`secoc::Profile`): a 32-bit tag and one freshness byte on the wire.
Both are configurable; the unit tests also exercise a 64-bit tag with two
freshness bytes.

## Freshness truncation and anti-replay

Only the low byte of the counter is sent, to save bus space. The receiver keeps
the full counter and reconstructs the sender's value as the smallest counter
with those low bits that is greater than the last accepted one (within a
window), then checks the MAC against it. A replayed message carries stale low
bits whose reconstruction no longer matches the counter its tag was made with,
so it fails — and the verifier also scans backward to tell a genuine-but-old
replay (reported as `stale`) from a random bad tag (`bad-mac`).

## The crypto

SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104) are implemented here so the lab
has no external crypto dependency. They are checked three ways:

- SHA-256 against the NIST example digests; HMAC against the RFC 4231 vectors
  (unit tests).
- Streaming `update()` in odd-sized chunks against a one-shot hash.
- Every push, against Python's `hashlib`/`hmac` on 3000 random (key, message)
  pairs (`tools/crosscheck_crypto.py` driving the `vn-mac` helper).

AUTOSAR SecOC normally uses AES-128-CMAC. HMAC-SHA256 is used here because it
is straightforward to implement correctly and to validate against public
vectors; the construction (data ID, freshness, truncated MAC in a companion
secured PDU) is the same, and the MAC primitive is the one piece that would
change. See [ADR 0004](adr/0004-secoc-message-authentication.md).

## Closing the loop with M3

Running M3's attacks against a protected log shows the difference between
detecting and preventing:

| Attack | Verdict |
|---|---|
| Spoof (extra false-speed frames, no tag) | rejected, unauthenticated |
| Forge or alter a value under a captured tag | rejected, bad-mac |
| Replay an earlier authenticated message | rejected, stale |
| Wrong key | rejected, bad-mac |

A SecOC receiver accepts a message on a protected PGN only if a valid
authenticator arrives for it, so a spoofed frame that carries no tag is
rejected as `unauthenticated`, not silently passed.

## Cost

One extra CAN frame per authenticated message. Authenticating two high-rate
safety PGNs (vehicle speed at 100 ms, brakes at 100 ms) adds about 7% of bus
bits on the simulated truck and about 10% on the real Kenworth T660. The cost
scales with how many PGNs, and how fast, you choose to protect; a real
deployment authenticates a small set of safety-relevant groups, not everything.

## Limits

- **Key management is out of scope.** The key is passed in directly. A real
  system provisions and rotates per-ECU or per-group keys; that is its own
  large problem.
- **The companion-frame scheme is a lab simplification.** It pairs each
  authenticator with the preceding genuine frame of the same PGN and source.
  J1939-91C defines the standardized on-the-wire format; this lab predates
  needing that fidelity and documents the simplification rather than claiming
  the standard.
- **HMAC-SHA256, not AES-CMAC.** Functionally equivalent for this purpose; a
  production SecOC stack would match the OEM's chosen primitive.
- **Authentication is not confidentiality.** The payload is still in clear;
  SecOC authenticates, it does not encrypt. That is the J1939 threat model:
  the concern is forged and replayed commands, not eavesdropping.
