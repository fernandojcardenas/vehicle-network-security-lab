# M4 message authentication (2026-10-09)

## Crypto, checked against independent implementations

Unit tests check SHA-256 against the NIST example digests and HMAC-SHA256 against the
RFC 4231 test vectors. In addition, every push cross-checks both against Python's hashlib
and hmac on random inputs:

    python3 tools/crosscheck_crypto.py ./build/vn-mac 3000
    checked 3000 random (key,message) pairs; 0 mismatches

## Protect and verify on simulated traffic

Two safety-relevant PGNs authenticated (CCVS1 vehicle speed 65265, EBC1 brakes 61441),
the companion authenticator carrying a 1-byte freshness value and a 32-bit truncated tag
in one extra CAN frame per message.

    vn-secoc protect clean.log --pgn 65265 --pgn 61441 --out prot.log
    vn-secoc verify prot.log --pgn 65265 --pgn 61441

Genuine traffic:

    vn-secoc: 2396 authenticator frames
      accepted 2396; rejected 0 (bad-mac 0, stale 0, malformed 0, unauthenticated 0)
      bandwidth overhead: 7.05299 % of bus bits are authenticator frames

## The M3 attacks, now rejected

The same spoof and replay that M3 detects are run against the protected log. SecOC rejects
them: a spoofed frame carries no valid tag, and a replayed frame's freshness is stale.

Spoof:

    vn-secoc: 2396 authenticator frames
      accepted 2396; rejected 400 (bad-mac 0, stale 0, malformed 0, unauthenticated 400)
      bandwidth overhead: 6.96291 % of bus bits are authenticator frames

Replay:

    vn-secoc: 2792 authenticator frames
      accepted 2396; rejected 396 (bad-mac 0, stale 396, malformed 0, unauthenticated 0)
      bandwidth overhead: 7.04671 % of bus bits are authenticator frames

A forged or altered tag, and the wrong key, are rejected as bad-mac (unit tests
SecOc.ForgedMacIsRejected, AlteredPayloadIsRejected, WrongKeyIsRejected).

## On real truck traffic (2015 Kenworth T660, fetched by tools/fetch_csu.py)

Genuine:

    vn-secoc: 16435 authenticator frames
      accepted 16435; rejected 0 (bad-mac 0, stale 0, malformed 0, unauthenticated 0)
      bandwidth overhead: 9.91043 % of bus bits are authenticator frames

Replay:

    vn-secoc: 17233 authenticator frames
      accepted 16435; rejected 798 (bad-mac 0, stale 798, malformed 0, unauthenticated 0)
      bandwidth overhead: 9.91149 % of bus bits are authenticator frames

## Cost

One extra CAN frame per authenticated message. On this traffic the authenticator frames
are about 7% (simulated) to 10% (T660) of all bus bits, the price of authenticating two
high-rate PGNs. Authenticating fewer or lower-rate PGNs costs proportionally less.
