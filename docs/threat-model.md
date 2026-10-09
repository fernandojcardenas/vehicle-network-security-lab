# Threat model (M6)

This is the synthesis of the project: the earlier milestones each answer a specific
weakness of a heavy-vehicle CAN network, and this document sets them against a
structured STRIDE analysis so the coverage — and the gaps — are explicit.

It models a J1939 network like the one on the trucks whose real traffic this project
decodes and tests against (a 2015 Kenworth T660, a Renault T520), together with the
defensive stack built here: a passive decoder (M1), a deterministic bus and vehicle
simulator (M2), a learned intrusion detector (M3), SecOC-style message authentication
(M4), and a default-deny gateway with a hardened host (M5).

## System and trust boundaries

A modern vehicle does not have one flat bus. The parts an outsider can reach — the
OBD-II diagnostic port, an aftermarket telematics dongle, a cellular/telematics unit,
the infotainment head unit — sit on a body/diagnostic bus. The parts that move the
truck — engine, transmission, brakes — sit on a powertrain bus. A gateway between them
decides what may cross.

```
  attacker reach                         trust boundary                 safety-critical
 ┌───────────────────────────┐          (the gateway)          ┌───────────────────────────┐
 │  Body / diagnostic bus     │                                │  Powertrain bus            │
 │   OBD-II port              │      ┌──────────────────┐      │   engine (EEC1/EEC2)       │
 │   telematics / modem       │─────▶│  vn-gateway      │─────▶│   transmission (ETC)       │
 │   infotainment             │      │  default-deny    │      │   brakes / ABS (EBC)       │
 │                            │◀─────│  + rate-limit    │◀─────│   instrument cluster       │
 └───────────────────────────┘      └──────────────────┘      └───────────────────────────┘
        untrusted                     host: nftables                     trusted
                                      + SELinux confinement
```

**Assets** (in priority order): the integrity and availability of powertrain actuation
(brakes, engine, transmission); the integrity of the safety telemetry other ECUs act on
(wheel speed, engine speed); the availability of the bus itself; and the vehicle's
identifying/operational data (VIN, odometer, driver-hours, location via telematics).

**Attacker model.** The attacker can read and write the body/diagnostic bus — through a
malicious OBD dongle, a compromised telematics modem (remote), or a pivot from
infotainment — but does not begin with direct access to the powertrain bus. The gateway
is the boundary they must cross. Physical tampering with powertrain wiring, and
provisioning of the authentication keys, are assumed outside the attacker's reach
(see Assumptions).

## Why CAN/J1939 is exposed by design

The protocol gives an attacker on the bus a lot for free, and naming these is the point
of the model:

- **No source authentication.** A frame's 29-bit identifier carries a source address, but
  nothing binds a frame to the node that sent it. Any node can emit any identifier, and the
  J1939-81 address-claim procedure can be abused to take another ECU's address.
- **No integrity.** Payloads are unprotected; a modified value is indistinguishable from a
  genuine one.
- **No confidentiality.** CAN is a broadcast medium — every node receives every frame.
- **Priority arbitration.** The lowest identifier always wins the bus, so a node that sends
  high-priority frames quickly can starve everything else.
- **No accountability.** There is no built-in logging or non-repudiation.

## STRIDE analysis

Each row is the concrete threat, the milestone(s) that address it, and the residual risk
that is honestly left over.

### Spoofing — impersonating an ECU or forging a message's origin

- **Threat.** Forge engine/brake telemetry or a command frame from a source that should not
  send it; or claim another ECU's address (J1939-81) to displace it.
- **Mitigations.** **M3** flags `unknown-source` and `address-claim-conflict` against the
  per-truck baseline it learned. **M4** authenticates selected safety PGNs with an
  HMAC-SHA256 tag bound to the source and a freshness counter, so a spoofed safety message
  carries no valid tag and is rejected (`unauthenticated` / `bad-mac`). **M5** default-deny
  forwarding bounds which sources and PGNs can even reach the powertrain bus from the
  diagnostic side.
- **Residual.** Only the PGNs chosen for SecOC are cryptographically protected; other PGNs
  remain spoofable on the local bus and are covered only by detection. Key provisioning is
  out of scope.

### Tampering — altering a message in flight or at rest

- **Threat.** Inject modified values (false wheel speed, engine rpm, a brake request) that
  other ECUs act on.
- **Mitigations.** **M4**'s HMAC tag detects any change to an authenticated payload. **M3**
  flags `value-out-of-range` and `impossible-jump` for signals it has learned. **M5**
  prevents a modified frame from crossing from the diagnostic side into the powertrain bus.
- **Residual.** Non-protected PGNs are covered only by detection; the gateway is
  allowlist-only and does not inspect payload contents.

### Repudiation — denying that a message was sent

- **Threat.** A compromised or malicious node sends a harmful frame and there is no trail
  tying it to an origin.
- **Mitigations (partial).** **M4** binds each authenticated message to a source and a
  monotonic freshness value, giving message-origin evidence for protected PGNs. **M1/M2**'s
  recorder (`vn-record`) and the **M3** IDS alert stream provide an audit trail of what was
  seen and what fired.
- **Residual.** Logs are local and unsigned; full non-repudiation would need per-node keys
  and secure, tamper-evident logging. Out of scope, stated.

### Information disclosure — reading data off the bus

- **Threat.** A passive tap or a compromised low-trust node harvests the VIN (PGN 65260),
  odometer and driver-hours, and — through a telematics unit — location.
- **Mitigations.** This project is deliberately a *defensive-monitoring* effort, not a
  confidentiality one: SecOC authenticates but does **not** encrypt. What it does offer is
  **segmentation** — **M5** limits what of the powertrain bus is exposed to the less-trusted
  bus — and **host non-exposure**: the appliance's nftables ruleset defaults to drop so it
  serves nothing over IP, and the SELinux module keeps the daemon off the filesystem and off
  IP sockets. The decoder and every document deliberately avoid printing the VIN even though
  it is present in the capture.
- **Residual.** On a single shared bus, any node reads every frame — confidentiality is not a
  CAN property and is not claimed here.

### Denial of service — starving or disrupting the bus

- **Threat.** A babbling or flooding node wins arbitration and starves the powertrain bus; an
  address-claim storm; transport-protocol session exhaustion.
- **Mitigations.** **M3** detects `flood-rate` and transport anomalies. **M5** is the real
  containment: default-deny plus a per-rule token-bucket rate limit means a compromised
  diagnostic-side node cannot flood the powertrain bus, and even a permitted PGN is capped to
  its rule's rate. Every parser in the defensive path (decoder, IDS, gateway) is fuzzed under
  libFuzzer and built with ASan/UBSan, so a malformed frame does not crash the monitor.
- **Residual.** A node already on a single physical bus can still contend for arbitration on
  that bus; software cannot fully prevent on-bus DoS. Segmentation and rate-limiting bound the
  blast radius across the boundary; this is stated rather than overclaimed.

### Elevation of privilege — crossing from low trust to high

- **Threat.** (network) A low-trust node — infotainment, telematics, OBD dongle — gains
  control over the powertrain. (host) An attacker exploits the gateway daemon to run code or
  reach the host OS.
- **Mitigations.** (network) **M5** default-deny: the diagnostic side has no rule permitting a
  command to the powertrain, so it does not cross. (host) The **SELinux** module confines the
  daemon to CAN sockets — no file writes, no IP sockets, no `exec` — so a compromised daemon
  is boxed in; **nftables** defaults to drop; the C++ is compiled `-Werror` under ASan/UBSan
  in CI and the frame/parser paths are fuzzed to reduce memory-safety bugs that EoP relies on.
- **Residual.** A kernel or CAN-stack vulnerability, or a policy misconfiguration, is out of
  the daemon's control. The hardened image is built and booted under QEMU offline, not on
  every push (documented in `deploy/README.md`).

## Coverage matrix

| STRIDE | M1 decode | M2 sim | M3 detect | M4 authenticate | M5 contain/harden |
|---|:--:|:--:|:--:|:--:|:--:|
| Spoofing | · | · | ● detect | ● reject | ● bound |
| Tampering | · | · | ● detect | ● reject | ● bound |
| Repudiation | ○ log | ○ record | ○ log | ● origin+freshness | · |
| Information disclosure | (never prints VIN) | · | · | · (auth, not encryption) | ● segment + host non-exposure |
| Denial of service | ○ safe parse | · | ● detect | · | ● rate-limit + default-deny |
| Elevation of privilege | ○ safe parse | · | · | · | ● default-deny + SELinux/nftables |

● direct mitigation  ○ partial / supporting  · not addressed by that milestone

## Assumptions

1. The attacker reaches the body/diagnostic bus but not, initially, the powertrain bus — the
   gateway is the boundary they must cross.
2. Powertrain wiring is physically secure; a direct physical tap on the powertrain bus is out
   of scope for these software defenses (though M3 would still see the resulting anomalies).
3. SecOC keys are provisioned and stored securely; key management is out of scope.
4. The defensive host runs the shipped nftables and SELinux policy with SELinux enforcing.

## What is demonstrated, and where it is checked

`scripts/demo.sh` runs the whole story end to end on the deterministic simulator and
**asserts** each layer fires: the IDS detects a spoof (M3), SecOC rejects the spoof and a
replay (M4), and the gateway keeps a diagnostic-side command off the powertrain bus (M5).
The `demo` CI job runs it on every push, so the claims above are exercised, not asserted on
faith. Captured output: [evidence](evidence/m6-demo.md). Per-milestone evidence and the
engineering decisions behind each defense are in the other `docs/` files and ADRs 0001–0006.

## Limitations (consolidated)

- SecOC protects selected PGNs, not the whole bus, and authenticates without encrypting (no
  confidentiality).
- The gateway is allowlist-only by PGN / source / rate / direction; it does not inspect
  payloads.
- The IDS is a per-truck learned baseline plus explainable rules (no ML); an attack that
  stays inside the learned ranges can evade detection.
- On a single physical bus, disclosure and arbitration-level DoS are inherent CAN properties;
  the defenses bound cross-boundary impact rather than eliminating them.
- The hardened appliance image is validated by building and booting it under QEMU offline,
  not on every CI run.
