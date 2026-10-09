# ADR 0005: A default-deny CAN gateway, shipped as a hardened appliance

Date: 2026-10-09
Status: Accepted

## Context

M3 detects attacks and M4 authenticates individual messages, but neither stops
an untrusted device on one bus from reaching the powertrain on another. Real
vehicles segment their networks and put a gateway between segments. M5 builds
that gateway and the appliance it runs on. The open questions: what the
forwarding model should be, and how much of the "hardened embedded Linux in
QEMU" to actually build versus configure, given that a full Buildroot image
build takes tens of minutes and gigabytes.

## Decision

A default-deny forwarding gateway, plus host hardening delivered as real,
individually-checked configuration with the full image build documented as an
offline step.

- **Default-deny, allowlist policy.** A frame crosses only if a rule permits it
  by direction, PGN and source; everything else is dropped. This is the safe
  default for a security boundary: you enumerate what is allowed, not what is
  forbidden.
- **Per-rule rate limiting.** Each rule carries an optional token-bucket rate,
  so an allowed-but-flooded message still cannot saturate the far bus. This is
  the gateway's answer to the flood M3 only detects.
- **Pure policy, offline == live.** The gateway is a function of frames and
  policy, so the same binary runs over a log (tested, deterministic) and live
  between two `vcan` interfaces (exercised in CI). No separate "real" path to
  drift.
- **Hardening as checked config, image build offline.** The nftables ruleset
  (`nft -c`) and the SELinux module (`checkmodule`) are validated on every push;
  the Buildroot tree is real and reviewable; the 30-minute image build and QEMU
  boot are a documented offline step, not a CI job. Claiming "boots in CI" when
  it does not would violate the project's rule that every claim is backed by a
  real run.

## Consequences

- The three defences layer: the policy bounds the buses, nftables bounds the
  host's IP surface to nothing, SELinux bounds the daemon if it is ever
  compromised.
- The policy is allowlist-only (PGN/SA/rate/direction), not payload-aware, and
  does not run the M3 detector or M4 verifier inline; those are documented
  extensions.
- "Hardened image boots under QEMU with SELinux enforcing" is verified by
  building it offline, not on every push — an honest boundary, stated in
  docs/gateway.md and deploy/README.md.
