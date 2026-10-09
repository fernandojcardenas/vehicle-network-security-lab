# The hardened gateway (M5)

M3 watches a bus and M4 authenticates messages on it. M5 is the structural
defence: a gateway between two buses that forwards almost nothing. On a real
vehicle the untrusted things — the OBD/diagnostic port, a telematics or
infotainment unit — sit on one bus, and the powertrain (engine, transmission,
brakes) on another. A gateway between them decides what may cross.

## Default-deny forwarding

`vn-gateway` forwards a frame from one bus to the other only if a rule in its
policy allows it. Anything not matched is dropped. The policy is a few lines of
text:

```
B>A pgn=61444 rate=60     # engine controller may report outward, capped ~60 Hz
B>A pgn=65265 rate=12     # vehicle speed
# (no A>B rules: nothing from the diagnostic side reaches the powertrain)
```

Each rule names a direction, optionally a PGN and source address (`*` for any),
and an optional rate in Hz. The first matching rule decides. A rule's rate limit
is a per-stream token bucket, so even a message the policy allows cannot be used
to flood the far bus: a compromised engine ECU spraying vehicle-speed frames is
held to the cap.

The gateway is a pure function of the frames it sees and the policy, so the same
code runs two ways:

- **offline** over a candump log, for tests and analysis;
- **live** between two Linux SocketCAN interfaces (`--in vcan0 --out vcan1`),
  which is how it runs on the appliance and in CI.

## What it blocks, on real traffic

With the shipped `deploy/gateway.policy` (eight powertrain report groups
allowed B>A at their rates, nothing A>B), on the 2015 Kenworth T660 drive:

- Only the eight permitted PGNs cross; every other group on the bus is dropped
  as `deny-no-rule`.
- A burst flood of an allowed PGN is cut to the rule's rate (a 1000-frame,
  1 kHz burst of vehicle speed → 27 forwarded at a 12 Hz cap).
- 1000 command frames injected from the diagnostic side (A>B): none reach the
  powertrain bus, because the policy has no A>B rule.

See [the evidence](evidence/m5-gateway.md).

## Shipping it as a locked-down appliance

The `deploy/` directory turns the daemon into a minimal, hardened appliance.
Each piece is checked for what can be checked without a full OS build:

| Piece | What it is | Checked in CI by |
|---|---|---|
| `gateway.policy` | the default-deny forwarding policy | the unit tests and the live vcan run |
| `nftables.conf` | host firewall: every IP chain defaults to drop; only loopback and established connections accepted; the appliance serves nothing | `nft -c -f` |
| `selinux/vn_gateway.te` | an SELinux module confining the daemon to CAN sockets — no file writes, no IP sockets, no exec | `checkmodule` |
| `buildroot/` | a Buildroot external tree: kernel with CAN + SELinux, nftables, can-utils, the `vn-gateway` package, and an init script that raises the two buses and runs a forwarder each way | the image build + QEMU boot (offline; see `deploy/README.md`) |

The defence is layered: the forwarding policy bounds what crosses the buses;
nftables bounds the host's IP exposure to nothing; SELinux bounds what the
daemon can do if a malformed frame ever compromised it.

## What CI runs, and the one offline step

Every push, CI builds the gateway, raises two real `vcan` interfaces, streams
the simulated truck onto one, runs `vn-gateway` between them, injects an
attacker command from the diagnostic side, and checks (with
`tools/check_gateway.py`) that only policy-permitted PGNs reached the far bus
and the attacker's frame did not. It also validates the nftables ruleset and
compiles the SELinux module.

It does not build the Buildroot image: that fetches a toolchain and compiles a
kernel, tens of minutes and gigabytes, which does not belong on every push.
Building and booting the image under QEMU is the one documented offline step
(`deploy/README.md`).

## Limits

- **The image build is not in CI.** The configuration is real and the pieces
  are individually checked, but "boots under QEMU with SELinux enforcing" is
  validated by running it yourself, not on every push.
- **The policy is allowlist-only, by PGN/SA/rate and direction.** It does not
  inspect payloads. Payload-level rules, and running the M3 detector or M4
  verifier inline at the gateway, are natural extensions left for later.
- **Two unidirectional forwarders.** The appliance runs one `vn-gateway` per
  direction rather than one bidirectional process; simpler, and each enforces
  the same policy for its direction.
