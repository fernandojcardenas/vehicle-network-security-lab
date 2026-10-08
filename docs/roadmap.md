# Roadmap

The goal is a security lab for heavy-vehicle networks: decode SAE J1939, run a
simulated vehicle bus, attack it, detect the attacks, authenticate messages and
harden an embedded-Linux gateway. No hardware: real truck traffic from a public
dataset, and a virtual CAN bus on Linux.

| Milestone | What it adds | Status |
|---|---|---|
| M1 J1939 decoder | Identifier split, transport protocol (BAM and RTS/CTS) as a passive listener with limits and timeouts, 92 public SPNs with J1939's reserved ranges, DM1, NAME, Time/Date; `vn-decode`; unit tests, real-capture tests, a cross-check against can-j1939, physical-consistency checks, three fuzz targets | Done ([decoder notes](j1939-decoder.md)): 15,640 messages identical to can-j1939 on real truck traffic; truck clock consistent to 0.42 s |
| M2 Virtual bus | SocketCAN backend on `vcan`; a simulated ECU network (engine, transmission, brakes, gateway) with address claim; candump record and replay; CI on GitHub's Linux runners (the development sandbox has no CAN in its kernel) | Planned |
| M3 Attacks and detection | Spoofing, flooding, replay and address-claim hijack on the simulated bus; an intrusion detector using timing, content and transport-layer counters; detection and false-alarm rates measured on real traffic | Planned. Needs a longer real capture than the 20 s slice in M1 (see [data sources](data-sources.md)) |
| M4 Authenticated messages | A truncated MAC plus a freshness counter in the style of AUTOSAR SecOC; bandwidth and latency cost measured on the simulated bus | Planned |
| M5 Hardened gateway | Buildroot embedded-Linux image booted in QEMU in CI; SELinux enforcing, nftables default-deny, a gateway that filters between two buses | Planned |
| M6 Threat model and polish | STRIDE threat model of the whole lab, a demo and a write-up | Planned |

Targets: built ahead of the original plan (October 2027 – February 2028), at
about 8 hours a week alongside study.
