# Roadmap

The goal is a security lab for heavy-vehicle networks: decode SAE J1939, run a
simulated vehicle bus, attack it, detect the attacks, authenticate messages and
harden an embedded-Linux gateway. No hardware: real truck traffic from a public
dataset, and a virtual CAN bus on Linux.

| Milestone | What it adds | Status |
|---|---|---|
| M1 J1939 decoder | Identifier split, transport protocol (BAM and RTS/CTS) as a passive listener with limits and timeouts, 92 public SPNs with J1939's reserved ranges, DM1, NAME, Time/Date; `vn-decode`; unit tests, real-capture tests, a cross-check against can-j1939, physical-consistency checks, three fuzz targets | Done ([decoder notes](j1939-decoder.md)): 15,640 messages identical to can-j1939 on real truck traffic; truck clock consistent to 0.42 s |
| M2 Virtual bus | Discrete-event CAN bus with exact bit timing and arbitration; six simulated J1939 nodes (address claim, requests, BAM, RTS/CTS) driven by a vehicle model; `vn-sim`, live on SocketCAN `vcan` with `vn-record` and `vn-replay`; CI on GitHub's Linux runners | Done ([simulator notes](simulator.md)): 145,159 messages identical to can-j1939 including 12 RTS/CTS transfers; 7 physics checks pass; deterministic |
| M3 Attacks and detection | `vn-attack` injects five labelled attacks (flood, spoof, replay, jump, hijack); `vn-ids` is a passive detector that learns each truck's normal behaviour and flags deviations with explainable rules | Done ([notes](ids.md)): all five detected on real Kenworth truck traffic with zero false alarms over 1280 s held-out; validated on two CSU trucks fetched by script |
| M4 Authenticated messages | SecOC-style authentication (`vn-secoc`): HMAC-SHA256 truncated tag + freshness counter in a companion frame; `vn-mac` + crypto cross-check against hashlib | Done ([notes](secoc.md)): genuine traffic verifies, M3's spoof/replay/forge all rejected, on real Kenworth traffic; ~7-10% bus overhead |
| M5 Hardened gateway | Buildroot embedded-Linux image booted in QEMU in CI; SELinux enforcing, nftables default-deny, a gateway that filters between two buses | Planned |
| M6 Threat model and polish | STRIDE threat model of the whole lab, a demo and a write-up | Planned |

Targets: built ahead of the original plan (October 2027 – February 2028), at
about 8 hours a week alongside study.
