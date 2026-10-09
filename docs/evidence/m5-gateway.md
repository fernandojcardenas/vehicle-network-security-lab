# M5 hardened gateway (2026-10-09)

## Default-deny filtering on real truck traffic (2015 Kenworth T660)

Policy: deploy/gateway.policy (eight powertrain groups allowed B>A at their rates, nothing A>B).

    vn-gateway offline t660.log --policy deploy/gateway.policy --direction 'B>A'

    vn-gateway: seen 137309, forwarded 58417, denied 78892 (no-rule 62432, rate 16460)

Only the eight permitted PGNs cross; the ~62k deny-no-rule are groups not in the
allowlist, and the ~16k deny-rate are permitted groups trimmed to their caps.

## A command injected from the diagnostic side (A>B) is blocked

    1000 frames of PGN 0 (a command) from SA 0xF9, direction A>B
    vn-gateway: seen 1000, forwarded 0, denied 1000 (no-rule 1000, rate 0)
    forwarded to the powertrain bus: 0

## A flood of an allowed message is rate-capped

    2000 CCVS1 (vehicle speed) frames at 1 kHz; policy caps that group at 12 Hz
    vn-gateway: seen 2000, forwarded 27, denied 1973 (no-rule 0, rate 1973)

## Appliance configuration, checked in CI

- nftables host firewall validated: `nft -c -f deploy/nftables.conf`
- SELinux policy compiles: `checkmodule -M -m -o vn_gateway.mod deploy/selinux/vn_gateway.te`
- live default-deny on two vcan interfaces, checked by tools/check_gateway.py
- Buildroot image build + QEMU boot: documented offline step (deploy/README.md)
