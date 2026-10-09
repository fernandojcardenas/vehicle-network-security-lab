# Deploying the gateway as a hardened appliance (M5)

`vn-gateway` is the enforcement point; this directory is how it ships as a locked-down
embedded-Linux appliance with two CAN interfaces.

## What runs where

- **`gateway.policy`** — the default-deny forwarding policy (see the file for the format).
- **`nftables.conf`** — host firewall: every IP chain defaults to drop; only loopback and
  established connections are accepted. The appliance offers no network services. Validated in
  CI with `nft -c -f`.
- **`selinux/vn_gateway.te`** — an SELinux type-enforcement module confining the daemon to CAN
  sockets and nothing else (no filesystem writes, no IP sockets, no exec). Compiled in CI with
  `checkmodule` + `semodule_package`.
- **`buildroot/`** — a Buildroot external tree that builds a minimal x86-64 image: the kernel
  with CAN and SELinux, nftables, can-utils, the `vn-gateway` package, and a rootfs overlay
  whose init script brings up the two buses and starts a forwarder in each direction.

## Building and booting the image (offline)

A full Buildroot build fetches a toolchain and compiles a kernel and userland; it takes tens
of minutes and gigabytes of disk, so it is **not** run in CI. To build and boot it yourself:

```
git clone https://github.com/buildroot/buildroot
cd buildroot
make BR2_EXTERNAL=/path/to/vehicle-network-security-lab/deploy/buildroot vnsl_qemu_defconfig
make                      # ~30-60 min the first time
qemu-system-x86_64 -m 512 -kernel output/images/bzImage \
    -drive file=output/images/rootfs.ext4,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0 enforcing=1" -nographic
```

On boot the appliance enforces SELinux, applies the nftables ruleset, creates `vcan0`/`vcan1`
and runs the gateway between them.

## What CI checks every push

CI does not build the image, but it checks everything about this directory that can be checked
without a 30-minute build: the gateway's filtering behaviour (unit tests and a live run on real
`vcan` interfaces), the nftables ruleset syntax, and that the SELinux policy compiles. The
image build and QEMU boot are the one documented offline step.
