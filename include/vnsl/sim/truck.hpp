#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "vnsl/sim/j1939_node.hpp"
#include "vnsl/sim/simulator.hpp"
#include "vnsl/sim/vehicle.hpp"

namespace vnsl::sim {

struct TruckConfig {
    std::uint64_t seed = 1;
    std::uint64_t start_epoch_s = 1791460800;  ///< 2026-10-08 12:00:00 UTC; the Time/Date ECU starts here
    bool address_conflict = false;  ///< a second service tool powers up at 10 s and claims 0xF9 too
    double fault_at_s = 90;         ///< two trouble codes become active (DM1 goes multi-packet)
};

/// A simulated heavy truck: the vehicle model plus six J1939 nodes on one bus.
///
/// | Node                | Address | Sends (period)                                                  |
/// |---------------------|---------|-----------------------------------------------------------------|
/// | Engine              | 0x00    | EEC1 20 ms, EEC2 50 ms, LFE1 100 ms, EFL/P1 500 ms, ET1, AMB, HOURS, LFC, HRLFC, VEP1, DM1 1 s; VI on request |
/// | Transmission        | 0x03    | ETC1 10 ms, ETC2 100 ms                                         |
/// | Brakes              | 0x0B    | EBC1 100 ms                                                     |
/// | Instrument cluster  | 0x17    | CCVS1 100 ms, VDHR 1 s, DD 1 s                                  |
/// | Tachograph          | 0xEE    | TCO1 50 ms, TD 1 s                                              |
/// | Service tool        | 0xF9    | requests: address claims, vehicle ID (point to point), engine hours, DM1 |
///
/// Rates follow the FMS-Standard where it defines them, which also matches the real truck in
/// testdata/. NAME fields are illustrative values, not registered ones.
class Truck {
public:
    Truck(Simulator& sim, const TruckConfig& cfg);
    ~Truck();
    Truck(const Truck&) = delete;
    Truck& operator=(const Truck&) = delete;
    Truck(Truck&&) = delete;
    Truck& operator=(Truck&&) = delete;

    [[nodiscard]] const VehicleModel& model() const;
    [[nodiscard]] std::vector<const J1939Node*> nodes() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace vnsl::sim
