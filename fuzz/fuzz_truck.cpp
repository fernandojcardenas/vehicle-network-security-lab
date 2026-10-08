// Injects arbitrary frames into a running simulated truck. The simulated ECUs take part in the
// network (they answer requests, defend addresses, run RTS/CTS as sender and receiver), so this
// fuzzes the active J1939 stack the way a hostile node on the bus would.
//
// Input layout, repeated: 1 byte time step (ms), 1 byte selector, 1 byte DLC, 8 data bytes.
// The selector picks the group (TP.CM, TP.DT, Request, Address Claimed, Acknowledgment, EEC1)
// and source/destination from addresses the truck uses, so the stack's states are reachable.
// Checks: no crash or undefined behaviour, and every node's address/claim state stays coherent.
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "vnsl/j1939/id.hpp"
#include "vnsl/sim/j1939_node.hpp"
#include "vnsl/sim/simulator.hpp"
#include "vnsl/sim/truck.hpp"

using namespace vnsl;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    sim::Simulator s(250'000);
    sim::TruckConfig cfg;
    cfg.address_conflict = (size % 2) == 1;
    sim::Truck truck(s, cfg);
    std::uint64_t t = 300'000;  // after the address claims
    s.run_until(t);
    static constexpr std::uint8_t kAddresses[] = {0x00, 0x03, 0x0B, 0x17, 0xEE, 0xF9, 0x80, 0xFF};
    static constexpr std::uint32_t kPgns[] = {j1939::kPgnTpConnection, j1939::kPgnTpDataTransfer, j1939::kPgnRequest,
                                              j1939::kPgnAddressClaimed, 0xE800, 61444};
    std::size_t frames = 0;
    for (std::size_t i = 0; i + 11 <= size && frames < 200; i += 11, ++frames) {
        t += static_cast<std::uint64_t>(data[i]) * 1000;
        const std::uint8_t sel = data[i + 1];
        can::Frame f;
        f.extended = true;
        f.id = j1939::encode_id(static_cast<std::uint8_t>(sel >> 5), kPgns[(sel & 0x7) % 6], kAddresses[(sel >> 3) & 0x7],
                                kAddresses[data[i + 2] >> 5]);
        f.dlc = static_cast<std::uint8_t>((data[i + 2] & 0x0F) % 9);
        for (std::size_t k = 0; k < 8; ++k) f.data[k] = data[i + 3 + k];
        s.run_until(t);
        s.inject(f);
    }
    s.run_until(t + 2'000'000);  // let every transfer finish or time out
    for (const auto* n : truck.nodes()) {
        const auto st = n->claim_state();
        if (st == sim::J1939Node::ClaimState::CannotClaim && n->address() != j1939::kNullAddress) std::abort();
        if (st == sim::J1939Node::ClaimState::Claimed && n->address() > 253) std::abort();
    }
    return 0;
}
