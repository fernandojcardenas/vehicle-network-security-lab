// Fuzzes the gateway policy parser and the forwarding decision. The parser must never crash on
// arbitrary text; the decision must never crash on arbitrary frames. Half the input seeds the
// policy text, half drives frames through whatever policy parsed.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "vnsl/can/frame.hpp"
#include "vnsl/gateway/gateway.hpp"
#include "vnsl/gateway/policy.hpp"

using namespace vnsl;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 2) return 0;
    const std::size_t split = 1 + (data[0] % size);
    const std::string_view text(reinterpret_cast<const char*>(data), std::min(split, size));
    std::string err;
    auto parsed = gateway::Policy::parse(text, &err);
    if (!parsed) return 0;
    gateway::Gateway gw(std::move(*parsed));
    for (std::size_t i = split; i + 6 <= size; i += 6) {
        can::Frame f;
        f.t_us = static_cast<std::uint64_t>(data[i]) * 1000;
        f.extended = true;
        f.id = (static_cast<std::uint32_t>(data[i + 1]) << 24 | static_cast<std::uint32_t>(data[i + 2]) << 16 |
                static_cast<std::uint32_t>(data[i + 3]) << 8 | data[i + 4]) & 0x1FFFFFFF;
        f.dlc = static_cast<std::uint8_t>(data[i + 5] % 9);
        gw.forward(f, (data[i + 5] & 0x80) ? gateway::Direction::AtoB : gateway::Direction::BtoA);
    }
    return 0;
}
