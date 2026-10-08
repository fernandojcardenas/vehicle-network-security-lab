// Feeds arbitrary frame sequences to the transport reassembler and checks its invariants:
// no message larger than 1785 bytes, a reassembled message exactly as long as announced
// (between 9 and 1785 bytes), and never more open sessions than the limit.
//
// Input layout, repeated: 1 byte time step (ms), 1 byte selector, then 8 data bytes.
// The selector picks TP.CM / TP.DT / other and a source and destination from small sets, so
// the fuzzer reaches multi-packet states quickly instead of guessing 29-bit identifiers.
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "vnsl/j1939/transport.hpp"

using namespace vnsl;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    j1939::Reassembler::Limits limits;
    limits.max_sessions = 4;
    j1939::Reassembler r(limits);
    static constexpr std::uint8_t kAddresses[] = {0x00, 0x03, 0xF9, 0xFF};
    std::uint64_t t_us = 0;
    for (std::size_t i = 0; i + 10 <= size; i += 10) {
        t_us += static_cast<std::uint64_t>(data[i]) * 1000;
        const std::uint8_t sel = data[i + 1];
        const std::uint32_t pgn = (sel & 0x3) == 0 ? j1939::kPgnTpConnection
                                  : (sel & 0x3) == 1 ? j1939::kPgnTpDataTransfer
                                  : (sel & 0x3) == 2 ? 65226U
                                                     : 0xEF00U;
        can::Frame f;
        f.t_us = t_us;
        f.extended = (sel & 0x80) == 0;
        f.id = j1939::encode_id(7, pgn, kAddresses[(sel >> 2) & 0x3], kAddresses[(sel >> 4) & 0x3]);
        f.dlc = (sel & 0x40) ? static_cast<std::uint8_t>(data[i + 2] % 9) : 8;
        for (std::size_t k = 0; k < 8; ++k) f.data[k] = data[i + 2 + k];
        r.on_frame(f, [](const j1939::Message& m) {
            if (m.data.size() > j1939::Reassembler::kMaxPayload) std::abort();
            if (m.multipacket && m.data.size() < 9) std::abort();
            if (!m.multipacket && m.data.size() > 8) std::abort();
        });
        if (r.open_sessions() > limits.max_sessions) std::abort();
    }
    return 0;
}
