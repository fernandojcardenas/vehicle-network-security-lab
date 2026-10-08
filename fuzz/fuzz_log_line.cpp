// Fuzzes both log-line parsers and checks that a parsed candump line formats back to a line
// that parses to the same frame.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "vnsl/can/frame.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    std::string iface;
    if (const auto f = vnsl::can::parse_candump_line(text, &iface)) {
        if (f->dlc > 8) std::abort();
        if (iface.find(' ') == std::string::npos && !iface.empty()) {
            const auto again = vnsl::can::parse_candump_line(vnsl::can::format_candump(*f, iface));
            if (!again || !(*again == *f)) std::abort();
        }
    }
    if (const auto f = vnsl::can::parse_turku_csv_line(text)) {
        if (f->dlc > 8 || f->id > 0x1FFFFFFFU) std::abort();
    }
    return 0;
}
