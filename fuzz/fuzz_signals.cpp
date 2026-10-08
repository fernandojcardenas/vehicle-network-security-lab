// Decodes arbitrary payloads as every known parameter group plus DM1, Time/Date and NAME,
// and checks basic invariants of the results.
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "vnsl/j1939/signals.hpp"

using namespace vnsl::j1939;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::uint8_t> payload(data, size);
    for (const auto& def : spn_table()) {
        for (const auto& v : decode_signals(def.pgn, payload)) {
            if (v.status == Status::Valid && !std::isfinite(v.value)) std::abort();
            if (v.def->length < 32 && v.raw >= (1U << v.def->length)) std::abort();
        }
    }
    if (const auto dm = decode_dm1(payload)) {
        if (dm->dtcs.size() > size / 4) std::abort();
        for (const auto& d : dm->dtcs)
            if (d.spn > 0x7FFFF || d.fmi > 31 || d.occurrences > 127) std::abort();
    }
    if (const auto td = decode_time_date(payload)) {
        if (td->day < 1 || td->day > 31 || td->month < 1 || td->month > 12 || td->second >= 60) std::abort();
    }
    (void)decode_name(payload);
    return 0;
}
