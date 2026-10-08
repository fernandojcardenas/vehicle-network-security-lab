#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace vnsl::can {

/// One classic CAN data frame (not CAN FD) with a receive time.
struct Frame {
    std::uint64_t t_us = 0;      ///< receive time, microseconds since the Unix epoch
    std::uint32_t id = 0;        ///< 29-bit identifier if `extended`, else 11-bit
    bool extended = false;       ///< true for a 29-bit identifier (every J1939 frame)
    std::uint8_t dlc = 0;        ///< number of data bytes, 0..8
    std::array<std::uint8_t, 8> data{};

    [[nodiscard]] std::span<const std::uint8_t> payload() const { return {data.data(), dlc}; }
    friend bool operator==(const Frame&, const Frame&) = default;
};

/// Parses one line of a can-utils `candump -l` log:
///   `(1606390200.265340) can0 0CFE6CE6#FFFFFFFFFFFFFFFF`
/// Eight hex digits before `#` mean a 29-bit identifier, three mean 11-bit.
/// Remote frames, CAN FD frames (`##`) and anything malformed return nullopt.
/// `iface`, if given, receives the interface name.
std::optional<Frame> parse_candump_line(std::string_view line, std::string* iface = nullptr);

/// Formats a frame as a `candump -l` line (no trailing newline). Round-trips with parse_candump_line.
std::string format_candump(const Frame& frame, std::string_view iface);

/// Parses one data row of the University of Turku heavy-duty truck dataset:
///   `2020-11-26 11:30:00.265340;0xcfe6ce6;8;255;255;255;255;255;255;255;255`
/// The dataset does not state a time zone; the timestamp is read as UTC.
/// The header row, short rows and malformed fields return nullopt. A trailing '\r' is accepted.
std::optional<Frame> parse_turku_csv_line(std::string_view line);

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
constexpr std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
    y -= m <= 2 ? 1 : 0;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

}  // namespace vnsl::can
