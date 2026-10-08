#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "vnsl/can/frame.hpp"

namespace vnsl::can {

/// CRC-15/CAN over a bit sequence (polynomial 0x4599, initial value 0), as the CAN
/// controller computes it from start-of-frame through the last data bit.
std::uint16_t crc15_bits(std::span<const std::uint8_t> bits);

/// CRC-15/CAN over whole bytes, most significant bit first. Exists so the CRC can be checked
/// against the published catalogue value (CRC-15/CAN of "123456789" is 0x059E).
std::uint16_t crc15_bytes(std::span<const std::uint8_t> bytes);

/// The breakdown of one classic CAN data frame on the wire.
struct FrameBits {
    std::size_t unstuffed = 0;  ///< SOF through CRC, before stuffing (the stuffed region)
    std::size_t stuff = 0;      ///< stuff bits the controller inserts in that region
    std::size_t fixed = 0;      ///< CRC delimiter, ACK slot, ACK delimiter, 7-bit end of frame
    std::size_t interframe = 3; ///< intermission before the next frame may start
    std::uint16_t crc = 0;

    /// Bits the frame occupies the bus for, intermission included.
    [[nodiscard]] std::size_t total() const { return unstuffed + stuff + fixed + interframe; }
};

/// Builds the frame's real bit sequence (identifier, control field, data, CRC) and counts the
/// stuff bits exactly: after five equal bits the transmitter inserts one of the opposite value,
/// and that stuff bit counts towards the next run. Works for 11-bit and 29-bit data frames.
FrameBits frame_bits(const Frame& frame);

/// Time on the bus, in microseconds (rounded up), at `bitrate` bits per second.
std::uint64_t frame_duration_us(const Frame& frame, std::uint32_t bitrate);

/// The textbook worst case (Tindell and Burns): 8n + 67 + floor((54 + 8n - 1) / 4) bits for a
/// 29-bit frame with n data bytes, intermission included; 8n + 47 + floor((34 + 8n - 1) / 4)
/// for an 11-bit one. Used as an upper bound in tests.
std::size_t worst_case_bits(bool extended, std::size_t dlc);

}  // namespace vnsl::can
