#include "vnsl/can/bit_timing.hpp"

#include <array>
#include <vector>

namespace vnsl::can {
namespace {

constexpr std::uint16_t kPoly = 0x4599;

void push_bits(std::vector<std::uint8_t>& out, std::uint32_t value, unsigned count) {
    for (unsigned i = count; i-- > 0;) out.push_back(static_cast<std::uint8_t>((value >> i) & 1U));
}

}  // namespace

std::uint16_t crc15_bits(std::span<const std::uint8_t> bits) {
    std::uint16_t crc = 0;
    for (const auto b : bits) {
        const bool top = ((crc >> 14) & 1U) != (b & 1U);
        crc = static_cast<std::uint16_t>((crc << 1) & 0x7FFF);
        if (top) crc ^= kPoly;
    }
    return crc;
}

std::uint16_t crc15_bytes(std::span<const std::uint8_t> bytes) {
    std::vector<std::uint8_t> bits;
    bits.reserve(bytes.size() * 8);
    for (const auto byte : bytes) push_bits(bits, byte, 8);
    return crc15_bits(bits);
}

FrameBits frame_bits(const Frame& frame) {
    std::vector<std::uint8_t> bits;
    bits.reserve(128);
    bits.push_back(0);  // start of frame (dominant)
    const unsigned dlc = frame.dlc > 8 ? 8U : frame.dlc;
    if (frame.extended) {
        push_bits(bits, (frame.id >> 18) & 0x7FF, 11);  // base identifier
        bits.push_back(1);                             // SRR (recessive)
        bits.push_back(1);                             // IDE: extended format
        push_bits(bits, frame.id & 0x3FFFF, 18);       // identifier extension
        bits.push_back(0);                             // RTR: data frame
        bits.push_back(0);                             // r1
        bits.push_back(0);                             // r0
    } else {
        push_bits(bits, frame.id & 0x7FF, 11);
        bits.push_back(0);  // RTR
        bits.push_back(0);  // IDE: standard format
        bits.push_back(0);  // r0
    }
    push_bits(bits, dlc, 4);
    for (unsigned i = 0; i < dlc; ++i) push_bits(bits, frame.data[i], 8);

    FrameBits fb;
    fb.crc = crc15_bits(bits);
    push_bits(bits, fb.crc, 15);
    fb.unstuffed = bits.size();

    // Bit stuffing over SOF..CRC. A stuff bit is part of the stream, so it starts a new run.
    std::uint8_t last = 2;
    unsigned run = 0;
    for (const auto b : bits) {
        if (b == last) {
            ++run;
        } else {
            last = b;
            run = 1;
        }
        if (run == 5) {
            ++fb.stuff;
            last = static_cast<std::uint8_t>(1 - b);
            run = 1;
        }
    }
    fb.fixed = 1 + 1 + 1 + 7;  // CRC delimiter, ACK slot, ACK delimiter, end of frame
    return fb;
}

std::uint64_t frame_duration_us(const Frame& frame, std::uint32_t bitrate) {
    if (bitrate == 0) return 0;
    const std::uint64_t bits = frame_bits(frame).total();
    return (bits * 1'000'000ULL + bitrate - 1) / bitrate;
}

std::size_t worst_case_bits(bool extended, std::size_t dlc) {
    const std::size_t n = dlc > 8 ? 8 : dlc;
    if (extended) return 8 * n + 67 + (54 + 8 * n - 1) / 4;
    return 8 * n + 47 + (34 + 8 * n - 1) / 4;
}

}  // namespace vnsl::can
