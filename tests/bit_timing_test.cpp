#include <gtest/gtest.h>

#include <array>
#include <fstream>
#include <string>
#include <random>

#include "vnsl/can/bit_timing.hpp"

using namespace vnsl::can;

TEST(Crc15, MatchesTheCatalogueCheckValue) {
    // CRC-15/CAN (poly 0x4599, init 0, no reflection, no xor-out): check value for "123456789".
    const std::array<std::uint8_t, 9> text{'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    EXPECT_EQ(crc15_bytes(text), 0x059E);
}

TEST(FrameBits, UnstuffedLengthsAreExact) {
    Frame f;
    f.extended = true;
    f.id = 0x18FEF100;
    for (std::uint8_t dlc = 0; dlc <= 8; ++dlc) {
        f.dlc = dlc;
        const auto fb = frame_bits(f);
        EXPECT_EQ(fb.unstuffed, 54u + 8u * dlc);  // SOF..CRC of a 29-bit frame
        EXPECT_EQ(fb.fixed, 10u);
        EXPECT_EQ(fb.interframe, 3u);
    }
    f.extended = false;
    f.id = 0x123;
    f.dlc = 8;
    EXPECT_EQ(frame_bits(f).unstuffed, 34u + 64u);
}

TEST(FrameBits, StuffingStaysWithinTheTextbookBounds) {
    std::mt19937 rng(1);
    for (int i = 0; i < 20000; ++i) {
        Frame f;
        f.extended = (i % 2) == 0;
        f.id = f.extended ? (rng() & 0x1FFFFFFF) : (rng() & 0x7FF);
        f.dlc = static_cast<std::uint8_t>(rng() % 9);
        for (auto& b : f.data) b = static_cast<std::uint8_t>(rng());
        const auto fb = frame_bits(f);
        EXPECT_GE(fb.total(), (f.extended ? 67u : 47u) + 8u * f.dlc);
        EXPECT_LE(fb.total(), worst_case_bits(f.extended, f.dlc));
    }
}

TEST(FrameBits, MatchesAnIndependentImplementationOn1000Frames) {
    // testdata/can-bit-vectors.txt comes from tools/make_bit_vectors.py, a separate
    // implementation of the CRC and of bit stuffing.
    std::ifstream in(VNSL_TESTDATA_DIR "/can-bit-vectors.txt");
    std::string kind, id_hex, data_hex, crc_hex;
    std::size_t stuff = 0, n = 0;
    while (in >> kind >> id_hex >> data_hex >> crc_hex >> stuff) {
        Frame f;
        f.extended = kind == "x";
        f.id = static_cast<std::uint32_t>(std::stoul(id_hex, nullptr, 16));
        if (data_hex != "-") {
            f.dlc = static_cast<std::uint8_t>(data_hex.size() / 2);
            for (std::size_t i = 0; i < f.dlc; ++i)
                f.data[i] = static_cast<std::uint8_t>(std::stoul(data_hex.substr(2 * i, 2), nullptr, 16));
        }
        const auto fb = frame_bits(f);
        EXPECT_EQ(fb.crc, std::stoul(crc_hex, nullptr, 16)) << id_hex << " " << data_hex;
        EXPECT_EQ(fb.stuff, stuff) << id_hex << " " << data_hex;
        ++n;
    }
    EXPECT_EQ(n, 1000u);
}

TEST(FrameBits, AllZeroFrameStuffs19Bits) {
    // The first line of can-bit-vectors.txt, named here so a reader can see a concrete case:
    // the zero identifier, control field and data give long runs of dominant bits, and every
    // stuff bit starts a new run, so 19 bits are inserted (not one per five data bits).
    Frame f;
    f.extended = true;
    f.id = 0;
    f.dlc = 8;
    const auto fb = frame_bits(f);
    EXPECT_EQ(fb.stuff, 19u);
    EXPECT_EQ(fb.crc, 0x3DAF);
}

TEST(FrameBits, DurationAt250kbit) {
    Frame f;
    f.extended = true;
    f.id = 0x0CF00400;
    f.dlc = 8;
    f.data = {0xF0, 0x7D, 0x8C, 0xE0, 0x2E, 0x00, 0xFF, 0xFF};
    const auto bits = frame_bits(f).total();
    EXPECT_EQ(frame_duration_us(f, 250'000), bits * 4);  // 4 us per bit
}
