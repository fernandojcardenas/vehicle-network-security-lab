#include <gtest/gtest.h>

#include <array>
#include <cmath>
#include <set>

#include "vnsl/j1939/signals.hpp"

using namespace vnsl::j1939;

namespace {
const SignalValue* find(const std::vector<SignalValue>& v, std::uint32_t spn) {
    for (const auto& s : v)
        if (s.def->spn == spn) return &s;
    return nullptr;
}
}  // namespace

TEST(Signals, TableIsConsistent) {
    EXPECT_EQ(spn_table().size(), 92u);  // the README states this number
    std::set<std::uint32_t> seen;
    std::set<std::uint32_t> groups;
    for (const auto& d : spn_table()) {
        EXPECT_TRUE(seen.insert(d.spn).second) << "duplicate SPN " << d.spn;
        EXPECT_GE(d.length, 1);
        EXPECT_LE(d.length, 32);
        // Every parameter fits in a single 8-byte frame for these groups.
        EXPECT_LE(d.start_bit + d.length, 64) << d.spn;
        EXPECT_FALSE(pgn_name(d.pgn).empty()) << d.pgn;
        groups.insert(d.pgn);
    }
    EXPECT_EQ(groups.size(), 18u);
    // Parameters of one group never overlap.
    for (const auto& a : spn_table())
        for (const auto& b : spn_table())
            if (&a != &b && a.pgn == b.pgn) {
                const bool disjoint = a.start_bit + a.length <= b.start_bit || b.start_bit + b.length <= a.start_bit;
                EXPECT_TRUE(disjoint) << a.spn << " overlaps " << b.spn;
            }
}

TEST(Signals, ExtractsLittleEndianAndSubByteFields) {
    const std::array<std::uint8_t, 8> d{0b1110'0100, 0x34, 0x12, 0, 0, 0, 0, 0xAB};
    EXPECT_EQ(extract_bits(d, 0, 2), 0u);
    EXPECT_EQ(extract_bits(d, 2, 2), 1u);
    EXPECT_EQ(extract_bits(d, 5, 3), 7u);
    EXPECT_EQ(extract_bits(d, 8, 16), 0x1234u);
    EXPECT_EQ(extract_bits(d, 56, 8), 0xABu);
    EXPECT_EQ(extract_bits(d, 4, 8), 0x4Eu);  // straddles bytes 1 and 2
    EXPECT_EQ(extract_bits(d, 32, 32), 0xAB000000u);
    EXPECT_FALSE(extract_bits(d, 57, 8));
    EXPECT_FALSE(extract_bits(d, 0, 33));
    EXPECT_FALSE(extract_bits(d, 0, 0));
}

TEST(Signals, ClassifiesTheReservedRanges) {
    EXPECT_EQ(classify(250, 8, false), Status::Valid);
    EXPECT_EQ(classify(251, 8, false), Status::Reserved);
    EXPECT_EQ(classify(254, 8, false), Status::Error);
    EXPECT_EQ(classify(255, 8, false), Status::NotAvailable);
    EXPECT_EQ(classify(0xFAFF, 16, false), Status::Valid);
    EXPECT_EQ(classify(0xFB00, 16, false), Status::Reserved);
    EXPECT_EQ(classify(0xFE12, 16, false), Status::Error);
    EXPECT_EQ(classify(0xFF00, 16, false), Status::NotAvailable);
    EXPECT_EQ(classify(0xFAFFFFFF, 32, false), Status::Valid);
    EXPECT_EQ(classify(0xFE000000, 32, false), Status::Error);
    EXPECT_EQ(classify(0xFFFFFFFF, 32, false), Status::NotAvailable);
    EXPECT_EQ(classify(0, 2, true), Status::Valid);
    EXPECT_EQ(classify(1, 2, true), Status::Valid);
    EXPECT_EQ(classify(2, 2, true), Status::Error);
    EXPECT_EQ(classify(3, 2, true), Status::NotAvailable);
    EXPECT_EQ(classify(0xE, 4, true), Status::Error);
    EXPECT_EQ(classify(0xF, 4, true), Status::NotAvailable);
    EXPECT_EQ(classify(0, 1, true), Status::Valid);
    EXPECT_EQ(classify(1, 1, true), Status::NotAvailable);
}

TEST(Signals, DecodesEec1EngineSpeed) {
    // 1500 rpm = 12000 counts of 0.125 rpm = 0x2EE0 in bytes 4-5.
    const std::array<std::uint8_t, 8> d{0xF0, 0x7D, 0x8C, 0xE0, 0x2E, 0x00, 0xFF, 0xFF};
    const auto v = decode_signals(61444, d);
    const auto* speed = find(v, 190);
    ASSERT_NE(speed, nullptr);
    EXPECT_EQ(speed->status, Status::Valid);
    EXPECT_DOUBLE_EQ(speed->value, 1500.0);
    EXPECT_DOUBLE_EQ(find(v, 513)->value, 15.0);  // 0x8C = 140 - 125
    EXPECT_DOUBLE_EQ(find(v, 512)->value, 0.0);   // 0x7D = 125 - 125
    EXPECT_EQ(find(v, 2432)->status, Status::NotAvailable);
    EXPECT_EQ(find(v, 1675)->status, Status::NotAvailable);  // 0xF in bits 1-4 of byte 7
}

TEST(Signals, DecodesCcvsWheelSpeedAndSwitches) {
    // 80.5 km/h = 20608/256 -> 0x5080; brake switch pressed (01 in bits 5-6 of byte 4).
    const std::array<std::uint8_t, 8> d{0xFF, 0x80, 0x50, 0b1101'1111, 0xFF, 0xFF, 0xFF, 0xFF};
    const auto v = decode_signals(65265, d);
    EXPECT_DOUBLE_EQ(find(v, 84)->value, 80.5);
    EXPECT_EQ(find(v, 597)->raw, 1u);
    EXPECT_EQ(find(v, 597)->status, Status::Valid);
    EXPECT_EQ(find(v, 598)->status, Status::NotAvailable);
}

TEST(Signals, ShortPayloadGivesMissing) {
    const std::array<std::uint8_t, 2> d{0x10, 0x20};
    const auto v = decode_signals(65265, d);
    EXPECT_EQ(find(v, 84)->status, Status::Missing);
    EXPECT_EQ(find(v, 69)->status, Status::Valid);
}

TEST(Signals, UnknownPgnDecodesNothing) {
    const std::array<std::uint8_t, 8> d{};
    EXPECT_TRUE(decode_signals(0x1FF5C, d).empty());
}

TEST(Dm1, DecodesLampsAndCodes) {
    // MIL on, amber on; DTC SPN 100 (oil pressure) FMI 1, 3 occurrences; DTC SPN 0x7FFFF FMI 31.
    const std::array<std::uint8_t, 10> d{0b0100'0100, 0xFF, 100, 0, 1, 3, 0xFF, 0xFF, 0xFF, 0x7F};
    const auto dm = decode_dm1(d);
    ASSERT_TRUE(dm);
    EXPECT_EQ(dm->malfunction_lamp, 1);
    EXPECT_EQ(dm->amber_warning_lamp, 1);
    EXPECT_EQ(dm->red_stop_lamp, 0);
    ASSERT_EQ(dm->dtcs.size(), 2u);
    EXPECT_EQ(dm->dtcs[0], (Dtc{100, 1, 3, false}));
    EXPECT_EQ(dm->dtcs[1].spn, 0x7FFFFu);
    EXPECT_EQ(dm->dtcs[1].fmi, 31);
}

TEST(Dm1, NoActiveCodesAndPadding) {
    const std::array<std::uint8_t, 8> d{0x00, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF};
    const auto dm = decode_dm1(d);
    ASSERT_TRUE(dm);
    EXPECT_TRUE(dm->dtcs.empty());
}

TEST(Dm1, RejectsPartialCodes) {
    const std::array<std::uint8_t, 9> d{0, 0xFF, 1, 2, 3, 4, 5, 6, 7};
    EXPECT_FALSE(decode_dm1(d));
    const std::array<std::uint8_t, 4> s{0, 0, 0, 0};
    EXPECT_FALSE(decode_dm1(s));
}

TEST(Name, DecodesEveryField) {
    // Built field by field so the expected values are independent of the decoder.
    const std::uint64_t raw = (1ULL << 63) | (0ULL << 60) | (5ULL << 56) | (0x11ULL << 49) | (0ULL << 48) |
                              (0x00ULL << 40) | (3ULL << 35) | (2ULL << 32) | (0x123ULL << 21) | 0x1ABCDEULL;
    std::array<std::uint8_t, 8> d{};
    for (std::size_t i = 0; i < 8; ++i) d[i] = static_cast<std::uint8_t>(raw >> (8 * i));
    const auto n = decode_name(d);
    ASSERT_TRUE(n);
    EXPECT_EQ(n->raw, raw);
    EXPECT_EQ(n->identity_number, 0x1ABCDEu);
    EXPECT_EQ(n->manufacturer_code, 0x123);
    EXPECT_EQ(n->ecu_instance, 2);
    EXPECT_EQ(n->function_instance, 3);
    EXPECT_EQ(n->function, 0);
    EXPECT_EQ(n->vehicle_system, 0x11);
    EXPECT_EQ(n->vehicle_system_instance, 5);
    EXPECT_EQ(n->industry_group, 0);
    EXPECT_TRUE(n->arbitrary_address_capable);
    const std::array<std::uint8_t, 7> s{};
    EXPECT_FALSE(decode_name(s));
}

TEST(TimeDate, DayCountsQuarterDays) {
    std::array<std::uint8_t, 8> d{0, 0, 0, 1, 1, 35, 125, 127};  // raw day 1 = the 1st
    auto td = decode_time_date(d);
    ASSERT_TRUE(td);
    EXPECT_EQ(td->day, 1);
    EXPECT_EQ(td->year, 2020);
    EXPECT_EQ(td->local_offset_minutes, 120);  // +2 h, +0 min
    d[4] = 4;
    EXPECT_EQ(decode_time_date(d)->day, 1);
    d[4] = 5;
    EXPECT_EQ(decode_time_date(d)->day, 2);
    d[4] = 124;
    EXPECT_EQ(decode_time_date(d)->day, 31);
}

TEST(TimeDate, RejectsNullErrorAndOutOfRange) {
    const std::array<std::uint8_t, 6> ok{0, 0, 0, 1, 1, 35};
    EXPECT_TRUE(decode_time_date(ok));
    for (std::size_t field = 0; field < 6; ++field) {
        auto bad = ok;
        bad[field] = 0xFE;  // error indicator
        EXPECT_FALSE(decode_time_date(bad)) << field;
    }
    auto day0 = ok;
    day0[4] = 0;
    EXPECT_FALSE(decode_time_date(day0));
    auto month13 = ok;
    month13[3] = 13;
    EXPECT_FALSE(decode_time_date(month13));
    auto minute60 = ok;
    minute60[1] = 60;
    EXPECT_FALSE(decode_time_date(minute60));
    const std::array<std::uint8_t, 5> short_frame{};
    EXPECT_FALSE(decode_time_date(short_frame));
}

TEST(Encode, InsertIsTheInverseOfExtract) {
    std::array<std::uint8_t, 8> d{};
    d.fill(0xFF);
    ASSERT_TRUE(insert_bits(d, 4, 8, 0x4E));
    EXPECT_EQ(extract_bits(d, 4, 8), 0x4Eu);
    EXPECT_EQ(d[0] & 0x0F, 0x0F);  // neighbouring bits untouched
    ASSERT_TRUE(insert_bits(d, 32, 32, 0xDEADBEEF));
    EXPECT_EQ(extract_bits(d, 32, 32), 0xDEADBEEFu);
    EXPECT_FALSE(insert_bits(d, 60, 8, 1));  // runs past the end: nothing written
    EXPECT_EQ(extract_bits(d, 32, 32), 0xDEADBEEFu);
}

TEST(Encode, EverySpnRoundTripsThroughTheDecoder) {
    // For every parameter in the table: encode a mid-range value, decode it back.
    for (const auto& def : spn_table()) {
        const std::uint32_t max = def.length >= 8 && !def.discrete() ? (0xFAU << (def.length - 8)) : 1U;
        const std::uint32_t raw = max / 2;
        const double value = def.discrete() ? static_cast<double>(raw) : raw * def.scale + def.offset;
        const SignalInput in{def.spn, value};
        const auto payload = encode_signals(def.pgn, std::span<const SignalInput>(&in, 1));
        bool found = false;
        for (const auto& v : decode_signals(def.pgn, payload)) {
            if (v.def->spn == def.spn) {
                found = true;
                EXPECT_EQ(v.status, Status::Valid) << def.spn;
                EXPECT_EQ(v.raw, raw) << def.spn;
            } else {
                EXPECT_NE(v.status, Status::Valid) << def.spn << " leaked into " << v.def->spn;  // others stay n/a
            }
        }
        EXPECT_TRUE(found) << def.spn;
    }
}

TEST(Encode, ClampsInsteadOfProducingReservedCodes) {
    const SignalInput too_fast{190, 1e9};  // engine speed far above 8031.875 rpm
    const SignalInput negative{84, -5};    // vehicle speed below zero
    const auto a = encode_signals(61444, std::span<const SignalInput>(&too_fast, 1));
    const auto b = encode_signals(65265, std::span<const SignalInput>(&negative, 1));
    EXPECT_EQ(extract_bits(a, 24, 16), 0xFAFFu);  // largest valid value, not 0xFExx/0xFFxx
    EXPECT_EQ(extract_bits(b, 8, 16), 0u);
    const SignalInput nan{110, std::nan("")};
    const auto c = encode_signals(65262, std::span<const SignalInput>(&nan, 1));
    EXPECT_EQ(classify(c[0], 8, false), Status::Valid);
}

TEST(Encode, Dm1RoundTrips) {
    Dm1 dm;
    dm.malfunction_lamp = 1;
    dm.amber_warning_lamp = 1;
    dm.red_stop_lamp = 0;
    dm.protect_lamp = 0;
    EXPECT_TRUE(decode_dm1(encode_dm1(dm))->dtcs.empty());
    EXPECT_EQ(encode_dm1(dm).size(), 8u);
    dm.dtcs = {{100, 1, 3, false}};
    EXPECT_EQ(encode_dm1(dm).size(), 8u);
    dm.dtcs.push_back({0x7FFFE, 31, 126, true});
    const auto bytes = encode_dm1(dm);
    EXPECT_EQ(bytes.size(), 10u);  // two codes: needs the transport protocol
    const auto back = decode_dm1(bytes);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->dtcs, dm.dtcs);
    EXPECT_EQ(back->malfunction_lamp, 1);
    EXPECT_EQ(back->amber_warning_lamp, 1);
}
