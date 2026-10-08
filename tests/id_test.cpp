#include <gtest/gtest.h>

#include "vnsl/j1939/id.hpp"

using namespace vnsl::j1939;

TEST(Id, DecodesPdu2Broadcast) {
    // EEC1 from the engine (SA 0x00) at priority 3, as on every J1939 truck.
    const Id id = decode_id(0x0CF00400);
    EXPECT_EQ(id.priority, 3);
    EXPECT_EQ(id.pgn, 61444U);
    EXPECT_EQ(id.sa, 0x00);
    EXPECT_EQ(id.da, kGlobalAddress);
    EXPECT_FALSE(id.pdu1());
}

TEST(Id, DecodesPdu1WithDestination) {
    // A request (PGN 59904) from SA 0xF9 to the engine (0x00).
    const Id id = decode_id(0x18EA00F9);
    EXPECT_EQ(id.priority, 6);
    EXPECT_EQ(id.pgn, kPgnRequest);
    EXPECT_EQ(id.da, 0x00);
    EXPECT_EQ(id.sa, 0xF9);
    EXPECT_TRUE(id.pdu1());
}

TEST(Id, KeepsDataPageAndExtendedDataPage) {
    // Taken from the Turku truck: 0x15FF5CE6 is priority 5, DP 1, PF 0xFF, PS 0x5C.
    const Id id = decode_id(0x15FF5CE6);
    EXPECT_EQ(id.priority, 5);
    EXPECT_EQ(id.pgn, 0x1FF5CU);
    EXPECT_EQ(id.sa, 0xE6);
}

TEST(Id, EncodeIsTheInverseOfDecode) {
    for (const std::uint32_t raw : {0x0CF00400U, 0x18EA00F9U, 0x15FF5CE6U, 0x18ECFFE6U, 0x1CEBFF00U, 0x00000000U}) {
        const Id id = decode_id(raw);
        EXPECT_EQ(encode_id(id.priority, id.pgn, id.sa, id.da), raw) << std::hex << raw;
    }
}

TEST(Id, EncodeIgnoresDestinationForPdu2) {
    EXPECT_EQ(encode_id(3, 61444, 0x00, 0x17), 0x0CF00400U);
}
