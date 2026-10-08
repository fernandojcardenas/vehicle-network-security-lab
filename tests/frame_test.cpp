#include <gtest/gtest.h>

#include "vnsl/can/frame.hpp"

using vnsl::can::Frame;
using vnsl::can::format_candump;
using vnsl::can::parse_candump_line;
using vnsl::can::parse_turku_csv_line;

TEST(Candump, ParsesAnExtendedFrame) {
    std::string iface;
    const auto f = parse_candump_line("(1606390200.265340) can0 0CFE6CE6#FFFFFFFF00FF1234", &iface);
    ASSERT_TRUE(f);
    EXPECT_EQ(f->t_us, 1606390200265340ULL);
    EXPECT_EQ(iface, "can0");
    EXPECT_TRUE(f->extended);
    EXPECT_EQ(f->id, 0x0CFE6CE6U);
    EXPECT_EQ(f->dlc, 8);
    EXPECT_EQ(f->data[4], 0x00);
    EXPECT_EQ(f->data[7], 0x34);
}

TEST(Candump, ParsesStandardAndEmptyFrames) {
    const auto f = parse_candump_line("(1.5) vcan0 123#");
    ASSERT_TRUE(f);
    EXPECT_FALSE(f->extended);
    EXPECT_EQ(f->id, 0x123U);
    EXPECT_EQ(f->dlc, 0);
    EXPECT_EQ(f->t_us, 1'500'000ULL);  // short fractions are scaled, not read as micros
}

TEST(Candump, RejectsMalformedAndUnsupportedLines) {
    for (const char* bad : {
             "", "(", "()", "(1.0) can0", "(1.0) can0 123", "(x.0) can0 123#00", "(1.0)can0 123#00",
             "(1.0) can0 12#00",            // 2-digit id
             "(1.0) can0 1234#00",          // 4-digit id
             "(1.0) can0 800#00",           // 11-bit id out of range
             "(1.0) can0 20000000#00",      // 29-bit id out of range
             "(1.0) can0 123#0",            // odd hex length
             "(1.0) can0 123#00112233445566778899",  // more than 8 bytes
             "(1.0) can0 123#GG",           // not hex
             "(1.0) can0 123#R",            // remote frame
             "(1.0) can0 123##100",         // CAN FD
             "(1.1234567) can0 123#00",     // 7 fraction digits
             "(99999999999999999999.0) can0 123#00",  // seconds overflow
         }) {
        EXPECT_FALSE(parse_candump_line(bad)) << bad;
    }
}

TEST(Candump, FormatRoundTrips) {
    Frame f;
    f.t_us = 1606390200000001ULL;
    f.extended = true;
    f.id = 0x18FEF100;
    f.dlc = 3;
    f.data = {0xAB, 0x00, 0x7F};
    const auto line = format_candump(f, "can1");
    EXPECT_EQ(line, "(1606390200.000001) can1 18FEF100#AB007F");
    std::string iface;
    const auto back = parse_candump_line(line, &iface);
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, f);
    EXPECT_EQ(iface, "can1");
}

TEST(TurkuCsv, ParsesARealRow) {
    const auto f = parse_turku_csv_line("2020-11-26 11:30:00.265340;0xcfe6ce6;8;255;255;255;255;255;255;255;254\r");
    ASSERT_TRUE(f);
    EXPECT_EQ(f->t_us, 1606390200265340ULL);  // 2020-11-26 11:30:00 UTC
    EXPECT_TRUE(f->extended);
    EXPECT_EQ(f->id, 0x0CFE6CE6U);
    EXPECT_EQ(f->dlc, 8);
    EXPECT_EQ(f->data[7], 254);
}

TEST(TurkuCsv, ParsesShortRows) {
    const auto f = parse_turku_csv_line("2020-11-26 11:30:00.5;0x18ea00f9;3;0;238;0");
    ASSERT_TRUE(f);
    EXPECT_EQ(f->dlc, 3);
    EXPECT_EQ(f->data[1], 238);
    EXPECT_EQ(f->t_us % 1'000'000ULL, 500'000ULL);
}

TEST(TurkuCsv, RejectsHeaderAndBadRows) {
    for (const char* bad : {
             "timestamp;id;dlc;data",
             "2020-11-26 11:30:00.265340;0xcfe6ce6;8;255;255",           // fewer bytes than dlc
             "2020-11-26 11:30:00.265340;0xcfe6ce6;2;255;255;255",       // more bytes than dlc
             "2020-11-26 11:30:00.265340;0xcfe6ce6;9;1;2;3;4;5;6;7;8;9",  // dlc > 8
             "2020-11-26 11:30:00.265340;cfe6ce6;1;1",                   // no 0x
             "2020-11-26 11:30:00.265340;0x3fffffff;1;1",                // > 29 bits
             "2020-11-26 11:30:00.265340;0xcfe6ce6;1;256",               // byte > 255
             "2020-13-26 11:30:00.265340;0xcfe6ce6;1;1",                 // month 13
             "2020-11-26T11:30:00.265340;0xcfe6ce6;1;1",                 // wrong separator
             "2020-11-26 11:30:00.1234567;0xcfe6ce6;1;1",                // 7 fraction digits
             "",
         }) {
        EXPECT_FALSE(parse_turku_csv_line(bad)) << bad;
    }
}

TEST(Civil, DaysFromCivil) {
    EXPECT_EQ(vnsl::can::days_from_civil(1970, 1, 1), 0);
    EXPECT_EQ(vnsl::can::days_from_civil(2000, 3, 1), 11017);
    EXPECT_EQ(vnsl::can::days_from_civil(2020, 11, 26), 18592);
}
