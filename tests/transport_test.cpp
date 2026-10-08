#include <gtest/gtest.h>

#include <algorithm>
#include <numeric>
#include <vector>

#include "vnsl/j1939/transport.hpp"

using namespace vnsl::j1939;
using vnsl::can::Frame;

namespace {

Frame frame(std::uint64_t t_ms, std::uint8_t pri, std::uint32_t pgn, std::uint8_t sa, std::uint8_t da,
            std::vector<std::uint8_t> bytes) {
    Frame f;
    f.t_us = t_ms * 1000;
    f.extended = true;
    f.id = encode_id(pri, pgn, sa, da);
    f.dlc = static_cast<std::uint8_t>(bytes.size());
    std::copy(bytes.begin(), bytes.end(), f.data.begin());
    return f;
}

std::uint8_t lo(std::size_t v) { return static_cast<std::uint8_t>(v & 0xFF); }
std::uint8_t hi(std::size_t v) { return static_cast<std::uint8_t>((v >> 8) & 0xFF); }

Frame cm(std::uint64_t t, std::uint8_t sa, std::uint8_t da, std::uint8_t control, std::size_t size,
         std::size_t packets, std::uint32_t pgn, std::uint8_t b4 = 0xFF) {
    return frame(t, 7, kPgnTpConnection, sa, da,
                 {control, lo(size), hi(size), static_cast<std::uint8_t>(packets), b4,
                  static_cast<std::uint8_t>(pgn & 0xFF), static_cast<std::uint8_t>((pgn >> 8) & 0xFF),
                  static_cast<std::uint8_t>((pgn >> 16) & 0xFF)});
}

Frame cts(std::uint64_t t, std::uint8_t from, std::uint8_t to, std::uint8_t count, std::uint8_t next,
          std::uint32_t pgn) {
    return frame(t, 7, kPgnTpConnection, from, to,
                 {17, count, next, 0xFF, 0xFF, static_cast<std::uint8_t>(pgn & 0xFF),
                  static_cast<std::uint8_t>((pgn >> 8) & 0xFF), static_cast<std::uint8_t>((pgn >> 16) & 0xFF)});
}

/// TP.DT packet `seq` (1-based) of `payload`, padded with 0xFF.
Frame dt(std::uint64_t t, std::uint8_t sa, std::uint8_t da, std::uint8_t seq, const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> b(8, 0xFF);
    b[0] = seq;
    for (std::size_t i = 0; i < 7; ++i) {
        const std::size_t k = (seq - 1u) * 7u + i;
        if (k < payload.size()) b[1 + i] = payload[k];
    }
    return frame(t, 7, kPgnTpDataTransfer, sa, da, b);
}

std::vector<std::uint8_t> bytes(std::size_t n) {
    std::vector<std::uint8_t> v(n);
    std::iota(v.begin(), v.end(), std::uint8_t{1});
    return v;
}

struct Collect {
    std::vector<Message> out;
    Reassembler::Sink sink() {
        return [this](const Message& m) { out.push_back(m); };
    }
};

}  // namespace

TEST(Transport, PassesSingleFramesThrough) {
    Reassembler r;
    Collect c;
    r.on_frame(frame(0, 3, 61444, 0x00, 0xFF, {1, 2, 3, 4, 5, 6, 7, 8}), c.sink());
    ASSERT_EQ(c.out.size(), 1u);
    EXPECT_EQ(c.out[0].pgn, 61444u);
    EXPECT_EQ(c.out[0].data.size(), 8u);
    EXPECT_FALSE(c.out[0].multipacket);
}

TEST(Transport, IgnoresStandardFrames) {
    Reassembler r;
    Collect c;
    Frame f;
    f.id = 0x123;
    f.dlc = 1;
    r.on_frame(f, c.sink());
    EXPECT_TRUE(c.out.empty());
    EXPECT_EQ(r.stats().ignored_non_j1939, 1u);
}

TEST(Transport, ReassemblesBam) {
    Reassembler r;
    Collect c;
    const auto payload = bytes(20);  // 3 packets, last one 6 bytes + padding
    r.on_frame(cm(0, 0x00, 0xFF, 32, 20, 3, 65226), c.sink());
    for (std::uint8_t s = 1; s <= 3; ++s) r.on_frame(dt(50 * s, 0x00, 0xFF, s, payload), c.sink());
    ASSERT_EQ(c.out.size(), 1u);
    EXPECT_EQ(c.out[0].pgn, 65226u);
    EXPECT_EQ(c.out[0].sa, 0x00);
    EXPECT_EQ(c.out[0].da, 0xFF);
    EXPECT_TRUE(c.out[0].multipacket);
    EXPECT_EQ(c.out[0].data, payload);  // padding not included
    EXPECT_EQ(c.out[0].t_us, 150'000u);
    EXPECT_EQ(r.stats().completed_bam, 1u);
    EXPECT_EQ(r.open_sessions(), 0u);
}

TEST(Transport, ReassemblesLargestAllowedTransfer) {
    Reassembler r;
    Collect c;
    const auto payload = bytes(1785);
    r.on_frame(cm(0, 0x03, 0xFF, 32, 1785, 255, 65260), c.sink());
    for (std::size_t s = 1; s <= 255; ++s) r.on_frame(dt(s, 0x03, 0xFF, static_cast<std::uint8_t>(s), payload), c.sink());
    ASSERT_EQ(c.out.size(), 1u);
    EXPECT_EQ(c.out[0].data, payload);
}

TEST(Transport, ReassemblesConnectionModeWithCts) {
    Reassembler r;
    Collect c;
    const auto payload = bytes(23);  // 4 packets
    r.on_frame(cm(0, 0xF9, 0x00, 16, 23, 4, 65260, 2), c.sink());   // RTS, max 2 per CTS
    r.on_frame(cts(5, 0x00, 0xF9, 2, 1, 65260), c.sink());
    r.on_frame(dt(10, 0xF9, 0x00, 1, payload), c.sink());
    r.on_frame(dt(20, 0xF9, 0x00, 2, payload), c.sink());
    r.on_frame(cts(25, 0x00, 0xF9, 2, 3, 65260), c.sink());
    r.on_frame(dt(30, 0xF9, 0x00, 3, payload), c.sink());
    r.on_frame(dt(40, 0xF9, 0x00, 4, payload), c.sink());
    r.on_frame(cm(45, 0x00, 0xF9, 19, 23, 4, 65260), c.sink());  // EndOfMsgAck
    ASSERT_EQ(c.out.size(), 1u);
    EXPECT_EQ(c.out[0].da, 0x00);
    EXPECT_EQ(c.out[0].sa, 0xF9);
    EXPECT_EQ(c.out[0].data, payload);
    EXPECT_EQ(r.stats().completed_cmdt, 1u);
    EXPECT_EQ(r.stats().cts, 2u);
    EXPECT_EQ(r.stats().end_of_msg_ack, 1u);
}

TEST(Transport, FollowsARetransmissionRequest) {
    Reassembler r;
    Collect c;
    const auto payload = bytes(21);  // 3 packets
    r.on_frame(cm(0, 0xF9, 0x00, 16, 21, 3, 65260), c.sink());
    r.on_frame(cts(1, 0x00, 0xF9, 3, 1, 65260), c.sink());
    r.on_frame(dt(2, 0xF9, 0x00, 1, payload), c.sink());
    r.on_frame(dt(3, 0xF9, 0x00, 2, payload), c.sink());
    r.on_frame(cts(4, 0x00, 0xF9, 2, 2, 65260), c.sink());  // receiver asks for packet 2 again
    r.on_frame(dt(5, 0xF9, 0x00, 2, payload), c.sink());
    r.on_frame(dt(6, 0xF9, 0x00, 3, payload), c.sink());
    ASSERT_EQ(c.out.size(), 1u);
    EXPECT_EQ(c.out[0].data, payload);
}

TEST(Transport, CtsAskingForUnsentPacketsDropsTheSession) {
    Reassembler r;
    Collect c;
    r.on_frame(cm(0, 0xF9, 0x00, 16, 21, 3, 65260), c.sink());
    r.on_frame(cts(1, 0x00, 0xF9, 1, 3, 65260), c.sink());  // packet 3 before 1 and 2
    EXPECT_EQ(r.stats().sequence_errors, 1u);
    EXPECT_EQ(r.open_sessions(), 0u);
}

TEST(Transport, OutOfOrderDataDropsTheSession) {
    Reassembler r;
    Collect c;
    const auto payload = bytes(20);
    r.on_frame(cm(0, 0x00, 0xFF, 32, 20, 3, 65226), c.sink());
    r.on_frame(dt(50, 0x00, 0xFF, 1, payload), c.sink());
    r.on_frame(dt(100, 0x00, 0xFF, 3, payload), c.sink());
    r.on_frame(dt(150, 0x00, 0xFF, 2, payload), c.sink());
    EXPECT_TRUE(c.out.empty());
    EXPECT_EQ(r.stats().sequence_errors, 1u);
    EXPECT_EQ(r.stats().orphan_data, 1u);  // packet 2 arrives after the session was dropped
}

TEST(Transport, BamTimesOutAfterT1) {
    Reassembler r;
    Collect c;
    const auto payload = bytes(20);
    r.on_frame(cm(0, 0x00, 0xFF, 32, 20, 3, 65226), c.sink());
    r.on_frame(dt(50, 0x00, 0xFF, 1, payload), c.sink());
    r.on_frame(dt(801, 0x00, 0xFF, 2, payload), c.sink());  // 751 ms gap
    EXPECT_TRUE(c.out.empty());
    EXPECT_EQ(r.stats().timeouts, 1u);
}

TEST(Transport, ConnectionTimesOutAfterT2) {
    Reassembler r;
    r.on_frame(cm(0, 0xF9, 0x00, 16, 21, 3, 65260), [](const Message&) {});
    r.expire(1'250'000);
    EXPECT_EQ(r.open_sessions(), 1u);
    r.expire(1'250'001);
    EXPECT_EQ(r.open_sessions(), 0u);
    EXPECT_EQ(r.stats().timeouts, 1u);
}

TEST(Transport, AbortClosesTheConnectionFromEitherSide) {
    Reassembler r;
    const auto none = [](const Message&) {};
    r.on_frame(cm(0, 0xF9, 0x00, 16, 21, 3, 65260), none);
    r.on_frame(cm(1, 0x00, 0xF9, 255, 0, 0, 65260), none);  // receiver aborts
    EXPECT_EQ(r.open_sessions(), 0u);
    EXPECT_EQ(r.stats().aborted_sessions, 1u);
    r.on_frame(cm(2, 0xF9, 0x00, 16, 21, 3, 65260), none);
    r.on_frame(cm(3, 0xF9, 0x00, 255, 0, 0, 65260), none);  // originator aborts
    EXPECT_EQ(r.open_sessions(), 0u);
    EXPECT_EQ(r.stats().aborted_sessions, 2u);
}

TEST(Transport, RejectsImpossibleAnnouncements) {
    Reassembler r;
    const auto none = [](const Message&) {};
    r.on_frame(cm(0, 0x00, 0xFF, 32, 8, 2, 65226), none);      // 8 bytes fit in one frame
    r.on_frame(cm(0, 0x00, 0xFF, 32, 1786, 255, 65226), none);  // over the 1785-byte limit
    r.on_frame(cm(0, 0x00, 0xFF, 32, 20, 4, 65226), none);      // 20 bytes need 3 packets, not 4
    r.on_frame(cm(0, 0x00, 0xFF, 32, 20, 3, kPgnTpDataTransfer), none);  // transport inside transport
    r.on_frame(cm(0, 0x00, 0xFF, 32, 20, 3, 0x40000), none);    // PGN wider than 18 bits
    r.on_frame(cm(0, 0x00, 0xFF, 32, 20, 3, 0xEA05), none);     // PDU1 PGN with a destination byte
    r.on_frame(cm(0, 0x00, 0x17, 32, 20, 3, 65226), none);      // BAM to one node
    r.on_frame(cm(0, 0xF9, 0xFF, 16, 20, 3, 65260), none);      // RTS to everyone
    EXPECT_EQ(r.stats().bad_announcements, 8u);
    EXPECT_EQ(r.open_sessions(), 0u);
}

TEST(Transport, ANewAnnouncementReplacesAnOpenOne) {
    Reassembler r;
    Collect c;
    const auto payload = bytes(20);
    r.on_frame(cm(0, 0x00, 0xFF, 32, 20, 3, 65226), c.sink());
    r.on_frame(dt(50, 0x00, 0xFF, 1, payload), c.sink());
    r.on_frame(cm(60, 0x00, 0xFF, 32, 20, 3, 65227), c.sink());
    for (std::uint8_t s = 1; s <= 3; ++s) r.on_frame(dt(60 + 50 * s, 0x00, 0xFF, s, payload), c.sink());
    ASSERT_EQ(c.out.size(), 1u);
    EXPECT_EQ(c.out[0].pgn, 65227u);
    EXPECT_EQ(r.stats().replaced_sessions, 1u);
}

TEST(Transport, BoundsTheNumberOfOpenSessions) {
    Reassembler::Limits limits;
    limits.max_sessions = 4;
    Reassembler r(limits);
    for (std::uint8_t sa = 0; sa < 10; ++sa) r.on_frame(cm(0, sa, 0xFF, 32, 20, 3, 65226), [](const Message&) {});
    EXPECT_EQ(r.open_sessions(), 4u);
    EXPECT_EQ(r.stats().rejected_too_many_sessions, 6u);
}

TEST(Transport, CountsMalformedTransportFrames) {
    Reassembler r;
    const auto none = [](const Message&) {};
    r.on_frame(frame(0, 7, kPgnTpConnection, 0, 0xFF, {32, 20, 0}), none);  // short TP.CM
    r.on_frame(frame(0, 7, kPgnTpConnection, 0, 0xFF, {99, 0, 0, 0, 0, 0, 0, 0}), none);  // unknown control
    r.on_frame(frame(0, 7, kPgnTpDataTransfer, 0, 0xFF, {1, 2}), none);  // short TP.DT
    EXPECT_EQ(r.stats().malformed_tp_frames, 3u);
}
