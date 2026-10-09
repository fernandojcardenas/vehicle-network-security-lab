#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include "vnsl/can/frame.hpp"
#include "vnsl/gateway/gateway.hpp"
#include "vnsl/gateway/policy.hpp"
#include "vnsl/j1939/id.hpp"

using namespace vnsl;
using vnsl::gateway::Decision;
using vnsl::gateway::Direction;

namespace {
can::Frame frame(std::uint64_t t_us, std::uint32_t pgn, std::uint8_t sa) {
    can::Frame f;
    f.t_us = t_us;
    f.extended = true;
    f.id = j1939::encode_id(6, pgn, sa);
    f.dlc = 8;
    return f;
}
}  // namespace

TEST(Policy, ParsesRulesAndComments) {
    std::string err;
    auto p = gateway::Policy::parse("# comment\nB>A pgn=65265 sa=0x17 rate=12\nA>B pgn=59904\n", &err);
    ASSERT_TRUE(p) << err;
    EXPECT_EQ(p->size(), 2u);
}

TEST(Policy, RejectsMalformedLines) {
    for (const char* bad : {"X>Y pgn=1", "B>A foo=1", "B>A pgn=notnum", "B>A sa=0x1FF", "nonsense"}) {
        std::string err;
        EXPECT_FALSE(gateway::Policy::parse(bad, &err)) << bad;
        EXPECT_FALSE(err.empty());
    }
}

TEST(Policy, DefaultDenyBlocksWhatIsNotListed) {
    auto p = gateway::Policy::parse("B>A pgn=65265\n").value();
    EXPECT_EQ(p.decide(frame(0, 65265, 0x17), Direction::BtoA), Decision::Allow);
    EXPECT_EQ(p.decide(frame(0, 61444, 0x00), Direction::BtoA), Decision::DenyNoRule);  // not listed
    EXPECT_EQ(p.decide(frame(0, 65265, 0x17), Direction::AtoB), Decision::DenyNoRule);  // wrong direction
}

TEST(Policy, SourceAndPgnWildcards) {
    auto p = gateway::Policy::parse("B>A pgn=65265 sa=*\nB>A pgn=* sa=0x00\n").value();
    EXPECT_EQ(p.decide(frame(0, 65265, 0x42), Direction::BtoA), Decision::Allow);  // any sa
    EXPECT_EQ(p.decide(frame(0, 61444, 0x00), Direction::BtoA), Decision::Allow);  // any pgn from 0x00
    EXPECT_EQ(p.decide(frame(0, 61444, 0x42), Direction::BtoA), Decision::DenyNoRule);
}

TEST(Policy, RateLimitStopsAFloodOfAnAllowedMessage) {
    auto p = gateway::Policy::parse("B>A pgn=65265 rate=10 burst=4\n").value();  // 10 Hz, burst 4
    // Four back-to-back pass (the burst), then further frames at 0 ms are denied.
    int allowed = 0, denied = 0;
    for (int i = 0; i < 20; ++i)
        (p.decide(frame(0, 65265, 0x17), Direction::BtoA) == Decision::Allow ? allowed : denied)++;
    EXPECT_EQ(allowed, 4);
    EXPECT_EQ(denied, 16);
    // After 1 second, 10 more tokens have accrued (capped at burst=4), so a few pass again.
    int later = 0;
    for (int i = 0; i < 20; ++i)
        if (p.decide(frame(1'000'000, 65265, 0x17), Direction::BtoA) == Decision::Allow) ++later;
    EXPECT_EQ(later, 4);
}

TEST(Policy, RateLimitIsPerStream) {
    auto p = gateway::Policy::parse("B>A pgn=* rate=5 burst=1\n").value();
    // Two different sources each get their own bucket.
    EXPECT_EQ(p.decide(frame(0, 65265, 0x00), Direction::BtoA), Decision::Allow);
    EXPECT_EQ(p.decide(frame(0, 65265, 0x03), Direction::BtoA), Decision::Allow);
    EXPECT_EQ(p.decide(frame(0, 65265, 0x00), Direction::BtoA), Decision::DenyRateExceeded);
}

TEST(Gateway, CountsForwardedAndDenied) {
    auto p = gateway::Policy::parse("B>A pgn=65265\n").value();
    gateway::Gateway gw(std::move(p));
    EXPECT_TRUE(gw.forward(frame(0, 65265, 0x17), Direction::BtoA));
    EXPECT_FALSE(gw.forward(frame(0, 61444, 0x00), Direction::BtoA));
    EXPECT_FALSE(gw.forward(frame(0, 65265, 0x17), Direction::AtoB));
    EXPECT_EQ(gw.stats().seen, 3u);
    EXPECT_EQ(gw.stats().forwarded, 1u);
    EXPECT_EQ(gw.stats().denied_no_rule, 2u);
}

TEST(Gateway, DiagnosticSideCannotReachThePowertrainByDefault) {
    // The shipped-style policy: B>A powertrain reports allowed, nothing A>B.
    auto p = gateway::Policy::parse("B>A pgn=61444 rate=60\nB>A pgn=65265 rate=12\n").value();
    gateway::Gateway gw(std::move(p));
    // An attacker on bus A tries to push a command onto the powertrain bus B.
    EXPECT_FALSE(gw.forward(frame(0, 61444, 0xF9), Direction::AtoB));
    EXPECT_FALSE(gw.forward(frame(0, 0, 0xF9), Direction::AtoB));
    EXPECT_EQ(gw.stats().forwarded, 0u);
}
