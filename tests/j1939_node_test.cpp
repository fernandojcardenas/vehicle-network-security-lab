#include <gtest/gtest.h>

#include <numeric>
#include <vector>

#include "vnsl/j1939/id.hpp"
#include "vnsl/j1939/transport.hpp"
#include "vnsl/sim/j1939_node.hpp"

using namespace vnsl;

namespace {

/// Answers requests for PGN 65260 with a payload of a chosen size; records what it receives.
class TestNode : public sim::J1939Node {
public:
    using sim::J1939Node::J1939Node;
    std::size_t vi_size = 30;
    std::vector<j1939::Message> got;
    bool claimed_called = false;
    std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> requests_to_send;  // (time, request frame data)
    std::uint8_t request_da = 0;

    void request(sim::Simulator& s, std::uint32_t pgn, std::uint8_t da) {
        const std::vector<std::uint8_t> d{static_cast<std::uint8_t>(pgn & 0xFF), static_cast<std::uint8_t>((pgn >> 8) & 0xFF),
                                          static_cast<std::uint8_t>((pgn >> 16) & 0xFF)};
        send(s, 6, j1939::kPgnRequest, da, d);
    }
    void send_payload(sim::Simulator& s, std::uint32_t pgn, std::uint8_t da, std::size_t n) {
        std::vector<std::uint8_t> d(n);
        std::iota(d.begin(), d.end(), std::uint8_t{0});
        send(s, 6, pgn, da, d);
    }

protected:
    void on_claimed(sim::Simulator&) override { claimed_called = true; }
    void on_message(sim::Simulator&, const j1939::Message& m) override { got.push_back(m); }
    std::optional<std::vector<std::uint8_t>> on_request(sim::Simulator&, std::uint32_t pgn, std::uint8_t) override {
        if (pgn != 65260) return std::nullopt;
        std::vector<std::uint8_t> d(vi_size);
        std::iota(d.begin(), d.end(), std::uint8_t{'A'});
        return d;
    }
};

/// A passive observer on the wire, as an intrusion detector would be.
struct Observer {
    j1939::Reassembler r;
    std::vector<j1939::Message> messages;
    void attach(sim::Simulator& s) {
        s.on_wire([this](const can::Frame& f, std::size_t) { r.on_frame(f, [this](const j1939::Message& m) { messages.push_back(m); }); });
    }
};

}  // namespace

TEST(J1939Node, ClaimsItsAddressAndWaits250ms) {
    sim::Simulator s;
    TestNode a("a", 0x1000, 0x00, false);
    s.add(a);
    s.run_until(249'000);
    EXPECT_EQ(a.claim_state(), sim::J1939Node::ClaimState::Claiming);
    s.run_until(260'000);
    EXPECT_EQ(a.claim_state(), sim::J1939Node::ClaimState::Claimed);
    EXPECT_TRUE(a.claimed_called);
    EXPECT_EQ(a.address(), 0x00);
}

TEST(J1939Node, LowerNameKeepsTheAddressAndTheOtherMoves) {
    sim::Simulator s;
    TestNode strong("strong", 0x100, 0x80, true);
    TestNode weak("weak", 0x200, 0x80, true);  // higher NAME = lower priority
    s.add(weak);
    s.add(strong);
    s.run_until(2'000'000);
    EXPECT_EQ(strong.address(), 0x80);
    EXPECT_EQ(strong.claim_state(), sim::J1939Node::ClaimState::Claimed);
    EXPECT_EQ(weak.address(), 0x81);  // first free address in 128..247
    EXPECT_EQ(weak.claim_state(), sim::J1939Node::ClaimState::Claimed);
    EXPECT_EQ(weak.node_stats().claims_lost, 1u);
}

TEST(J1939Node, NodeThatCannotMoveSendsCannotClaim) {
    sim::Simulator s;
    TestNode strong("strong", 0x100, 0x80, false);
    TestNode weak("weak", 0x200, 0x80, false);
    s.add(strong);
    s.add(weak);
    std::size_t cannot_claim = 0;
    s.on_wire([&](const can::Frame& f, std::size_t) {
        const auto id = j1939::decode_id(f.id);
        if (id.pgn == j1939::kPgnAddressClaimed && id.sa == j1939::kNullAddress) ++cannot_claim;
    });
    s.run_until(2'000'000);
    EXPECT_EQ(weak.claim_state(), sim::J1939Node::ClaimState::CannotClaim);
    EXPECT_EQ(weak.address(), j1939::kNullAddress);
    EXPECT_EQ(cannot_claim, 1u);
}

TEST(J1939Node, SpecificRequestIsAnsweredPointToPoint) {
    sim::Simulator s;
    TestNode engine("engine", 0x10, 0x00, false);
    TestNode tool("tool", 0x20, 0xF9, true);
    s.add(engine);
    s.add(tool);
    Observer obs;
    obs.attach(s);
    s.run_until(500'000);
    tool.request(s, 65260, 0x00);
    s.run_until(5'000'000);
    ASSERT_EQ(tool.got.size(), 1u);
    EXPECT_EQ(tool.got[0].pgn, 65260u);
    EXPECT_EQ(tool.got[0].da, 0xF9);
    EXPECT_EQ(tool.got[0].data.size(), 30u);
    EXPECT_EQ(tool.got[0].data[0], 'A');
    EXPECT_EQ(engine.node_stats().cmdt_sent, 1u);   // EndOfMsgAck received
    EXPECT_EQ(tool.node_stats().cmdt_received, 1u);
    // The passive observer followed the same connection without taking part.
    EXPECT_EQ(obs.r.stats().completed_cmdt, 1u);
    EXPECT_EQ(obs.r.stats().cts, 1u);
    EXPECT_EQ(obs.r.stats().end_of_msg_ack, 1u);
    EXPECT_EQ(obs.r.stats().sequence_errors + obs.r.stats().timeouts + obs.r.stats().bad_announcements, 0u);
}

TEST(J1939Node, LongTransfersAreGrantedInBatchesOf16) {
    sim::Simulator s;
    TestNode engine("engine", 0x10, 0x00, false);
    TestNode tool("tool", 0x20, 0xF9, true);
    engine.vi_size = 200;  // 29 packets: CTS for 16, then 13
    s.add(engine);
    s.add(tool);
    Observer obs;
    obs.attach(s);
    s.run_until(500'000);
    tool.request(s, 65260, 0x00);
    s.run_until(5'000'000);
    ASSERT_EQ(tool.got.size(), 1u);
    EXPECT_EQ(tool.got[0].data.size(), 200u);
    EXPECT_EQ(obs.r.stats().cts, 2u);
    EXPECT_EQ(obs.r.stats().completed_cmdt, 1u);
}

TEST(J1939Node, GlobalRequestIsAnsweredByBam) {
    sim::Simulator s;
    TestNode engine("engine", 0x10, 0x00, false);
    TestNode tool("tool", 0x20, 0xF9, true);
    s.add(engine);
    s.add(tool);
    Observer obs;
    obs.attach(s);
    s.run_until(500'000);
    tool.request(s, 65260, j1939::kGlobalAddress);
    s.run_until(5'000'000);
    ASSERT_EQ(tool.got.size(), 1u);
    EXPECT_EQ(tool.got[0].da, j1939::kGlobalAddress);
    EXPECT_EQ(engine.node_stats().bam_sent, 1u);
    EXPECT_EQ(obs.r.stats().completed_bam, 1u);
    // 5 packets, 50 ms apart.
    EXPECT_GT(tool.got[0].t_us, 500'000u + 5 * 50'000u - 1000u);
}

TEST(J1939Node, UnsupportedSpecificRequestGetsANack) {
    sim::Simulator s;
    TestNode engine("engine", 0x10, 0x00, false);
    TestNode tool("tool", 0x20, 0xF9, true);
    s.add(engine);
    s.add(tool);
    s.run_until(500'000);
    tool.request(s, 65253, 0x00);
    s.run_until(1'000'000);
    EXPECT_EQ(engine.node_stats().nacks_sent, 1u);
    ASSERT_EQ(tool.got.size(), 1u);
    EXPECT_EQ(tool.got[0].pgn, 0xE800u);
    EXPECT_EQ(tool.got[0].data[0], 1);    // NACK
    EXPECT_EQ(tool.got[0].data[4], 0xF9);  // the requester
}

TEST(J1939Node, TransferToAnAbsentNodeTimesOutAndAborts) {
    sim::Simulator s;
    TestNode a("a", 0x10, 0x00, false);
    s.add(a);
    std::size_t aborts = 0;
    s.on_wire([&](const can::Frame& f, std::size_t) {
        const auto id = j1939::decode_id(f.id);
        if (id.pgn == j1939::kPgnTpConnection && f.data[0] == 255) ++aborts;
    });
    s.run_until(500'000);
    a.send_payload(s, 65260, 0x42, 20);  // nobody at 0x42
    s.run_until(1'740'000);
    EXPECT_EQ(a.node_stats().cmdt_failed, 0u);
    s.run_until(1'800'000);
    EXPECT_EQ(a.node_stats().cmdt_failed, 1u);
    EXPECT_EQ(aborts, 1u);
}
