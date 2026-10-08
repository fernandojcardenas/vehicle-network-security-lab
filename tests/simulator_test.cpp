#include <gtest/gtest.h>

#include <vector>

#include "vnsl/can/bit_timing.hpp"
#include "vnsl/sim/simulator.hpp"

using namespace vnsl;

namespace {

can::Frame make(std::uint32_t id, std::uint8_t tag) {
    can::Frame f;
    f.extended = true;
    f.id = id;
    f.dlc = 1;
    f.data[0] = tag;
    return f;
}

/// Sends a list of frames when its timer fires, and records what it receives.
struct Sender : sim::Node {
    std::vector<std::pair<std::uint64_t, can::Frame>> to_send;  // (time, frame)
    std::vector<can::Frame> received;
    void start(sim::Simulator& s) override {
        for (std::size_t i = 0; i < to_send.size(); ++i) s.schedule(*this, to_send[i].first, static_cast<int>(i));
    }
    void on_timer(sim::Simulator& s, int id) override { s.transmit(*this, to_send[static_cast<std::size_t>(id)].second); }
    void on_frame(sim::Simulator&, const can::Frame& f) override { received.push_back(f); }
};

}  // namespace

TEST(Simulator, LowestIdentifierWinsArbitration) {
    sim::Simulator s;
    Sender a, b, c, listener;
    a.to_send = {{1000, make(0x18FEF100, 1)}};
    b.to_send = {{1000, make(0x0CF00400, 2)}};  // priority 3: wins
    c.to_send = {{1000, make(0x18FEF200, 3)}};
    for (auto* n : {&a, &b, &c, &listener}) s.add(*n);
    s.run_until(1'000'000);
    ASSERT_EQ(listener.received.size(), 3u);
    EXPECT_EQ(listener.received[0].data[0], 2);
    EXPECT_EQ(listener.received[1].data[0], 1);
    EXPECT_EQ(listener.received[2].data[0], 3);
    EXPECT_EQ(s.stats().arbitrations, 2u);  // three contenders, then two
    EXPECT_EQ(s.stats().lost_arbitration, 3u);
}

TEST(Simulator, FramesTakeTheirRealTimeOnTheWire) {
    sim::Simulator s(250'000);
    Sender a, listener;
    const auto f1 = make(0x18FEF100, 1);
    const auto f2 = make(0x18FEF100, 2);
    a.to_send = {{0, f1}, {0, f2}};
    s.add(a);
    s.add(listener);
    s.run_until(1'000'000);
    ASSERT_EQ(listener.received.size(), 2u);
    const auto d1 = can::frame_duration_us(f1, 250'000);
    const auto d2 = can::frame_duration_us(f2, 250'000);
    EXPECT_EQ(listener.received[0].t_us, d1);
    EXPECT_EQ(listener.received[1].t_us, d1 + d2);  // back to back, same node, in order
    EXPECT_EQ(s.stats().busy_us, d1 + d2);
    EXPECT_TRUE(a.received.empty());  // a sender does not receive its own frames
}

TEST(Simulator, InjectedFramesReachEveryNodeAndObservers) {
    sim::Simulator s;
    Sender a, b;
    s.add(a);
    s.add(b);
    std::vector<std::size_t> senders;
    s.on_wire([&](const can::Frame&, std::size_t sender) { senders.push_back(sender); });
    s.run_until(10);
    s.inject(make(0x18EA00F1, 9));
    s.run_until(10'000);
    EXPECT_EQ(a.received.size(), 1u);
    EXPECT_EQ(b.received.size(), 1u);
    ASSERT_EQ(senders.size(), 1u);
    EXPECT_EQ(senders[0], sim::Simulator::kExternal);
}

TEST(Simulator, IsDeterministic) {
    const auto run = [] {
        sim::Simulator s;
        Sender a, b, l;
        for (int i = 0; i < 50; ++i) {
            a.to_send.push_back({static_cast<std::uint64_t>(i * 300), make(0x18FEF100 + static_cast<std::uint32_t>(i % 3), 1)});
            b.to_send.push_back({static_cast<std::uint64_t>(i * 310), make(0x0CF00400, 2)});
        }
        for (auto* n : {&a, &b, &l}) s.add(*n);
        s.run_until(1'000'000);
        std::vector<std::uint64_t> t;
        for (const auto& f : l.received) t.push_back(f.t_us ^ f.id);
        return t;
    };
    EXPECT_EQ(run(), run());
}
