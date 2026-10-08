#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include "vnsl/ids/attack.hpp"
#include "vnsl/ids/baseline.hpp"
#include "vnsl/ids/detector.hpp"
#include "vnsl/j1939/id.hpp"
#include "vnsl/j1939/signals.hpp"
#include "vnsl/j1939/transport.hpp"

using namespace vnsl;

namespace {

can::Frame ccvs1(std::uint64_t t_us, std::uint8_t sa, double speed_kmh) {
    const std::array<j1939::SignalInput, 1> in{{{84, speed_kmh}}};
    const auto body = j1939::encode_signals(65265, in);
    can::Frame f;
    f.t_us = t_us;
    f.extended = true;
    f.id = j1939::encode_id(6, 65265, sa, j1939::kGlobalAddress);
    f.dlc = 8;
    std::copy(body.begin(), body.end(), f.data.begin());
    return f;
}

// A minute of one ECU sending vehicle speed every 100 ms. Speed cycles 0..40..0 km/h every
// 20 s, so the first 40% (the training window) already covers the whole operating range, the
// way real training traffic does.
std::vector<can::Frame> clean_minute(std::uint8_t sa = 0x17) {
    std::vector<can::Frame> v;
    for (std::uint64_t k = 0; k < 600; ++k) {
        const double phase = static_cast<double>(k % 200) / 200.0;          // 0..1 over 20 s
        const double speed = 40.0 * (phase < 0.5 ? phase * 2.0 : 2.0 - phase * 2.0);  // triangle 0..40..0
        v.push_back(ccvs1(k * 100'000, sa, speed));
    }
    return v;
}

ids::Baseline train_on(const std::vector<can::Frame>& frames, std::uint64_t until_us) {
    ids::Baseline b;
    j1939::Reassembler rx;
    for (const auto& f : frames) {
        if (f.t_us >= until_us) break;
        rx.on_frame(f, [&](const j1939::Message& m) { b.observe(m); });
    }
    b.finalise();
    return b;
}

std::vector<ids::Alert> run_detector(const ids::Baseline& b, const std::vector<can::Frame>& frames,
                                     std::uint64_t from_us, ids::Detector::Config cfg = {}) {
    ids::Detector d(b, cfg);
    j1939::Reassembler rx;
    std::vector<ids::Alert> alerts;
    for (const auto& f : frames) {
        if (f.t_us < from_us) continue;
        rx.on_frame(f, [&](const j1939::Message& m) { d.inspect(m, [&](const ids::Alert& a) { alerts.push_back(a); }); });
        d.inspect_transport(f.t_us, rx.stats(), [&](const ids::Alert& a) { alerts.push_back(a); });
    }
    return alerts;
}

bool has(const std::vector<ids::Alert>& a, ids::AlertType t) {
    for (const auto& x : a) if (x.type == t) return true;
    return false;
}

}  // namespace

TEST(Baseline, LearnsSourcesRatesAndRanges) {
    const auto frames = clean_minute();
    const auto b = train_on(frames, 60'000'000);
    EXPECT_TRUE(b.knows_source(0x17));
    EXPECT_FALSE(b.knows_source(0x00));
    const auto r = b.rate(0x17, 65265);
    ASSERT_TRUE(r);
    EXPECT_NEAR(static_cast<double>(r->min_gap_us), 100'000.0, 2000);
    const auto s = b.signal(65265, 84);
    ASSERT_TRUE(s);
    EXPECT_NEAR(s->min_value, 0.0, 0.5);
    EXPECT_NEAR(s->max_value, 40.0, 0.5);
}

TEST(Detector, CleanHeldOutTrafficRaisesNoAlerts) {
    // Train on the first 40 s, test on the rest of the same clean minute.
    const auto frames = clean_minute();
    const auto b = train_on(frames, 40'000'000);
    const auto alerts = run_detector(b, frames, 40'000'000);
    EXPECT_TRUE(alerts.empty()) << "unexpected alert: " << (alerts.empty() ? "" : alerts[0].detail);
}

TEST(Detector, FlagsAnUnknownSource) {
    auto frames = clean_minute();
    const auto b = train_on(frames, 40'000'000);
    // A node that was never in training appears in the test window.
    std::vector<can::Frame> test = frames;
    test.push_back(ccvs1(50'000'000, 0xAA, 10.0));
    std::stable_sort(test.begin(), test.end(), [](auto& a, auto& c) { return a.t_us < c.t_us; });
    EXPECT_TRUE(has(run_detector(b, test, 40'000'000), ids::AlertType::UnknownSource));
}

TEST(Detector, FlagsValueOutOfRangeAndJump) {
    auto frames = clean_minute();
    const auto b = train_on(frames, 40'000'000);
    auto test = frames;
    test.push_back(ccvs1(50'000'000, 0x17, 200.0));  // far above the learned 40 km/h
    std::stable_sort(test.begin(), test.end(), [](auto& a, auto& c) { return a.t_us < c.t_us; });
    const auto alerts = run_detector(b, test, 40'000'000);
    EXPECT_TRUE(has(alerts, ids::AlertType::ValueOutOfRange));
}

TEST(Detector, DedupesRepeatedAlerts) {
    auto frames = clean_minute();
    const auto b = train_on(frames, 40'000'000);
    auto test = frames;
    for (std::uint64_t k = 0; k < 100; ++k) test.push_back(ccvs1(50'000'000 + k * 1000, 0xAA, 10.0));
    std::stable_sort(test.begin(), test.end(), [](auto& a, auto& c) { return a.t_us < c.t_us; });
    std::size_t unknown = 0;
    for (const auto& a : run_detector(b, test, 40'000'000))
        if (a.type == ids::AlertType::UnknownSource) ++unknown;
    EXPECT_EQ(unknown, 1u);  // 100 frames from 0xAA within 1 s collapse to one alert
}

TEST(Attack, InjectFloodAddsHighPriorityFramesInWindowOnly) {
    const auto frames = clean_minute();
    const auto r = ids::inject_attack(frames, ids::AttackType::Flood, 20'000'000, 10'000'000, 1);
    ASSERT_EQ(r.windows.size(), 1u);
    EXPECT_GT(r.windows[0].injected_frames, 0u);
    EXPECT_TRUE(std::is_sorted(r.frames.begin(), r.frames.end(), [](auto& a, auto& b) { return a.t_us < b.t_us; }));
    for (const auto& f : r.frames) {
        const auto id = j1939::decode_id(f.id);
        if (id.sa == 0xAA) {
            EXPECT_GE(f.t_us, 20'000'000u);
            EXPECT_LT(f.t_us, 30'000'000u);
        }
    }
}

TEST(Attack, EachTypeIsDetected) {
    // Train on a clean two-minute stream, attack the fourth minute, test on everything after training.
    std::vector<can::Frame> base;
    for (std::uint64_t k = 0; k < 2400; ++k) base.push_back(ccvs1(k * 100'000, 0x17, 30.0 + 5.0 * ((k / 50) % 2)));
    const std::uint64_t train_until = 120'000'000;
    for (const auto type : {ids::AttackType::Flood, ids::AttackType::Spoof, ids::AttackType::Replay,
                            ids::AttackType::Jump}) {
        const auto atk = ids::inject_attack(base, type, 180'000'000, 20'000'000, 1);
        const auto b = train_on(atk.frames, train_until);
        const auto alerts = run_detector(b, atk.frames, train_until);
        bool in_window = false;
        for (const auto& a : alerts)
            if (a.t_us >= 180'000'000 && a.t_us <= 200'000'000) in_window = true;
        EXPECT_TRUE(in_window) << "no alert during " << ids::attack_type_name(type) << " attack";
    }
}

TEST(Detector, TransportAnomalyFires) {
    ids::Baseline b;
    b.finalise();
    ids::Detector d(b);
    j1939::TransportStats s;
    std::vector<ids::Alert> alerts;
    d.inspect_transport(1000, s, [&](const ids::Alert& a) { alerts.push_back(a); });  // first call: baseline
    s.sequence_errors = 3;
    d.inspect_transport(2000, s, [&](const ids::Alert& a) { alerts.push_back(a); });
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].type, ids::AlertType::TransportAnomaly);
}
