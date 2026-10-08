// Fuzzes the IDS: arbitrary frames train a baseline, then arbitrary frames are judged against
// it. Checks only that nothing crashes and the detector stays within its invariants; there is
// no oracle for which alerts "should" fire on random input.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "vnsl/can/frame.hpp"
#include "vnsl/ids/baseline.hpp"
#include "vnsl/ids/detector.hpp"
#include "vnsl/j1939/transport.hpp"

using namespace vnsl;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Each 12-byte record is a frame: 4-byte id, 1-byte dlc, 8 data bytes (we read 8 regardless).
    std::vector<can::Frame> frames;
    std::uint64_t t = 0;
    for (std::size_t i = 0; i + 13 <= size; i += 13) {
        can::Frame f;
        t += data[i] * 1000ULL;
        f.t_us = t;
        f.extended = true;
        f.id = (static_cast<std::uint32_t>(data[i + 1]) << 24 | static_cast<std::uint32_t>(data[i + 2]) << 16 |
                static_cast<std::uint32_t>(data[i + 3]) << 8 | data[i + 4]) & 0x1FFFFFFF;
        f.dlc = static_cast<std::uint8_t>(data[i + 5] % 9);
        for (std::size_t k = 0; k < 8; ++k) f.data[k] = data[i + 5 + k];
        frames.push_back(f);
    }
    if (frames.empty()) return 0;
    const std::uint64_t split = frames[frames.size() / 2].t_us;
    ids::Baseline b;
    j1939::Reassembler rx;
    for (const auto& f : frames) {
        if (f.t_us >= split) break;
        rx.on_frame(f, [&](const j1939::Message& m) { b.observe(m); });
    }
    b.finalise();
    (void)b.to_text();
    ids::Detector d(b);
    j1939::Reassembler rx2;
    for (const auto& f : frames) {
        if (f.t_us < split) continue;
        rx2.on_frame(f, [&](const j1939::Message& m) { d.inspect(m, [](const ids::Alert&) {}); });
        d.inspect_transport(f.t_us, rx2.stats(), [](const ids::Alert&) {});
    }
    return 0;
}
