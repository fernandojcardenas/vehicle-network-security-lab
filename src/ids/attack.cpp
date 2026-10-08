#include "vnsl/ids/attack.hpp"

#include <algorithm>
#include <array>
#include <random>

#include "vnsl/j1939/id.hpp"
#include "vnsl/j1939/signals.hpp"

namespace vnsl::ids {
namespace {

constexpr std::uint32_t kPgnCcvs1 = 65265;
constexpr std::uint32_t kSpnWheelSpeed = 84;

can::Frame make(std::uint64_t t_us, std::uint8_t priority, std::uint32_t pgn, std::uint8_t sa, std::uint8_t da,
                std::span<const std::uint8_t> data) {
    can::Frame f;
    f.t_us = t_us;
    f.extended = true;
    f.id = j1939::encode_id(priority, pgn, sa, da);
    f.dlc = static_cast<std::uint8_t>(std::min<std::size_t>(data.size(), 8));
    std::copy_n(data.begin(), f.dlc, f.data.begin());
    return f;
}

/// A source address that transmits `pgn` somewhere in `base`, or 0x00 if none does.
std::uint8_t genuine_source_of(const std::vector<can::Frame>& base, std::uint32_t pgn) {
    for (const auto& f : base) {
        if (!f.extended) continue;
        if (j1939::decode_id(f.id).pgn == pgn) return j1939::decode_id(f.id).sa;
    }
    return 0x00;
}

}  // namespace

bool parse_attack_type(std::string_view s, AttackType& out) {
    if (s == "flood")  { out = AttackType::Flood;  return true; }
    if (s == "spoof")  { out = AttackType::Spoof;  return true; }
    if (s == "replay") { out = AttackType::Replay; return true; }
    if (s == "jump")   { out = AttackType::Jump;   return true; }
    if (s == "hijack") { out = AttackType::Hijack; return true; }
    return false;
}

std::string_view attack_type_name(AttackType t) {
    switch (t) {
        case AttackType::Flood:  return "flood";
        case AttackType::Spoof:  return "spoof";
        case AttackType::Replay: return "replay";
        case AttackType::Jump:   return "jump";
        case AttackType::Hijack: return "hijack";
    }
    return "?";
}

AttackResult inject_attack(const std::vector<can::Frame>& base, AttackType type, std::uint64_t start_us,
                           std::uint64_t duration_us, std::uint64_t seed) {
    AttackResult out;
    out.frames = base;
    const std::mt19937_64 rng(seed);
    const std::uint64_t end_us = start_us + duration_us;
    std::vector<can::Frame> injected;

    switch (type) {
        case AttackType::Flood: {
            // A new node (address 0xAA) sends the highest-priority PGN as fast as it can.
            const std::array<std::uint8_t, 8> payload{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            for (std::uint64_t t = start_us; t < end_us; t += 500)
                injected.push_back(make(t, 0, 0x0000, 0xAA, j1939::kGlobalAddress, payload));
            break;
        }
        case AttackType::Spoof: {
            // Extra vehicle-speed frames at a genuine source's address, false high speed, interleaved
            // with the real ones so that source's message rate roughly doubles.
            const std::uint8_t sa = genuine_source_of(base, kPgnCcvs1);
            const std::array<j1939::SignalInput, 1> in{{{kSpnWheelSpeed, 200.0}}};  // 200 km/h
            const auto body = j1939::encode_signals(kPgnCcvs1, in);
            for (std::uint64_t t = start_us; t < end_us; t += 50'000)
                injected.push_back(make(t + 25'000, 6, kPgnCcvs1, sa, j1939::kGlobalAddress, body));
            break;
        }
        case AttackType::Replay: {
            // Re-send a 20 s stretch of earlier real traffic during the window (stale, in-range).
            const std::uint64_t src_from = base.empty() ? 0 : base.front().t_us;
            const std::uint64_t src_to = src_from + 20'000'000;
            std::vector<can::Frame> chunk;
            for (const auto& f : base)
                if (f.t_us >= src_from && f.t_us < src_to) chunk.push_back(f);
            if (!chunk.empty()) {
                const std::uint64_t base_t = chunk.front().t_us;
                for (const auto& f : chunk) {
                    const std::uint64_t t = start_us + (f.t_us - base_t);
                    if (t >= end_us) break;
                    auto g = f;
                    g.t_us = t;
                    injected.push_back(g);
                }
            }
            break;
        }
        case AttackType::Jump: {
            // One wheel-speed frame with a physically impossible value, mid-window.
            const std::uint8_t sa = genuine_source_of(base, kPgnCcvs1);
            const std::array<j1939::SignalInput, 1> in{{{kSpnWheelSpeed, 250.0}}};  // 250 km/h
            const auto body = j1939::encode_signals(kPgnCcvs1, in);
            injected.push_back(make(start_us + duration_us / 2, 6, kPgnCcvs1, sa, j1939::kGlobalAddress, body));
            break;
        }
        case AttackType::Hijack: {
            // Address Claimed for a genuine address with a different NAME, a few times.
            const std::uint8_t sa = base.empty() ? 0x00 : j1939::decode_id(base.front().id).sa;
            std::array<std::uint8_t, 8> name{};
            const std::uint64_t forged = 0xA5A5A5A5A5A5A5A5ULL ^ (static_cast<std::uint64_t>(seed) << 1);
            for (std::size_t i = 0; i < 8; ++i) name[i] = static_cast<std::uint8_t>(forged >> (8 * i));
            for (std::uint64_t t = start_us; t < end_us; t += 1'000'000)
                injected.push_back(make(t, 6, j1939::kPgnAddressClaimed, sa, j1939::kGlobalAddress, name));
            break;
        }
    }

    out.windows.push_back({type, start_us, end_us, injected.size()});
    out.frames.insert(out.frames.end(), injected.begin(), injected.end());
    std::stable_sort(out.frames.begin(), out.frames.end(),
                     [](const can::Frame& a, const can::Frame& b) { return a.t_us < b.t_us; });
    return out;
}

}  // namespace vnsl::ids
