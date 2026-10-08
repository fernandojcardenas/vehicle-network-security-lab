#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "vnsl/can/frame.hpp"

namespace vnsl::ids {

enum class AttackType : std::uint8_t {
    Flood,       ///< a new node floods the bus with highest-priority frames
    Spoof,       ///< extra CCVS1 frames with a false vehicle speed, at the genuine source's address
    Replay,      ///< a stretch of earlier real frames re-sent later (stale but in-range values)
    Jump,        ///< one wheel-speed frame with a physically impossible value
    Hijack,      ///< an Address Claimed for a genuine address with a different NAME
};

bool parse_attack_type(std::string_view s, AttackType& out);
std::string_view attack_type_name(AttackType t);

/// A window of injected malicious traffic, for scoring.
struct AttackWindow {
    AttackType type;
    std::uint64_t start_us = 0;
    std::uint64_t end_us = 0;
    std::uint64_t injected_frames = 0;
};

struct AttackResult {
    std::vector<can::Frame> frames;    ///< the original frames plus the injected ones, sorted by time
    std::vector<AttackWindow> windows; ///< one per attack applied
};

/// Splices an attack into a recorded frame stream. `base` must be sorted by time. The attack
/// runs in [start_us, start_us + duration_us); injected frames are interleaved and the whole
/// stream is returned sorted. Deterministic given `seed`. Works the same on real captures and
/// on simulated ones, so the injected frames are the only difference between a clean and an
/// attacked log, and the window bounds are the ground truth for scoring.
AttackResult inject_attack(const std::vector<can::Frame>& base, AttackType type, std::uint64_t start_us,
                           std::uint64_t duration_us, std::uint64_t seed = 1);

}  // namespace vnsl::ids
