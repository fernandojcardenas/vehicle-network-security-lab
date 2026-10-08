#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "vnsl/j1939/transport.hpp"

namespace vnsl::ids {

/// What one source address was seen doing on the bus during the training window.
struct SourceProfile {
    std::uint64_t name = 0;              ///< NAME from Address Claimed, 0 if none seen
    bool name_seen = false;
    std::set<std::uint32_t> pgns;        ///< parameter groups this source transmitted
};

/// How often one (source address, PGN) pair was sent, in microseconds between messages.
struct RateProfile {
    std::uint64_t count = 0;
    std::uint64_t min_gap_us = 0;        ///< shortest inter-arrival seen
    double mean_gap_us = 0;              ///< mean inter-arrival
};

/// The observed envelope of one signal (SPN): value range and how fast it changed.
struct SignalProfile {
    std::uint64_t count = 0;
    double min_value = 0;
    double max_value = 0;
    double max_abs_rate_per_s = 0;       ///< largest |delta value / delta time| between consecutive samples
};

/// A truck's normal behaviour, learned from one stretch of its own traffic.
///
/// It stores only what a passive observer can see: which addresses transmit, which groups each
/// sends and how often, each measured signal's range and rate of change, and the NAME behind
/// each address. Nothing here is specific to one truck model; the numbers are learned per
/// capture, because two real trucks disagree on final-drive ratio, which sensors they populate,
/// and which proprietary groups they carry.
class Baseline {
public:
    /// Feeds one decoded message from the training window.
    void observe(const j1939::Message& m);

    /// Finalises the learned statistics (call once after the last observe()).
    void finalise();

    [[nodiscard]] bool knows_source(std::uint8_t sa) const { return sources_.contains(sa); }
    [[nodiscard]] const std::map<std::uint8_t, SourceProfile>& sources() const { return sources_; }
    [[nodiscard]] std::optional<RateProfile> rate(std::uint8_t sa, std::uint32_t pgn) const;
    [[nodiscard]] std::optional<SignalProfile> signal(std::uint32_t pgn, std::uint32_t spn) const;
    [[nodiscard]] std::uint64_t messages() const { return messages_; }
    [[nodiscard]] std::uint64_t window_us() const { return last_us_ > first_us_ ? last_us_ - first_us_ : 0; }

    /// Serialises the baseline to a stable text form (for `vn-ids --dump-baseline`), so a human
    /// can read what "normal" was learned to be.
    [[nodiscard]] std::string to_text() const;

private:
    struct RateAccum {
        std::uint64_t count = 0;
        std::uint64_t last_us = 0;
        std::uint64_t min_gap_us = UINT64_MAX;
        double sum_gap_us = 0;
    };
    struct SignalAccum {
        std::uint64_t count = 0;
        double min_value = 0;
        double max_value = 0;
        double last_value = 0;
        std::uint64_t last_us = 0;
        double max_abs_rate = 0;
    };

    std::map<std::uint8_t, SourceProfile> sources_;
    std::map<std::pair<std::uint8_t, std::uint32_t>, RateAccum> rates_;
    std::map<std::pair<std::uint32_t, std::uint32_t>, SignalAccum> signals_;
    std::map<std::pair<std::uint8_t, std::uint32_t>, RateProfile> rate_out_;
    std::map<std::pair<std::uint32_t, std::uint32_t>, SignalProfile> signal_out_;
    std::uint64_t messages_ = 0;
    std::uint64_t first_us_ = 0;
    std::uint64_t last_us_ = 0;
    bool finalised_ = false;
};

}  // namespace vnsl::ids
