#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "vnsl/ids/baseline.hpp"
#include "vnsl/j1939/transport.hpp"

namespace vnsl::ids {

enum class AlertType : std::uint8_t {
    UnknownSource,        ///< a message from an address never seen in training
    UnexpectedPgn,        ///< a known source sending a group it never sent in training
    FloodRate,            ///< a (source, PGN) arriving far faster than its learned minimum gap
    ValueOutOfRange,      ///< a decoded signal outside its learned range (with margin)
    ImpossibleJump,       ///< a signal changing faster than physically seen in training
    TransportAnomaly,     ///< the transport layer reported a new failure (sequence error, orphan, abort, ...)
    AddressClaimConflict, ///< Address Claimed for a known address with a different NAME (hijack)
};

std::string_view alert_type_name(AlertType t);

struct Alert {
    std::uint64_t t_us = 0;
    AlertType type;
    std::uint8_t sa = 0;
    std::uint32_t pgn = 0;
    std::uint32_t spn = 0;    ///< for value/jump alerts, else 0
    std::string detail;       ///< human-readable specifics
};

/// A passive J1939 intrusion detector.
///
/// It takes a learned Baseline and then judges a test stream against it, the way a monitor on
/// the bus would. Every rule is explainable and deterministic: there is no model to train
/// beyond the baseline's observed ranges. The thresholds are multiples of what the baseline
/// saw (configurable), chosen so clean held-out traffic raises essentially no alerts while the
/// injected attacks do. It emits at most one alert of a given (type, sa, pgn, spn) per
/// `dedupe_us` so a flood is one finding, not thousands.
struct DetectorConfig {
    double flood_gap_fraction = 0.5;    ///< flag when a gap is below this fraction of the learned minimum
    double range_margin = 0.1;          ///< widen the learned [min,max] by this fraction of its span each side
    double jump_factor = 3.0;           ///< flag a rate above this multiple of the learned maximum
    std::uint64_t dedupe_us = 1'000'000; ///< collapse repeat alerts of the same key within this window
    std::uint64_t flood_min_gap_floor_us = 1000;  ///< never flag gaps at or above this as a flood (1 ms)
};

class Detector {
public:
    using Config = DetectorConfig;

    Detector(const Baseline& baseline, Config config = {}) : baseline_(baseline), cfg_(config) {}

    using Sink = std::function<void(const Alert&)>;

    /// Judges one decoded message against the baseline, emitting alerts to `sink`.
    void inspect(const j1939::Message& m, const Sink& sink);

    /// Reports transport-layer failures. Call with the reassembler's stats after each frame (or
    /// periodically); the detector alerts on any newly increased failure counter.
    void inspect_transport(std::uint64_t t_us, const j1939::TransportStats& stats, const Sink& sink);

    struct Counts {
        std::uint64_t alerts = 0;
        std::map<AlertType, std::uint64_t> by_type;
    };
    [[nodiscard]] const Counts& counts() const { return counts_; }

private:
    bool emit(const Alert& a, const Sink& sink);  ///< applies dedupe; returns true if emitted

    const Baseline& baseline_;
    Config cfg_;
    std::map<std::pair<std::uint8_t, std::uint32_t>, std::uint64_t> last_seen_us_;  ///< last arrival per (sa,pgn)
    std::map<std::pair<std::uint32_t, std::uint32_t>, std::pair<std::uint64_t, double>> last_signal_;  ///< (pgn,spn)->(t,val)
    std::map<std::pair<std::uint32_t, std::uint32_t>, double> accum_max_;  ///< running max of each accumulator
    std::map<std::string, std::uint64_t> last_alert_us_;
    j1939::TransportStats prev_stats_;
    bool have_prev_stats_ = false;
    Counts counts_;
};

}  // namespace vnsl::ids
