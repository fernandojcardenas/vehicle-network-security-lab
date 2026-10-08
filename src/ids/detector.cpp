#include "vnsl/ids/detector.hpp"

#include <array>
#include <cmath>
#include <format>

#include "vnsl/j1939/id.hpp"
#include "vnsl/j1939/signals.hpp"

namespace vnsl::ids {

std::string_view alert_type_name(AlertType t) {
    switch (t) {
        case AlertType::UnknownSource:        return "unknown-source";
        case AlertType::UnexpectedPgn:        return "unexpected-pgn";
        case AlertType::FloodRate:            return "flood-rate";
        case AlertType::ValueOutOfRange:      return "value-out-of-range";
        case AlertType::ImpossibleJump:       return "impossible-jump";
        case AlertType::TransportAnomaly:     return "transport-anomaly";
        case AlertType::AddressClaimConflict: return "address-claim-conflict";
    }
    return "?";
}

bool Detector::emit(const Alert& a, const Sink& sink) {
    const std::string key = std::format("{}:{:02x}:{:x}:{:x}", static_cast<int>(a.type), a.sa, a.pgn, a.spn);
    const auto it = last_alert_us_.find(key);
    if (it != last_alert_us_.end() && a.t_us >= it->second && a.t_us - it->second < cfg_.dedupe_us) return false;
    last_alert_us_[key] = a.t_us;
    ++counts_.alerts;
    ++counts_.by_type[a.type];
    sink(a);
    return true;
}

void Detector::inspect(const j1939::Message& m, const Sink& sink) {
    // Address claim with a changed NAME = someone taking a known address.
    if (m.pgn == j1939::kPgnAddressClaimed && m.data.size() >= 8) {
        std::uint64_t name = 0;
        for (std::size_t i = 8; i-- > 0;) name = (name << 8) | m.data[i];
        const auto it = baseline_.sources().find(m.sa);
        if (it != baseline_.sources().end() && it->second.name_seen && it->second.name != name) {
            emit({m.t_us, AlertType::AddressClaimConflict, m.sa, m.pgn, 0,
                  std::format("address 0x{:02X} now claims NAME {:#018x}, was {:#018x}", m.sa, name, it->second.name)},
                 sink);
        }
    }

    if (!baseline_.knows_source(m.sa)) {
        emit({m.t_us, AlertType::UnknownSource, m.sa, m.pgn, 0,
              std::format("no address 0x{:02X} in training", m.sa)}, sink);
        return;  // an unknown source's groups and values are meaningless against this baseline
    }
    const auto& src = baseline_.sources().at(m.sa);
    if (!src.pgns.contains(m.pgn)) {
        emit({m.t_us, AlertType::UnexpectedPgn, m.sa, m.pgn, 0,
              std::format("source 0x{:02X} never sent PGN {} in training", m.sa, m.pgn)}, sink);
    }

    // Rate: too-short a gap for this (source, PGN) means injected or flooded traffic.
    const auto rk = std::pair{m.sa, m.pgn};
    const auto last = last_seen_us_.find(rk);
    if (last != last_seen_us_.end() && m.t_us >= last->second) {
        const std::uint64_t gap = m.t_us - last->second;
        if (const auto r = baseline_.rate(m.sa, m.pgn); r && r->min_gap_us > 0) {
            const auto floor = static_cast<double>(r->min_gap_us) * cfg_.flood_gap_fraction;
            if (static_cast<double>(gap) < floor && gap < cfg_.flood_min_gap_floor_us) {
                emit({m.t_us, AlertType::FloodRate, m.sa, m.pgn, 0,
                      std::format("gap {}us below {:.0f}us (learned min {}us)", gap, floor, r->min_gap_us)}, sink);
            }
        }
    }
    last_seen_us_[rk] = m.t_us;

    // Values. How a signal is judged depends on what kind of signal it is: a learned range only
    // means something for a bounded operational signal that the vehicle drives. Accumulators
    // (odometer, fuel used) only grow, so a decrease is the anomaly. Slow/environmental signals
    // (temperatures, fuel level, the clock) drift past any training window and are not range-checked.
    // Discrete state signals are skipped here (a never-seen state is too noisy to flag this way).
    for (const auto& sv : j1939::decode_signals(m.pgn, m.data)) {
        if (sv.status != j1939::Status::Valid || sv.def->discrete()) continue;
        const auto s = baseline_.signal(m.pgn, sv.def->spn);
        if (!s || s->count < 2) continue;
        const auto sk = std::pair{m.pgn, sv.def->spn};
        const auto cls = j1939::signal_class(sv.def->spn);

        if (cls == j1939::SignalClass::Slow) {
            continue;
        }
        if (cls == j1939::SignalClass::Accumulator) {
            auto it = accum_max_.find(sk);
            double running = it == accum_max_.end() ? s->max_value : it->second;
            const double tol = std::max(std::abs(running) * 1e-3, 1.0);
            if (sv.value < running - tol) {
                emit({m.t_us, AlertType::ValueOutOfRange, m.sa, m.pgn, sv.def->spn,
                      std::format("{} went backwards to {:.6g} {} (was {:.6g}): a counter should not decrease",
                                  sv.def->name, sv.value, sv.def->unit, running)}, sink);
            }
            accum_max_[sk] = std::max(running, sv.value);
            continue;
        }

        // Operational: outside the learned envelope, or changing faster than ever seen.
        const double span = s->max_value - s->min_value;
        const double margin = span * cfg_.range_margin;
        if (sv.value < s->min_value - margin || sv.value > s->max_value + margin) {
            emit({m.t_us, AlertType::ValueOutOfRange, m.sa, m.pgn, sv.def->spn,
                  std::format("{} = {:.4g} {}, learned [{:.4g},{:.4g}]", sv.def->name, sv.value, sv.def->unit,
                              s->min_value, s->max_value)}, sink);
        }
        const auto prev = last_signal_.find(sk);
        if (prev != last_signal_.end() && m.t_us > prev->second.first && s->max_abs_rate_per_s > 0) {
            const double dt = static_cast<double>(m.t_us - prev->second.first) / 1e6;
            const double rate = std::abs(sv.value - prev->second.second) / dt;
            if (rate > s->max_abs_rate_per_s * cfg_.jump_factor) {
                emit({m.t_us, AlertType::ImpossibleJump, m.sa, m.pgn, sv.def->spn,
                      std::format("{} changed {:.4g}/s, learned max {:.4g}/s", sv.def->name, rate,
                                  s->max_abs_rate_per_s)}, sink);
            }
        }
        last_signal_[sk] = {m.t_us, sv.value};
    }
}

void Detector::inspect_transport(std::uint64_t t_us, const j1939::TransportStats& s, const Sink& sink) {
    if (have_prev_stats_) {
        const std::array checks{
            std::tuple{s.sequence_errors - prev_stats_.sequence_errors, "sequence errors"},
            std::tuple{s.orphan_data - prev_stats_.orphan_data, "orphan data packets"},
            std::tuple{s.bad_announcements - prev_stats_.bad_announcements, "bad announcements"},
            std::tuple{s.aborts_seen - prev_stats_.aborts_seen, "connection aborts"},
            std::tuple{s.malformed_tp_frames - prev_stats_.malformed_tp_frames, "malformed transport frames"},
            std::tuple{s.rejected_too_many_sessions - prev_stats_.rejected_too_many_sessions, "rejected sessions"},
        };
        for (const auto& [delta, what] : checks) {
            if (delta > 0)
                emit({t_us, AlertType::TransportAnomaly, 0, 0, 0, std::format("{} new {}", delta, what)}, sink);
        }
    }
    prev_stats_ = s;
    have_prev_stats_ = true;
}

}  // namespace vnsl::ids
