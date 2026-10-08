#include "vnsl/ids/baseline.hpp"

#include <cmath>
#include <format>

#include "vnsl/j1939/id.hpp"
#include "vnsl/j1939/signals.hpp"

namespace vnsl::ids {

void Baseline::observe(const j1939::Message& m) {
    ++messages_;
    if (messages_ == 1) first_us_ = m.t_us;
    last_us_ = m.t_us;

    auto& src = sources_[m.sa];
    src.pgns.insert(m.pgn);
    if (m.pgn == j1939::kPgnAddressClaimed && m.data.size() >= 8) {
        std::uint64_t name = 0;
        for (std::size_t i = 8; i-- > 0;) name = (name << 8) | m.data[i];
        src.name = name;
        src.name_seen = true;
    }

    auto& r = rates_[{m.sa, m.pgn}];
    if (r.count > 0 && m.t_us >= r.last_us) {
        const std::uint64_t gap = m.t_us - r.last_us;
        r.min_gap_us = std::min(r.min_gap_us, gap);
        r.sum_gap_us += static_cast<double>(gap);
    }
    r.last_us = m.t_us;
    ++r.count;

    for (const auto& sv : j1939::decode_signals(m.pgn, m.data)) {
        if (sv.status != j1939::Status::Valid) continue;
        auto& s = signals_[{m.pgn, sv.def->spn}];
        if (s.count == 0) {
            s.min_value = s.max_value = sv.value;
        } else {
            s.min_value = std::min(s.min_value, sv.value);
            s.max_value = std::max(s.max_value, sv.value);
            if (m.t_us > s.last_us) {
                const double dt = static_cast<double>(m.t_us - s.last_us) / 1e6;
                const double rate = std::abs(sv.value - s.last_value) / dt;
                s.max_abs_rate = std::max(s.max_abs_rate, rate);
            }
        }
        s.last_value = sv.value;
        s.last_us = m.t_us;
        ++s.count;
    }
}

void Baseline::finalise() {
    for (const auto& [key, r] : rates_) {
        RateProfile p;
        p.count = r.count;
        p.min_gap_us = r.count > 1 ? r.min_gap_us : 0;
        p.mean_gap_us = r.count > 1 ? r.sum_gap_us / static_cast<double>(r.count - 1) : 0;
        rate_out_[key] = p;
    }
    for (const auto& [key, s] : signals_) {
        signal_out_[key] = SignalProfile{s.count, s.min_value, s.max_value, s.max_abs_rate};
    }
    finalised_ = true;
}

std::optional<RateProfile> Baseline::rate(std::uint8_t sa, std::uint32_t pgn) const {
    const auto it = rate_out_.find({sa, pgn});
    if (it == rate_out_.end()) return std::nullopt;
    return it->second;
}

std::optional<SignalProfile> Baseline::signal(std::uint32_t pgn, std::uint32_t spn) const {
    const auto it = signal_out_.find({pgn, spn});
    if (it == signal_out_.end()) return std::nullopt;
    return it->second;
}

std::string Baseline::to_text() const {
    std::string out = std::format("# baseline: {} messages over {:.1f} s, {} sources\n", messages_,
                                  static_cast<double>(window_us()) / 1e6, sources_.size());
    for (const auto& [sa, src] : sources_) {
        out += std::format("source 0x{:02X} name={} groups={}\n", sa, src.name_seen ? std::format("{:#018x}", src.name) : "none",
                           src.pgns.size());
        for (const auto pgn : src.pgns) {
            const auto it = rate_out_.find({sa, pgn});
            const auto name = j1939::pgn_name(pgn);
            if (it != rate_out_.end())
                out += std::format("  pgn {:>6} {:<6} count={} min_gap={}us mean_gap={:.0f}us\n", pgn, name,
                                   it->second.count, it->second.min_gap_us, it->second.mean_gap_us);
        }
    }
    for (const auto& [key, s] : signal_out_) {
        out += std::format("signal pgn {:>6} spn {:>5} count={} range=[{:.4g},{:.4g}] max_rate={:.4g}/s\n", key.first,
                           key.second, s.count, s.min_value, s.max_value, s.max_abs_rate_per_s);
    }
    return out;
}

}  // namespace vnsl::ids
