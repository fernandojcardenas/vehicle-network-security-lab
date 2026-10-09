#include "vnsl/gateway/policy.hpp"

#include <charconv>
#include <string>

#include "vnsl/j1939/id.hpp"

namespace vnsl::gateway {

std::string_view direction_name(Direction d) { return d == Direction::AtoB ? "A>B" : "B>A"; }

std::string_view decision_name(Decision d) {
    switch (d) {
        case Decision::Allow:            return "allow";
        case Decision::DenyNoRule:       return "deny-no-rule";
        case Decision::DenyRateExceeded: return "deny-rate-exceeded";
    }
    return "?";
}

Decision Policy::decide(const can::Frame& frame, Direction direction) {
    const auto id = j1939::decode_id(frame.id);
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const Rule& r = rules_[i];
        if (r.direction != direction) continue;
        if (r.pgn && *r.pgn != id.pgn) continue;
        if (r.sa && *r.sa != id.sa) continue;
        // Matched. Enforce the rate limit, if any, with a token bucket for this exact stream.
        if (r.max_rate_hz <= 0) return Decision::Allow;
        auto& b = buckets_[{i, id.pgn, id.sa}];
        if (!b.seeded) {
            b.tokens = static_cast<double>(r.burst);
            b.last_us = frame.t_us;
            b.seeded = true;
        } else if (frame.t_us > b.last_us) {
            b.tokens += static_cast<double>(frame.t_us - b.last_us) / 1e6 * r.max_rate_hz;
            b.tokens = std::min(b.tokens, static_cast<double>(r.burst));
            b.last_us = frame.t_us;
        }
        if (b.tokens >= 1.0) {
            b.tokens -= 1.0;
            return Decision::Allow;
        }
        return Decision::DenyRateExceeded;
    }
    return Decision::DenyNoRule;
}

namespace {

bool parse_u32(std::string_view s, std::uint32_t& out) {
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s.remove_prefix(2);
    }
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out, base);
    return ec == std::errc{} && p == s.data() + s.size();
}

}  // namespace

std::optional<Policy> Policy::parse(std::string_view text, std::string* error) {
    Policy policy;
    std::size_t line_no = 0;
    const auto fail = [&](const std::string& msg) {
        if (error != nullptr) *error = "line " + std::to_string(line_no) + ": " + msg;
        return std::nullopt;
    };
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t nl = text.find('\n', pos);
        std::string_view line = text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? text.size() + 1 : nl + 1;
        ++line_no;
        if (const auto h = line.find('#'); h != std::string_view::npos) line = line.substr(0, h);
        // trim
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t' || line.front() == '\r')) line.remove_prefix(1);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r')) line.remove_suffix(1);
        if (line.empty()) continue;

        Rule rule;
        bool first = true;
        std::size_t tpos = 0;
        while (tpos < line.size()) {
            std::size_t sp = line.find(' ', tpos);
            while (sp != std::string_view::npos && sp == tpos) { ++tpos; sp = line.find(' ', tpos); }
            if (tpos >= line.size()) break;
            const std::string_view tok = line.substr(tpos, sp == std::string_view::npos ? std::string_view::npos : sp - tpos);
            tpos = sp == std::string_view::npos ? line.size() : sp + 1;
            if (tok.empty()) continue;
            if (first) {
                if (tok == "A>B") rule.direction = Direction::AtoB;
                else if (tok == "B>A") rule.direction = Direction::BtoA;
                else return fail("line must start with A>B or B>A, got '" + std::string(tok) + "'");
                first = false;
                continue;
            }
            const auto eq = tok.find('=');
            if (eq == std::string_view::npos) return fail("expected key=value, got '" + std::string(tok) + "'");
            const std::string_view key = tok.substr(0, eq);
            const std::string_view val = tok.substr(eq + 1);
            if (key == "pgn") {
                if (val != "*") { std::uint32_t v = 0; if (!parse_u32(val, v)) return fail("bad pgn"); rule.pgn = v; }
            } else if (key == "sa") {
                if (val != "*") { std::uint32_t v = 0; if (!parse_u32(val, v) || v > 0xFF) return fail("bad sa"); rule.sa = static_cast<std::uint8_t>(v); }
            } else if (key == "rate") {
                char* end = nullptr;
                const std::string vs(val);
                rule.max_rate_hz = std::strtod(vs.c_str(), &end);
                if (end != vs.c_str() + vs.size() || rule.max_rate_hz < 0) return fail("bad rate");
            } else if (key == "burst") {
                std::uint32_t v = 0; if (!parse_u32(val, v) || v == 0) return fail("bad burst"); rule.burst = v;
            } else {
                return fail("unknown key '" + std::string(key) + "'");
            }
        }
        if (first) return fail("empty rule");
        policy.add(rule);
    }
    return policy;
}

}  // namespace vnsl::gateway
