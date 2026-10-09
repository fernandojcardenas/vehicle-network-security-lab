#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "vnsl/can/frame.hpp"

namespace vnsl::gateway {

/// Which way a frame crosses the gateway between its two buses.
enum class Direction : std::uint8_t { AtoB, BtoA };

std::string_view direction_name(Direction d);

/// One allow rule. A frame is forwarded only if a rule matches its direction, PGN and source,
/// and it is within that rule's rate limit. Anything not matched is denied (default-deny).
struct Rule {
    Direction direction = Direction::AtoB;
    std::optional<std::uint32_t> pgn;   ///< nullopt = any PGN
    std::optional<std::uint8_t> sa;     ///< nullopt = any source address
    double max_rate_hz = 0;             ///< 0 = no rate limit; else a token bucket at this rate
    std::uint32_t burst = 4;            ///< token-bucket depth (frames allowed back to back)
};

enum class Decision : std::uint8_t {
    Allow,
    DenyNoRule,       ///< no allow rule matched (default-deny)
    DenyRateExceeded, ///< a rule matched but its rate limit was exceeded
};

std::string_view decision_name(Decision d);

/// A default-deny forwarding policy for the CAN gateway: a frame crosses only if explicitly
/// allowed. The policy is a list of rules; the first matching rule decides, and its rate limit
/// (if any) is enforced with a per-rule, per-(PGN,SA) token bucket so a flood of an otherwise
/// allowed message cannot pass the gateway.
class Policy {
public:
    void add(const Rule& rule) { rules_.push_back(rule); }

    /// Decides whether `frame` may cross in `direction` at time `frame.t_us`.
    Decision decide(const can::Frame& frame, Direction direction);

    /// Parses a text policy. One rule per line:
    ///   `A>B pgn=65265 sa=0x17 rate=12`  (rate in Hz, optional; sa/pgn optional or `*`)
    ///   `B>A pgn=59904`                  (a diagnostic request may go back)
    /// `#` starts a comment. Returns nullopt and sets `error` on a malformed line.
    static std::optional<Policy> parse(std::string_view text, std::string* error = nullptr);

    [[nodiscard]] std::size_t size() const { return rules_.size(); }

private:
    struct Bucket {
        double tokens = 0;
        std::uint64_t last_us = 0;
        bool seeded = false;
    };
    std::vector<Rule> rules_;
    // One bucket per (rule index, PGN, SA) so each stream is limited independently.
    std::map<std::tuple<std::size_t, std::uint32_t, std::uint8_t>, Bucket> buckets_;
};

}  // namespace vnsl::gateway
