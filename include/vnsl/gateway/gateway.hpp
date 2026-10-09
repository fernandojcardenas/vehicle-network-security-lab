#pragma once

#include <cstdint>
#include <map>

#include "vnsl/can/frame.hpp"
#include "vnsl/gateway/policy.hpp"

namespace vnsl::gateway {

/// A CAN gateway between two buses. It forwards a frame from one bus to the other only if the
/// policy allows it, and counts what it forwarded and what it dropped and why. This is the
/// enforcement point: a diagnostic tool on bus A reaches the powertrain on bus B only through
/// rules the policy author wrote, and even an allowed message cannot flood across because each
/// rule can cap its rate. It is a pure function of the frames it sees, so it runs identically
/// offline over a log and live between two SocketCAN interfaces.
class Gateway {
public:
    explicit Gateway(Policy policy) : policy_(std::move(policy)) {}

    /// Returns true if the frame should be forwarded to the other bus.
    bool forward(const can::Frame& frame, Direction direction);

    struct Stats {
        std::uint64_t seen = 0;
        std::uint64_t forwarded = 0;
        std::uint64_t denied_no_rule = 0;
        std::uint64_t denied_rate = 0;
    };
    [[nodiscard]] const Stats& stats() const { return stats_; }

private:
    Policy policy_;
    Stats stats_;
};

}  // namespace vnsl::gateway
