#include "vnsl/gateway/gateway.hpp"

namespace vnsl::gateway {

bool Gateway::forward(const can::Frame& frame, Direction direction) {
    ++stats_.seen;
    switch (policy_.decide(frame, direction)) {
        case Decision::Allow:
            ++stats_.forwarded;
            return true;
        case Decision::DenyNoRule:
            ++stats_.denied_no_rule;
            return false;
        case Decision::DenyRateExceeded:
            ++stats_.denied_rate;
            return false;
    }
    return false;
}

}  // namespace vnsl::gateway
