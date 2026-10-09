#include "vnsl/secoc/secoc.hpp"

#include <algorithm>

#include "vnsl/crypto/hmac_sha256.hpp"

namespace vnsl::secoc {

std::vector<std::uint8_t> Auth::bytes() const {
    std::vector<std::uint8_t> out = freshness_low;
    out.insert(out.end(), mac.begin(), mac.end());
    return out;
}

std::array<std::uint8_t, 32> mac_over(const Key& key, std::uint32_t pgn, std::uint8_t sa, std::uint32_t freshness,
                                      std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> msg;
    msg.reserve(8 + payload.size());
    msg.push_back(static_cast<std::uint8_t>(pgn >> 16));
    msg.push_back(static_cast<std::uint8_t>(pgn >> 8));
    msg.push_back(static_cast<std::uint8_t>(pgn));
    msg.push_back(sa);
    msg.push_back(static_cast<std::uint8_t>(freshness >> 24));
    msg.push_back(static_cast<std::uint8_t>(freshness >> 16));
    msg.push_back(static_cast<std::uint8_t>(freshness >> 8));
    msg.push_back(static_cast<std::uint8_t>(freshness));
    msg.insert(msg.end(), payload.begin(), payload.end());
    return crypto::hmac_sha256(key, msg);
}

std::string_view verdict_name(Verdict v) {
    switch (v) {
        case Verdict::Accepted:       return "accepted";
        case Verdict::BadMac:         return "bad-mac";
        case Verdict::StaleFreshness: return "stale-freshness";
        case Verdict::Malformed:      return "malformed";
    }
    return "?";
}

namespace {
std::vector<std::uint8_t> low_bytes(std::uint32_t v, std::uint8_t n) {
    std::vector<std::uint8_t> out(n);
    for (std::size_t i = 0; i < n; ++i) out[n - 1 - i] = static_cast<std::uint8_t>(v >> (8 * i));
    return out;
}
}  // namespace

Auth Protector::protect(std::uint32_t pgn, std::uint8_t sa, std::span<const std::uint8_t> payload,
                        std::uint32_t* used_counter) {
    const std::uint32_t counter = counter_[pgn];
    counter_[pgn] = counter + 1;
    if (used_counter != nullptr) *used_counter = counter;
    const auto full = mac_over(key_, pgn, sa, counter, payload);
    Auth a;
    a.freshness_low = low_bytes(counter, profile_.freshness_bytes);
    a.mac.assign(full.begin(), full.begin() + std::min<std::size_t>(profile_.mac_bytes, full.size()));
    return a;
}

Verdict Verifier::verify(std::uint32_t pgn, std::uint8_t sa, std::span<const std::uint8_t> payload,
                         std::span<const std::uint8_t> auth) {
    const std::size_t want = static_cast<std::size_t>(profile_.freshness_bytes) + profile_.mac_bytes;
    if (auth.size() != want) {
        ++counts_.malformed;
        return Verdict::Malformed;
    }
    std::uint32_t low = 0;
    for (std::uint8_t i = 0; i < profile_.freshness_bytes; ++i) low = (low << 8) | auth[i];
    const auto mac = auth.subspan(profile_.freshness_bytes);

    const auto key = std::pair{sa, pgn};
    const bool seen = seen_[key];
    const std::uint32_t last = last_[key];
    const std::uint32_t low_mask = profile_.freshness_bytes >= 4
                                       ? 0xFFFFFFFFU
                                       : ((1U << (8 * profile_.freshness_bytes)) - 1U);
    const std::uint32_t stride = low_mask + 1;  // 0 if full counter on the wire (handled below)

    auto mac_matches = [&](std::uint32_t candidate) -> bool {
        const auto full = mac_over(key_, pgn, sa, candidate, payload);
        std::uint8_t diff = 0;  // compare the whole truncated tag regardless of a mismatch
        for (std::size_t i = 0; i < mac.size(); ++i) diff |= static_cast<std::uint8_t>(full[i] ^ mac[i]);
        return diff == 0;
    };

    // The full counter the whole freshness is on the wire: exactly one candidate.
    if (low_mask == 0xFFFFFFFFU) {
        if (mac_matches(low)) {
            if (seen && low <= last) { ++counts_.stale; return Verdict::StaleFreshness; }
            last_[key] = low; seen_[key] = true; ++counts_.accepted; return Verdict::Accepted;
        }
        ++counts_.bad_mac; return Verdict::BadMac;
    }

    // Forward: smallest candidate with these low bytes that is strictly greater than `last`
    // (or the smallest non-negative one if nothing has been accepted yet), then onwards.
    const std::uint32_t base_high = seen ? (last & ~low_mask) : 0;
    for (std::uint32_t step = 0; step <= kWindow; ++step) {
        const std::uint32_t candidate = base_high + step * stride + (low & low_mask);
        if (seen && candidate <= last) continue;  // must advance past the last accepted
        if (mac_matches(candidate)) {
            last_[key] = candidate; seen_[key] = true; ++counts_.accepted; return Verdict::Accepted;
        }
    }
    // Backward: a MAC that verifies at or below `last` is a genuine-but-old message (a replay).
    if (seen) {
        for (std::uint32_t step = 0; step <= kWindow; ++step) {
            const std::uint32_t candidate = base_high + (low & low_mask) - step * stride;
            if (candidate > last) continue;
            if (mac_matches(candidate)) { ++counts_.stale; return Verdict::StaleFreshness; }
            if (base_high < step * stride) break;  // underflowed past zero
        }
    }
    ++counts_.bad_mac;
    return Verdict::BadMac;
}

}  // namespace vnsl::secoc
