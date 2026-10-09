#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <span>
#include <string_view>
#include <vector>

namespace vnsl::secoc {

/// A 128-bit shared secret. In a real system this is provisioned per ECU or per group; here it
/// is passed in directly, because key management is out of scope for the lab.
using Key = std::array<std::uint8_t, 16>;

/// A SecOC profile: how many bytes of the HMAC tag are transmitted, and how many low bytes of
/// the freshness counter travel with each message (the rest is kept in sync at both ends).
/// Defaults: a 32-bit tag and one freshness byte, which fit with the payload in a companion
/// CAN frame. AUTOSAR SecOC usually uses AES-128-CMAC; HMAC-SHA256 is the pluggable primitive
/// here (see ADR 0004).
struct Profile {
    std::uint8_t mac_bytes = 4;          ///< truncated tag length, 1..32
    std::uint8_t freshness_bytes = 1;    ///< low bytes of the counter sent on the wire, 1..4
};

/// The authentication data a sender transmits alongside the payload (in a companion frame):
/// the low bytes of the freshness counter, then the truncated MAC.
struct Auth {
    std::vector<std::uint8_t> freshness_low;  ///< `Profile::freshness_bytes` bytes, big-endian low part
    std::vector<std::uint8_t> mac;            ///< `Profile::mac_bytes` bytes
    [[nodiscard]] std::vector<std::uint8_t> bytes() const;  ///< freshness_low || mac, as sent
};

/// Computes the full 32-byte tag over the authenticated fields. Exposed for tests and so the
/// Protector and Verifier share exactly one definition of what is authenticated:
/// pgn(3) || sa(1) || freshness(4, big-endian) || payload.
std::array<std::uint8_t, 32> mac_over(const Key& key, std::uint32_t pgn, std::uint8_t sa,
                                      std::uint32_t freshness, std::span<const std::uint8_t> payload);

/// Sender side: holds a monotonic freshness counter per PGN and produces the auth data.
class Protector {
public:
    Protector(Key key, Profile profile = {}) : key_(key), profile_(profile) {}

    /// Authenticates one message and advances this PGN's counter. The returned counter is the
    /// value used (so a caller can log it); the next call uses counter + 1.
    Auth protect(std::uint32_t pgn, std::uint8_t sa, std::span<const std::uint8_t> payload,
                 std::uint32_t* used_counter = nullptr);

    [[nodiscard]] const Profile& profile() const { return profile_; }

private:
    Key key_;
    Profile profile_;
    std::map<std::uint32_t, std::uint32_t> counter_;  ///< next freshness per PGN
};

enum class Verdict : std::uint8_t {
    Accepted,         ///< MAC valid and freshness advanced
    BadMac,           ///< MAC did not verify (forged, altered, or wrong key)
    StaleFreshness,   ///< freshness did not advance (a replay of an old message)
    Malformed,        ///< the auth data was the wrong size
};

std::string_view verdict_name(Verdict v);

/// Receiver side: holds the last accepted freshness per (source, PGN) and verifies messages.
///
/// Anti-replay: the transmitted low freshness bytes are extended to a full counter just above
/// the last accepted one; the MAC is recomputed over that full counter. A replayed message
/// carries stale low bytes whose extension no longer matches the counter its MAC was made
/// with, so it fails the MAC check; a genuine new message advances the counter and is accepted.
class Verifier {
public:
    Verifier(Key key, Profile profile = {}) : key_(key), profile_(profile) {}

    /// Verifies one message against its auth data (`freshness_low || mac`, as sent).
    Verdict verify(std::uint32_t pgn, std::uint8_t sa, std::span<const std::uint8_t> payload,
                   std::span<const std::uint8_t> auth);

    struct Counts {
        std::uint64_t accepted = 0;
        std::uint64_t bad_mac = 0;
        std::uint64_t stale = 0;
        std::uint64_t malformed = 0;
    };
    [[nodiscard]] const Counts& counts() const { return counts_; }

    static constexpr std::uint32_t kWindow = 256;  ///< how far ahead a freshness jump may skip

private:
    Key key_;
    Profile profile_;
    std::map<std::pair<std::uint8_t, std::uint32_t>, std::uint32_t> last_;  ///< last accepted counter per (sa,pgn)
    std::map<std::pair<std::uint8_t, std::uint32_t>, bool> seen_;
    Counts counts_;
};

}  // namespace vnsl::secoc
