#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace vnsl::crypto {

/// SHA-256 (FIPS 180-4). A small, self-contained implementation so the lab has no external
/// crypto dependency; it is validated against the NIST example digests and, in CI, against
/// Python's hashlib on thousands of random inputs.
class Sha256 {
public:
    static constexpr std::size_t kDigestSize = 32;
    static constexpr std::size_t kBlockSize = 64;

    Sha256() { reset(); }
    void reset();
    void update(std::span<const std::uint8_t> data);
    [[nodiscard]] std::array<std::uint8_t, kDigestSize> finish();  ///< finalises; the object is reset afterwards

    static std::array<std::uint8_t, kDigestSize> hash(std::span<const std::uint8_t> data);

private:
    void process(const std::uint8_t* block);

    std::array<std::uint32_t, 8> h_{};
    std::array<std::uint8_t, kBlockSize> buffer_{};
    std::size_t buffer_len_ = 0;
    std::uint64_t total_len_ = 0;
};

/// HMAC-SHA256 (RFC 2104), validated against RFC 4231. Returns the full 32-byte tag; SecOC
/// truncates it.
std::array<std::uint8_t, 32> hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message);

}  // namespace vnsl::crypto
