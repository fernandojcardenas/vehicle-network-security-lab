#include "vnsl/crypto/hmac_sha256.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>

namespace vnsl::crypto {
namespace {

constexpr std::array<std::uint32_t, 64> kK{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

std::uint32_t rotr(std::uint32_t x, unsigned n) { return std::rotr(x, static_cast<int>(n)); }

std::uint32_t load_be32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) << 24 | static_cast<std::uint32_t>(p[1]) << 16 |
           static_cast<std::uint32_t>(p[2]) << 8 | static_cast<std::uint32_t>(p[3]);
}

}  // namespace

void Sha256::reset() {
    h_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    buffer_len_ = 0;
    total_len_ = 0;
}

void Sha256::process(const std::uint8_t* block) {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) w[i] = load_be32(block + 4 * i);
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, h] = h_;
    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = h + s1 + ch + kK[i] + w[i];
        const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> data) {
    total_len_ += data.size();
    std::size_t off = 0;
    if (buffer_len_ > 0) {
        const std::size_t need = kBlockSize - buffer_len_;
        const std::size_t take = std::min(need, data.size());
        std::memcpy(buffer_.data() + buffer_len_, data.data(), take);
        buffer_len_ += take;
        off += take;
        if (buffer_len_ == kBlockSize) {
            process(buffer_.data());
            buffer_len_ = 0;
        }
    }
    for (; off + kBlockSize <= data.size(); off += kBlockSize) process(data.data() + off);
    const std::size_t rem = data.size() - off;
    if (rem > 0) {
        std::memcpy(buffer_.data(), data.data() + off, rem);
        buffer_len_ = rem;
    }
}

std::array<std::uint8_t, Sha256::kDigestSize> Sha256::finish() {
    const std::uint64_t bit_len = total_len_ * 8;
    const std::uint8_t one = 0x80;
    update({&one, 1});
    const std::uint8_t zero = 0;
    while (buffer_len_ != kBlockSize - 8) update({&zero, 1});
    std::array<std::uint8_t, 8> len_be{};
    for (std::size_t i = 0; i < 8; ++i) len_be[i] = static_cast<std::uint8_t>(bit_len >> (56 - 8 * i));
    update(len_be);
    std::array<std::uint8_t, kDigestSize> out{};
    for (std::size_t i = 0; i < 8; ++i) {
        out[4 * i] = static_cast<std::uint8_t>(h_[i] >> 24);
        out[4 * i + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
        out[4 * i + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
        out[4 * i + 3] = static_cast<std::uint8_t>(h_[i]);
    }
    reset();
    return out;
}

std::array<std::uint8_t, Sha256::kDigestSize> Sha256::hash(std::span<const std::uint8_t> data) {
    Sha256 s;
    s.update(data);
    return s.finish();
}

std::array<std::uint8_t, 32> hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message) {
    std::array<std::uint8_t, Sha256::kBlockSize> k0{};
    if (key.size() > Sha256::kBlockSize) {
        const auto kh = Sha256::hash(key);
        std::copy(kh.begin(), kh.end(), k0.begin());
    } else {
        std::copy(key.begin(), key.end(), k0.begin());
    }
    std::array<std::uint8_t, Sha256::kBlockSize> ipad{};
    std::array<std::uint8_t, Sha256::kBlockSize> opad{};
    for (std::size_t i = 0; i < Sha256::kBlockSize; ++i) {
        ipad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x36);
        opad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x5c);
    }
    Sha256 inner;
    inner.update(ipad);
    inner.update(message);
    const auto inner_digest = inner.finish();
    Sha256 outer;
    outer.update(opad);
    outer.update(inner_digest);
    return outer.finish();
}

}  // namespace vnsl::crypto
