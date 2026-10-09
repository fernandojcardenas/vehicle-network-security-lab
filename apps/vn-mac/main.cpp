// vn-mac: a tiny helper for tools/crosscheck_crypto.py. Reads lines of "keyhex messagehex"
// and prints "sha256(message) hmac_sha256(key,message)" as hex. Not part of the lab's
// function; it exists so an independent implementation (Python hashlib) can check the crypto.
#include <cstdint>
#include <array>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "vnsl/crypto/hmac_sha256.hpp"

namespace {
std::vector<std::uint8_t> unhex(const std::string& s) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return out;
}
std::string hex(std::span<const std::uint8_t> d) {
    static constexpr std::array<char, 17> k{"0123456789abcdef"};
    std::string o;
    for (auto b : d) { o.push_back(k[b >> 4]); o.push_back(k[b & 0xF]); }
    return o;
}
}  // namespace

int main() {
    std::string key_hex;
    std::string msg_hex;
    while (std::cin >> key_hex >> msg_hex) {
        const auto key = unhex(key_hex == "-" ? "" : key_hex);
        const auto msg = unhex(msg_hex == "-" ? "" : msg_hex);
        const auto sha = vnsl::crypto::Sha256::hash(msg);
        const auto mac = vnsl::crypto::hmac_sha256(key, msg);
        std::cout << hex(sha) << ' ' << hex(mac) << '\n';
    }
    return 0;
}
