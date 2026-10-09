#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "vnsl/crypto/hmac_sha256.hpp"

using namespace vnsl::crypto;

namespace {
std::vector<std::uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }
std::string hex(std::span<const std::uint8_t> d) {
    static constexpr char k[] = "0123456789abcdef";
    std::string o;
    for (auto b : d) { o.push_back(k[b >> 4]); o.push_back(k[b & 0xF]); }
    return o;
}
}  // namespace

TEST(Sha256, NistExampleDigests) {
    EXPECT_EQ(hex(Sha256::hash({})), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(hex(Sha256::hash(bytes("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(hex(Sha256::hash(bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256, UpdateInChunksMatchesOneShot) {
    std::vector<std::uint8_t> data(1000);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i * 7 + 3);
    const auto once = Sha256::hash(data);
    Sha256 s;
    for (std::size_t i = 0; i < data.size(); i += 7) {
        const std::size_t n = std::min<std::size_t>(7, data.size() - i);
        s.update({data.data() + i, n});
    }
    EXPECT_EQ(s.finish(), once);
}

TEST(HmacSha256, Rfc4231Vectors) {
    EXPECT_EQ(hex(hmac_sha256(bytes("Jefe"), bytes("what do ya want for nothing?"))),
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    const std::vector<std::uint8_t> key1(20, 0x0b);
    EXPECT_EQ(hex(hmac_sha256(key1, bytes("Hi There"))),
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    const std::vector<std::uint8_t> key6(131, 0xaa);
    EXPECT_EQ(hex(hmac_sha256(key6, bytes("Test Using Larger Than Block-Size Key - Hash Key First"))),
              "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}
