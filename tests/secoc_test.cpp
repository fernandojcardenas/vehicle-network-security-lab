#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "vnsl/secoc/secoc.hpp"

using namespace vnsl::secoc;

namespace {
const Key kKey{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
std::vector<std::uint8_t> payload(std::uint8_t a, std::uint8_t b) { return {a, b, 0, 0, 0, 0, 0, 0}; }
}  // namespace

TEST(SecOc, GenuineMessagesAreAccepted) {
    Protector p(kKey);
    Verifier v(kKey);
    for (int i = 0; i < 100; ++i) {
        const auto data = payload(static_cast<std::uint8_t>(i), 0x10);
        const auto auth = p.protect(65265, 0x17, data).bytes();
        EXPECT_EQ(v.verify(65265, 0x17, data, auth), Verdict::Accepted) << "message " << i;
    }
    EXPECT_EQ(v.counts().accepted, 100u);
}

TEST(SecOc, ForgedMacIsRejected) {
    Protector p(kKey);
    Verifier v(kKey);
    const auto data = payload(5, 5);
    auto auth = p.protect(65265, 0x17, data).bytes();
    auth.back() ^= 0x01;  // flip a MAC bit
    EXPECT_EQ(v.verify(65265, 0x17, data, auth), Verdict::BadMac);
}

TEST(SecOc, AlteredPayloadIsRejected) {
    Protector p(kKey);
    Verifier v(kKey);
    auto data = payload(5, 5);
    const auto auth = p.protect(65265, 0x17, data).bytes();
    data[0] = 99;  // attacker changes the speed but keeps the captured MAC
    EXPECT_EQ(v.verify(65265, 0x17, data, auth), Verdict::BadMac);
}

TEST(SecOc, WrongKeyIsRejected) {
    Protector p(kKey);
    Key other = kKey;
    other[0] ^= 0xFF;
    Verifier v(other);
    const auto data = payload(5, 5);
    const auto auth = p.protect(65265, 0x17, data).bytes();
    EXPECT_EQ(v.verify(65265, 0x17, data, auth), Verdict::BadMac);
}

TEST(SecOc, ReplayOfAnOldMessageIsRejected) {
    Protector p(kKey);
    Verifier v(kKey);
    const auto d0 = payload(1, 1);
    const auto a0 = p.protect(65265, 0x17, d0).bytes();  // counter 0
    ASSERT_EQ(v.verify(65265, 0x17, d0, a0), Verdict::Accepted);
    for (int i = 1; i < 10; ++i) {
        const auto d = payload(static_cast<std::uint8_t>(i + 1), 1);
        EXPECT_EQ(v.verify(65265, 0x17, d, p.protect(65265, 0x17, d).bytes()), Verdict::Accepted);
    }
    // Attacker re-sends the very first captured (payload, auth): stale freshness.
    EXPECT_EQ(v.verify(65265, 0x17, d0, a0), Verdict::StaleFreshness);
}

TEST(SecOc, FreshnessWrapAcrossAByteBoundaryStillVerifies) {
    Protector p(kKey);
    Verifier v(kKey);
    Verdict last = Verdict::Accepted;
    for (int i = 0; i < 600; ++i) {  // more than 256, so the 1-byte freshness wraps twice
        const auto d = payload(static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(i >> 8));
        last = v.verify(65265, 0x17, d, p.protect(65265, 0x17, d).bytes());
        ASSERT_EQ(last, Verdict::Accepted) << "message " << i;
    }
}

TEST(SecOc, EachPgnHasItsOwnCounter) {
    Protector p(kKey);
    Verifier v(kKey);
    const auto d = payload(7, 7);
    EXPECT_EQ(v.verify(65265, 0x17, d, p.protect(65265, 0x17, d).bytes()), Verdict::Accepted);
    EXPECT_EQ(v.verify(61444, 0x00, d, p.protect(61444, 0x00, d).bytes()), Verdict::Accepted);
    EXPECT_EQ(v.verify(61444, 0x00, d, p.protect(61444, 0x00, d).bytes()), Verdict::Accepted);
}

TEST(SecOc, MalformedAuthIsRejected) {
    Verifier v(kKey);
    const auto d = payload(1, 1);
    const std::vector<std::uint8_t> too_short{0x00, 0x11};
    EXPECT_EQ(v.verify(65265, 0x17, d, too_short), Verdict::Malformed);
}

TEST(SecOc, LongerTagAndFreshnessAlsoWork) {
    const Profile prof{8, 2};  // 64-bit tag, 2 freshness bytes
    Protector p(kKey, prof);
    Verifier v(kKey, prof);
    for (int i = 0; i < 50; ++i) {
        const auto d = payload(static_cast<std::uint8_t>(i), 3);
        const auto auth = p.protect(65265, 0x17, d).bytes();
        EXPECT_EQ(auth.size(), 10u);
        EXPECT_EQ(v.verify(65265, 0x17, d, auth), Verdict::Accepted);
    }
}
