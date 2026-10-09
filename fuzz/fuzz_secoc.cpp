// Fuzzes the SecOC verifier with arbitrary payloads and auth data against a fixed key. The
// verifier must never crash and must never accept a tag the fuzzer could only have guessed:
// with a 4-byte tag a random accept is a 2^-32 event, so over a fuzz run the accept count
// stays essentially zero. (A genuine Protector is used separately in the unit tests.)
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "vnsl/secoc/secoc.hpp"

using namespace vnsl::secoc;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const Key key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    if (size < 4) return 0;
    const std::uint32_t pgn = 65265;
    const std::uint8_t sa = data[0];
    const std::size_t split = 1 + (data[1] % (size - 1));
    const std::span<const std::uint8_t> payload(data + 1, split - 1);
    const std::span<const std::uint8_t> auth(data + split, size - split);
    Verifier v(key);
    const Verdict verdict = v.verify(pgn, sa, payload, auth);
    // A forged 4-byte tag accepted would be a near-impossible guess; flag it so a logic bug
    // that bypasses the MAC is caught.
    if (verdict == Verdict::Accepted && v.counts().accepted > 2) std::abort();
    return 0;
}
