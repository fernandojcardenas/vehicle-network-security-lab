// vn-secoc: adds and checks SecOC-style message authentication on a J1939 log.
//
//   vn-secoc protect IN.log --pgn P [--pgn P ...] [--key HEX] [--out OUT.log]
//   vn-secoc verify  IN.log --pgn P [--pgn P ...] [--key HEX]
//
// protect: for every genuine message of an authenticated PGN, emit a companion authenticator
//   frame (one extra CAN frame) carrying the data PGN, the low freshness byte and a truncated
//   HMAC-SHA256 tag. verify: pair each authenticator with the preceding genuine frame of that
//   PGN and source, check the tag and the freshness, and report the verdict counts and the
//   bandwidth overhead. The authenticator travels on a proprietary PGN (0xFF77); its payload is
//   data-pgn-low(2) || freshness-low(1) || tag(4) = 7 bytes, which fits one 8-byte frame.

#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "vnsl/can/bit_timing.hpp"
#include "vnsl/can/frame.hpp"
#include "vnsl/j1939/id.hpp"
#include "vnsl/secoc/secoc.hpp"

namespace {

constexpr std::uint32_t kSecOcPgn = 0xFF77;  // proprietary B, carries the authenticator

vnsl::secoc::Key parse_key(const std::string& hex) {
    vnsl::secoc::Key k{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};  // default demo key
    if (hex.empty()) return k;
    if (hex.size() != 32) throw std::invalid_argument("--key must be 32 hex chars (16 bytes)");
    for (std::size_t i = 0; i < 16; ++i) k[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
    return k;
}

vnsl::can::Frame authenticator_frame(std::uint64_t t_us, std::uint8_t sa, std::uint32_t data_pgn,
                                     const vnsl::secoc::Auth& a) {
    vnsl::can::Frame f;
    f.t_us = t_us;
    f.extended = true;
    f.id = vnsl::j1939::encode_id(7, kSecOcPgn, sa);
    std::vector<std::uint8_t> body{static_cast<std::uint8_t>(data_pgn >> 8), static_cast<std::uint8_t>(data_pgn)};
    const auto ab = a.bytes();
    body.insert(body.end(), ab.begin(), ab.end());
    f.dlc = static_cast<std::uint8_t>(std::min<std::size_t>(body.size(), 8));
    for (std::size_t i = 0; i < f.dlc; ++i) f.data[i] = body[i];
    return f;
}

std::vector<vnsl::can::Frame> read_log(const std::string& path, std::string& iface, std::uint64_t& unparsed) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path);
    std::vector<vnsl::can::Frame> frames;
    std::string line;
    std::string got;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (auto f = vnsl::can::parse_candump_line(line, &got)) { frames.push_back(*f); iface = got; }
        else ++unparsed;
    }
    return frames;
}

int do_protect(const std::vector<vnsl::can::Frame>& frames, const std::set<std::uint32_t>& pgns,
                const vnsl::secoc::Key& key, const std::string& iface, std::ostream& out) {
    vnsl::secoc::Protector protector(key);
    std::uint64_t added = 0;
    for (const auto& f : frames) {
        out << vnsl::can::format_candump(f, iface) << '\n';
        const auto id = vnsl::j1939::decode_id(f.id);
        if (f.extended && pgns.contains(id.pgn)) {
            const auto auth = protector.protect(id.pgn, id.sa, f.payload());
            const auto af = authenticator_frame(f.t_us, id.sa, id.pgn, auth);
            out << vnsl::can::format_candump(af, iface) << '\n';
            ++added;
        }
    }
    std::cerr << "vn-secoc: protected " << pgns.size() << " PGN(s); added " << added << " authenticator frames\n";
    return 0;
}

int do_verify(const std::vector<vnsl::can::Frame>& frames, const std::set<std::uint32_t>& pgns,
               const vnsl::secoc::Key& key) {
    vnsl::secoc::Verifier verifier(key);
    // Each genuine authenticated-PGN frame is "awaiting" its companion authenticator, which the
    // protector emits immediately after it. A SecOC receiver accepts a message on an
    // authenticated PGN only if a valid authenticator arrives for it; one that never does (a
    // spoofed frame with no MAC, or a stripped authenticator) is rejected as unauthenticated.
    struct Awaiting { std::vector<std::uint8_t> payload; };
    std::map<std::pair<std::uint8_t, std::uint32_t>, Awaiting> awaiting;
    std::uint64_t auth_frames = 0;
    std::uint64_t unauthenticated = 0;
    std::uint64_t orphan_auth = 0;
    std::uint64_t auth_bits = 0;
    std::uint64_t total_bits = 0;

    const auto flush_unauthenticated = [&](std::pair<std::uint8_t, std::uint32_t> key_pair) {
        if (awaiting.erase(key_pair) > 0) ++unauthenticated;
    };

    for (const auto& f : frames) {
        total_bits += vnsl::can::frame_bits(f).total();
        if (!f.extended) continue;
        const auto id = vnsl::j1939::decode_id(f.id);
        if (id.pgn == kSecOcPgn) {
            ++auth_frames;
            auth_bits += vnsl::can::frame_bits(f).total();
            const auto p = f.payload();
            if (p.size() < 3) { verifier.verify(0, id.sa, {}, {}); continue; }  // malformed auth
            const std::uint32_t data_pgn = (static_cast<std::uint32_t>(p[0]) << 8) | p[1];
            const auto it = awaiting.find({id.sa, data_pgn});
            if (it == awaiting.end()) { ++orphan_auth; continue; }  // authenticator with nothing to authenticate
            verifier.verify(data_pgn, id.sa, it->second.payload, p.subspan(2));
            awaiting.erase(it);
        } else if (pgns.contains(id.pgn)) {
            // A previous genuine frame of this PGN+SA that never got its authenticator is unauthenticated.
            flush_unauthenticated({id.sa, id.pgn});
            const auto pl = f.payload();
            awaiting[{id.sa, id.pgn}] = Awaiting{std::vector<std::uint8_t>(pl.begin(), pl.end())};
        }
    }
    unauthenticated += awaiting.size();  // any still-awaiting frame at the end

    const auto& c = verifier.counts();
    const std::uint64_t rejected = c.bad_mac + c.stale + c.malformed + unauthenticated;
    std::cerr << "vn-secoc: " << auth_frames << " authenticator frames\n";
    std::cerr << "  accepted " << c.accepted << "; rejected " << rejected << " (bad-mac " << c.bad_mac << ", stale "
              << c.stale << ", malformed " << c.malformed << ", unauthenticated " << unauthenticated << ")";
    if (orphan_auth > 0) std::cerr << "; " << orphan_auth << " orphan authenticators";
    std::cerr << '\n';
    if (total_bits > 0)
        std::cerr << "  bandwidth overhead: " << (100.0 * static_cast<double>(auth_bits) / static_cast<double>(total_bits))
                  << " % of bus bits are authenticator frames\n";
    return rejected == 0 ? 0 : 3;  // nonzero exit if anything was rejected
}

int run(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: vn-secoc protect|verify IN.log --pgn P [--pgn P ...] [--key HEX] [--out OUT.log]\n";
        return 2;
    }
    const std::string mode = argv[1];
    const std::string in_path = argv[2];
    std::set<std::uint32_t> pgns;
    std::string key_hex;
    std::string out_path;
    for (int i = 3; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--pgn" && i + 1 < argc) pgns.insert(static_cast<std::uint32_t>(std::stoul(argv[++i])));
        else if (a == "--key" && i + 1 < argc) key_hex = argv[++i];
        else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
        else { std::cerr << "vn-secoc: unknown argument " << a << '\n'; return 2; }
    }
    if (pgns.empty()) { std::cerr << "vn-secoc: give at least one --pgn\n"; return 2; }
    const auto key = parse_key(key_hex);
    std::string iface = "can0";
    std::uint64_t unparsed = 0;
    const auto frames = read_log(in_path, iface, unparsed);
    std::ios::sync_with_stdio(false);

    if (mode == "protect") {
        std::ofstream file;
        if (!out_path.empty()) { file.open(out_path); if (!file) { std::cerr << "vn-secoc: cannot write " << out_path << '\n'; return 1; } }
        return do_protect(frames, pgns, key, iface, out_path.empty() ? std::cout : file);
    }
    if (mode == "verify") return do_verify(frames, pgns, key);
    std::cerr << "vn-secoc: mode must be protect or verify\n";
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        (void)std::fputs("vn-secoc: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("vn-secoc: unexpected error\n", stderr);
    }
    return 1;
}
