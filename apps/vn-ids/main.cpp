// vn-ids: a passive J1939 intrusion detector. It learns one truck's normal behaviour from a
// training window, then reports anomalies in the rest of the log.
//
//   vn-ids LOG [--format auto|candump|turku] [--train SECONDS] [--train-frac F]
//              [--dump-baseline] [--jsonl]
//
// --train SECONDS      train on the first SECONDS of the log (default: 40% of it)
// --train-frac F       train on the first fraction F (0..1) instead
// --dump-baseline      print the learned baseline and stop
// --jsonl              one JSON object per alert (default: human-readable lines)

#include <cstdint>
#include <cstdio>
#include <exception>
#include <format>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "vnsl/can/frame.hpp"
#include "vnsl/ids/baseline.hpp"
#include "vnsl/ids/detector.hpp"
#include "vnsl/j1939/transport.hpp"

namespace {

enum class Format : std::uint8_t { Auto, Candump, Turku };

std::vector<vnsl::can::Frame> read_log(std::istream& in, Format fmt, std::uint64_t& unparsed) {
    std::vector<vnsl::can::Frame> frames;
    std::string line;
    bool first = true;
    while (std::getline(in, line)) {
        if (first && fmt == Format::Auto)
            fmt = (!line.empty() && line[0] == '(') ? Format::Candump : Format::Turku;
        const bool header = first && fmt == Format::Turku && line.starts_with("timestamp");
        first = false;
        if (header || line.empty() || line == "\r") continue;
        const auto f = fmt == Format::Candump ? vnsl::can::parse_candump_line(line)
                                              : vnsl::can::parse_turku_csv_line(line);
        if (f) frames.push_back(*f); else ++unparsed;
    }
    return frames;
}

int run(int argc, char** argv) {
    std::string path;
    Format fmt = Format::Auto;
    double train_s = -1;
    double train_frac = 0.4;
    bool dump = false;
    bool jsonl = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--format" && i + 1 < argc) {
            const std::string_view f = argv[++i];
            fmt = Format::Auto;
            if (f == "candump") fmt = Format::Candump;
            else if (f == "turku") fmt = Format::Turku;
        } else if (a == "--train" && i + 1 < argc) {
            train_s = std::stod(argv[++i]);
        } else if (a == "--train-frac" && i + 1 < argc) {
            train_frac = std::stod(argv[++i]);
        } else if (a == "--dump-baseline") {
            dump = true;
        } else if (a == "--jsonl") {
            jsonl = true;
        } else if (!a.empty() && a[0] != '-') {
            path = a;
        } else if (a == "-h" || a == "--help") {
            std::cerr << "usage: vn-ids LOG [--train SECONDS|--train-frac F] [--dump-baseline] [--jsonl]\n";
            return 0;
        } else {
            std::cerr << "vn-ids: unknown argument " << a << '\n';
            return 2;
        }
    }

    std::ifstream file;
    if (!path.empty()) {
        file.open(path, std::ios::binary);
        if (!file) { std::cerr << "vn-ids: cannot open " << path << '\n'; return 1; }
    }
    std::istream& in = path.empty() ? std::cin : file;
    std::ios::sync_with_stdio(false);

    std::uint64_t unparsed = 0;
    const auto frames = read_log(in, fmt, unparsed);
    if (frames.size() < 2) { std::cerr << "vn-ids: need at least two frames\n"; return 1; }
    const std::uint64_t t0 = frames.front().t_us;
    const std::uint64_t t_end = frames.back().t_us;
    const std::uint64_t split = train_s >= 0 ? t0 + static_cast<std::uint64_t>(train_s * 1e6)
                                             : t0 + static_cast<std::uint64_t>(static_cast<double>(t_end - t0) * train_frac);

    // Train: decode frames up to the split and learn the baseline.
    vnsl::ids::Baseline baseline;
    vnsl::j1939::Reassembler train_rx;
    for (const auto& f : frames) {
        if (f.t_us >= split) break;
        train_rx.on_frame(f, [&](const vnsl::j1939::Message& m) { baseline.observe(m); });
    }
    baseline.finalise();

    if (dump) { std::cout << baseline.to_text(); return 0; }

    std::cerr << std::format("vn-ids: trained on {:.1f} s ({} messages, {} sources), testing on {:.1f} s\n",
                             static_cast<double>(split - t0) / 1e6, baseline.messages(), baseline.sources().size(),
                             static_cast<double>(t_end >= split ? t_end - split : 0) / 1e6);

    // Test: decode the rest and run the detector.
    vnsl::ids::Detector detector(baseline);
    vnsl::j1939::Reassembler test_rx;
    const auto on_alert = [&](const vnsl::ids::Alert& a) {
        if (jsonl) {
            std::cout << std::format(R"({{"t":{}.{:06},"type":"{}","sa":{},"pgn":{},"spn":{},"detail":"{}"}})",
                                     a.t_us / 1'000'000ULL, a.t_us % 1'000'000ULL,
                                     vnsl::ids::alert_type_name(a.type), a.sa, a.pgn, a.spn, a.detail)
                      << '\n';
        } else {
            std::cout << std::format("{:.6f}  {:<22} sa=0x{:02X} pgn={:<6} {}\n", static_cast<double>(a.t_us) / 1e6,
                                     vnsl::ids::alert_type_name(a.type), a.sa, a.pgn, a.detail);
        }
    };
    for (const auto& f : frames) {
        if (f.t_us < split) continue;
        test_rx.on_frame(f, [&](const vnsl::j1939::Message& m) { detector.inspect(m, on_alert); });
        detector.inspect_transport(f.t_us, test_rx.stats(), on_alert);
    }

    std::cerr << std::format("vn-ids: {} alerts\n", detector.counts().alerts);
    for (const auto& [type, n] : detector.counts().by_type)
        std::cerr << std::format("  {:<22} {}\n", vnsl::ids::alert_type_name(type), n);
    if (unparsed > 0) std::cerr << "vn-ids: " << unparsed << " unparsed lines\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        (void)std::fputs("vn-ids: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("vn-ids: unexpected error\n", stderr);
    }
    return 1;
}
